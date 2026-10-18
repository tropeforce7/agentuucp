package auu

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/tropeforce7/agentuucp/internal/client"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/regular"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/store"
	"github.com/tropeforce7/agentuucp/internal/stream"
	"github.com/tropeforce7/agentuucp/internal/wire"
)

// The outbox holds what has been sealed but not yet delivered: a stream, and
// a copy of a message to several.
//
// A sealed stream cannot be rebuilt. The HPKE context advances its nonce on
// every chunk and cannot be rewound, so a chunk the relay did not receive
// could never be sealed identically a second time; the bytes on disk are the
// only bytes that will ever open. That is why the sealed file survives a
// crash, and why it is paired with a small record of everything the upload
// needs to be picked up again in a later process.
//
// A copy of a message to several is sealed with every other copy before
// any is posted (D48), so that a copy the relay refuses is still the
// message the others are, under the same id, and can be posted later
// without sealing it again; a message to one is sealed and posted at once
// and never comes here.
//
// The two kinds are told apart by the sealed file beside the record, a
// .stream or an .env, and by nothing in the record, so a record v0.15.0
// wrote reads as it was written. A stream to one is named by its message id;
// a copy, of either kind, by the id and the first sixteen characters of its
// recipient's fingerprint, since the id is one for every copy and a file
// name must not be.
//
// Both files are removed together the moment the relay acknowledges the
// message. Anything left in the outbox is an interruption or a refusal.

// pending is the record beside a sealed stream or copy: who it is for, how
// far the upload got, and enough of the message to write the sent/ copy at
// the end.
type pending struct {
	MessageID string `json:"message_id"`
	To        string `json:"to"`
	ToName    string `json:"to_name,omitempty"`
	// Relay is the name of the relay the upload was opened on. It cannot be
	// finished anywhere else: the relay holds a prefix of these exact bytes
	// under an identifier that is its own. Every record names one, so the
	// key is always written, and a record without it is broken.
	Relay  string `json:"relay"`
	Upload string `json:"upload,omitempty"`
	// Channel is the recipient's channel the stream is for, so a resumed
	// upload is opened for the same one; empty is default.
	Channel   string       `json:"channel,omitempty"`
	Started   time.Time    `json:"started"`
	Time      time.Time    `json:"time"`
	Body      message.Body `json:"body"`
	Bytes     int64        `json:"bytes"`
	Chunks    int64        `json:"chunks"`
	ChunkSize int          `json:"chunk_size"`
	// Path is the relays a copy goes by before its recipient's, joined by
	// "!", empty for a recipient on the relay it is posted to.
	Path string `json:"path,omitempty"`
	// RecipientCount is how many recipients the message a copy belongs to
	// went to, said again to the relay whenever the copy is posted by a
	// route that carries a count, so that a resumed copy is held as the
	// first attempt was; zero for a message to one.
	RecipientCount int `json:"recipient_count,omitempty"`
	// RefusedCode and Refused are the relay's code and sentence the last
	// time it refused this copy, so that the outbox says why a copy waits.
	// The sentence is the relay's, kept in a file this program wrote, and
	// is held to a rule at the read and escaped wherever it is shown.
	RefusedCode string `json:"refused_code,omitempty"`
	Refused     string `json:"refused,omitempty"`

	// stem is the name the record's files share, as listPending read it or
	// as the writer chose it; kind is which sealed file is beside it.
	stem string
	kind string
}

const (
	kindStream   = "stream"
	kindEnvelope = "envelope"
)

func outboxDir(s *store.Store) string { return filepath.Join(s.Root(), "outbox") }

// copyStem is the name a copy's files share: the message id and the first
// sixteen characters of the recipient's fingerprint, both held to their
// rules before this is called.
func copyStem(messageID, to string) string {
	return messageID + "-" + to[:identity.ShortIDLen]
}

// name is the stem of the record's files: the one it was read from or
// written under, or, for a stream to one made before that was known, its
// message id.
func (p *pending) name() string {
	if p.stem != "" {
		return p.stem
	}
	return p.MessageID
}

func streamPath(s *store.Store, stem string) string {
	return filepath.Join(outboxDir(s), stem+".stream")
}

func envPath(s *store.Store, stem string) string {
	return filepath.Join(outboxDir(s), stem+".env")
}

func pendingPath(s *store.Store, stem string) string {
	return filepath.Join(outboxDir(s), stem+".json")
}

// sealedPath is the sealed file beside the record, by its kind.
func (p *pending) sealedPath(s *store.Store) string {
	if p.kind == kindEnvelope {
		return envPath(s, p.name())
	}
	return streamPath(s, p.name())
}

// save writes the record atomically. It is rewritten each time the upload
// identifier changes, which is the one field a later process cannot derive,
// and each time a copy is refused, with the relay's words.
func (p *pending) save(s *store.Store) error {
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	dir := outboxDir(s)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".pending-*")
	if err != nil {
		return err
	}
	defer func() {
		tmp.Close()
		os.Remove(tmp.Name())
	}()
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), pendingPath(s, p.name()))
}

// remove clears both halves. The record goes first: without it the sealed file
// is unfinishable, so a crash between the two leaves nothing that looks
// resumable. What will not go is the error, never discarded (G43, R59): a
// record that will not go leaves its sealed file beside it, so the copy is
// still whole and the next 'send --resume' sends it; a sealed file that will
// not go, its record gone, is an orphan nothing lists or sends.
func (p *pending) remove(s *store.Store) error {
	record := pendingPath(s, p.name())
	if err := os.Remove(record); err != nil && !errors.Is(err, os.ErrNotExist) {
		return &removeError{path: record, err: err}
	}
	sealed := p.sealedPath(s)
	if err := os.Remove(sealed); err != nil && !errors.Is(err, os.ErrNotExist) {
		return &removeError{path: sealed, err: err, orphan: true}
	}
	return nil
}

// removeError is a half of an outbox entry that would not go, said for what
// it leaves behind.
type removeError struct {
	path   string
	err    error
	orphan bool
}

func (e *removeError) Error() string {
	if e.orphan {
		return fmt.Sprintf("the outbox record is gone but the sealed file %s could not be removed: %v; "+
			"nothing lists it now, and unless another %s is sending it at this moment it can be removed by hand",
			e.path, e.err, prog)
	}
	return fmt.Sprintf("the outbox record %s could not be removed: %v; the next '%s send --resume' would send that copy",
		e.path, e.err, prog)
}

func (e *removeError) Unwrap() error { return e.err }

// withLeftovers is err with what of written would not be taken back, for a
// caller that gives a message up before any of it went, and whether any
// was left: the outbox keeps what is named there, and the next 'send
// --resume' would send a record that stayed.
func withLeftovers(err error, written []*pending, s *store.Store) (bool, error) {
	var left []string
	for _, p := range written {
		if rerr := p.remove(s); rerr != nil {
			left = append(left, rerr.Error())
		}
	}
	if len(left) == 0 {
		return false, err
	}
	return true, fmt.Errorf("%w; and what was written of it could not all be taken back: %s", err, strings.Join(left, "; "))
}

// clear is remove for a caller whose own work has ended, a send finished or
// one given up before it went: a half that will not go is said on standard
// error, with its path and what it leaves, and the caller's outcome stands.
func (p *pending) clear(s *store.Store) {
	if err := p.remove(s); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", prog, err)
	}
}

// listPending returns every unfinished stream and copy, oldest first. A
// record whose sealed file has gone, or which has both kinds beside it, is
// not resumable and is reported by its file's name rather than returned,
// because the bytes cannot be made again.
func listPending(s *store.Store) ([]*pending, []string, error) {
	entries, err := os.ReadDir(outboxDir(s))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	var out []*pending
	var broken []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".json") {
			continue
		}
		stem := strings.TrimSuffix(name, ".json")
		data, err := regular.ReadFile(filepath.Join(outboxDir(s), name))
		if err != nil {
			return nil, nil, err
		}
		// Strictly: a record from before this wire carries fields this
		// record does not (max_request), and would be resumed against a
		// PUT it never had; it is broken by name and abandoned.
		var p pending
		if err := wire.Decode(data, &p); err != nil {
			broken = append(broken, stem)
			continue
		}
		// The id and the recipient are what the sender wrote, an id and
		// a fingerprint; a label shows the first twelve of each. The
		// relay is a name this home gave; a record that names none is
		// from before a home could know more than one relay, and
		// nothing on this machine is from before.
		// The upload id is the relay's, kept from its answer, and goes
		// into a request's path on a resume (F9).
		if message.ValidID(p.MessageID) != nil || !identity.ValidFingerprint(p.To) ||
			store.ValidRelayName(p.Relay) != nil || p.Upload != "" && !client.ValidUploadID(p.Upload) {
			broken = append(broken, stem)
			continue
		}
		// The stem names the files, so a record that disagrees with its
		// own name would point the upload at somebody else's bytes: it is
		// the id, for a stream to one, or the id and the recipient's
		// short fingerprint, for a copy.
		copied := stem == copyStem(p.MessageID, p.To)
		if stem != p.MessageID && !copied {
			broken = append(broken, stem)
			continue
		}
		p.stem = stem
		// The kind is the sealed file beside the record, and exactly one.
		_, streamErr := os.Stat(streamPath(s, stem))
		_, envErr := os.Stat(envPath(s, stem))
		switch {
		case streamErr == nil && envErr != nil:
			p.kind = kindStream
		case envErr == nil && streamErr != nil:
			p.kind = kindEnvelope
		default:
			broken = append(broken, stem)
			continue
		}
		if !p.validShape(copied) {
			broken = append(broken, stem)
			continue
		}
		out = append(out, &p)
	}
	// Oldest first, and the copies of one message, started together, in the
	// order of their names, so that a listing reads the same each time.
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Started.Equal(out[j].Started) {
			return out[i].Started.Before(out[j].Started)
		}
		return out[i].name() < out[j].name()
	})
	return out, broken, nil
}

// validShape holds a record to what this program writes for its kind. The
// numbers are the sender's own from when the upload began; a record whose
// numbers could not have been written by it is broken, before any of them
// is a seek, a piece or a count. A copy is always one of several and
// always named as one; a message to one has no count. The kept refusal is
// the relay's sentence, held to what the relay that reports one is held
// to, a line of at most relayapi.MaxSaid bytes, and its code to the name
// rule, since both are shown.
func (p *pending) validShape(copied bool) bool {
	if copied != (p.RecipientCount != 0) {
		return false
	}
	if p.RecipientCount != 0 && (p.RecipientCount < 2 || p.RecipientCount > relayapi.MaxRecipients) {
		return false
	}
	if p.Path != "" && store.CheckAddress(strings.Split(p.Path, "!"), nil, relayapi.MaxHops) != nil {
		return false
	}
	if p.RefusedCode != "" && wire.ValidName(p.RefusedCode) != nil {
		return false
	}
	// The recipient's name is the one this machine gave them, which the
	// peer list holds to the name rule, and every print of a record says
	// it: a record that names them otherwise was not written here.
	if p.ToName != "" && identity.ValidName(p.ToName) != nil {
		return false
	}
	if len(p.Refused) > relayapi.MaxSaid || message.ValidOneLine("refused", p.Refused) != nil {
		return false
	}
	switch p.kind {
	case kindStream:
		// A stream crosses no relay, so its record names no path.
		return p.Path == "" && p.Bytes >= 0 && p.Chunks >= 0 &&
			p.ChunkSize >= stream.MinChunkSize && p.ChunkSize <= stream.MaxChunkSize
	case kindEnvelope:
		// A copy is posted whole, never uploaded, so it has none of an
		// upload's numbers.
		return copied && p.Upload == "" && p.Chunks == 0 && p.ChunkSize == 0 && p.Bytes >= 0
	}
	return false
}

// warnPending tells somebody sending a new message that an old one never
// arrived. It is a warning and never an error: the new message is not the
// place to make them deal with the old one.
func warnPending(s *store.Store) {
	waiting, _, err := listPending(s)
	if err != nil || len(waiting) == 0 {
		return
	}
	var streams, copies int
	for _, p := range waiting {
		if p.kind == kindEnvelope {
			copies++
		} else {
			streams++
		}
	}
	var kinds []string
	if streams > 0 {
		kinds = append(kinds, howMany(streams, "stream", "streams"))
	}
	if copies > 0 {
		kinds = append(kinds, howMany(copies, "copy", "copies"))
	}
	fmt.Fprintf(os.Stderr, "warning: %s in the outbox (%s); finish with '%s send --resume' or give one up with '%s outbox drop ID'\n",
		howMany(len(waiting), "unfinished message", "unfinished messages"), strings.Join(kinds, ", "), prog, prog)
}

// howMany is n and the word for that many, for a word whose plural is not
// its singular with an s, as plural's is.
func howMany(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}
