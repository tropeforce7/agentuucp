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

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/store"
	"github.com/tropeforce7/agentuucp/internal/stream"
)

// The outbox holds streams that have been sealed but not yet delivered.
//
// A sealed stream cannot be rebuilt. The HPKE context advances its nonce on
// every chunk and cannot be rewound, so a chunk the relay did not receive
// could never be sealed identically a second time; the bytes on disk are the
// only bytes that will ever open. That is why the sealed file survives a
// crash, and why it is paired with a small record of everything the upload
// needs to be picked up again in a later process.
//
// Both files are removed together the moment the relay acknowledges the
// message. Anything left in the outbox is an interruption.

// pending is the record beside a sealed stream: who it is for, how far the
// upload got, and enough of the message to write the sent/ copy at the end.
type pending struct {
	MessageID string `json:"message_id"`
	To        string `json:"to"`
	ToName    string `json:"to_name,omitempty"`
	// Relay is the name of the relay the upload was opened on. It cannot be
	// finished anywhere else: the relay holds a prefix of these exact bytes
	// under an identifier that is its own. A record written before a home
	// could know more than one relay names none, and is resumed on the
	// default, which is where it was opened.
	Relay  string `json:"relay,omitempty"`
	Upload string `json:"upload,omitempty"`
	// MaxRequest is what the relay said it would take in one PATCH when the
	// upload was opened. It is recorded because a resume does not reopen the
	// upload and so never hears it again; without it a resumed upload would
	// fall back to a guess and send several times as many requests.
	MaxRequest int64 `json:"max_request,omitempty"`
	// Channel is the recipient's channel the stream is for, so a resumed
	// upload is opened for the same one; empty is default.
	Channel   string       `json:"channel,omitempty"`
	Started   time.Time    `json:"started"`
	Time      time.Time    `json:"time"`
	Body      message.Body `json:"body"`
	Bytes     int64        `json:"bytes"`
	Chunks    int64        `json:"chunks"`
	ChunkSize int          `json:"chunk_size"`
}

func outboxDir(s *store.Store) string { return filepath.Join(s.Root(), "outbox") }

func streamPath(s *store.Store, id string) string {
	return filepath.Join(outboxDir(s), id+".stream")
}

func pendingPath(s *store.Store, id string) string {
	return filepath.Join(outboxDir(s), id+".json")
}

// save writes the record atomically. It is rewritten each time the upload
// identifier changes, which is the one field a later process cannot derive.
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
	return os.Rename(tmp.Name(), pendingPath(s, p.MessageID))
}

// remove clears both halves. The record goes first: without it the sealed file
// is unfinishable, so a crash between the two leaves nothing that looks
// resumable.
func (p *pending) remove(s *store.Store) {
	os.Remove(pendingPath(s, p.MessageID))
	os.Remove(streamPath(s, p.MessageID))
}

// listPending returns every unfinished stream, oldest first. A record whose
// sealed file has gone is not resumable and is reported rather than returned,
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
		data, err := os.ReadFile(filepath.Join(outboxDir(s), name))
		if err != nil {
			return nil, nil, err
		}
		var p pending
		if err := json.Unmarshal(data, &p); err != nil {
			broken = append(broken, strings.TrimSuffix(name, ".json"))
			continue
		}
		// The id names the file, so a record that disagrees with its own name
		// would point the upload at somebody else's bytes.
		if p.MessageID != strings.TrimSuffix(name, ".json") {
			broken = append(broken, strings.TrimSuffix(name, ".json"))
			continue
		}
		// The id and the recipient are what the sender wrote, an id and
		// a fingerprint; a label shows the first twelve of each.
		if message.ValidID(p.MessageID) != nil || !identity.ValidFingerprint(p.To) {
			broken = append(broken, p.MessageID)
			continue
		}
		// The numbers are the sender's own from when the upload began; a
		// record whose numbers could not have been written by it is
		// broken, before any of them is a seek, a piece or a count.
		if p.Bytes < 0 || p.Chunks < 0 || p.MaxRequest < 0 ||
			p.ChunkSize < stream.MinChunkSize || p.ChunkSize > stream.MaxChunkSize {
			broken = append(broken, p.MessageID)
			continue
		}
		if _, err := os.Stat(streamPath(s, p.MessageID)); err != nil {
			broken = append(broken, p.MessageID)
			continue
		}
		out = append(out, &p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Started.Before(out[j].Started) })
	return out, broken, nil
}

// warnPending tells somebody sending a new message that an old one never
// arrived. It is a warning and never an error: the new message is not the
// place to make them deal with the old one.
func warnPending(s *store.Store) {
	waiting, _, err := listPending(s)
	if err != nil || len(waiting) == 0 {
		return
	}
	noun := "stream"
	if len(waiting) > 1 {
		noun = "streams"
	}
	fmt.Fprintf(os.Stderr, "warning: %d unfinished %s in the outbox; finish with '%s send --resume'\n",
		len(waiting), noun, prog)
}
