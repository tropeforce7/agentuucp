package auu

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/tropeforce7/agentuucp/internal/client"
	"github.com/tropeforce7/agentuucp/internal/envelope"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/regular"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/store"
	"github.com/tropeforce7/agentuucp/internal/term"
	"github.com/tropeforce7/agentuucp/internal/wire"
)

// sealedCopy is one copy of a message to several as SealMany made it, with
// what the outbox keeps beside it: the recipient's name on this machine and
// the relays the copy goes by.
type sealedCopy struct {
	env    *envelope.Envelope
	inner  *envelope.Inner
	toName string
	path   []string
}

// writeCopies writes every copy of a message to several to the outbox
// before any is posted (D48): each sealed envelope as it will be posted,
// its channel on the outer field as the post puts it there, beside a record
// naming its recipient, its relay, its path and how many the message went
// to. The sealed file is made exclusively, so two recipients whose
// fingerprints begin with the same sixteen characters are refused by name
// rather than one copy written over another. A copy that cannot be written
// takes the ones written before it with it, so an error part way leaves
// none of the message in the outbox; a crash part way leaves the copies
// written so far, each whole and resumable, which `auu outbox` lists and
// `auu outbox drop` gives up.
func writeCopies(s *store.Store, r *store.Relay, channel string, copies []sealedCopy) ([]*pending, error) {
	if err := os.MkdirAll(outboxDir(s), 0o700); err != nil {
		return nil, err
	}
	var written []*pending
	undo := func() {
		for _, p := range written {
			p.remove(s)
		}
	}
	started := time.Now().UTC().Truncate(time.Second)
	for _, c := range copies {
		outer := *c.env
		outer.Ch = channel
		raw, err := json.Marshal(&outer)
		if err != nil {
			undo()
			return nil, err
		}
		p := &pending{
			MessageID:      c.inner.ID,
			To:             c.env.To,
			ToName:         c.toName,
			Relay:          r.Name,
			Channel:        channel,
			Started:        started,
			Time:           c.inner.Time,
			Body:           c.inner.Body,
			Bytes:          int64(len(raw)),
			Path:           store.JoinAddress(c.path),
			RecipientCount: len(copies),
			stem:           copyStem(c.inner.ID, c.env.To),
			kind:           kindEnvelope,
		}
		f, err := os.OpenFile(envPath(s, p.stem), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, os.ErrExist) {
			undo()
			return nil, fmt.Errorf("two recipients' fingerprints begin with %s, which names a copy's file in the outbox; "+
				"send to them in separate messages", p.To[:identity.ShortIDLen])
		}
		if err != nil {
			undo()
			return nil, err
		}
		_, werr := f.Write(raw)
		if serr := f.Sync(); werr == nil {
			werr = serr
		}
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			os.Remove(envPath(s, p.stem))
			undo()
			return nil, werr
		}
		// The record goes down after the sealed copy, so a crash between
		// the two leaves a file nothing lists, never a record with nothing
		// to post.
		if err := p.save(s); err != nil {
			os.Remove(envPath(s, p.stem))
			undo()
			return nil, err
		}
		written = append(written, p)
	}
	return written, nil
}

// finishCopy posts one copy from the outbox, by its record's path, and
// removes it once the relay has it. A refusal keeps the record with the
// relay's code and sentence, so that the outbox says why the copy waits and
// --resume tries it again; a refusal is any answer the relay gave, a fault
// of its own among them, which its sentence says. Anything else, a relay
// that could not be reached, keeps the record as it was. Either way the
// message's sent record says so, when there is one (ruling 74, point 4).
func finishCopy(s *store.Store, id *identity.Identity, r *store.Relay, p *pending) (sentJSON, error) {
	c, err := dial(s, id, r)
	if err != nil {
		return sentJSON{}, err
	}
	relayID, err := postCopy(c, s, p)
	if err != nil {
		refuseCopy(s, p, err)
		return sentJSON{}, transportErr(err)
	}
	landCopy(s, p, relayID)
	return sentJSON{
		ID: p.MessageID, Thread: p.Body.Thread, To: p.To, ToName: p.ToName,
		RelayID: relayID, Bytes: int(p.Bytes), InReplyTo: p.Body.InReplyTo,
		Kind: kindEnvelope, Channel: p.Channel, Path: p.Path,
	}, nil
}

// finishStreamCopy uploads one stream of a message to several from the
// outbox, as --resume finishes it, and lands it in the message's sent record
// as finishCopy lands an envelope: never a record of its own, which would
// write over the message's one record with a copy's. A refusal keeps the
// sealed stream with the relay's code and sentence, as an envelope copy's is
// kept (D48), whatever it costs on disk, since the sealed bytes are the only
// ones that will open and the person decides whether to give them up.
func finishStreamCopy(s *store.Store, id *identity.Identity, r *store.Relay, p *pending) (sentJSON, error) {
	c, err := dial(s, id, r)
	if err != nil {
		return sentJSON{}, err
	}
	relayID, err := uploadStream(c, s, p)
	if err != nil {
		refuseCopy(s, p, err)
		// What stays is the whole payload on disk, so the sentence names
		// the drop beside --resume, as the send that sealed it did.
		return sentJSON{}, transportErr(fmt.Errorf("%w; the sealed stream waits in the outbox: finish it with '%s send --resume', "+
			"or give it up with '%s outbox drop %s %s'",
			streamFullHint(streamChannelHint(err, s, id, c, r, p), p.label()), prog, prog, p.MessageID[:12], p.label()))
	}
	landCopy(s, p, relayID)
	return sentJSON{
		ID: p.MessageID, Thread: p.Body.Thread, To: p.To, ToName: p.ToName,
		RelayID: relayID, Bytes: int(p.Bytes), InReplyTo: p.Body.InReplyTo,
		Kind: kindStream, Chunks: p.Chunks, ChunkSize: p.ChunkSize, Channel: p.Channel,
	}, nil
}

// postCopy posts one sealed copy as its record says: by its path or into
// its recipient's mailbox, saying how many the message went to on a
// forward. The file is this program's own, written beside the record; it is
// read strictly all the same, and must be the copy the record names.
func postCopy(c *client.Client, s *store.Store, p *pending) (int64, error) {
	raw, err := regular.ReadFile(envPath(s, p.name()))
	if err != nil {
		return 0, err
	}
	var env envelope.Envelope
	if err := wire.Decode(raw, &env); err != nil {
		return 0, fmt.Errorf("the sealed copy in the outbox cannot be read: %v", err)
	}
	if env.To != p.To {
		return 0, errors.New("the sealed copy in the outbox is not addressed to the recipient its record names")
	}
	var path []string
	if p.Path != "" {
		path = strings.Split(p.Path, "!")
	}
	return postOrForward(c, &env, sendMode{channel: p.Channel, path: path, recipients: p.RecipientCount})
}

// landCopy is a copy the relay has: its outbox record and file go, and the
// sent record says where it is.
func landCopy(s *store.Store, p *pending, relayID int64) {
	p.remove(s)
	updateSentCopy(s, p.MessageID, p.To, func(c *store.SentCopy) {
		c.RelayID, c.RefusedCode, c.Refused, c.Dropped = relayID, "", "", false
	})
}

// refuseCopy is a copy the relay refused: the outbox record keeps the
// relay's code and words, and so does the sent record. An error that is no
// answer from a relay changes neither.
func refuseCopy(s *store.Store, p *pending, err error) {
	var he *client.HTTPError
	if !errors.As(err, &he) {
		return
	}
	p.RefusedCode = he.Code
	if wire.ValidName(p.RefusedCode) != nil {
		p.RefusedCode = ""
	}
	p.Refused = keptSentence(he)
	if serr := p.save(s); serr != nil {
		fmt.Fprintf(os.Stderr, "warning: the refusal could not be kept with the copy: %v\n", serr)
	}
	updateSentCopy(s, p.MessageID, p.To, func(c *store.SentCopy) {
		c.RefusedCode, c.Refused = p.RefusedCode, p.Refused
	})
}

// updateSentCopy changes one copy in a message's sent record. A message with
// no sent record is one whose sender stopped between writing its copies and
// writing the record, and its copies are finished all the same: nothing is
// said of the record that is not there. One that will not read, or has no
// copy for this recipient, is said once, and the copy is finished anyway.
func updateSentCopy(s *store.Store, messageID, to string, change func(*store.SentCopy)) {
	m, err := s.Holding(store.Sent, messageID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: the sent record of %s could not be read to update: %v\n", messageID[:12], err)
		return
	}
	if m == nil {
		return
	}
	for i := range m.Copies {
		if m.Copies[i].Fingerprint == to {
			change(&m.Copies[i])
			if err := s.Save(store.Sent, m); err != nil {
				fmt.Fprintf(os.Stderr, "warning: the sent record of %s could not be updated: %v\n", messageID[:12], err)
			}
			return
		}
	}
	fmt.Fprintf(os.Stderr, "warning: the sent record of %s has no copy for %s to update\n", messageID[:12], to[:identity.ShortIDLen])
}

// keptSentence is a refusal's sentence as the outbox keeps it, for
// `auu outbox` to show and for nothing to read: escaped, as HTTPError's
// constructor escaped it already, its tabs made spaces, since the escaper
// keeps a tab and a kept sentence is a line with no control character in
// it, and cut on a rune boundary to the relayapi.MaxSaid bytes a kept
// sentence may be. What it returns is what listPending holds a record's
// sentence to, so a refusal kept is a record read back. The sentence goes
// only to the escaper, as every refusal's does (ruling 68).
func keptSentence(he *client.HTTPError) string {
	s := identity.PrintableText(he.Message)
	s = strings.ReplaceAll(s, "\t", " ")
	if len(s) <= relayapi.MaxSaid {
		return s
	}
	n := relayapi.MaxSaid
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// outboxJSON is one waiting thing as `auu outbox --json` prints it.
type outboxJSON struct {
	Kind        string    `json:"kind"`
	ID          string    `json:"id"`
	To          string    `json:"to"`
	ToName      string    `json:"to_name,omitempty"`
	Relay       string    `json:"relay"`
	Path        string    `json:"path,omitempty"`
	Channel     string    `json:"channel,omitempty"`
	Bytes       int64     `json:"bytes"`
	Started     time.Time `json:"started"`
	RefusedCode string    `json:"refused_code,omitempty"`
	Refused     string    `json:"refused,omitempty"`
}

func outboxEntry(p *pending) outboxJSON {
	return outboxJSON{
		Kind: p.kind, ID: p.MessageID, To: p.To, ToName: p.ToName, Relay: p.Relay,
		Path: p.Path, Channel: p.Channel, Bytes: p.Bytes, Started: p.Started,
		RefusedCode: p.RefusedCode, Refused: p.Refused,
	}
}

// cmdOutbox is `auu outbox`: what waits to be sent, and `auu outbox drop`,
// which gives one up.
func cmdOutbox(args []string) error {
	if len(args) > 0 && args[0] == "drop" {
		return outboxDrop(args[1:])
	}
	fs := newFlagSet("outbox")
	asJSON := fs.Bool("json", false, "machine readable output")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) > 0 {
		return usageErrf("usage: %s outbox [--json] | %s outbox drop ID [PEER]", prog, prog)
	}
	s, err := openStore()
	if err != nil {
		return err
	}
	waiting, broken, err := listPending(s)
	if err != nil {
		return err
	}
	for _, b := range broken {
		fmt.Fprintf(os.Stderr, "warning: outbox record %s cannot be resumed and is not listed\n", b)
	}
	if *asJSON {
		out := make([]outboxJSON, 0, len(waiting))
		for _, p := range waiting {
			out = append(out, outboxEntry(p))
		}
		return printJSON(out)
	}
	if len(waiting) == 0 {
		fmt.Println("the outbox is empty")
		return nil
	}
	for _, p := range waiting {
		fmt.Println(outboxLine(p))
	}
	return nil
}

// outboxLine is one waiting thing as a person reads it, every word that came
// from somewhere else escaped: the peer's name is the one this machine gave
// them, held to the name rule at listPending and escaped all the same, and
// the kept sentence is the relay's.
func outboxLine(p *pending) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%-6s %s to %s on %s", outboxKind(p), p.MessageID[:12], p.label(), p.Relay)
	if p.Path != "" {
		fmt.Fprintf(&b, " by %s", p.Path)
	}
	fmt.Fprintf(&b, ", %s", term.HumanBytes(p.Bytes))
	if p.Refused != "" {
		code := ""
		if p.RefusedCode != "" {
			code = p.RefusedCode + ": "
		}
		fmt.Fprintf(&b, "; refused, %s%s", code, identity.PrintableText(p.Refused))
	}
	return b.String()
}

func outboxKind(p *pending) string {
	if p.kind == kindEnvelope {
		return "copy"
	}
	return "stream"
}

// outboxDrop is `auu outbox drop ID [PEER]`: one thing waiting in the
// outbox given up, its record and its sealed file removed, record first.
// It does not ask first, as `auu rm` does not: a dropped message can be sent
// again. The id may be a prefix of four or more; the peer, a name on this
// machine or a fingerprint prefix of eight or more, picks one copy of a
// message to several, which an id alone cannot.
func outboxDrop(args []string) error {
	fs := newFlagSet("outbox drop")
	asJSON := fs.Bool("json", false, "machine readable output")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) < 1 || len(positional) > 2 {
		return usageErrf("usage: %s outbox drop ID [PEER]", prog)
	}
	idArg := strings.ToLower(positional[0])
	if len(idArg) < 4 || len(idArg) > 32 || !lowerHexString(idArg) {
		return usageErrf("%q is not a message id or a prefix of one: four to thirty-two hex characters", positional[0])
	}
	peer := ""
	if len(positional) == 2 {
		peer = positional[1]
	}
	s, err := openStore()
	if err != nil {
		return err
	}
	waiting, _, err := listPending(s)
	if err != nil {
		return err
	}
	// self is the owner's own copy of a message they sent to several with
	// themselves among the recipients, as --to took it.
	self := ""
	if me, err := s.Self(); err == nil {
		self = me.Fingerprint()
	}
	var hits []*pending
	for _, p := range waiting {
		if strings.HasPrefix(p.MessageID, idArg) && (peer == "" || peerNames(p, peer, self)) {
			hits = append(hits, p)
		}
	}
	switch {
	case len(hits) == 0 && peer == "":
		return usageErrf("nothing in the outbox has an id beginning %s", idArg)
	case len(hits) == 0:
		return usageErrf("nothing in the outbox with an id beginning %s is for %s", idArg, identity.Printable(peer))
	case len(hits) > 1:
		var ids, whom []string
		for _, p := range hits {
			ids = append(ids, p.MessageID[:12])
			whom = append(whom, p.label())
		}
		if distinct(ids) > 1 {
			return usageErrf("%s begins %d messages in the outbox (%s); give more of the id",
				idArg, distinct(ids), strings.Join(ids, ", "))
		}
		return usageErrf("message %s has %d copies waiting, for %s; name the one to drop: %s outbox drop %s PEER",
			hits[0].MessageID[:12], len(hits), strings.Join(whom, ", "), prog, idArg)
	}
	p := hits[0]
	p.remove(s)
	// A copy of a message to several, an envelope or a stream, is given up
	// in its sent record too,
	// so that auu read does not go on saying it waits.
	if p.RecipientCount != 0 {
		// A copy another process placed while this one dropped it is
		// placed, and stays so.
		updateSentCopy(s, p.MessageID, p.To, dropCopy)
	}
	if *asJSON {
		return printJSON(outboxEntry(p))
	}
	fmt.Printf("dropped the %s of %s to %s\n", outboxKind(p), p.MessageID[:12], p.label())
	if p.kind == kindStream && p.Upload != "" {
		fmt.Printf("the relay %s lets its part of the upload go when the resume window ends\n", p.Relay)
	}
	return nil
}

// dropCopy gives a copy up in its sent record, unless another process
// placed it meanwhile, which stays placed: a copy is never both.
func dropCopy(c *store.SentCopy) {
	if c.RelayID == 0 {
		c.Dropped = true
	}
}

// peerNames says whether the peer argument names a record's recipient: as
// the name this machine gave them when the copy was written, as a
// fingerprint prefix of eight or more, or as self for the owner's own copy.
func peerNames(p *pending, peer, self string) bool {
	if peer == p.ToName || (peer == "self" && self != "" && p.To == self) {
		return true
	}
	lower := strings.ToLower(peer)
	return len(lower) >= 8 && lowerHexString(lower) && strings.HasPrefix(p.To, lower)
}

func lowerHexString(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func distinct(ss []string) int {
	seen := map[string]bool{}
	for _, s := range ss {
		seen[s] = true
	}
	return len(seen)
}
