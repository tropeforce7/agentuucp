package auu

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/tropeforce7/agentuucp/internal/agent"
	"github.com/tropeforce7/agentuucp/internal/client"
	"github.com/tropeforce7/agentuucp/internal/envelope"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/regular"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/store"
	"github.com/tropeforce7/agentuucp/internal/wire"
	"github.com/tropeforce7/agentuucp/internal/withdraw"
)

// withdrawLevel is the wire level a relay takes withdrawals at.
const withdrawLevel = 3

// afterSaid is the line for a note posted after a message the relay no
// longer held, or could not take back.
const afterSaid = "no longer on the relay, or not withdrawable there: the note was sent after it"

// withdrawTarget is one copy of a sent message as auu withdraw takes it up:
// whose it is, the relay that took it and its id there, and the key the
// relay may take it back by.
type withdrawTarget struct {
	fp, name, path, relay string
	relayID               int64
	key                   string
	withdrawn             time.Time
	// waiting is a copy of a message to several that no relay took, which
	// waits in the outbox or was refused there.
	waiting bool
}

func (t withdrawTarget) label() string {
	label := identity.Printable(orNone(t.name))
	if t.path != "" {
		label += " by " + identity.Printable(t.path)
	}
	return label
}

// withdrawResult is what became of one copy.
type withdrawResult struct {
	target   withdrawTarget
	note     string
	relayID  int64
	replaced bool
	at       time.Time
	said     string
	err      error
	code     int
	refusal  string
}

// withdrawnJSON is what auu withdraw --json prints: the message and each
// copy the relay took, in the record's order.
type withdrawnJSON struct {
	ID     string              `json:"id"`
	Copies []withdrawnCopyJSON `json:"copies"`
}

// withdrawnCopyJSON is one copy: whose, the note sent for it and its id at
// the relay, whether the note took the place of the relay's copy, when this
// machine marked the copy withdrawn, the line that says what happened, and
// for a copy not withdrawn the relay's code and the error.
type withdrawnCopyJSON struct {
	Fingerprint string    `json:"fingerprint"`
	Name        string    `json:"name,omitempty"`
	Path        string    `json:"path,omitempty"`
	Note        string    `json:"note,omitempty"`
	RelayID     int64     `json:"relay_id,omitempty"`
	Replaced    bool      `json:"replaced"`
	Withdrawn   time.Time `json:"withdrawn,omitzero"`
	Said        string    `json:"said,omitempty"`
	Code        string    `json:"code,omitempty"`
	Error       string    `json:"error,omitempty"`
}

// cmdWithdraw is `auu withdraw MESSAGE-ID [--reason TEXT] [--yes] [--json]`:
// a message this home sent, taken back. Each recipient is sent a note,
// sealed to them alone through envelope.SealWithdrawal, that says the
// sender withdrew it, with the reason when one is given; where the relay
// that took the copy still holds it and keeps its key, the note takes its
// place there, and otherwise the note goes after it. Nothing is removed
// from anybody's machine: a recipient's auu marks the message it holds.
//
// The id is looked up in the sent box alone (R146 P3). Refused before
// anything is sealed, exit 1, each by name: no such sent message, a
// withdrawal note, a message with no copy a relay took, a knock, and a
// message already withdrawn from everybody it went to.
//
// It asks first, and --yes skips the question. It needs the keys unlocked
// to send. Exit 0 when every copy is marked withdrawn, 2 when a relay could
// not be reached or refused, 4 when the keys are locked, 1 otherwise.
func cmdWithdraw(args []string) error {
	fs := newFlagSet("withdraw")
	reason := fs.String("reason", "", "one line saying why, sent in the note; at most 4,096 bytes")
	yes := fs.Bool("yes", false, "withdraw without asking first")
	asJSON := fs.Bool("json", false, "machine readable output")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		return usageErrf("usage: %s withdraw MESSAGE-ID [--reason TEXT] [--yes] [--json]", prog)
	}
	if err := withdraw.ValidReason(*reason); err != nil {
		return usageErrf("--reason: %v", err)
	}
	s, self, err := requireIdentity()
	if err != nil {
		return err
	}
	_, m, err := s.FindIn(positional[0], store.Sent)
	if errors.Is(err, store.ErrNoMatch) {
		return usageErrf("no message you sent has an id beginning %s; only a message in your sent box can be withdrawn",
			identity.Printable(positional[0]))
	}
	if err != nil {
		return usageErrf("%v", err)
	}
	targets, err := withdrawTargets(s, m)
	if err != nil {
		return err
	}
	if !*yes {
		var whom []string
		for _, t := range targets {
			if t.withdrawn.IsZero() && !t.waiting {
				whom = append(whom, t.label())
			}
		}
		question := fmt.Sprintf("withdraw %s (%s) from %s? Each is sent a note saying you withdrew it, "+
			"which takes its place where the relay still holds it",
			m.Inner.ID[:12], orNone(identity.PrintableText(m.Inner.Body.Subject)), strings.Join(whom, ", "))
		if !confirm(question) {
			fmt.Fprintf(os.Stderr, "nothing was withdrawn\n")
			return &exitError{code: exitUsage, err: errors.New("cancelled")}
		}
	}
	s, id, err := loadIdentity()
	if err != nil {
		return err
	}
	if id.Remote() {
		if err := ensureUnlocked(s, agent.ScopeSend); err != nil {
			return err
		}
	}

	results := make([]withdrawResult, 0, len(targets))
	for _, t := range targets {
		if !t.withdrawn.IsZero() {
			clearNotesFor(s, m.Inner.ID, t.fp)
			results = append(results, withdrawResult{target: t, at: t.withdrawn, said: "withdrawn already"})
			continue
		}
		if t.waiting {
			results = append(results, withdrawResult{target: t, code: exitUsage,
				err: fmt.Errorf("no relay took this copy, which still waits to be sent; '%s outbox drop %s %s' gives it up, "+
					"and 'auu send --resume' would deliver it with no note", prog, m.Inner.ID[:12], t.fp[:identity.ShortIDLen])})
			continue
		}
		results = append(results, withdrawCopy(s, id, self, m, t, *reason))
	}

	failed, worst := 0, 0
	for _, res := range results {
		if res.err != nil {
			failed++
			worst = max(worst, res.code)
		}
	}
	if *asJSON {
		out := withdrawnJSON{ID: m.Inner.ID, Copies: make([]withdrawnCopyJSON, 0, len(results))}
		for _, res := range results {
			cj := withdrawnCopyJSON{
				Fingerprint: res.target.fp, Name: res.target.name, Path: res.target.path,
				Note: res.note, RelayID: res.relayID, Replaced: res.replaced, Withdrawn: res.at, Said: res.said,
			}
			if res.err != nil {
				cj.Error, cj.Code = res.err.Error(), res.refusal
			}
			out.Copies = append(out.Copies, cj)
		}
		if err := printJSON(out); err != nil {
			return err
		}
	} else {
		fmt.Printf("withdrawing %s\n", m.Inner.ID[:12])
		for _, res := range results {
			if res.err != nil {
				fmt.Printf("  %s: not withdrawn: %v\n", res.target.label(), res.err)
				continue
			}
			fmt.Printf("  %s: %s\n", res.target.label(), res.said)
		}
	}
	if failed == 0 {
		return nil
	}
	msg := fmt.Sprintf("%d of %d copies were not withdrawn; '%s withdraw %s' takes up the rest",
		failed, len(results), prog, m.Inner.ID[:12])
	return &exitError{code: max(worst, exitUsage), err: errors.New(msg)}
}

// withdrawTargets is each copy of m a relay took, in the record's order, or
// the refusal that comes before anything is sealed. A copy a relay never
// took has nothing to take back and is said once here: what waits in the
// outbox is given up there.
func withdrawTargets(s *store.Store, m *store.Stored) ([]withdrawTarget, error) {
	id := m.Inner.ID[:12]
	if w, _ := withdraw.CheckSections(m.Inner.Sections, m.Inner.Body); w != nil {
		return nil, usageErrf("%s is a withdrawal note, which is not withdrawn in its turn", id)
	}
	var targets []withdrawTarget
	if len(m.Copies) == 0 {
		if m.RelayID != 0 {
			targets = append(targets, withdrawTarget{
				fp: m.Inner.To, name: m.SenderName, path: m.Path, relay: m.Relay,
				relayID: m.RelayID, key: m.WithdrawKey, withdrawn: m.Withdrawn,
			})
		}
	} else {
		for _, c := range m.Copies {
			if c.RelayID == 0 {
				// A copy no relay took has nothing to take back, but it
				// still waits to be sent: it is a copy not withdrawn,
				// said with what gives it up, since 'send --resume'
				// would deliver it with no note.
				if !c.Dropped {
					targets = append(targets, withdrawTarget{fp: c.Fingerprint, name: c.Name, path: c.Path, waiting: true})
				}
				continue
			}
			relay := m.Relay
			if c.Relay != "" {
				relay = c.Relay
			}
			targets = append(targets, withdrawTarget{
				fp: c.Fingerprint, name: c.Name, path: c.Path, relay: relay,
				relayID: c.RelayID, key: c.WithdrawKey, withdrawn: c.Withdrawn,
			})
		}
	}
	placed := 0
	for _, t := range targets {
		if !t.waiting {
			placed++
		}
	}
	if placed == 0 {
		return nil, usageErrf("no copy of %s was taken by a relay, so there is nothing to withdraw; "+
			"what waits in the outbox is given up with '%s outbox drop %s'", id, prog, id)
	}
	if m.Inner.Body.Type == message.TypeKnock {
		return nil, usageErrf("%s is a knock, which cannot be withdrawn", id)
	}
	waiting := 0
	for _, t := range targets {
		if t.waiting {
			waiting++
			continue
		}
		if t.withdrawn.IsZero() {
			return targets, nil
		}
	}
	for _, t := range targets {
		clearNotesFor(s, m.Inner.ID, t.fp)
	}
	still := ""
	if waiting > 0 {
		still = fmt.Sprintf("; %s no relay took still waiting in the outbox, which '%s outbox drop %s PEER' gives up",
			howMany(waiting, "copy", "copies"), prog, id)
	}
	return nil, usageErrf("%s was withdrawn on %s, from everybody a relay took it for%s",
		id, m.Withdrawn.Local().Format(time.RFC1123), still)
}

// withdrawCopy sends one copy's note and marks the copy withdrawn when a
// relay has taken the note.
//
// The note is the one already in the outbox for this copy, from a run that
// sealed it and did not see it placed, so that a note whose answer was lost
// goes again as itself and is answered as a repeat; otherwise it is sealed
// now, to the copy's recipient alone, for the original's channel and
// thread, and written to the outbox before anything is posted.
//
// The route is the copy's:
//   - by a path, the note goes by the same path, and only the first relay
//     could have been asked to take the message back;
//   - with no key, a message sent before the key was kept, or to a relay
//     below wire level 3, the note goes by the ordinary route and the
//     relay's copy stays;
//   - otherwise the withdrawal route, and on its 404 not-withdrawable, and
//     on that alone, the ordinary route, held to the ordinary rules, so a
//     channel closed or deleted since refuses it (D196).
//
// A note the relay refuses stays in the outbox with the relay's words, as a
// refused copy does, and the copy is not marked; note-too-large is the
// exception, since the same note would be refused again: it is taken out,
// so that the next run seals one without the reason.
func withdrawCopy(s *store.Store, id *identity.Identity, self *identity.Public, m *store.Stored, t withdrawTarget, reason string) withdrawResult {
	res := withdrawResult{target: t}
	// fail is the copy not withdrawn: said as err, with the relay's code
	// from cause, the answer err explains, when there is one.
	failAs := func(code int, err, cause error) withdrawResult {
		// An error that carries its own exit code keeps it: a key locked
		// part way is the person's to unlock, whatever else failed.
		var e *exitError
		if errors.As(err, &e) {
			code = e.code
		}
		res.err, res.code, res.said, res.replaced = err, code, "", false
		var he *client.HTTPError
		if errors.As(cause, &he) && wire.ValidName(he.Code) == nil {
			res.refusal = he.Code
		}
		return res
	}
	fail := func(code int, err error) withdrawResult { return failAs(code, err, err) }
	// F5: a note is sealed only to somebody this machine still holds.
	pub := peerByFingerprint(s, self, t.fp)
	if pub == nil {
		return fail(exitUsage, fmt.Errorf("%s is no longer on your peer list, and a note is sealed only to a peer", t.fp[:identity.ShortIDLen]))
	}
	p, err := waitingNote(s, m.Inner.ID, t.fp)
	if err != nil {
		return fail(exitUsage, err)
	}
	if p != nil && p.Reason != reason {
		fmt.Fprintf(os.Stderr, "%s: the note an earlier run sealed for %s is sent as it was, with its reason\n",
			m.Inner.ID[:12], t.label())
	}
	if p == nil {
		env, inner, err := envelope.SealWithdrawal(id, pub, m.Channel, m.Inner.Body.Thread, m.Inner.ID, reason)
		if err != nil {
			return fail(exitUsage, err)
		}
		if p, err = writeNote(s, t, m.Channel, env, inner, reason); err != nil {
			return fail(exitUsage, err)
		}
	}
	res.note = p.MessageID
	r, err := s.Relay(p.Relay)
	if err != nil {
		return fail(exitUsage, fmt.Errorf("the message went by %s: %v", p.Relay, err))
	}
	env, err := readNote(s, p)
	if err != nil {
		return fail(exitUsage, err)
	}
	c, err := dial(s, id, r)
	if err != nil {
		return fail(exitTransport, err)
	}
	var path []string
	if p.Path != "" {
		path = strings.Split(p.Path, "!")
	}
	post := func() (int64, error) {
		return postOrForward(c, env, sendMode{channel: p.Channel, path: path})
	}
	var relayID int64
	switch {
	case p.Fallback:
		relayID, err = post()
		res.said = afterSaid
	case len(path) > 0:
		relayID, err = post()
		res.said = fmt.Sprintf("the note went by %s; only the first relay could have been asked to take the message back, and it was not", identity.Printable(p.Path))
	case t.key == "":
		relayID, err = post()
		res.said = "the note was sent; the relay's copy stays, since it was sent before auu kept the key a relay takes a message back by"
	default:
		if c.WireLevel() == 0 {
			if _, err := c.HealthInfo(ctx()); err != nil {
				return fail(exitTransport, err)
			}
		}
		if level := c.WireLevel(); level < withdrawLevel {
			relayID, err = post()
			res.said = fmt.Sprintf("the note was sent; the relay's copy stays, since %s does not take a message back (its wire level is %d, and 3 does)", r.Name, level)
			break
		}
		relayID, err = c.Withdraw(ctx(), t.relayID, t.key, env, p.Channel)
		switch {
		case err == nil:
			res.replaced = true
			res.said = "replaced on the relay"
		case isNotWithdrawable(err):
			p.Fallback = true
			if serr := p.save(s); serr != nil {
				return fail(exitUsage, serr)
			}
			relayID, err = post()
			res.said = afterSaid
		case isNoteTooLarge(err):
			p.clear(s)
			res.note = ""
			return failAs(exitUsage, noteTooLargeSentence(m, p), err)
		}
	}
	if err != nil {
		refuseNote(s, p, err)
		said := err
		if len(path) == 0 {
			said = noteChannelHint(err, t, p.Channel)
		}
		return failAs(exitTransport, said, err)
	}
	res.relayID = relayID
	res.at = time.Now().UTC().Truncate(time.Second)
	// The note's own record, then the copy's mark, then the outbox lets
	// the note go. A stop before the mark leaves the note waiting, which
	// the next run posts again as itself, answered as a repeat, and whose
	// record it saves again; a stop after it leaves a marked copy and a
	// note the next run clears. Never a note gone with nothing marked,
	// which would be sealed again, and never a note sent with no record.
	if err := saveSent(s, noteRecord(id, r, p, relayID)); err != nil {
		fmt.Fprintf(os.Stderr, "warning: the note was sent but the local copy failed: %v\n", err)
	}
	if err := markSentWithdrawn(s, m.Inner.ID, t.fp, p.MessageID, p.Reason, res.at); err != nil {
		return fail(exitUsage, fmt.Errorf("the note was sent, but the sent record could not be marked: %v", err))
	}
	p.clear(s)
	return res
}

// noteChannelHint says, for a note the relay refused for its channel, why:
// a note goes on the message's channel alone, so a channel the recipient
// has deleted since is said as that, and one closed since by the relay's
// sentence with its time in this zone (D196). Any other refusal is said as
// it came. Read by code and status alone.
func noteChannelHint(err error, t withdrawTarget, channel string) error {
	var he *client.HTTPError
	if !errors.As(err, &he) {
		return err
	}
	switch {
	case he.Status == http.StatusNotFound && he.Code == relayapi.CodeNoSuchChannel:
		return fmt.Errorf("the channel %s the message went to is no longer in %s's directory, and a note goes on the message's channel alone",
			identity.PrintableText(channelName(channel)), identity.Printable(orNone(t.name)))
	case he.Status == http.StatusForbidden && he.Code == relayapi.CodeChannelClosed && !he.At.IsZero():
		return errors.New(closedSentence(he, time.Local))
	}
	return err
}

// isNotWithdrawable is the withdrawal route's 404 for every row the key
// does not open, read by its code and status alone.
func isNotWithdrawable(err error) bool {
	var he *client.HTTPError
	return errors.As(err, &he) && he.Status == http.StatusNotFound && he.Code == relayapi.CodeNotWithdrawable
}

// isNoteTooLarge is a closed channel's refusal of a note larger than the
// message it would take the place of and the floor (D198), read by its
// code and status alone.
func isNoteTooLarge(err error) bool {
	var he *client.HTTPError
	return errors.As(err, &he) && he.Status == http.StatusBadRequest && he.Code == relayapi.CodeNoteTooLarge
}

// noteTooLargeSentence is what the command says for note-too-large: the
// channel is closed, the note with this reason is too large to take the
// message's place there, and the same withdrawal without a reason fits.
// It does not try that itself: the reason was the person's to give, and is
// theirs to leave out.
func noteTooLargeSentence(m *store.Stored, p *pending) error {
	if p.Reason == "" {
		return fmt.Errorf("the channel %s is closed, and the relay refused the note as larger than the message it takes the place of (%s)",
			identity.PrintableText(channelName(p.Channel)), relayapi.CodeNoteTooLarge)
	}
	return fmt.Errorf("the channel %s is closed, and the note with this reason is too large to take the message's place there; "+
		"'%s withdraw %s' again without --reason fits", identity.PrintableText(channelName(p.Channel)), prog, m.Inner.ID[:12])
}

// peerByFingerprint is the key a note is sealed to: this identity's own, for
// a message sent to self, or a peer's on this machine now, by its whole
// fingerprint; nil for anybody else.
func peerByFingerprint(s *store.Store, self *identity.Public, fp string) *identity.Public {
	if self.Fingerprint() == fp {
		return self
	}
	peers, err := s.Peers()
	if err != nil {
		return nil
	}
	for _, p := range peers {
		if p.Fingerprint() == fp {
			return p
		}
	}
	return nil
}

// waitingNote is the note the outbox holds for one copy of a message, from
// a run that sealed it and did not see it placed; nil when there is none.
func waitingNote(s *store.Store, messageID, to string) (*pending, error) {
	waiting, _, err := listPending(s)
	if err != nil {
		return nil, err
	}
	for _, p := range waiting {
		if p.Withdraws == messageID && p.To == to {
			return p, nil
		}
	}
	return nil, nil
}

// clearNotesFor takes out of the outbox any note still waiting for a copy
// already marked withdrawn: a run that stopped after the mark and before
// the outbox let the note go left it, and sending it again would only send
// the recipient a second note.
func clearNotesFor(s *store.Store, messageID, to string) {
	if p, err := waitingNote(s, messageID, to); err == nil && p != nil {
		p.clear(s)
	}
}

// writeNote writes a sealed note to the outbox, beside its record, as a
// copy of a message to several is written (writeCopies): the envelope as
// it will be posted, its channel on the outer field, and a record naming
// the message it withdraws and its reason. The record goes down after the
// sealed file.
func writeNote(s *store.Store, t withdrawTarget, channel string, env *envelope.Envelope, inner *envelope.Inner, reason string) (*pending, error) {
	if err := os.MkdirAll(outboxDir(s), 0o700); err != nil {
		return nil, err
	}
	outer := *env
	outer.Ch = channel
	raw, err := json.Marshal(&outer)
	if err != nil {
		return nil, err
	}
	p := &pending{
		MessageID: inner.ID, To: env.To, ToName: t.name, Relay: t.relay, Channel: channel,
		Started: time.Now().UTC().Truncate(time.Second), Time: inner.Time, Body: inner.Body,
		Bytes: int64(len(raw)), Path: t.path, Withdraws: inner.Body.InReplyTo, Reason: reason,
		stem: inner.ID, kind: kindEnvelope,
	}
	f, err := os.OpenFile(envPath(s, p.stem), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	_, werr := f.Write(raw)
	if serr := f.Sync(); werr == nil {
		werr = serr
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = p.save(s)
	}
	if werr != nil {
		os.Remove(envPath(s, p.stem))
		return nil, werr
	}
	return p, nil
}

// readNote is the sealed note beside its record, read strictly as postCopy
// reads a copy, and addressed to the recipient its record names.
func readNote(s *store.Store, p *pending) (*envelope.Envelope, error) {
	raw, err := regular.ReadFile(envPath(s, p.name()))
	if err != nil {
		return nil, err
	}
	var env envelope.Envelope
	if err := wire.Decode(raw, &env); err != nil {
		return nil, fmt.Errorf("the sealed note in the outbox cannot be read: %v", err)
	}
	if env.To != p.To {
		return nil, errors.New("the sealed note in the outbox is not addressed to the recipient its record names")
	}
	return &env, nil
}

// refuseNote keeps a relay's refusal of a note with the note in the
// outbox, as refuseCopy keeps a copy's, so that auu outbox says why it
// waits. An error that is no answer from a relay changes nothing.
func refuseNote(s *store.Store, p *pending, err error) {
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
		fmt.Fprintf(os.Stderr, "warning: the refusal could not be kept with the note: %v\n", serr)
	}
}

// markSentWithdrawn marks a copy of a sent message withdrawn, under the
// sent lock: a message to one at its top, and a copy of a message to
// several by its recipient, the record marked with the note and the reason
// when its first copy is. A mark already made stays as it was.
func markSentWithdrawn(s *store.Store, messageID, to, noteID, reason string, at time.Time) error {
	return s.UpdateSent(messageID, func(m *store.Stored) *store.Stored {
		if m == nil {
			return nil
		}
		for i := range m.Copies {
			if m.Copies[i].Fingerprint == to && m.Copies[i].Withdrawn.IsZero() {
				m.Copies[i].Withdrawn = at
			}
		}
		if m.Withdrawn.IsZero() {
			m.Withdrawn, m.WithdrawnBy, m.WithdrawnReason = at, noteID, reason
		}
		return m
	})
}

// noteRecord is the sent record of a note a relay took, written from its
// outbox record, the note's section built again from what the record names
// as the sealer built it. It keeps no withdrawal key: a note is not
// withdrawn in its turn, and one a closed channel took keeps none at the
// relay either.
func noteRecord(id *identity.Identity, r *store.Relay, p *pending, relayID int64) *store.Stored {
	var sections []wire.Section
	if sec, err := withdraw.Section(p.Withdraws, p.Reason); err == nil {
		sections = []wire.Section{sec}
	}
	return &store.Stored{
		RelayID:  relayID,
		Relay:    r.Name,
		Received: time.Now().UTC().Truncate(time.Second),
		Read:     true,
		Inner: &envelope.Inner{
			V: envelope.Version, ID: p.MessageID, From: id.Fingerprint(), FromBundle: id.Public().Bundle(),
			To: p.To, Time: p.Time, Body: p.Body, Channel: p.Channel, Sections: sections,
		},
		SenderName: p.ToName,
		Channel:    p.Channel,
		Path:       p.Path,
	}
}
