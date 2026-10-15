package auu

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/tropeforce7/agentuucp/internal/client"
	"github.com/tropeforce7/agentuucp/internal/envelope"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/recipients"
	"github.com/tropeforce7/agentuucp/internal/regular"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/store"
	"github.com/tropeforce7/agentuucp/internal/term"
	"github.com/tropeforce7/agentuucp/internal/wire"
)

type sentJSON struct {
	ID        string `json:"id"`
	Thread    string `json:"thread"`
	To        string `json:"to"`
	ToName    string `json:"to_name"`
	RelayID   int64  `json:"relay_id"`
	Bytes     int    `json:"bytes"`
	InReplyTo string `json:"in_reply_to,omitempty"`
	// Kind is envelope or stream, and the two chunk fields are set only for
	// a stream.
	Kind      string `json:"kind"`
	Chunks    int64  `json:"chunks,omitempty"`
	ChunkSize int    `json:"chunk_size,omitempty"`
	// Channel is the recipient's channel the message went to; absent for
	// default.
	Channel string `json:"channel,omitempty"`
	// Path is the relays the message went by, nearest first, joined by
	// "!"; absent for a recipient on the relay it was posted to.
	Path string `json:"path,omitempty"`
}

func cmdSend(args []string) error {
	fs := newFlagSet("send")
	var tos stringList
	fs.Var(&tos, "to", "recipient: peer name or fingerprint, or self for a note to yourself; "+
		"'bar!bob' sends to bob by way of the relay your relay calls bar; repeat it, or separate "+
		"names with commas, for a message to several")
	via := fs.String("via", "", "relays to send by way of, nearest first, as 'bar' or 'bar!baz'; "+
		"the same as putting them in --to, for a script that would rather not quote a bang")
	subject := fs.String("subject", "", "one-line subject")
	thread := fs.String("thread", "", "existing thread id (default: start a new thread)")
	replyTo := fs.String("reply-to", "", "message id this answers")
	msgType := fs.String("type", message.TypeAsk, "message type: ask or note")
	bodyFile := fs.String("body-file", "", "read the message text from this file")
	asJSON := fs.Bool("json", false, "machine readable output")
	forceStream := fs.Bool("stream", false, "send as a chunked stream whatever the size")
	forceInline := fs.Bool("inline", false, "send as a single envelope, failing if it is too large")
	resume := fs.Bool("resume", false, "finish any message left unsent in the outbox, and send nothing new")
	edit := fs.Bool("edit", false, "compose the message in your editor, starting from any text given")
	channel := channelFlag(fs)
	relay := relayFlag(fs)
	var attach stringList
	fs.Var(&attach, "attach", "attach a file (repeatable)")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if *resume {
		if len(tos) > 0 || *via != "" || len(attach) > 0 || len(positional) > 0 || *channel != "" {
			return usageErrf("--resume finishes what is already sealed; it takes no other arguments")
		}
		s, id, err := loadIdentity()
		if err != nil {
			return err
		}
		return resumePending(s, id, *asJSON, *relay)
	}
	if len(tos) == 0 {
		return usageErrf("--to is required")
	}
	elems, err := splitTo(tos)
	if err != nil {
		return err
	}
	// One recipient is the message to one it always was; several are
	// resolved together once the home is open, every one before anything
	// is written.
	var path []string
	var peer string
	if len(elems) == 1 {
		if path, peer, err = address(elems[0], *via); err != nil {
			return err
		}
	} else if len(elems) > relayapi.MaxRecipients {
		return usageErrf("%d recipients; a message may go to at most %d", len(elems), relayapi.MaxRecipients)
	}
	if *msgType != message.TypeAsk && *msgType != message.TypeNote {
		return usageErrf("--type must be ask or note")
	}
	// Before the editor opens, not after: a thread id has a message id's
	// shape, though a new thread is given an id of its own and not its
	// first message's. A value of any other shape is refused everywhere a
	// message is made, since it becomes a directory name under an
	// expert's home.
	if *thread != "" {
		if err := message.ValidID(*thread); err != nil {
			return usageErrf("--thread %q is %v; a thread id is the thread that auu send printed or auu read shows", *thread, err)
		}
	}
	if *replyTo != "" {
		if err := message.ValidID(*replyTo); err != nil {
			return usageErrf("--reply-to %q is %v", *replyTo, err)
		}
	}
	if err := validChannelFlag(*channel); err != nil {
		return err
	}
	// The text comes from the arguments, a file or stdin as ever. With none
	// of those and a person at the terminal, or on request, it comes from an
	// editor instead; anything that was given becomes the starting point.
	compose := *edit || (len(positional) == 0 && *bodyFile == "" && interactive())
	var text string
	if len(positional) > 0 || *bodyFile != "" || !compose {
		text, err = readText(positional, *bodyFile)
		if err != nil {
			return err
		}
	}

	s, id, err := loadIdentity()
	if err != nil {
		return err
	}
	r, err := selectRelay(s, *relay)
	if err != nil {
		return err
	}
	// A room's name is tried before the peer list, by its whole name in any
	// case and never a prefix, and its members take its place in the list
	// (D56): from here on it is a message to them, as if each had been named.
	rooms, err := s.Rooms()
	if err != nil {
		return err
	}
	self, err := s.Self()
	if err != nil {
		return err
	}
	targets, used, err := expandRooms(s, self, rooms, elems, *via)
	if err != nil {
		return err
	}
	var several []addressed
	var recipient *identity.Public
	switch {
	case len(used) > 0:
		if len(targets) > relayapi.MaxRecipients {
			return usageErrf("%d recipients once %s %s counted; a message may go to at most %d",
				len(targets), roomsSaid(used), roomsVerb(used), relayapi.MaxRecipients)
		}
		if several, err = resolveSeveral(s, targets, *via); err != nil {
			return err
		}
		// A room of one is a message to one, with no list on it, as one
		// --to with one name is; the member's relays are its path.
		if len(several) == 1 {
			recipient, path = several[0].pub, several[0].path
			if len(path) > 0 {
				if err := store.CheckAddress(path, nil, relayapi.MaxHops); err != nil {
					return usageErrf("%v", err)
				}
			}
		}
	case len(elems) > 1:
		if several, err = resolveSeveral(s, targets, *via); err != nil {
			return err
		}
	default:
		if recipient, err = s.Resolve(peer); err != nil {
			return usageErrf("%v", err)
		}
		several = []addressed{{pub: recipient, path: path}}
	}
	warnPending(s)
	if compose {
		cfg, err := s.Config()
		if err != nil {
			return err
		}
		var edited string
		text, edited, err = composeIn(s, cfg, composeTemplate(publicsOf(several), *subject, attach, nil, text))
		if err != nil {
			return err
		}
		switch {
		case *subject == "":
			// No Subject line in the template: the first line is it, as
			// a commit message's summary is.
			*subject, text = splitSubject(text)
		case edited != "":
			// The template's Subject line, edited in the editor: what is
			// typed there is what was meant.
			*subject = edited
		}
		keepDraft(s, text)
	}

	// The attachment bytes are deliberately not read here. A message large
	// enough becomes a stream, which reads its files a chunk at a time;
	// loading them first would cost the whole payload in memory before
	// anything had decided that.
	body := message.Body{
		Type:      *msgType,
		Subject:   *subject,
		Thread:    *thread,
		InReplyTo: *replyTo,
		Text:      text,
	}
	mode := sendMode{stream: *forceStream, inline: *forceInline, channel: *channel, path: path, rooms: used}
	if len(several) > 1 {
		mode.path = nil
		err = sendToSeveral(s, id, r, several, body, attach, mode, *asJSON)
	} else {
		err = sealAndSend(s, id, r, recipient, body, attach, mode, *asJSON)
	}
	// A draft is kept for a message that never went; a message to several
	// whose copies are in the outbox is finished by --resume, and keeping
	// the draft too would invite sending it all over again.
	var waiting copiesWaiting
	if err != nil && compose && !errors.As(err, &waiting) {
		return draftKept(s, err)
	}
	return err
}

func cmdReply(args []string) error {
	fs := newFlagSet("reply")
	to := fs.String("to", "", "override the address: 'bar!bob', for a reply that cannot go back "+
		"the way the message came")
	via := fs.String("via", "", "override the relays to reply by way of, nearest first")
	bodyFile := fs.String("body-file", "", "read the message text from this file")
	subject := fs.String("subject", "", "override the subject (default: keep the original)")
	asJSON := fs.Bool("json", false, "machine readable output")
	forceStream := fs.Bool("stream", false, "send as a chunked stream whatever the size")
	forceInline := fs.Bool("inline", false, "send as a single envelope, failing if it is too large")
	edit := fs.Bool("edit", false, "compose the reply in your editor, starting from any text given")
	all := fs.Bool("all", false, "answer the sender and everyone else the message went to")
	channel := channelFlag(fs)
	relay := relayFlag(fs)
	var attach stringList
	fs.Var(&attach, "attach", "attach a file (repeatable)")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) == 0 {
		return usageErrf("usage: %s reply MESSAGE-ID|THREAD-ID [TEXT]", prog)
	}
	// Everyone is answered as the message came, through the relay it
	// arrived on: an address per person is not one a reply can be given,
	// and a room carries one for each.
	if *all && (*to != "" || *via != "") {
		return usageErrf("--all answers everyone through the relay the message came by, and takes no --to " +
			"or --via; to reach somebody by other relays, send a new message to them or to a room, which carries an address for each person")
	}
	if err := validChannelFlag(*channel); err != nil {
		return err
	}
	target, textArgs := positional[0], positional[1:]
	compose := *edit || (len(textArgs) == 0 && *bodyFile == "" && interactive())

	s, id, err := loadIdentity()
	if err != nil {
		return err
	}
	warnPending(s)
	// A message id, or a thread id: the same shape, the message tried first.
	// Replying to a thread answers whatever is latest on it, including your
	// own last message, in which case this is a follow-up to the person it
	// went to.
	box, original, err := s.Find(target)
	viaThread := false
	if err != nil {
		var amb *store.ErrAmbiguous
		if errors.As(err, &amb) {
			return usageErrf("%v", err)
		}
		tbox, latest, terr := s.FindThread(target)
		if terr != nil {
			if errors.As(terr, &amb) {
				return usageErrf("%v", terr)
			}
			return usageErrf("no message or thread matches %q", target)
		}
		box, original, viaThread = tbox, latest, true
	}
	if original.Newer != "" {
		return usageErrf("%s", waitsForNewer(original))
	}
	if box == store.Sent && !viaThread {
		return usageErrf("%s is a message you sent; reply to one you received, or to its thread %s",
			target, original.Inner.Body.Thread[:12])
	}
	// The other party: whoever wrote what is being answered, or, when that
	// was you, whoever you wrote it to.
	otherFP := original.Inner.From
	if box == store.Sent {
		otherFP = original.Inner.To
	}
	// Your own message to several has no one person to follow up with:
	// the sender is you, and the first recipient alone is not who you
	// wrote to. --to names one of them, and the follow-up goes the way that
	// copy went unless --via says otherwise.
	toArg := *to
	var several []addressed
	if *all {
		set, err := replyAllSet(s, box, original)
		if err != nil {
			return err
		}
		if len(set) == 1 {
			otherFP = set[0].pub.Fingerprint()
		} else {
			several = set
			otherFP = set[0].pub.Fingerprint()
		}
	} else if box == store.Sent && len(original.Copies) > 0 {
		c, err := followUpCopy(s, original, *to)
		if err != nil {
			return err
		}
		otherFP = c.Fingerprint
		if c.Path != "" && *via == "" && !strings.Contains(*to, "!") {
			toArg = c.Path + "!" + *to
		}
	}
	recipient, err := s.Resolve(otherFP)
	if err != nil {
		return usageErrf("cannot reply: %s is not in your peer list", otherFP[:16])
	}
	// A reply goes back the way the message came, without being told.
	r, err := relayOf(s, original, *relay)
	if err != nil {
		return err
	}
	var path []string
	if len(several) == 0 {
		if path, err = replyPath(s, original, recipient, toArg, *via); err != nil {
			return err
		}
	}
	if viaThread && !*asJSON {
		who := "you"
		if box != store.Sent {
			who = peerLabel(recipient)
		}
		fmt.Printf("thread %s: replying to its latest message, %s from %s\n",
			original.Inner.Body.Thread[:12], original.Inner.ID[:12], who)
	}
	var text string
	if len(textArgs) > 0 || *bodyFile != "" || !compose {
		text, err = readText(textArgs, *bodyFile)
		if err != nil {
			return err
		}
	}

	subj := original.Inner.Body.Subject
	if *subject != "" {
		subj = *subject
	}
	if compose {
		// A reply always has a subject, the original's, so the whole of what
		// is written is the message.
		cfg, err := s.Config()
		if err != nil {
			return err
		}
		var edited string
		to := []*identity.Public{recipient}
		if len(several) > 0 {
			to = publicsOf(several)
		}
		text, edited, err = composeIn(s, cfg, composeTemplate(to, subj, attach, original, text))
		if err != nil {
			return err
		}
		if edited != "" {
			// A reply's own subject, typed over the thread's in the
			// editor. The record carries it; the thread is the thread.
			subj = edited
		}
		keepDraft(s, text)
	}
	body := message.Body{
		Type:      message.TypeReply,
		Subject:   subj,
		Thread:    original.Inner.Body.Thread,
		InReplyTo: original.Inner.ID,
		Text:      text,
	}
	// A reply goes to the sender's default unless --channel says otherwise:
	// a channel is the receiver's sorting, not a thread.
	if len(several) > 0 {
		err = sendToSeveral(s, id, r, several, body, attach,
			sendMode{stream: *forceStream, inline: *forceInline, channel: *channel, replyAll: true}, *asJSON)
	} else {
		err = sealAndSend(s, id, r, recipient, body, attach,
			sendMode{stream: *forceStream, inline: *forceInline, channel: *channel, path: path,
				reply: *to == "" && *via == ""}, *asJSON)
	}
	var waiting copiesWaiting
	if err != nil && compose && !errors.As(err, &waiting) {
		return draftKept(s, err)
	}
	return err
}

// replyPath is the address a reply takes: back the way the message came, or
// the one the person gave instead.
//
// The default is the record's via reversed, which is the way it came read
// backwards. That it routes at all rests on a convention: the names in via
// are what each hop calls the hop before, out of its couriers file, and a
// path is resolved against a relay's courier home — the side it dials. An
// operator is meant to use one name in both, and a relay says at its start
// which names appear in one and not the other, but nothing can enforce it
// and one-way peering is a thing an operator may want. So the reversal is
// right where the convention holds and unroutable where it does not, and
// what a person meets in the second case is the first hop's own refusal,
// which sayReplyRefused turns into a sentence about this reply.
//
// A bang path in --to, or --via, is how somebody answers anyway. Either
// replaces the whole path. When --to names a peer as well, it has to be the
// one being replied to: a reply that went to somebody else while keeping the
// thread would be a surprise nobody asked for, and saying so costs one
// comparison.
func replyPath(s *store.Store, original *store.Stored, recipient *identity.Public,
	to, via string) ([]string, error) {

	switch {
	case to == "" && via == "":
		return sameWayAgain(original), nil
	case to == "":
		// The relays alone, which is what a reply usually wants: who it
		// goes to is the message's and not the person's to restate. So the
		// address rule runs here rather than through address, which is
		// send's and requires a recipient at the end.
		path := strings.Split(via, "!")
		if err := store.CheckAddress(path, nil, relayapi.MaxHops); err != nil {
			return nil, usageErrf("%v", err)
		}
		return path, nil
	}
	path, peer, err := address(to, via)
	if err != nil {
		return nil, err
	}
	if peer != "" {
		named, err := s.Resolve(peer)
		if err != nil {
			return nil, usageErrf("%v", err)
		}
		if named.Fingerprint() != recipient.Fingerprint() {
			return nil, usageErrf("--to %q names %s, and this is a reply to %s: pass the relays "+
				"alone, as --via %q, or send a new message",
				to, peerLabel(named), peerLabel(recipient), store.JoinAddress(path))
		}
	}
	return path, nil
}

// sameWayAgain is the address a reply or a follow-up takes when nobody has
// given one: whichever way the message being answered travelled.
//
// The two boxes hold that differently and neither can be read as the other.
// A received message keeps Via, the hops it came by, nearest its sender
// first — reversed, that is the way back. A message this machine sent keeps
// Path, the address it went by, already pointing away from here: it is the
// way onward, and reversing it would send a follow-up back through the
// relays in the wrong order.
//
// Both are reached in ordinary use. `auu reply` takes a thread as well as a
// message id, and the latest message on a thread you started and nobody has
// answered yet is your own — so a follow-up on a cross-relay thread comes
// here with a Sent record. Reading only Via would have dropped the address
// and posted it into a mailbox on this machine's own relay, which either
// succeeds in the wrong place or fails saying the recipient is not
// registered, about somebody who has been answering all day.
func sameWayAgain(m *store.Stored) []string {
	if m.Via != "" {
		return reversePath(m.Via)
	}
	// A sent record's own address, as it was sent: the hops from here.
	if m.Path != "" {
		return strings.Split(m.Path, "!")
	}
	return nil
}

// reversePath is a via read backwards: the hops a message came by, nearest
// the sender first, are the hops a reply takes, nearest this machine first.
func reversePath(via string) []string {
	if via == "" {
		return nil
	}
	names := strings.Split(via, "!")
	slices.Reverse(names)
	return names
}

// sendMode is what the flags say, before the size is consulted: the two
// that force a shape, and the recipient's channel, empty for default.
// address reads where a message is going: the relays to send it by way of,
// nearest first, and the peer at the end.
//
// Two spellings, one meaning. "bar!baz!bob" is the address as a person
// writes it; --to bob --via 'bar!baz' is the same address for a script that
// would rather not put a bang inside quotes. Both at once is a usage error
// rather than a merge, because there is no order between them a reader could
// guess, and a silent guess about where somebody's mail goes is the wrong
// kind of convenience.
//
// The rule runs here, before anything is sealed or dialled, and it is
// store.CheckAddress — the same function the relay runs on every forward
// request. What differs is the ceiling: this holds an address to the
// protocol's, since nothing on the wire says what a given relay allows, so
// an address inside 32 hops but over that relay's own courier.max_hops
// passes here and is refused at the first hop, in that hop's words.
func address(to, via string) (path []string, peer string, err error) {
	path, peer = store.SplitAddress(to)
	if via != "" {
		if len(path) > 0 {
			return nil, "", usageErrf("--to %q already names the relays to go by; "+
				"--via is for giving them separately, as --to %q --via %q", to, peer, strings.Join(path, "!"))
		}
		path = strings.Split(via, "!")
	}
	if len(path) == 0 {
		return nil, peer, nil
	}
	if peer == "" {
		return nil, "", usageErrf("an address ends in the recipient: %q names relays and nobody to give it to", to)
	}
	if err := store.CheckAddress(path, nil, relayapi.MaxHops); err != nil {
		return nil, "", usageErrf("%v", err)
	}
	return path, peer, nil
}

type sendMode struct {
	stream, inline bool
	channel        string
	// sealed is where a caller that sends one answer again and again keeps
	// the envelope it was sealed as, empty for every other send: serve,
	// which retries a reply whose post may have reached the relay with its
	// answer lost. See sealOnce.
	sealed string
	// path is the relays an address names before the recipient, nearest
	// first, empty for a recipient on the relay being posted to — which is
	// every message anybody sent before relays could forward, and still
	// most of them. A path sends to the first hop's forward route instead
	// of the recipient's mailbox.
	path []string
	// reply says this path was worked out from the record rather than typed,
	// so that a refusal of it is explained as a reply's and not handed back
	// as though the person had written the address.
	reply bool
	// recipients is how many the message went to when this is a copy of a
	// message to several, said to the first relay on a forward so that it
	// can hold the sender to its max_recipients; zero for a message to one.
	recipients int
	// rooms is the rooms the recipients were expanded from, for the
	// sentences that refuse too many recipients.
	rooms []string
	// replyAll says this message to several is reply --all, whose copies
	// all go through the relay the original came by, so that a recipient
	// on another relay is told how to be reached.
	replyAll bool
}

// sealAndSend is the common tail of send and reply: the message sent, and
// then said.
func sealAndSend(s *store.Store, id *identity.Identity, r *store.Relay, recipient *identity.Public,
	body message.Body, attachments []string, mode sendMode, asJSON bool) error {

	out, newThread, err := sendSealed(s, id, r, recipient, body, attachments, mode)
	if err != nil {
		return err
	}
	return printSent(out, r, newThread, asJSON)
}

// sendSealed is sealAndSend without a word printed, and with the message as
// it went out returned rather than described: serve sends this way, since
// its own output is its own and the reply's id goes in its ledger. It says
// whether the message opened a thread, which only the printing cares about.
//
// A message small enough goes as a single envelope, exactly as it always has.
// Above the threshold it becomes a stream, without being asked: the point of
// the switch is that nobody has to know which one they wanted.
func sendSealed(s *store.Store, id *identity.Identity, r *store.Relay, recipient *identity.Public,
	body message.Body, attachments []string, mode sendMode) (sentJSON, bool, error) {

	if mode.stream && mode.inline {
		return sentJSON{}, false, usageErrf("--stream and --inline contradict each other")
	}
	// A thread with no id starts one, under an id of its own: a thread
	// outlives the message that opened it and is not named after it.
	newThread := body.Thread == ""
	if newThread {
		tid, err := envelope.NewID()
		if err != nil {
			return sentJSON{}, false, err
		}
		body.Thread = tid
	}
	// Once here, whoever named it: a reply copies the thread of the message
	// it answers, and a record written by hand may carry anything. Both
	// the envelope and the stream refuse it further down; this is the one
	// sentence for it, before anything is read or sealed.
	if err := message.ValidHeader(body.Type, body.Thread, body.InReplyTo, body.Subject); err != nil {
		return sentJSON{}, newThread, usageErrf("%v", err)
	}

	cfg, err := s.Config()
	if err != nil {
		return sentJSON{}, newThread, err
	}
	set, err := settingsFrom(cfg)
	if err != nil {
		return sentJSON{}, newThread, err
	}
	// The estimate comes from the files' sizes, not their contents: nothing is
	// read until the shape of the message has been decided.
	raw, err := estimateSize(body, attachments)
	if err != nil {
		return sentJSON{}, newThread, err
	}
	estimate := raw + raw/3
	// Whether this becomes a stream, decided once and used twice: a message
	// that would become one cannot cross a relay, and the two questions have
	// to be the same question. Asked separately they were not — the refusal
	// asked whether the message was over the relay's own limit, 16 MiB,
	// where the switch asks whether it is over the stream threshold, 64 KiB
	// — so everything between fell through to sendStream, which takes a
	// channel and no path, and went into a mailbox on the sender's own
	// relay with the path dropped and nothing said. One expression, so
	// there is no between.
	becomesStream := mode.stream || (!mode.inline && estimate > set.threshold)
	// A message that crosses a relay goes as one envelope or it does not go.
	// A stream is an upload held open at the relay it is going to, resumed
	// by a route that names its id, and nothing carries one to a neighbour;
	// both spellings of "this is large" are refused here, before anything is
	// read, rather than at a relay that would have to explain a route it
	// does not have.
	if len(mode.path) > 0 && becomesStream {
		return sentJSON{}, newThread, usageErrf("a large message does not cross a relay yet%s",
			largestAttachmentHint(attachments))
	}
	if becomesStream {
		out, err := sendStream(s, id, r, recipient, body, attachments, set, mode.channel)
		// A stream has never printed the line that says how to wait for an
		// answer, and this is not the change that starts.
		return out, false, err
	}

	// Reading a payload we already know is too big wastes time and memory on
	// large attachments, so the estimate decides before anything is loaded.
	// Attachments travel base64 encoded, which costs about a third again on
	// top of the raw bytes. DefaultMaxBytes is under relayapi.MaxPageBytes,
	// so what this client sends inline is what a relay of this release
	// stores and every client of it lists.
	if estimate > relayapi.DefaultMaxBytes {
		return sentJSON{}, newThread, usageErrf("message is about %s once encoded, over the %s relay limit%s; "+
			"drop --inline to send it as a stream instead",
			term.HumanBytes(estimate), term.HumanBytes(relayapi.DefaultMaxBytes),
			largestAttachmentHint(attachments))
	}

	// Inline: only now are the bytes needed.
	loaded, err := loadAttachments(attachments)
	if err != nil {
		return sentJSON{}, newThread, err
	}
	body.Attachments = loaded

	env, inner, err := sealOnce(id, recipient, mode, body)
	if err != nil {
		return sentJSON{}, newThread, err
	}
	// The estimate above is a fast path. This is the number that decides.
	size, err := client.EnvelopeSize(env)
	if err != nil {
		return sentJSON{}, newThread, err
	}
	if int64(size) > relayapi.DefaultMaxBytes {
		return sentJSON{}, newThread, usageErrf("message is %s, over the %s relay limit%s",
			term.HumanBytes(int64(size)), term.HumanBytes(relayapi.DefaultMaxBytes), largestAttachmentHint(attachments))
	}

	c, err := dial(s, id, r)
	if err != nil {
		return sentJSON{}, newThread, err
	}
	relayID, err := postOrForward(c, env, mode)
	if err != nil {
		if len(mode.path) == 0 {
			// The channel hints first: their 404 begins "no such channel" and
			// must not be read as a mailbox that is not there.
			err = channelHint(err, s, id, c, r, recipient, mode.channel)
			return sentJSON{}, newThread, transportErr(notRegisteredHint(storageFullHint(err, recipient), s, recipient, r))
		}
		// None of those hints is about the relay this was posted to. A
		// channel belongs to the recipient and is checked at the last hop;
		// whether the recipient is registered, and whose disk is full, are
		// the last hop's too. The first hop's own refusals — it forwards
		// nothing, it does not know that neighbour, its queue is full —
		// say what they are, and anything further down comes back later as
		// a failed row rather than as an answer to this request.
		return sentJSON{}, newThread, transportErr(replyCannotGoBack(err, mode))
	}

	// Keep our own copy so threads can be reconstructed later: once, on the
	// first post that succeeded, since a kept envelope posted again is the
	// same message under the same id.
	if prior, err := s.Holding(store.Sent, inner.ID); err == nil && prior != nil {
		// Already kept.
	} else if err := s.Save(store.Sent, &store.Stored{
		RelayID:    relayID,
		Relay:      r.Name,
		Received:   time.Now().UTC().Truncate(time.Second),
		Read:       true,
		Inner:      inner,
		SenderName: recipient.Name,
		Channel:    mode.channel,
		// The address it went by, so that the record says where a message
		// went and not only to whom. The id beside it is the first hop's
		// row and not a mailbox's message, which is what an undeliverable
		// coming back will name.
		Path: store.JoinAddress(mode.path),
	}); err != nil {
		fmt.Fprintf(os.Stderr, "warning: message sent but the local copy failed: %v\n", err)
	}

	out := sentJSON{
		ID:        inner.ID,
		Thread:    body.Thread,
		To:        recipient.Fingerprint(),
		ToName:    recipient.Name,
		RelayID:   relayID,
		Bytes:     size,
		InReplyTo: body.InReplyTo,
		Channel:   mode.channel,
	}
	out.Kind = "envelope"
	out.Path = store.JoinAddress(mode.path)
	return out, newThread, nil
}

// keptSeal is the envelope a message was sealed as, with the inner record
// the sent box keeps, as sealOnce writes it down.
type keptSeal struct {
	Envelope *envelope.Envelope `json:"envelope"`
	Inner    *envelope.Inner    `json:"inner"`
}

// sealOnce is the envelope a message goes as. For a send with nowhere to
// keep one that is a fresh seal, as it always was. Where the caller keeps
// one (mode.sealed), the envelope sealed for an earlier attempt is posted
// again unchanged, so that an attempt whose post reached the relay and
// whose answer was lost, or after which the caller's own record could not
// be written, is not a second message under a new id: the recipient's
// store holds one message by its id and drops the other copy on its fetch
// (G41, R57). The relay keeps no hash for a post to a mailbox, so the copy
// posted again is a second row there until that fetch; a relay that
// refuses it outright is S50, after this release.
//
// The file is written whole before the first post. One that is not there,
// or that does not decode, as a write that stopped part way leaves it, is
// an envelope no post was made from, and a fresh seal is the first; one
// that is there and cannot be read is the caller's failure, never a seal
// afresh, which would be the second message this is here to prevent. An
// envelope kept for another recipient, a peer whose key changed between
// attempts, or for other words or files than these, an answer an earlier
// auu made again in between, is sealed again for this one.
//
// It is written to the disk before the post, the file and its directory
// both, so that a post the relay took is never followed by a kept envelope
// a lost power cut has emptied, which would read as no post at all.
//
// Envelopes only: a message that becomes a stream is sealed under a new
// upload at every attempt, as before.
func sealOnce(id *identity.Identity, recipient *identity.Public, mode sendMode, body message.Body) (*envelope.Envelope, *envelope.Inner, error) {
	if mode.sealed != "" {
		data, err := regular.ReadFile(mode.sealed)
		switch {
		case err == nil:
			var k keptSeal
			if wire.Decode(data, &k) == nil && k.Envelope != nil && k.Inner != nil &&
				k.Envelope.To == recipient.Fingerprint() && k.Envelope.Ch == mode.channel &&
				sameMessage(k.Inner.Body, body) {
				return k.Envelope, k.Inner, nil
			}
		case !errors.Is(err, os.ErrNotExist):
			return nil, nil, fmt.Errorf("the envelope kept for this message could not be read: %w", err)
		}
	}
	env, inner, err := envelope.SealFor(id, recipient, mode.channel, body)
	if err != nil {
		return nil, nil, usageErrf("%v", err)
	}
	if mode.sealed != "" {
		data, err := json.Marshal(keptSeal{Envelope: env, Inner: inner})
		if err != nil {
			return nil, nil, err
		}
		if err := keepSealed(mode.sealed, data); err != nil {
			return nil, nil, err
		}
	}
	return env, inner, nil
}

// sameMessage says whether a kept envelope's inner body is the message
// being sent: the same header, words and files, byte for byte.
func sameMessage(kept, body message.Body) bool {
	if kept.Type != body.Type || kept.Subject != body.Subject || kept.Thread != body.Thread ||
		kept.InReplyTo != body.InReplyTo || kept.Text != body.Text || len(kept.Attachments) != len(body.Attachments) {
		return false
	}
	for i, a := range kept.Attachments {
		b := body.Attachments[i]
		if a.Name != b.Name || a.SHA256 != b.SHA256 || !bytes.Equal(a.Data, b.Data) {
			return false
		}
	}
	return true
}

// keepSealed is writeNew with the file and its directory synced: what it
// keeps has to be on the disk before the post it guards is made.
func keepSealed(path string, data []byte) error {
	f, err := createNew(path)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(path)
		return err
	}
	if runtime.GOOS == "windows" {
		// No directory fsync there; NTFS journals the metadata itself.
		return nil
	}
	d, err := regular.Dir(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer d.Close()
	// A directory cannot be synced on every filesystem; the file's own
	// sync above is the part that always holds.
	d.Sync()
	return nil
}

// replyCannotGoBack turns the first hop's refusal of an address nobody typed
// into a sentence about the reply it refused.
//
// A reply's path is the way the message came, read backwards, and that rests
// on a convention nothing enforces: the names it is built from are what each
// hop calls the hop before, out of its couriers file, while a path is
// resolved against the courier home a relay dials from. Where an operator
// used one name in both, the reversal routes. Where they did not, or where
// the peering only goes one way, the first hop answers that it knows no such
// neighbour — naming a relay the person never typed, about a name they had no
// way to get right, for a message they are answering rather than addressing.
//
// So the sentence says what happened and what to do, and only for a reply:
// somebody who typed a bang path and got this wants the refusal as it came.
func replyCannotGoBack(err error, mode sendMode) error {
	if !mode.reply || len(mode.path) == 0 {
		return err
	}
	var he *client.HTTPError
	if !errors.As(err, &he) || he.Status != http.StatusNotFound || he.Code != relayapi.CodeNoNeighbour {
		return err
	}
	return fmt.Errorf("%w\n\nthat message came by %s, and this relay cannot send back the way it "+
		"came: the relays in an address are each relay's own names for its neighbours, and these "+
		"are the names the hops used coming this way. Answer by an address you have been given, as "+
		"--via NAME[!NAME], or on another relay you share with them, as --relay NAME",
		err, store.JoinAddress(mode.path))
}

// postOrForward sends one envelope the way its address says: into the
// recipient's mailbox on this relay, or onto the first hop's forward route
// with the rest of the address for it to carry.
//
// The answer is an id either way, and they are different kinds of id — a
// message in a mailbox, or a row in a queue — which is why the record keeps
// the path beside it.
func postOrForward(c *client.Client, env *envelope.Envelope, mode sendMode) (int64, error) {
	if len(mode.path) == 0 {
		return c.Post(ctx(), env, mode.channel)
	}
	// The channel goes on the envelope here, as Post puts it on there: it
	// is the one field outside the seal, and SealFor deliberately leaves it
	// to whoever posts, since the relay that reads it is the one being
	// posted to. On a path that relay is the last hop, and these bytes are
	// what every hop stores and passes on unchanged — so a channel not set
	// here is a channel no hop ever sees, and the last one would file the
	// message under default while the sealed copy inside said otherwise,
	// which is what the recipient quarantines as misfiled.
	outer := *env
	outer.Ch = mode.channel
	raw, err := json.Marshal(&outer)
	if err != nil {
		return 0, err
	}
	// A copy of a message to several says how many it went to, for the
	// first relay to hold to its max_recipients; a message to one says
	// nothing, and its request is the bytes it always was. A plain post
	// above carries no count: its body is the envelope alone (D54).
	count, err := recipients.CountSection(mode.recipients)
	if err != nil {
		return 0, err
	}
	// Via is empty and always present: the hops so far are the relays'
	// to write, and a sender that wrote one would be forging a return
	// path, which the route refuses by name.
	id, err := c.Forward(ctx(), &relayapi.ForwardRequest{
		Sections: relayapi.Sections{Sections: count},
		Envelope: raw,
		Path:     mode.path,
		Via:      []string{},
	})
	// A 409 says the relay is already holding this envelope, which is not a
	// failure: the message is queued, once, and the id is the row it is in.
	// Reading it as a failure would tell somebody their message did not go
	// when it did, and have them send it again so the relay held two.
	//
	// Nothing in `auu send` walks this today, and the comment should not
	// pretend otherwise: each send seals afresh, so the ciphertext and its
	// hash are new, and the client retries only what a relay answered 503
	// or 429 to — never a request whose answer was lost. What meets it is
	// the relay's own worker, retrying bytes it has stored after an attempt
	// was cut off. This is that contract honoured at the one other caller
	// of the route, so that a retry added here later is right by
	// construction rather than by somebody remembering.
	//
	// This end reads every 409 as placed, which is not what a relay's worker
	// does with one (ruling 45), and the difference is deliberate. The
	// worker is a hop holding a row it must end one way or another; here
	// the relay being asked is the sender's own, and a row of theirs there
	// is in their own queue listing, where how it ended is printed with its
	// code. A 409 with no id would be the sender's own relay holding the
	// same ciphertext from somebody else, which a fresh seal rules out.
	var he *client.HTTPError
	if errors.As(err, &he) && he.Status == http.StatusConflict {
		return he.ForwardID, nil
	}
	return id, err
}

// printSent says what went out, as a person reads it or as --json gives it.
// The two shapes print differently and always have: a stream says its
// chunks, and only an envelope that opened a thread says how to wait on it.
func printSent(out sentJSON, r *store.Relay, newThread, asJSON bool) error {
	if asJSON {
		return printJSON(out)
	}
	if out.Kind == "stream" {
		fmt.Printf("sent to %s via %s as a stream%s\n", orNone(out.ToName), r.Name, channelSuffix(out.Channel))
		fmt.Printf("message: %s\n", out.ID)
		fmt.Printf("thread:  %s\n", out.Thread)
		fmt.Printf("size:    %s in %d chunks of %s\n",
			term.HumanBytes(int64(out.Bytes)), out.Chunks-1, term.HumanBytes(int64(out.ChunkSize)))
		return nil
	}
	fmt.Printf("sent to %s via %s%s\n", orNone(out.ToName), r.Name, channelSuffix(out.Channel))
	fmt.Printf("message: %s\n", out.ID)
	fmt.Printf("thread:  %s\n", out.Thread)
	fmt.Printf("size:    %s\n", term.HumanBytes(int64(out.Bytes)))
	if newThread {
		fmt.Printf("\nWait for an answer with: %s wait --thread %s\n", prog, out.Thread)
	}
	return nil
}

// notRegisteredHint turns the relay's "no such mailbox" into the question a
// person actually has, which is which relay this peer is on. The answer comes
// from the spool: every message records the relay it arrived through, so the
// home already knows where somebody's mail comes from.
//
// It chooses nothing. Sending somewhere else is one flag away and is the
// person's decision, not the program's.
func notRegisteredHint(err error, s *store.Store, recipient *identity.Public, r *store.Relay) error {
	var httpErr *client.HTTPError
	if !errors.As(err, &httpErr) || httpErr.Status != http.StatusNotFound {
		return err
	}
	label := peerLabel(recipient)
	return fmt.Errorf("%s is not registered on %s%s",
		label, r.Name, elsewhere(s, recipient.Fingerprint(), label, r))
}

// storageFullHint rewrites the relay's 507 as advice aimed at whoever can
// actually act on it. Nothing the sender does will help: either the recipient
// has to collect their mail, or the operator has to find some disk.
func storageFullHint(err error, recipient *identity.Public) error {
	return streamFullHint(err, peerLabel(recipient))
}

// streamFullHint is the same, for a recipient known only by the name recorded
// beside a sealed stream: a resumed upload has no peer record to hand.
func streamFullHint(err error, label string) error {
	var httpErr *client.HTTPError
	if !errors.As(err, &httpErr) || httpErr.Status != http.StatusInsufficientStorage {
		return err
	}
	switch httpErr.Code {
	case relayapi.CodeRelayFull:
		return fmt.Errorf("the relay is out of storage; whoever runs it needs to make room")
	case relayapi.CodeMailboxFull:
		// Reading the mail is no longer what makes room: with a channel
		// set to keep, which is the default, mail stays queued after it is
		// fetched until its owner removes it.
		return fmt.Errorf("%s's mailbox on the relay is full; they need to run '%s rm' to make room",
			label, prog)
	}
	// A 507 of another kind is the relay's own sentence.
	return err
}

// isStorageFull reports a 507 from the relay: the mailbox or the relay has
// no room, and asking again will not make any.
func isStorageFull(err error) bool {
	var httpErr *client.HTTPError
	return errors.As(err, &httpErr) && httpErr.Status == http.StatusInsufficientStorage
}

// peerLabel names a peer the way the person typing would recognise them.
func peerLabel(p *identity.Public) string {
	if p.Name != "" {
		return p.Name
	}
	return p.Short()
}

// loadAttachments reads each named file into an attachment.
func loadAttachments(paths []string) ([]message.Attachment, error) {
	var out []message.Attachment
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			return nil, usageErrf("attachment %s: %v", p, err)
		}
		if info.IsDir() {
			return nil, usageErrf("attachment %s is a directory; attach files individually", p)
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, usageErrf("reading %s: %v", p, err)
		}
		// The sender's rule, here as a usage error before anything is
		// sealed, naming the step a receiver would take with the name;
		// SealFor runs it again, for every path that seals.
		if err := message.ValidAttachmentName(filepath.Base(p)); err != nil {
			return nil, usageErrf("%v", err)
		}
		a, err := message.NewAttachment(filepath.Base(p), data)
		if err != nil {
			return nil, usageErrf("%v", err)
		}
		out = append(out, a)
	}
	return out, nil
}

// estimateSize is the plaintext cost of a message, from the text and the
// attachments' sizes on disk. It opens nothing.
func estimateSize(body message.Body, paths []string) (int64, error) {
	total := int64(len(body.Text) + len(body.Subject))
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			return 0, usageErrf("attachment %s: %v", p, err)
		}
		if info.IsDir() {
			return 0, usageErrf("attachment %s is a directory; attach files individually", p)
		}
		total += info.Size()
	}
	return total, nil
}

// largestAttachmentHint names the attachment most worth dropping when a message
// is too big, so the error says what to do rather than only what went wrong. It
// works from the paths, so it can be called before anything has been read.
func largestAttachmentHint(paths []string) string {
	if len(paths) == 0 {
		return "; the message text alone is too long"
	}
	type entry struct {
		name string
		size int64
	}
	var sizes []entry
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			continue
		}
		sizes = append(sizes, entry{filepath.Base(p), info.Size()})
	}
	if len(sizes) == 0 {
		return ""
	}
	sort.Slice(sizes, func(i, j int) bool { return sizes[i].size > sizes[j].size })
	return fmt.Sprintf("; the largest attachment is %s at %s",
		sizes[0].name, term.HumanBytes(sizes[0].size))
}
