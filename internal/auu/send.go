package auu

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/tropeforce7/agentuucp/internal/client"
	"github.com/tropeforce7/agentuucp/internal/envelope"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/store"
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
}

func cmdSend(args []string) error {
	fs := newFlagSet("send")
	to := fs.String("to", "", "recipient: peer name or fingerprint, or self for a note to yourself")
	subject := fs.String("subject", "", "one-line subject")
	thread := fs.String("thread", "", "existing thread id (default: start a new thread)")
	replyTo := fs.String("reply-to", "", "message id this answers")
	msgType := fs.String("type", message.TypeAsk, "message type: ask or note")
	bodyFile := fs.String("body-file", "", "read the message text from this file")
	asJSON := fs.Bool("json", false, "machine readable output")
	forceStream := fs.Bool("stream", false, "send as a chunked stream whatever the size")
	forceInline := fs.Bool("inline", false, "send as a single envelope, failing if it is too large")
	resume := fs.Bool("resume", false, "finish any stream left unsent in the outbox, and send nothing new")
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
		if *to != "" || len(attach) > 0 || len(positional) > 0 || *channel != "" {
			return usageErrf("--resume finishes what is already sealed; it takes no other arguments")
		}
		s, id, err := loadIdentity()
		if err != nil {
			return err
		}
		return resumeStreams(s, id, *asJSON, *relay)
	}
	if *to == "" {
		return usageErrf("--to is required")
	}
	if *msgType != message.TypeAsk && *msgType != message.TypeNote {
		return usageErrf("--type must be ask or note")
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
	recipient, err := s.Resolve(*to)
	if err != nil {
		return usageErrf("%v", err)
	}
	warnPending(s)
	if compose {
		cfg, err := s.Config()
		if err != nil {
			return err
		}
		var edited string
		text, edited, err = composeIn(s, cfg, composeTemplate(recipient, *subject, attach, nil, text))
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
	err = sealAndSend(s, id, r, recipient, body, attach, sendMode{*forceStream, *forceInline, *channel}, *asJSON)
	if err != nil && compose {
		return draftKept(s, err)
	}
	return err
}

func cmdReply(args []string) error {
	fs := newFlagSet("reply")
	bodyFile := fs.String("body-file", "", "read the message text from this file")
	subject := fs.String("subject", "", "override the subject (default: keep the original)")
	asJSON := fs.Bool("json", false, "machine readable output")
	forceStream := fs.Bool("stream", false, "send as a chunked stream whatever the size")
	forceInline := fs.Bool("inline", false, "send as a single envelope, failing if it is too large")
	edit := fs.Bool("edit", false, "compose the reply in your editor, starting from any text given")
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
	recipient, err := s.Resolve(otherFP)
	if err != nil {
		return usageErrf("cannot reply: %s is not in your peer list", otherFP[:16])
	}
	// A reply goes back the way the message came, without being told.
	r, err := relayOf(s, original, *relay)
	if err != nil {
		return err
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
		text, edited, err = composeIn(s, cfg, composeTemplate(recipient, subj, attach, original, text))
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
	err = sealAndSend(s, id, r, recipient, body, attach, sendMode{*forceStream, *forceInline, *channel}, *asJSON)
	if err != nil && compose {
		return draftKept(s, err)
	}
	return err
}

// sendMode is what the flags say, before the size is consulted: the two
// that force a shape, and the recipient's channel, empty for default.
type sendMode struct {
	stream, inline bool
	channel        string
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
	if mode.stream || (!mode.inline && estimate > set.threshold) {
		out, err := sendStream(s, id, r, recipient, body, attachments, set, mode.channel)
		// A stream has never printed the line that says how to wait for an
		// answer, and this is not the change that starts.
		return out, false, err
	}

	// Reading a payload we already know is too big wastes time and memory on
	// large attachments, so the estimate decides before anything is loaded.
	// Attachments travel base64 encoded, which costs about a third again on
	// top of the raw bytes.
	if estimate > relayapi.DefaultMaxBytes {
		return sentJSON{}, newThread, usageErrf("message is about %s once encoded, over the %s relay limit%s; "+
			"drop --inline to send it as a stream instead",
			humanBytes(estimate), humanBytes(relayapi.DefaultMaxBytes),
			largestAttachmentHint(attachments))
	}

	// Inline: only now are the bytes needed.
	loaded, err := loadAttachments(attachments)
	if err != nil {
		return sentJSON{}, newThread, err
	}
	body.Attachments = loaded

	env, inner, err := envelope.SealFor(id, recipient, mode.channel, body)
	if err != nil {
		return sentJSON{}, newThread, usageErrf("%v", err)
	}
	// The estimate above is a fast path. This is the number that decides.
	size, err := client.EnvelopeSize(env)
	if err != nil {
		return sentJSON{}, newThread, err
	}
	if int64(size) > relayapi.DefaultMaxBytes {
		return sentJSON{}, newThread, usageErrf("message is %s, over the %s relay limit%s",
			humanBytes(int64(size)), humanBytes(relayapi.DefaultMaxBytes), largestAttachmentHint(attachments))
	}

	c, err := dial(s, id, r)
	if err != nil {
		return sentJSON{}, newThread, err
	}
	relayID, err := c.Post(ctx(), env, mode.channel)
	if err != nil {
		// The channel hints first: their 404 begins "no such channel" and
		// must not be read as a mailbox that is not there.
		err = channelHint(err, s, id, c, r, recipient, mode.channel)
		return sentJSON{}, newThread, transportErr(notRegisteredHint(storageFullHint(err, recipient), s, recipient, r))
	}

	// Keep our own copy so threads can be reconstructed later.
	if err := s.Save(store.Sent, &store.Stored{
		RelayID:    relayID,
		Relay:      r.Name,
		Received:   time.Now().UTC().Truncate(time.Second),
		Read:       true,
		Inner:      inner,
		SenderName: recipient.Name,
		Channel:    mode.channel,
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
	return out, newThread, nil
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
			humanBytes(int64(out.Bytes)), out.Chunks-1, humanBytes(int64(out.ChunkSize)))
		return nil
	}
	fmt.Printf("sent to %s via %s%s\n", orNone(out.ToName), r.Name, channelSuffix(out.Channel))
	fmt.Printf("message: %s\n", out.ID)
	fmt.Printf("thread:  %s\n", out.Thread)
	fmt.Printf("size:    %s\n", humanBytes(int64(out.Bytes)))
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
	if httpErr.Message == relayapi.MsgRelayFull {
		return fmt.Errorf("the relay is out of storage; whoever runs it needs to make room")
	}
	// Reading the mail is no longer what makes room: with a channel set to
	// keep, which is the default, mail stays queued after it is fetched
	// until its owner removes it.
	return fmt.Errorf("%s's mailbox on the relay is full; they need to run '%s rm' to make room",
		label, prog)
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
		sizes[0].name, humanBytes(sizes[0].size))
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGT"[exp])
}
