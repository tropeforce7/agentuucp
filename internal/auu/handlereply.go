package auu

import (
	"cmp"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/regular"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// The reply: one per job, at the first terminal state that is not removed
// or skipped by a first start.
//
// It is composed once, when the job ends, into handle's kept directory for
// the job, which the script is never told of (S56): a first line handle
// writes, and, when the script left one, the text of its output/reply.txt,
// read once through a handle that refuses a link, after every process the
// script started has been killed. What is sent, and sent again after a
// failed send, is that kept file and the envelope it was sealed as, never
// anything under the job's directory.

// replyText is the reply's file in a job's kept directory.
func replyText(keptDir string) string { return filepath.Join(keptDir, "reply.txt") }

// attemptsAllowed is the most attempts the route allows for the kind of
// failure a job ended in: a started attempt on a route that is not
// idempotent is never run again, so it is one of one.
func attemptsAllowed(route *handleRoute) int {
	if route.Idempotent {
		return route.Retries
	}
	return 1
}

// headline is the reply's first line, fixed: what became of the job, how
// it ended, and which attempt of how many the reply is about.
func headline(job *handleJob, route *handleRoute) string {
	switch {
	case job.State == jobSucceeded:
		return fmt.Sprintf("handle: succeeded (exit 0, attempt %d of %d)", job.Attempt, attemptsAllowed(route))
	case job.Attempt == 0:
		// It never started: the failures before launch are counted against
		// the route's retries.
		return fmt.Sprintf("handle: failed (could not prepare: %s, attempt %d of %d)", job.Reason, job.Failures, route.Retries)
	case job.TimedOut:
		return fmt.Sprintf("handle: failed (timeout after %s, attempt %d of %d)", route.timeout, job.Attempt, attemptsAllowed(route))
	case job.Exit < 0:
		return fmt.Sprintf("handle: failed (could not start: %s, attempt %d of %d)", job.Reason, job.Attempt, attemptsAllowed(route))
	default:
		return fmt.Sprintf("handle: failed (exit %d, attempt %d of %d)", job.Exit, job.Attempt, attemptsAllowed(route))
	}
}

// scriptReply is the text of the script's output/reply.txt, or "" with the
// reason it is left out, or "" and "" when there is none. The file is the
// script's, so it is read as anything from outside is. output is a root on
// the attempt's output/ opened before the script ran, so the directory read
// is that one whatever the script did to its name since. reply.txt must be
// a regular file there, not a link, and the file opened must be the file
// looked at. It is read no more than the route's max_reply_bytes, CRLF
// folded as serve folds a handler's, and held to the text rule a message's
// words are. A reason names no path of this machine's: it goes to the asker.
func scriptReply(output *os.Root, route *handleRoute) (string, string) {
	seen, err := output.Lstat("reply.txt")
	if errors.Is(err, os.ErrNotExist) {
		return "", ""
	}
	if err != nil {
		return "", "it could not be looked at"
	}
	if !seen.Mode().IsRegular() {
		return "", "it is not a regular file"
	}
	// A FIFO put in the file's place between the look and the open would
	// otherwise hold the open, and the run, until something wrote to it.
	f, err := output.OpenFile("reply.txt", os.O_RDONLY|openNonblock, 0)
	if err != nil {
		return "", "it could not be opened"
	}
	defer f.Close()
	if opened, err := f.Stat(); err != nil || !os.SameFile(seen, opened) {
		return "", "it changed as it was opened"
	}
	// One byte past the cap is what tells a file at the cap from one over
	// it; at the type's maximum there is no byte past, and nothing is cut.
	var r io.Reader = f
	if route.MaxReplyBytes > 0 && route.MaxReplyBytes < math.MaxInt64 {
		r = io.LimitReader(f, route.MaxReplyBytes+1)
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return "", "it could not be read"
	}
	if route.MaxReplyBytes > 0 && int64(len(data)) > route.MaxReplyBytes {
		// len is at most the cap plus one here, an int.
		return "", fmt.Sprintf("it is over the route's max_reply_bytes of %d", route.MaxReplyBytes)
	}
	text := strings.TrimRight(foldCRLF(string(data)), " \t\r\n")
	if strings.TrimSpace(text) == "" {
		return "", ""
	}
	if err := message.ValidText(text); err != nil {
		return "", err.Error()
	}
	return text, ""
}

// compose writes a job's reply into its kept directory: the first line,
// and the script's reply.txt when the attempt the reply is about left one.
// output is a root on that attempt's output/, nil for a job that never ran.
func (r *handleRun) compose(id string, job *handleJob, output *os.Root) error {
	paths, err := r.pathsFor(job.Route, id)
	if err != nil {
		return err
	}
	if err := r.makeDirs(paths.kept); err != nil {
		return err
	}
	route := r.cfg.Routes[job.Route]
	text := headline(job, route)
	if output != nil {
		switch said, why := scriptReply(output, route); {
		case why != "":
			text += "\nthe script's reply.txt was not included: " + why
		case said != "":
			text += "\n\n" + said
		}
	}
	// The envelope and the mark kept for an earlier reply to this job are
	// not this one's.
	for _, kept := range []string{sealedFile(paths.kept, id), postedFile(paths.kept, id)} {
		if err := os.Remove(kept); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return writeNew(replyText(paths.kept), []byte(text))
}

// owesReply says a job's reply is due and unsent: it ended succeeded or in
// review, has no reply yet, has sends left, and the last one that failed is
// behind its backoff.
func (job *handleJob) owesReply(route *handleRoute, now time.Time) bool {
	if job.Reply != "" || !(job.State == jobSucceeded || (job.State == jobFailed && job.Review)) {
		return false
	}
	if job.ReplyFailures >= route.Retries {
		return false
	}
	return job.ReplyTried.IsZero() || !job.ReplyTried.Add(retryBackoff(job.ReplyFailures)).After(now)
}

// replies sends every reply that is due, in admission order: one composed
// this round, or one whose send failed before and is due again.
func (r *handleRun) replies() error {
	now := handleNow()
	for _, id := range r.led.bySeq() {
		job := r.led.Jobs[id]
		route := r.cfg.Routes[job.Route]
		if route == nil || !job.owesReply(route, now) {
			continue
		}
		if err := r.answer(id); err != nil {
			return err
		}
	}
	return nil
}

// answer sends a job's kept reply, sealed once and kept beside it so that
// every attempt posts the same envelope under the same id (sealOnce), to
// the asker's verified sender, on the ask's thread, by the relay it came
// through. The ledger records the reply before the ask is marked read. A
// send that fails is the reply's failure, counted against the route's
// retries with the job's state left as it is; keys that lock or a scope
// that ends under the run end the run, with nothing counted. It is the one
// place a reply is sent, and what an operator's retry that changes the
// outcome will call to send the second (D162).
func (r *handleRun) answer(id string) error {
	job := r.led.Jobs[id]
	paths, err := r.pathsFor(job.Route, id)
	if err != nil {
		return err
	}
	m, err := r.s.Holding(store.Inbox, id)
	if err != nil {
		return r.replyFailed(id, fmt.Sprintf("its message could not be read: %v", err))
	}
	if m == nil {
		// The asker's message is gone: the owner took it back, and there is
		// nobody's ask to answer.
		return r.removed(id, nil, "its message was removed from the inbox before its reply went")
	}
	text, err := regular.ReadFile(replyText(paths.kept))
	if errors.Is(err, os.ErrNotExist) {
		// Composed when the job ended; a run that stopped between the end
		// and the composing composes it now.
		if err := r.compose(id, job, nil); err != nil {
			return err
		}
		text, err = regular.ReadFile(replyText(paths.kept))
	}
	if err != nil {
		return err
	}
	recipient, err := r.s.Resolve(m.Inner.From)
	if err != nil {
		return r.replyFailed(id, fmt.Sprintf("%s is not in your peer list any more", job.From[:16]))
	}
	relay, err := relayOf(r.s, m, "")
	if err != nil {
		return r.replyFailed(id, err.Error())
	}
	body := message.Body{
		Type:      message.TypeReply,
		Subject:   m.Inner.Body.Subject,
		Thread:    m.Inner.Body.Thread,
		InReplyTo: id,
		Text:      string(text),
	}
	out, _, err := sendSealed(r.s, r.id, relay, recipient, body, nil,
		sendMode{sealed: sealedFile(paths.kept, id), posted: postedFile(paths.kept, id)})
	if err != nil {
		if isLocked(err) {
			return err
		}
		if isReceiveOnly(err) {
			return needsSendErr("auu handle run")
		}
		return r.replyFailed(id, err.Error())
	}
	job.Reply = out.ID
	job.ReplySent = handleNow()
	if r.event != nil && r.event.ID == id {
		r.event.Reply = out.ID
	}
	if err := r.led.save(); err != nil {
		return err
	}
	if err := r.s.MarkRead(store.Inbox, id); err != nil {
		return err
	}
	// Sent: the mark has done its work.
	os.Remove(postedFile(paths.kept, id))
	if !r.asJSON {
		fmt.Printf("%s: replied to %s from %s (reply %s)\n", job.Route, shortID(id),
			orNone(identity.Printable(m.SenderName)), shortID(out.ID))
	}
	if job.State == jobSucceeded {
		return r.clean(id)
	}
	return nil
}

// replyFailed counts a send of a job's reply that did not get through, and
// after the route's retries records why, the reply unsent, beside the
// job's own reason.
func (r *handleRun) replyFailed(id, why string) error {
	job := r.led.Jobs[id]
	route := r.cfg.Routes[job.Route]
	job.ReplyFailures++
	job.ReplyTried = handleNow()
	tail := fmt.Sprintf("send %d of %d", job.ReplyFailures, route.Retries)
	if job.ReplyFailures >= route.Retries {
		note := "the reply could not be sent: " + why
		if job.Reason != "" {
			note = job.Reason + "; " + note
		}
		job.Reason = cutReason(note)
		tail = "given up"
	}
	if err := r.led.save(); err != nil {
		return err
	}
	r.failed = true
	fmt.Fprintf(os.Stderr, "%s: the reply to %s could not be sent: %s (%s)\n",
		job.Route, shortID(id), identity.PrintableText(why), tail)
	return nil
}

// clean removes a job's two directories, by the route id and message id
// the ledger holds, under handle/ and nowhere else: a succeeded job's once
// its reply is saved, and a removed job's at once. The ledger's entry stays,
// since it is what stops a second admission of the same message.
func (r *handleRun) clean(id string) error {
	job := r.led.Jobs[id]
	paths, err := r.pathsFor(job.Route, id)
	if err != nil {
		return err
	}
	for _, dir := range []string{paths.job, paths.kept} {
		if err := os.RemoveAll(dir); err != nil {
			return err
		}
	}
	return nil
}

// bySeq is the ledger's job ids in admission order.
func (l *handleLedger) bySeq() []string {
	ids := make([]string, 0, len(l.Jobs))
	for id := range l.Jobs {
		ids = append(ids, id)
	}
	// Admission numbers are unique, so the order is total.
	slices.SortFunc(ids, func(a, b string) int { return cmp.Compare(l.Jobs[a].Seq, l.Jobs[b].Seq) })
	return ids
}
