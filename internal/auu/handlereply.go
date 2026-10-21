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
	"strconv"
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
	case job.State == jobSkipped:
		return "handle: skipped by the operator (" + lastAttempt(job, route) + ")"
	case job.State == jobSucceeded:
		return fmt.Sprintf("handle: succeeded (exit 0, %s)", ofAllowed(job, route))
	case job.Interrupted:
		return fmt.Sprintf("handle: failed (interrupted, %s)", ofAllowed(job, route))
	case job.Attempt == 0 || job.BeforeLaunch:
		// It never started: the failures before launch are counted against
		// the route's retries.
		return fmt.Sprintf("handle: failed (could not prepare: %s, attempt %d of %d)", job.Reason, job.Failures, route.Retries)
	case job.TimedOut:
		return fmt.Sprintf("handle: failed (timeout after %s, %s)", route.timeout, ofAllowed(job, route))
	case job.Exit < 0:
		return fmt.Sprintf("handle: failed (could not start: %s, %s)", job.Reason, ofAllowed(job, route))
	default:
		return fmt.Sprintf("handle: failed (exit %d, %s)", job.Exit, ofAllowed(job, route))
	}
}

// ofAllowed is "attempt N of M" for the attempt a job's state is about,
// M the most the route allows; an attempt past that is the operator's
// retry, and says so rather than counting past the route's own number.
func ofAllowed(job *handleJob, route *handleRoute) string {
	if job.Attempt > attemptsAllowed(route) {
		return fmt.Sprintf("attempt %d, run again by the operator", job.Attempt)
	}
	return fmt.Sprintf("attempt %d of %d", job.Attempt, attemptsAllowed(route))
}

// lastAttempt is how a skipped job's last attempt ended, as its first line
// says it: "not run" when none started.
func lastAttempt(job *handleJob, route *handleRoute) string {
	switch {
	case job.Attempt == 0:
		return "not run"
	case job.BeforeLaunch:
		// Its last try never started: what an earlier attempt did is not
		// what ended it.
		return fmt.Sprintf("could not prepare: %s, after attempt %d", job.Reason, job.Attempt)
	case job.Interrupted:
		return fmt.Sprintf("interrupted, %s", ofAllowed(job, route))
	case job.TimedOut:
		return fmt.Sprintf("timeout after %s, %s", route.timeout, ofAllowed(job, route))
	default:
		return fmt.Sprintf("exit %d, %s", job.Exit, ofAllowed(job, route))
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
	attach := attachDir(paths.kept, job.Attempt)
	if err := os.RemoveAll(attach); err != nil {
		return err
	}
	if output != nil {
		said, why := scriptReply(output, route)
		switch {
		case why != "":
			text += "\nthe script's reply.txt was not included: " + why
		case said != "":
			text += "\n\n" + said
		}
		// The files and the text are bounded together: what the text took
		// is what the files cannot.
		budget := int64(-1)
		if route.MaxReplyBytes > 0 {
			budget = route.MaxReplyBytes - int64(len(said))
		}
		left, err := keepFiles(output, attach, budget, route.MaxReplyBytes)
		if err != nil {
			return err
		}
		for _, line := range left {
			text += "\n" + line
		}
	} else if job.Attempt > 0 && !job.Interrupted && !job.BeforeLaunch && !job.Redecided && job.State != jobSkipped {
		// A job that ran, composed with nothing of its attempt's: the run
		// that ended it stopped before what the script left was kept, and
		// the asker is told rather than given the first line alone.
		text += "\nthe script's reply.txt and files were not kept: the run stopped before they were"
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

// awaitsReply says a job is where a reply is owed and none has gone: it
// ended succeeded, in review or skipped by the operator with no reply yet,
// or an operator's retry of a job whose reply had gone ended succeeded
// with its one more reply unsent (D162).
func (job *handleJob) awaitsReply() bool {
	if job.Reply != "" {
		return job.SecondOwed && job.SecondReply == "" && job.State == jobSucceeded
	}
	return job.State == jobSucceeded || job.State == jobFailed && job.Review ||
		job.State == jobSkipped && job.By == skippedByOperator
}

// owesReply says a job's reply is due and unsent: awaitsReply, with sends
// left, and the last one that failed behind its backoff.
func (job *handleJob) owesReply(route *handleRoute, now time.Time) bool {
	if !job.awaitsReply() {
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
// place a reply is sent, the second of D162 among them.
func (r *handleRun) answer(id string) error {
	job := r.led.Jobs[id]
	// One reply per job, and one more only when an operator's retry of a
	// job whose reply had gone ended succeeded (D162).
	if !job.awaitsReply() {
		return nil
	}
	second := job.Reply != ""
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
	files, err := keptAttachments(paths.kept, job.Attempt)
	if err != nil {
		return err
	}
	out, _, err := sendSealed(r.s, r.id, relay, recipient, body, files,
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
	if second {
		job.SecondReply = out.ID
	} else {
		job.Reply = out.ID
	}
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
		again := ""
		if second {
			again = " again, after the operator's retry"
		}
		fmt.Printf("%s: replied to %s from %s%s (reply %s)\n", job.Route, shortID(id),
			orNone(identity.Printable(m.SenderName)), again, shortID(out.ID))
	}
	if job.State == jobSucceeded {
		r.cleanOrSay(id)
		return nil
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
		if err := removeTree(dir); err != nil {
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

// attachDir is where the files an attempt's reply carries are kept, under
// handle's own directory for the job.
func attachDir(keptDir string, attempt int) string {
	return filepath.Join(keptDir, "attach-"+strconv.Itoa(attempt))
}

// keepFiles moves every regular file the script left in output/attachments/
// into handle's own attach directory, by copying it through a handle, so
// that the reply is sealed from what handle holds and nothing the script
// or a process it left can change after (S56). output is the root held from
// before the script ran. Each file must be a regular file there, not a link
// or a directory, under a name a sender may use, distinct where case does
// not count from those before it; they are taken in name order, each
// counted against budget as it is copied, which with the text bounds the
// reply to the route's max_reply_bytes (-1 for no cap). What is left out
// is said, one line each, naming the file and why and no path of this
// machine's. An empty or absent directory attaches nothing and says
// nothing. An error is the host's.
func keepFiles(output *os.Root, attach string, budget, max int64) ([]string, error) {
	seen, err := output.Lstat("attachments")
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return []string{"the script's attachments directory could not be looked at, and nothing in it was sent"}, nil
	}
	if !seen.IsDir() {
		return []string{"the script's attachments is not a directory, and nothing in it was sent"}, nil
	}
	dir, err := output.OpenRoot("attachments")
	if err != nil {
		return []string{"the script's attachments directory could not be opened, and nothing in it was sent"}, nil
	}
	defer dir.Close()
	listing, err := dir.Open(".")
	if err != nil {
		return []string{"the script's attachments directory could not be listed, and nothing in it was sent"}, nil
	}
	entries, err := listing.ReadDir(-1)
	listing.Close()
	if err != nil {
		return []string{"the script's attachments directory could not be listed, and nothing in it was sent"}, nil
	}
	slices.SortFunc(entries, func(a, b os.DirEntry) int { return cmp.Compare(a.Name(), b.Name()) })
	var left, taken []string
	made := false
	leave := func(name, why string) {
		left = append(left, fmt.Sprintf("the script's file %q was left out: %s", name, why))
	}
	for _, e := range entries {
		name := e.Name()
		if err := message.ValidAttachmentName(name); err != nil {
			leave(name, "its name is not one a sender may use")
			continue
		}
		if err := message.DistinctAttachmentNames(append(slices.Clone(taken), name)); err != nil {
			leave(name, "its name is another file's where case does not count")
			continue
		}
		info, err := dir.Lstat(name)
		if err != nil {
			leave(name, "it could not be looked at")
			continue
		}
		if info.IsDir() {
			leave(name, "it is a directory")
			continue
		}
		if !info.Mode().IsRegular() {
			leave(name, "it is not a regular file")
			continue
		}
		if !made {
			if err := os.Mkdir(attach, 0o700); err != nil {
				return nil, err
			}
			made = true
		}
		n, why, err := keepFile(dir, name, info, filepath.Join(attach, name), budget)
		if err != nil {
			return nil, err
		}
		if why == "over" {
			why = fmt.Sprintf("with the reply's text and the files before it, it is over the route's max_reply_bytes of %d", max)
		}
		if why != "" {
			leave(name, why)
			continue
		}
		if budget >= 0 {
			budget -= n
		}
		taken = append(taken, name)
	}
	return left, nil
}

// keepFile copies one of the script's files into handle's directory: opened
// through the root by its name, not blocking, and only if it is the file
// looked at; read no more than budget, the rest of the reply's allowance
// (-1 for none). A file over it is "over"; one that cannot be read is said
// why. The copy is created exclusively and removed again on any failure.
func keepFile(dir *os.Root, name string, seen os.FileInfo, to string, budget int64) (int64, string, error) {
	src, err := dir.OpenFile(name, os.O_RDONLY|openNonblock, 0)
	if err != nil {
		return 0, "it could not be opened", nil
	}
	defer src.Close()
	if opened, err := src.Stat(); err != nil || !os.SameFile(seen, opened) {
		return 0, "it changed as it was opened", nil
	}
	dst, err := regular.Create(to, 0o600)
	if err != nil {
		return 0, "", err
	}
	var r io.Reader = src
	if budget >= 0 && budget < math.MaxInt64 {
		r = io.LimitReader(src, budget+1)
	}
	n, err := io.Copy(dst, r)
	if cerr := dst.Close(); err == nil {
		err = cerr
	}
	switch {
	case err != nil:
		os.Remove(to)
		return 0, "it could not be read", nil
	case budget >= 0 && n > budget:
		os.Remove(to)
		return 0, "over", nil
	}
	return n, "", nil
}

// keptAttachments is the files a reply carries, in name order: the attempt's
// attach directory in handle's own, which keepFiles wrote, each name held
// to the sender's rule again before it is joined.
func keptAttachments(keptDir string, attempt int) ([]string, error) {
	dir := attachDir(keptDir, attempt)
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if message.ValidAttachmentName(e.Name()) != nil || !e.Type().IsRegular() {
			return nil, fmt.Errorf("%s holds %q, which handle did not write there", dir, e.Name())
		}
		out = append(out, filepath.Join(dir, e.Name()))
	}
	return out, nil
}
