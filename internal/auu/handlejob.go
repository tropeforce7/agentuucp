package auu

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/regular"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// One job, from the inbox record to the end of an attempt.
//
// handle/jobs/<route>/<message id>/ is the job's, and the script's to read:
// original/, the asker's files unpacked once, and an attempt-N/ for each
// attempt, with the attempt's own input/, an empty work/ it runs in, and a
// tmp-XXXXXXXX/ of its own holding output/. handle/kept/<route>/<message
// id>/ is handle's, and the script is never told of it: the attempt's two
// streams are files there, so that nothing a script leaves running holds a
// pipe the wait is waiting on.

// maxReason is the most of a failure's first line the ledger keeps.
const maxReason = 512

// jobPaths are a job's directories, every one made from a route id and a
// message id that the ledger and the file have held to their rules, joined
// under handle/ and nowhere else.
type jobPaths struct {
	job      string // handle/jobs/<route>/<id>
	kept     string // handle/kept/<route>/<id>
	original string // job/original
}

func (r *handleRun) pathsFor(route, id string) (jobPaths, error) {
	// Held again at the join, whatever held them before.
	if err := validRouteName(route); err != nil {
		return jobPaths{}, fmt.Errorf("a job's route %q is not a route's name: %v", route, err)
	}
	if message.ValidID(id) != nil {
		return jobPaths{}, fmt.Errorf("a job's id %q is not a message id", id)
	}
	job := filepath.Join(r.root, "jobs", route, id)
	return jobPaths{job: job, kept: filepath.Join(r.root, "kept", route, id), original: filepath.Join(job, "original")}, nil
}

// makeDirs makes each directory under handle/ down to dir, refusing any
// that is there and is not a directory: a link planted at a route's or a
// job's name is never followed into.
func (r *handleRun) makeDirs(dir string) error {
	rel, err := filepath.Rel(r.root, dir)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		return fmt.Errorf("%s is not under %s", dir, r.root)
	}
	at := r.root
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		at = filepath.Join(at, part)
		err := os.Mkdir(at, 0o700)
		if err == nil {
			continue
		}
		if !errors.Is(err, os.ErrExist) {
			return err
		}
		info, err := os.Lstat(at)
		if err != nil {
			return err
		}
		if !info.IsDir() {
			return fmt.Errorf("%s is not a directory of handle's; move it aside", at)
		}
	}
	return nil
}

// runJob takes one job a step to its end: removed when its message has left
// the inbox, prepared, run, and written down however it ended. An error is
// the host's fault and ends the run; the job's own faults are its state. It
// runs in a worker of its own, holding the run's lock for everything but the
// script's run.
func (r *handleRun) runJob(ctx context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	job := r.led.Jobs[id]
	route := r.cfg.Routes[job.Route]
	// A job that has run before is run again only as a retry, decided again
	// under the file as it is now, whatever state the way back left it in:
	// a failed retry, one queued again after a failure before launch or a
	// stop while preparing, or one a crash left preparing. A route made not
	// idempotent, or given fewer retries, since does not run the job a
	// second time (point 7).
	// The operator's retry is their word that it runs once more.
	if job.Attempt > 0 && !job.OperatorRetry && !(route.Idempotent && job.Attempt < route.Retries) {
		const notAgain = "; not run again: the route is no longer idempotent, or its attempts are spent"
		job.State, job.Review, job.RetryAt, job.Redecided = jobFailed, true, time.Time{}, true
		job.Reason = cutTo(job.Reason, maxReason-len(notAgain)) + notAgain
		if err := r.led.save(); err != nil {
			return err
		}
		r.report(id, job, nil)
		if err := r.compose(id, job, nil); err != nil {
			return err
		}
		return r.answer(id)
	}
	paths, err := r.pathsFor(job.Route, id)
	if err != nil {
		return err
	}
	// The owner may take a message back at any time. Gone is gone; a
	// record that is there and cannot be read is this attempt's failure,
	// and never taken for a removal (point 4).
	m, err := r.s.Holding(store.Inbox, id)
	if err != nil {
		return r.beforeLaunch(id, route, fmt.Sprintf("its message could not be read: %v", err))
	}
	if m == nil {
		return r.removed(id, nil, "its message was removed from the inbox")
	}
	resumed := r.resumed[id] || job.State == jobPreparing
	delete(r.resumed, id)
	job.State = jobPreparing
	if err := r.led.save(); err != nil {
		return err
	}
	for _, dir := range []string{paths.job, paths.kept} {
		if err := r.makeDirs(dir); err != nil {
			return err
		}
	}
	// A run that stopped while preparing left the unpack wherever it got
	// to, and the ledger cannot say where: it is started afresh (A7).
	if resumed {
		for _, dir := range []string{paths.original + ".tmp", paths.original} {
			if err := os.RemoveAll(dir); err != nil {
				return err
			}
		}
	}
	if why, err := r.unpack(m, paths); err != nil {
		return err
	} else if why != "" {
		return r.beforeLaunch(id, route, why)
	}
	files, why := originalFiles(m, paths.original)
	if why != "" {
		return r.beforeLaunch(id, route, why)
	}
	job0 := r.messageJSON(id, job, m, 0, filepath.Join(paths.job, "body.txt"), paths.original, files)
	for name, data := range map[string][]byte{"body.txt": []byte(m.Inner.Body.Text), "message.json": job0} {
		if err := writeNew(filepath.Join(paths.job, name), data); err != nil {
			return err
		}
	}

	n := job.Attempt + 1
	at, why, err := r.makeAttempt(id, job, m, paths, n, files)
	if err != nil {
		return err
	}
	if why != "" {
		return r.beforeLaunch(id, route, why)
	}
	// A bare name is the PATH's at each launch, as git is for serve (A1),
	// and what runs is the path it resolved to, never a name for the
	// working directory to answer.
	program := route.program
	if !hasSeparator(route.Command[0]) {
		found, err := exec.LookPath(route.Command[0])
		if err != nil {
			return r.beforeLaunch(id, route, fmt.Sprintf("command's program %q is not on the PATH: %v", route.Command[0], err))
		}
		if program, err = filepath.Abs(found); err != nil {
			return err
		}
	}

	stdinFile, err := regular.Open(at.body)
	if err != nil {
		return r.beforeLaunch(id, route, fmt.Sprintf("its body could not be read back: %v", err))
	}
	defer stdinFile.Close()
	outPath := filepath.Join(paths.kept, "stdout-"+strconv.Itoa(n)+".txt")
	errPath := filepath.Join(paths.kept, "stderr-"+strconv.Itoa(n)+".txt")
	stdout, err := createNew(outPath)
	if err != nil {
		return err
	}
	defer stdout.Close()
	stderr, err := createNew(errPath)
	if err != nil {
		return err
	}
	defer stderr.Close()

	// The directory the script's reply is read from, held from before the
	// script runs: renaming output/ and putting a link in its place points
	// nothing of handle's elsewhere.
	output, err := os.OpenRoot(at.output)
	if err != nil {
		return err
	}
	defer output.Close()

	// A stop that came while the job was being prepared leaves it to be
	// prepared again; no attempt is started only to be killed.
	if ctx.Err() != nil {
		job.State = jobQueued
		if err := r.led.save(); err != nil {
			return err
		}
		return ctx.Err()
	}
	job.State = jobRunning
	job.Attempt = n
	job.Started = handleNow()
	job.Ended, job.Exit, job.TimedOut, job.Killed, job.Interrupted = time.Time{}, 0, false, false, false
	job.Review, job.RetryAt, job.BeforeLaunch, job.Redecided = false, time.Time{}, false, false
	// The operator's word was for this attempt, and is spent on it.
	job.OperatorRetry = false
	if err := r.led.save(); err != nil {
		return err
	}
	// The program and the file's own arguments, and nothing of the
	// message's: what the message says reaches the script as files and
	// variables, never as a word on its command line. No shell is run.
	cmd := exec.Command(program, route.Command[1:]...)
	cmd.Args[0] = route.Command[0]
	env := r.env(id, job, m, at)
	// The one step no lock is held over: the script's run, which is what
	// the other workers run beside.
	r.mu.Unlock()
	run, runErr := runCommand(ctx, cmd, route.Command[0], at.work, env, stdinFile, stdout, stderr, route.timeout)
	r.mu.Lock()
	stdout.Close()
	stderr.Close()
	// Whatever the script left running is killed before anything it wrote
	// is read, so that nothing writes into output/ after handle has read
	// it. Not on Windows, where a pid the script's own has exited with may
	// be another program's by now.
	if runtime.GOOS != "windows" && cmd.Process != nil {
		killGroup(cmd)
	}
	// The logs are bounded after the run, not during it (D7): a file
	// handed to a child cannot be bounded while it writes, and the
	// attempt's timeout is what bounds the disk meanwhile.
	for _, path := range []string{outPath, errPath} {
		if wrote, err := cutLog(path, route.MaxLogBytes); err != nil {
			return err
		} else if wrote > 0 {
			fmt.Fprintf(os.Stderr, "%s: %s's %s was cut at max_log_bytes of %d; the script wrote %d bytes\n",
				job.Route, shortID(id), filepath.Base(path), route.MaxLogBytes, wrote)
		}
	}
	prefixedTo(os.Stderr, errPath, job.Route+" "+shortID(id))
	if runErr != nil && ctx.Err() != nil {
		// Stopped: the group is killed and its leader waited for, and that
		// is written before the run ends. A child that left the group, by
		// setsid or its own process group, outlives the kill, which the
		// guide says beside supervisor_reaps.
		job.State, job.Killed, job.Interrupted = jobInterrupted, true, true
		job.Ended = handleNow()
		job.Reason = "the service was stopped while it ran"
		if err := r.led.save(); err != nil {
			return err
		}
		return runErr
	}
	job.Ended = handleNow()
	job.Exit, job.TimedOut = run.exit, run.timedOut
	if runErr != nil {
		// A program that could not be started says so in its own words at
		// its first attempt, and that is the attempt's failure.
		job.Exit = -1
	}
	// A message the owner removed while its script ran is removed: the
	// attempt ran on its own copy, and the asker's message is gone.
	if gone, err := r.s.Holding(store.Inbox, id); err == nil && gone == nil {
		return r.removed(id, m, "its message was removed from the inbox while its script ran")
	}
	switch {
	case runErr != nil:
		// Said to the asker as could not start: neither the home nor the
		// program's place on this machine is named (S81).
		why := strings.ReplaceAll(runErr.Error(), program, "the route's program")
		job.State, job.Reason = jobFailed, cutReason(r.pathFree(why))
	case run.ok():
		job.State, job.Reason = jobSucceeded, ""
	default:
		job.State, job.Reason = jobFailed, cutReason(said(run, errPath))
	}
	// A started attempt that failed is run again only on an idempotent
	// route with attempts left, at serve's backoff; on any other it may
	// have done its work, and is for review at once (point 7).
	if job.State == jobFailed {
		if route.Idempotent && job.Attempt < route.Retries {
			job.Review, job.RetryAt = false, handleNow().Add(retryBackoff(job.Attempt))
		} else {
			job.Review = true
		}
	}
	if err := r.led.save(); err != nil {
		return err
	}
	r.report(id, job, m)
	if job.State == jobFailed && !job.Review {
		return nil
	}
	if beforeCompose != nil {
		if err := beforeCompose(); err != nil {
			return err
		}
	}
	if err := r.compose(id, job, output); err != nil {
		return err
	}
	return r.answer(id)
}

// beforeCompose, when a test sets it, runs between a job's end being saved
// and its reply being composed, and an error from it ends the run there, as
// a run that stops between the two stops.
var beforeCompose func() error

// unpack writes the asker's files into original/ once, under original.tmp
// until every one is there, as serve's in/<id> is, so that a run stopped
// part way leaves nothing the next attempt reads as the files. A message
// with none has an empty original/. The reason is the attempt's failure;
// the error is the host's.
func (r *handleRun) unpack(m *store.Stored, paths jobPaths) (string, error) {
	if info, err := os.Lstat(paths.original); err == nil && info.IsDir() {
		return "", nil
	}
	tmp := paths.original + ".tmp"
	if err := os.RemoveAll(tmp); err != nil {
		return "", err
	}
	if err := os.Mkdir(tmp, 0o700); err != nil {
		return "", err
	}
	if len(m.Inner.Body.Attachments) > 0 {
		if _, err := extractInto(r.s, store.Inbox, m, tmp); err != nil {
			os.RemoveAll(tmp)
			return fmt.Sprintf("the files it sent could not be unpacked: %v", err), nil
		}
	}
	if beforeOriginalRename != nil {
		if err := beforeOriginalRename(tmp); err != nil {
			return "", err
		}
	}
	return "", os.Rename(tmp, paths.original)
}

// beforeOriginalRename, when a test sets it, runs between an unpack and the
// rename that makes it original/, and an error from it ends the run there,
// as a run that stops part way stops.
var beforeOriginalRename func(tmp string) error

// originalFiles is the name each attachment was written under in
// original/, in the message's order: the name extractInto chose, SafeName
// numbered as writeUnique numbers it, found by its exact spelling in the
// directory's listing. The listing is of a directory handle wrote; each
// name is held to SafeName of itself before it is joined to anything.
func originalFiles(m *store.Stored, dir string) ([]string, string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Sprintf("the files it sent could not be listed: %v", err)
	}
	present := map[string]bool{}
	for _, e := range entries {
		if message.SafeName(e.Name()) == e.Name() && e.Type().IsRegular() {
			present[e.Name()] = true
		}
	}
	files := make([]string, len(m.Inner.Body.Attachments))
	for i, a := range m.Inner.Body.Attachments {
		safe := message.SafeName(a.Name)
		for n := 1; n <= maxNameTries; n++ {
			if name := message.Numbered(safe, n); present[name] {
				files[i] = name
				delete(present, name)
				break
			}
		}
		if files[i] == "" {
			return nil, fmt.Sprintf("the files it sent are not all in %s", dir)
		}
	}
	return files, ""
}

// attemptPaths are one attempt's directories and files.
type attemptPaths struct {
	dir, input, body, attachments, work, temp, output, outputAttachments, messageJSON string
}

// makeAttempt makes attempt-N afresh: input/ with the body, message.json
// and a copy of original/, an empty work/, and tmp-XXXXXXXX/ with output/
// and output/attachments/ under it (D171). A copy that fails is the
// attempt's failure; a directory that cannot be made is the host's.
func (r *handleRun) makeAttempt(id string, job *handleJob, m *store.Stored, paths jobPaths, n int, files []string) (attemptPaths, string, error) {
	var at attemptPaths
	at.dir = filepath.Join(paths.job, "attempt-"+strconv.Itoa(n))
	// What a run that stopped left under this attempt's number is not this
	// attempt's.
	if err := os.RemoveAll(at.dir); err != nil {
		return at, "", err
	}
	at.input = filepath.Join(at.dir, "input")
	at.body = filepath.Join(at.input, "body.txt")
	at.work = filepath.Join(at.dir, "work")
	at.messageJSON = filepath.Join(at.input, "message.json")
	for _, dir := range []string{at.dir, at.input, at.work} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			return at, "", err
		}
	}
	temp, err := os.MkdirTemp(at.dir, "tmp-")
	if err != nil {
		return at, "", err
	}
	at.temp = temp
	at.output = filepath.Join(temp, "output")
	at.outputAttachments = filepath.Join(at.output, "attachments")
	for _, dir := range []string{at.output, at.outputAttachments} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			return at, "", err
		}
	}
	if len(files) > 0 {
		at.attachments = filepath.Join(at.input, "attachments")
		if err := os.Mkdir(at.attachments, 0o700); err != nil {
			return at, "", err
		}
		for _, name := range files {
			if err := copyRegular(filepath.Join(paths.original, name), filepath.Join(at.attachments, name)); err != nil {
				return at, fmt.Sprintf("the files it sent could not be copied for attempt %d: %v", n, err), nil
			}
		}
	}
	if err := writeNew(at.body, []byte(m.Inner.Body.Text)); err != nil {
		return at, "", err
	}
	data := r.messageJSON(id, job, m, n, at.body, at.attachments, files)
	if err := writeNew(at.messageJSON, data); err != nil {
		return at, "", err
	}
	return at, "", nil
}

// copyRegular copies one regular file to a new one, the source opened by
// its handle and the target created exclusively, so that a script that
// edits its copy edits nothing the next attempt is given.
func copyRegular(from, to string) error {
	src, err := regular.Open(from)
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := regular.Create(to, 0o600)
	if err != nil {
		return err
	}
	_, err = io.Copy(dst, src)
	if cerr := dst.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(to)
	}
	return err
}

// handleMessage is message.json, the message as a script reads it: every
// key always written.
type handleMessage struct {
	V              int                `json:"v"`
	JobID          string             `json:"job_id"`
	Route          string             `json:"route"`
	Attempt        int                `json:"attempt"`
	MessageID      string             `json:"message_id"`
	Thread         string             `json:"thread"`
	InReplyTo      string             `json:"in_reply_to"`
	Type           string             `json:"type"`
	From           string             `json:"from"`
	FromName       string             `json:"from_name"`
	To             string             `json:"to"`
	Recipients     []string           `json:"recipients"`
	Channel        string             `json:"channel"`
	Relay          string             `json:"relay"`
	Subject        string             `json:"subject"`
	Time           time.Time          `json:"time"`
	Arrived        time.Time          `json:"arrived"`
	Seq            int64              `json:"seq"`
	Revision       string             `json:"revision"`
	BodyFile       string             `json:"body_file"`
	AttachmentsDir string             `json:"attachments_dir"`
	Attachments    []handleAttachment `json:"attachments"`
}

// handleAttachment is one of the asker's files as message.json names it:
// the sender's name for it, the name it was written under, the copy this
// attempt was given, and what the message says it is.
type handleAttachment struct {
	Name   string `json:"name"`
	File   string `json:"file"`
	Path   string `json:"path"`
	Media  string `json:"media"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// messageJSON is an attempt's message.json: attempt 0 for the job's own,
// whose paths are original/.
func (r *handleRun) messageJSON(id string, job *handleJob, m *store.Stored, attempt int, body, dir string, files []string) []byte {
	recipients := recipientsOf(m)
	if recipients == nil {
		recipients = []string{}
	}
	attachments := []handleAttachment{}
	for i, a := range m.Inner.Body.Attachments {
		attachments = append(attachments, handleAttachment{Name: a.Name, File: files[i], Path: filepath.Join(dir, files[i]),
			Media: a.Media, Size: a.Size, SHA256: a.SHA256})
	}
	doc := handleMessage{
		V: 1, JobID: job.Route + "/" + id, Route: job.Route, Attempt: attempt,
		MessageID: id, Thread: m.Inner.Body.Thread, InReplyTo: m.Inner.Body.InReplyTo, Type: m.Inner.Body.Type,
		From: m.Inner.From, FromName: m.SenderName, To: m.Inner.To, Recipients: recipients,
		Channel: channelOf(m), Relay: m.Relay, Subject: m.Inner.Body.Subject,
		Time: m.Inner.Time.UTC(), Arrived: m.Arrived.UTC(), Seq: job.Seq, Revision: job.Revision,
		BodyFile: body, AttachmentsDir: dir, Attachments: attachments,
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		// Strings, numbers and times always encode.
		panic(err)
	}
	return buf.Bytes()
}

// handleEnvNames are the names handle sets in a script's environment, and
// worktreeNames serve's that a job has no use for: an inherited value of
// either is dropped, so that no rule about which duplicate wins decides
// what a script reads.
var worktreeNames = []string{"AUU_TURN", "AUU_MODE", "AUU_WORKTREE", "AUU_BASE", "AUU_THREAD_DIR", "AUU_CHANNEL_DIR", "AUU_STATUS"}

// env is a script's environment: the process's own, less the credential
// variables, which handle never hands on, and less anything that would
// collide, plus the message and the attempt's places.
func (r *handleRun) env(id string, job *handleJob, m *store.Stored, at attemptPaths) []string {
	set := map[string]string{
		"AUU_MESSAGE_ID":         id,
		"AUU_THREAD_ID":          m.Inner.Body.Thread,
		"AUU_IN_REPLY_TO":        m.Inner.Body.InReplyTo,
		"AUU_TYPE":               m.Inner.Body.Type,
		"AUU_FROM":               m.Inner.From,
		"AUU_FROM_NAME":          m.SenderName,
		"AUU_RECIPIENTS":         strings.Join(recipientsOf(m), " "),
		"AUU_CHANNEL":            channelOf(m),
		"AUU_RELAY":              m.Relay,
		"AUU_SUBJECT":            m.Inner.Body.Subject,
		"AUU_ATTACHMENTS":        at.attachments,
		"AUU_JOB_ID":             job.Route + "/" + id,
		"AUU_ATTEMPT":            strconv.Itoa(job.Attempt),
		"AUU_WORK_DIR":           at.work,
		"AUU_OUTPUT_DIR":         at.output,
		"AUU_OUTPUT_ATTACHMENTS": at.outputAttachments,
		"AUU_TEMP_DIR":           at.temp,
		"AUU_MESSAGE_JSON":       at.messageJSON,
		"TMPDIR":                 at.temp,
	}
	if runtime.GOOS == "windows" {
		set["TMP"] = at.temp
		set["TEMP"] = at.temp
	}
	drop := map[string]bool{}
	for _, name := range append(slices.Clone(worktreeNames), credentialVars...) {
		drop[name] = true
	}
	inherited := os.Environ()
	out := make([]string, 0, len(inherited)+len(set))
	for _, kv := range inherited {
		name, _, _ := strings.Cut(kv, "=")
		// Windows names its variables without regard to case, so a
		// credential or one of handle's own under another case is the
		// same variable there.
		if runtime.GOOS == "windows" {
			name = strings.ToUpper(name)
		}
		if _, ours := set[name]; ours || drop[name] {
			continue
		}
		out = append(out, kv)
	}
	for _, name := range sortedKeys(set) {
		out = append(out, name+"="+set[name])
	}
	return out
}

// beforeLaunch is a failure before the script started: unpacking, the
// copy, the program not found. It counts, and the job is queued again at
// serve's backoff, or failed for review once the route's retries are spent.
func (r *handleRun) beforeLaunch(id string, route *handleRoute, why string) error {
	job := r.led.Jobs[id]
	job.Failures++
	// The reason goes to the asker in the reply's first line, and an
	// error from the filesystem names the path it failed on: the home is
	// said by its name and never by where it is on this machine (S81).
	job.Reason = cutReason(r.pathFree(why))
	// The last attempt the reply would be about never started: what an
	// earlier one left is not this failure's.
	job.BeforeLaunch, job.Interrupted, job.TimedOut, job.Exit = true, false, false, 0
	if job.Failures >= route.Retries {
		job.State, job.Review, job.RetryAt = jobFailed, true, time.Time{}
		endedNow(job)
	} else {
		job.State, job.RetryAt = jobQueued, handleNow().Add(retryBackoff(job.Failures))
	}
	if err := r.led.save(); err != nil {
		return err
	}
	r.report(id, job, nil)
	if job.State != jobFailed {
		return nil
	}
	// In review without having run: the reply says so, with nothing of the
	// script's.
	if err := r.compose(id, job, nil); err != nil {
		return err
	}
	return r.answer(id)
}

// endedNow gives a job that ends without an attempt having ended, never
// run or found running after a crash, the time it ended, which keep_failed
// counts from.
func endedNow(job *handleJob) {
	if job.Ended.IsZero() {
		job.Ended = handleNow()
	}
}

// pathFree is why with the home's path, as given and as the links under
// it resolve, said as AUU_HOME.
func (r *handleRun) pathFree(why string) string {
	home := r.s.Root()
	if real, err := filepath.EvalSymlinks(home); err == nil && real != home {
		why = strings.ReplaceAll(why, real, "AUU_HOME")
	}
	return strings.ReplaceAll(why, home, "AUU_HOME")
}

// removed is a job whose message the owner took back: written down, and
// nothing more done for it.
func (r *handleRun) removed(id string, m *store.Stored, why string) error {
	job := r.led.Jobs[id]
	job.State, job.Reason = jobRemoved, why
	if err := r.led.save(); err != nil {
		return err
	}
	r.report(id, job, m)
	// Nobody's ask is left to answer, and its files go at once.
	r.cleanOrSay(id)
	return nil
}

// report says what happened to a job, on standard output, and puts it in
// the round's JSON.
func (r *handleRun) report(id string, job *handleJob, m *store.Stored) {
	if job.State == jobFailed || (job.State == jobQueued && job.Failures > 0) {
		r.failed = true
	}
	r.out.Jobs = append(r.out.Jobs, handleJobEvent{ID: id, Route: job.Route, State: job.State, Attempt: job.Attempt, Reason: job.Reason})
	r.event = &r.out.Jobs[len(r.out.Jobs)-1]
	if r.asJSON {
		return
	}
	from := job.From[:16]
	if m != nil {
		from = orNone(identity.Printable(m.SenderName))
	}
	var what string
	switch {
	case job.State == jobSucceeded:
		what = fmt.Sprintf("succeeded (exit 0, attempt %d)", job.Attempt)
	case job.State == jobQueued:
		what = fmt.Sprintf("could not be prepared, and is tried again: %s (failure %d of %d)",
			job.Reason, job.Failures, r.cfg.Routes[job.Route].Retries)
	case job.State == jobFailed && job.Attempt == 0:
		what = fmt.Sprintf("failed for review, never run: %s", job.Reason)
	case job.State == jobFailed && !job.Review:
		what = fmt.Sprintf("failed, and is run again: %s (attempt %d of %d)", job.Reason, job.Attempt, r.cfg.Routes[job.Route].Retries)
	case job.State == jobFailed:
		what = fmt.Sprintf("failed for review: %s (attempt %d)", job.Reason, job.Attempt)
	default:
		what = job.State + ": " + job.Reason
	}
	// The reason may hold a script's first line, which a message may have
	// shaped: escaped, as every print of words from outside is.
	fmt.Printf("%s: %s from %s %s\n", job.Route, shortID(id), from, identity.PrintableText(what))
}

// cutReason is a failure's words as the ledger keeps them: the first line,
// at most maxReason bytes, cut on a rune.
func cutReason(why string) string { return cutTo(why, maxReason) }

// cutTo is the first line of why in at most n bytes, n zero or more, cut
// where a rune starts, so a rune is never split; bytes that were never a
// rune are the reason's own, and are escaped where it is shown.
func cutTo(why string, n int) string {
	why, _, _ = strings.Cut(why, "\n")
	if len(why) <= n {
		return why
	}
	end := n
	for end > 0 && end > n-utf8.UTFMax && !utf8.RuneStart(why[end]) {
		end--
	}
	return why[:end]
}
