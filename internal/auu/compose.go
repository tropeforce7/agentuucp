package auu

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/store"
	"github.com/tropeforce7/agentuucp/internal/term"
)

// Composing a message in an editor, the way git commit does without -m.
//
// The rules are git's, because people already know them: a template of
// comment lines describing what is about to be sent, the message written
// above them, lines beginning with '#' dropped, an empty result sending
// nothing, and the file kept afterwards so a send that fails has not lost the
// text. When no subject was given on the command line, the first line is the
// subject and the rest is the message, exactly as a commit's first line is
// its summary.

// composeFile is where the draft lives, beside the identity: the same idea as
// .git/COMMIT_EDITMSG.
const composeFile = "COMPOSE_MSG"

// editorFor picks the editor in git's order, with the program's own variable
// first so a wrapper can pin one: AUU_EDITOR, then the editor key in
// config.json, then VISUAL, then EDITOR, then vi.
func editorFor(cfg store.Config) string {
	for _, candidate := range []string{os.Getenv("AUU_EDITOR"), cfg.Editor, os.Getenv("VISUAL"), os.Getenv("EDITOR")} {
		if strings.TrimSpace(candidate) != "" {
			return candidate
		}
	}
	return "vi"
}

// interactive reports whether a person is at the other end: standard input
// and standard output are both terminals. An agent gives its text on the
// command line or pipes it in, and captures the output, so it has neither.
// Nothing opens an editor on an agent by accident.
func interactive() bool {
	for _, f := range []*os.File{os.Stdin, os.Stdout} {
		info, err := f.Stat()
		if err != nil || info.Mode()&os.ModeCharDevice == 0 {
			return false
		}
	}
	return true
}

// composePath is where the draft is written and kept.
func composePath(s *store.Store) string { return filepath.Join(s.Root(), composeFile) }

// composeIn opens the editor on the template and returns what was written,
// with the comment lines removed. The editor failing, or nothing being
// written, is an error that names the draft so it can be picked up again.
func composeIn(s *store.Store, cfg store.Config, template string) (text, subject string, err error) {
	path := composePath(s)
	if err := os.WriteFile(path, []byte(template), 0o600); err != nil {
		return "", "", err
	}
	editor := editorFor(cfg)
	// Through the shell, as git does, so that EDITOR="code --wait" or any
	// other command with arguments works. The path goes in as a positional
	// parameter, so nothing in it is ever interpreted.
	cmd := exec.Command("/bin/sh", "-c", editor+` "$1"`, "auu-editor", path)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return "", "", fmt.Errorf("editor %q: %v; nothing sent, and the draft is at %s", editor, err, path)
	}
	data, readErr := os.ReadFile(path)
	if readErr != nil {
		return "", "", readErr
	}
	text, subject = readComposed(string(data), template)
	if text == "" {
		return "", "", usageErrf("empty message; nothing sent")
	}
	return text, subject, nil
}

// readComposed is what came back from the editor: the message, and the
// subject when the template's own Subject line was edited.
//
// Two things are read before the comments are dropped. The Subject line is
// the template's, edited in place, so a subject typed there is the
// message's; unchanged, it says nothing and the caller keeps what it had.
// And a template line that came back without its '#' is still the comment
// it was: an editor that strips the character, or a person who deletes it,
// would otherwise put "Message to bob <…>." at the top of the message —
// which is how a reply of 2026-09-07 went out with the thread's subject on
// the record and the subject its writer had typed sitting in the body.
func readComposed(raw, template string) (text, subject string) {
	comments := templateComments(template)
	var lines []string
	for _, line := range strings.Split(foldCRLF(raw), "\n") {
		body, isComment := uncomment(line, comments)
		if !isComment {
			lines = append(lines, strings.TrimRight(line, " \t"))
			continue
		}
		if value, ok := subjectLine(body); ok {
			subject = value
		}
	}
	for len(lines) > 0 && lines[0] == "" {
		lines = lines[1:]
	}
	for len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	text = strings.Join(lines, "\n")
	if subject == templateSubject(template) {
		// Unchanged: the template said what the subject already was.
		subject = ""
	}
	return text, subject
}

// uncomment reports whether a line is one of the template's comments, and
// gives what followed the '#'. A line beginning with '#' always is. A line
// that does not is one only when what it says, less any leading space, is
// what one of the template's own comment lines said — the character gone
// and the text left behind.
func uncomment(line string, comments []string) (body string, isComment bool) {
	if after, ok := strings.CutPrefix(line, "#"); ok {
		return after, true
	}
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return "", false
	}
	for _, c := range comments {
		if trimmed == strings.TrimSpace(c) {
			return trimmed, true
		}
		// The Subject line is the one a person edits, so it is matched by
		// its opening rather than whole.
		if opensSubject(c) && opensSubject(trimmed) {
			return trimmed, true
		}
	}
	return "", false
}

// subjectPrefix opens the template's Subject line, after the '#' and any
// space that stood where it had been.
const subjectPrefix = "Subject: "

// opensSubject reports whether a comment's text is the Subject line's. The
// leading space is not part of it: the template writes one after the '#',
// an editor that strips the '#' leaves one in its place, and a person who
// deletes the character may leave none at all.
func opensSubject(body string) bool {
	return strings.HasPrefix(strings.TrimLeft(body, " \t"), subjectPrefix)
}

// subjectHint is what the template says beside the subject, and what is
// taken off again when the line comes back: a person who edits the value
// and leaves the hint means the value.
const subjectHint = "   (edit the subject here; keep the #)"

// subjectLine takes the value from a Subject comment, less the hint.
func subjectLine(body string) (string, bool) {
	value, ok := strings.CutPrefix(strings.TrimLeft(body, " \t"), subjectPrefix)
	if !ok {
		return "", false
	}
	value = strings.TrimSpace(strings.TrimSuffix(strings.TrimRight(value, " \t"), subjectHint))
	return value, true
}

// templateComments is every comment line of the template, '#' removed.
func templateComments(template string) []string {
	var out []string
	for _, line := range strings.Split(template, "\n") {
		if after, ok := strings.CutPrefix(line, "#"); ok && strings.TrimSpace(after) != "" {
			out = append(out, after)
		}
	}
	return out
}

// templateSubject is the subject the template opened with, or empty when it
// had no Subject line.
func templateSubject(template string) string {
	for _, c := range templateComments(template) {
		if value, ok := subjectLine(c); ok {
			return value
		}
	}
	return ""
}

// stripComments is git's cleanup of a commit message: comment lines dropped,
// trailing whitespace trimmed from every line, leading and trailing blank
// lines removed. Blank lines inside the message are kept; they are paragraphs.
func stripComments(raw string) string {
	var lines []string
	for _, line := range strings.Split(foldCRLF(raw), "\n") {
		if strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, strings.TrimRight(line, " \t"))
	}
	for len(lines) > 0 && lines[0] == "" {
		lines = lines[1:]
	}
	for len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return strings.Join(lines, "\n")
}

// splitSubject takes the first line as the subject and the rest, less the
// blank line that separates them, as the message. Used only when no subject
// was given on the command line, so that a message composed in the editor
// has one, the way a commit has a summary line.
func splitSubject(text string) (subject, body string) {
	subject, body, _ = strings.Cut(text, "\n")
	subject = strings.TrimSpace(subject)
	for strings.HasPrefix(body, "\n") {
		body = body[1:]
	}
	return subject, body
}

// composeTemplate is what the editor opens on: the seed text, if any, above a
// description of what is about to be sent. It begins with a blank line so the
// cursor lands where the message goes.
func composeTemplate(to *identity.Public, subject string, attachments []string, original *store.Stored, seed string) string {
	var b strings.Builder
	if seed != "" {
		b.WriteString(strings.TrimRight(seed, "\n"))
		b.WriteString("\n")
	}
	b.WriteString("\n")
	if original != nil {
		fmt.Fprintf(&b, "# Reply to %s from %s: %q.\n",
			original.Inner.ID[:12], orNone(original.SenderName), original.Inner.Body.Subject)
	}
	fmt.Fprintf(&b, "# Message to %s <%s>.\n", peerLabel(to), to.Short())
	if subject != "" {
		fmt.Fprintf(&b, "# %s%s%s\n", subjectPrefix, subject, subjectHint)
	} else {
		b.WriteString("# The first line is the subject; leave a blank line after it.\n")
	}
	if len(attachments) > 0 {
		parts := make([]string, 0, len(attachments))
		for _, p := range attachments {
			if info, err := os.Stat(p); err == nil {
				parts = append(parts, fmt.Sprintf("%s (%s)", filepath.Base(p), term.HumanBytes(info.Size())))
			} else {
				parts = append(parts, filepath.Base(p))
			}
		}
		fmt.Fprintf(&b, "# Attachments: %s\n", strings.Join(parts, ", "))
	}
	b.WriteString("#\n# Lines beginning with '#' are dropped. An empty message sends nothing.\n")
	return b.String()
}

// keepDraft writes the cleaned message back over the template, so that a
// send which fails from here on can be repeated with --body-file and nothing
// has to be typed twice. Failing to keep it is not worth failing the send.
func keepDraft(s *store.Store, text string) {
	os.WriteFile(composePath(s), []byte(text+"\n"), 0o600)
}

// draftKept adds to a failure after composing where the text still is. The
// exit code is the original's: the relay being down is still a transport
// failure, it just is not a lost message as well.
func draftKept(s *store.Store, err error) error {
	msg := fmt.Sprintf("%v; the message is kept at %s and can be sent again with --body-file",
		err, composePath(s))
	var e *exitError
	if errors.As(err, &e) {
		return &exitError{code: e.code, err: errors.New(msg)}
	}
	return errors.New(msg)
}
