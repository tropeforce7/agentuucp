package auu

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// A handler's line over the cap no longer hides what follows it (G49,
// R64): the scanner that copied a program's output stopped at a line of a
// mebibyte, and every line after it was dropped without a word. Codex's
// review found it with a generated log's one-line JSON object. Now the
// line is cut with a mark that says how much is not shown, and the lines
// after it are copied.
func TestALongHandlerLineDoesNotHideTheLinesAfterIt(t *testing.T) {
	got := prefixedOf(t, "before\n"+strings.Repeat("x", 1024*1024)+"\nimportant diagnostic after long line\n")
	if !strings.Contains(got, "thread: before\n") {
		t.Fatal("the ordinary line before was not copied")
	}
	if !strings.Contains(got, "thread: important diagnostic after long line\n") {
		t.Fatalf("the diagnostic after the long line disappeared; %d bytes copied", len(got))
	}
}

// The cut is at maxLogLine bytes, one before and one after it said, and
// never through a rune.
func TestLimitAHandlerLineIsCutAtTheCap(t *testing.T) {
	mark := func(n int) string { return " [cut: " + strconv.Itoa(n) + " more bytes of this line are not shown]\n" }
	for _, c := range []struct {
		name, line, want string
	}{
		{"one under", strings.Repeat("x", maxLogLine-1), "thread: " + strings.Repeat("x", maxLogLine-1) + "\n"},
		{"at the cap", strings.Repeat("x", maxLogLine), "thread: " + strings.Repeat("x", maxLogLine) + "\n"},
		{"one over", strings.Repeat("x", maxLogLine+1), "thread: " + strings.Repeat("x", maxLogLine) + mark(1)},
		{"through a rune", strings.Repeat("x", maxLogLine-1) + "é", "thread: " + strings.Repeat("x", maxLogLine-1) + mark(2)},
		{"far over", strings.Repeat("x", 3*maxLogLine), "thread: " + strings.Repeat("x", maxLogLine) + mark(2*maxLogLine)},
		{"windows ending", strings.Repeat("x", maxLogLine) + "\r", "thread: " + strings.Repeat("x", maxLogLine) + "\n"},
	} {
		got := prefixedOf(t, c.line+"\nnext\n")
		if want := c.want + "thread: next\n"; got != want {
			t.Errorf("%s: copied %d bytes ending %q, want %d ending %q", c.name, len(got), tailOf(got), len(want), tailOf(want))
		}
	}
}

// A last line with no newline is copied as a scanner of lines copies it,
// at a length the reader's buffer divides among them, where the line
// filled the buffer at the end of the file and was dropped; and a line's
// ending is a scanner's too, a carriage return before the end of the file
// and one split from its newline at the buffer's edge left out.
func TestAHandlersLastLineIsCopiedAsAScannerCopiesIt(t *testing.T) {
	mark := func(n int) string { return " [cut: " + strconv.Itoa(n) + " more bytes of this line are not shown]\n" }
	for _, c := range []struct {
		name, content, want string
	}{
		{"empty", "", ""},
		{"no newline", "a", "thread: a\n"},
		{"a buffer's length", strings.Repeat("x", 64*1024), "thread: " + strings.Repeat("x", 64*1024) + "\n"},
		{"after a line", "a\n" + strings.Repeat("x", 64*1024), "thread: a\nthread: " + strings.Repeat("x", 64*1024) + "\n"},
		{"two buffers", strings.Repeat("x", 128*1024), "thread: " + strings.Repeat("x", 128*1024) + "\n"},
		{"over the cap", strings.Repeat("x", 2*maxLogLine), "thread: " + strings.Repeat("x", maxLogLine) + mark(maxLogLine)},
		{"carriage return at the end", "a\r", "thread: a\n"},
		{"carriage return split from its newline", strings.Repeat("x", 64*1024-1) + "\r\nnext\n", "thread: " + strings.Repeat("x", 64*1024-1) + "\nthread: next\n"},
		{"carriage return inside", "a\rb\n", "thread: a\rb\n"},
		{"empty lines", "\n\na\n", "thread: \nthread: \nthread: a\n"},
	} {
		if got := prefixedOf(t, c.content); got != c.want {
			t.Errorf("%s: copied %d bytes ending %q, want %d ending %q", c.name, len(got), tailOf(got), len(c.want), tailOf(c.want))
		}
	}
}

// The first line of a failed run's output, which the sentence gives as
// the reason, is found after an empty line and cut at the cap with a mark.
func TestTheFirstLineOfAFailedRunIsCutAtTheCap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stderr")
	if err := os.WriteFile(path, []byte("\n  \n"+strings.Repeat("y", maxLogLine+5)+"\nsecond\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, want := firstLine(path), strings.Repeat("y", maxLogLine)+" [cut]"; got != want {
		t.Fatalf("firstLine gave %d bytes ending %q, want %d ending %q", len(got), tailOf(got), len(want), tailOf(want))
	}
}

func prefixedOf(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(dir, "stderr")
	if err := os.WriteFile(src, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := os.Create(filepath.Join(dir, "journal"))
	if err != nil {
		t.Fatal(err)
	}
	prefixedTo(out, src, "thread")
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(out.Name())
	if err != nil {
		t.Fatal(err)
	}
	return string(got)
}

func tailOf(s string) string {
	if len(s) > 80 {
		return s[len(s)-80:]
	}
	return s
}
