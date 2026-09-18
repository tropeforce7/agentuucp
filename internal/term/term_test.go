package term

import (
	"bytes"
	"errors"
	"io"
	"math"
	"os"
	"strings"
	"testing"
)

func TestReadLineStopsAtTheNewlineAndConsumesNoMore(t *testing.T) {
	r := strings.NewReader("passphrase\nthe next line\n")
	line, err := ReadLine(r)
	if err != nil {
		t.Fatal(err)
	}
	if string(line) != "passphrase" {
		t.Errorf("read %q, want %q", line, "passphrase")
	}
	// Nothing after the newline was taken: a caller may want it.
	rest, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if string(rest) != "the next line\n" {
		t.Errorf("what is left is %q, want the second line intact", rest)
	}
}

func TestReadLineHandlesTheWaysALineCanEnd(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input string
		want  string
		err   error
	}{
		{"a plain line", "secret\n", "secret", nil},
		{"a file with CRLF", "secret\r\n", "secret", nil},
		{"no trailing newline", "secret", "secret", nil},
		{"an empty line", "\n", "", nil},
		{"nothing at all", "", "", io.EOF},
		{"a carriage return alone", "secret\r", "secret", nil},
		{"a line with spaces, which are part of a passphrase", "  two words  \n", "  two words  ", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			line, err := ReadLine(strings.NewReader(tc.input))
			if !errors.Is(err, tc.err) {
				t.Fatalf("error is %v, want %v", err, tc.err)
			}
			if tc.err == nil && string(line) != tc.want {
				t.Errorf("read %q, want %q", line, tc.want)
			}
		})
	}
}

// TestReadLineBoundsWhatItWillReturn: a line is an allocation, and the reader
// is a file somebody could have pointed anywhere.
func TestReadLineBoundsWhatItWillReturn(t *testing.T) {
	for _, tc := range []struct {
		n  int
		ok bool
	}{
		{MaxLine - 1, true},
		{MaxLine, true},
		{MaxLine + 1, false},
	} {
		line, err := ReadLine(strings.NewReader(strings.Repeat("x", tc.n) + "\n"))
		if tc.ok {
			if err != nil {
				t.Errorf("a %d-byte line was refused: %v", tc.n, err)
			} else if len(line) != tc.n {
				t.Errorf("a %d-byte line came back %d bytes", tc.n, len(line))
			}
			continue
		}
		if err == nil {
			t.Errorf("a %d-byte line was accepted", tc.n)
		} else if !strings.Contains(err.Error(), "longer than") {
			t.Errorf("a %d-byte line gave %q, want the length error", tc.n, err)
		}
	}
	// A stream with no newline at all is bounded the same way, so a reader
	// pointed at something enormous does not read it all.
	if _, err := ReadLine(bytes.NewReader(bytes.Repeat([]byte("x"), 1<<20))); err == nil {
		t.Error("a stream with no newline was read to the end")
	}
}

// TestIsTerminalOnSomethingThatIsNot: a pipe and a regular file are what the
// tests and a script use, and neither may be mistaken for a terminal, or a
// passphrase would be prompted for where nobody can type one.
func TestIsTerminalOnSomethingThatIsNot(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	if IsTerminal(int(r.Fd())) {
		t.Error("a pipe is reported as a terminal")
	}

	f, err := os.CreateTemp(t.TempDir(), "file")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if IsTerminal(int(f.Fd())) {
		t.Error("a regular file is reported as a terminal")
	}
	// And a descriptor that is not open at all.
	if IsTerminal(-1) {
		t.Error("a closed descriptor is reported as a terminal")
	}
}

// TestDisableEchoOnSomethingThatIsNotATerminal fails rather than pretending
// it worked, so a caller never reads a passphrase believing the echo is off
// when it is not.
func TestDisableEchoOnSomethingThatIsNotATerminal(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	if _, err := DisableEcho(int(r.Fd())); err == nil {
		t.Error("turning the echo off on a pipe reported success")
	}
}

// HumanBytes renders every int64: the two copies it replaced indexed a
// unit string of four past its end at a pebibyte, and a size a peer or a
// relay declared at that scale panicked the tool that printed it.
func TestHumanBytesRendersEverySize(t *testing.T) {
	for _, tc := range []struct {
		n    int64
		want string
	}{
		{0, "0 B"},
		{1023, "1023 B"},
		{1024, "1.0 KiB"},
		{1536, "1.5 KiB"},
		{1 << 20, "1.0 MiB"},
		{1 << 30, "1.0 GiB"},
		{1 << 40, "1.0 TiB"},
		{1<<50 - 1, "1024.0 TiB"},
		{1 << 50, "1.0 PiB"},
		{1<<50 + 1, "1.0 PiB"},
		{1 << 60, "1.0 EiB"},
		{math.MaxInt64, "8.0 EiB"},
	} {
		if got := HumanBytes(tc.n); got != tc.want {
			t.Errorf("HumanBytes(%d) = %q, want %q", tc.n, got, tc.want)
		}
	}
}
