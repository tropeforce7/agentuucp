package regular

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestLimitAReparsePointIsJudgedByItsHandle: on Windows an open carries
// FILE_FLAG_OPEN_REPARSE_POINT and judge decides from the handle. Go
// reports a symbolic link as fs.ModeSymlink and every other tag, a mount
// point among them, as fs.ModeIrregular, and the handle's attributes tell
// a directory's from a file's (S57). A regular file is used, a link is
// refused as one, a directory's reparse point is refused saying so, any
// other tag is opened again, and everything else is refused by its mode
// as before; an irregular mode with no reparse attribute, which is what
// unix can report, is never opened again. The table runs everywhere, as
// does the reopen's check that the second handle is on the first one's
// file; the Windows half of TestLimitAPlantedEntryIsRefusedByItsHandle is
// where the platform says it.
func TestLimitAReparsePointIsJudgedByItsHandle(t *testing.T) {
	const (
		dir     = attributeDirectory
		reparse = attributeReparsePoint
	)
	for _, c := range []struct {
		name       string
		mode       fs.FileMode
		attributes uint32
		want       verdict
		kind       Reparse
	}{
		{"a regular file", 0o644, 0, use, ReparseNone},
		{"a deduplicated file, which Go reports as regular", 0o644, reparse, reopen, ReparseNone},
		{"a symbolic link to a file", fs.ModeSymlink | 0o666, reparse, refuse, ReparseNone},
		{"a symbolic link to a directory", fs.ModeSymlink | 0o666, reparse | dir, refuse, ReparseNone},
		{"a mount point", fs.ModeIrregular | 0o666, reparse | dir, refuseReparse, ReparseDirectory},
		{"a cloud file", fs.ModeIrregular | 0o666, reparse, reopen, ReparseNone},
		{"an irregular file with no reparse attribute", fs.ModeIrregular | 0o666, 0, refuse, ReparseNone},
		{"an irregular directory with no reparse attribute", fs.ModeIrregular | 0o666, dir, refuse, ReparseNone},
		{"a directory", fs.ModeDir | 0o777, dir, refuse, ReparseNone},
		{"a named pipe", fs.ModeNamedPipe | 0o666, 0, refuse, ReparseNone},
		{"a device", fs.ModeDevice | fs.ModeCharDevice | 0o666, 0, refuse, ReparseNone},
		{"a socket", fs.ModeSocket | 0o666, reparse, refuse, ReparseNone},
	} {
		if v, kind := judge(c.mode, c.attributes); v != c.want || kind != c.kind {
			t.Errorf("%s (%v, %#x): judged %d, %d; want %d, %d", c.name, c.mode, c.attributes, v, kind, c.want, c.kind)
		}
	}

	for _, c := range []struct {
		err  *ModeError
		want string
	}{
		{&ModeError{Path: "x", Mode: fs.ModeSymlink}, `"x" is a symbolic link, not a regular file`},
		{&ModeError{Path: "x", Mode: fs.ModeIrregular, Reparse: ReparseDirectory}, `"x" is a mount point or another directory's reparse point, not a regular file`},
		{&ModeError{Path: "x", Mode: fs.ModeIrregular, Reparse: ReparseChanged}, `"x" is a reparse point that named another file when it was opened again, not a regular file`},
	} {
		if got := c.err.Error(); got != c.want {
			t.Errorf("the sentence is %q, want %q", got, c.want)
		}
	}

	// The reopen holds the second handle to the first one's file: a name
	// that names another file by then is refused, the same file is used.
	d := t.TempDir()
	first, second := filepath.Join(d, "first"), filepath.Join(d, "second")
	for _, p := range []string{first, second} {
		if err := os.WriteFile(p, []byte(p), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	was, err := os.Stat(first)
	if err != nil {
		t.Fatal(err)
	}
	var me *ModeError
	if f, err := openAgain(second, os.O_RDONLY, 0, was); f != nil || !errors.As(err, &me) || me.Reparse != ReparseChanged {
		if f != nil {
			f.Close()
		}
		t.Errorf("openAgain on another file: %v, want it refused as changed", err)
	}
	f, err := openAgain(first, os.O_RDONLY, 0, was)
	if err != nil {
		t.Fatalf("openAgain on the same file: %v", err)
	}
	f.Close()
	// A truncate is made on the judged handle, never through a name that
	// names another file by then: that file is left whole, and the same
	// file is truncated as asked.
	if f, err := openAgain(second, os.O_WRONLY|os.O_TRUNC, 0, was); err == nil {
		f.Close()
		t.Error("openAgain for a truncate on another file was not refused")
	}
	if data, _ := os.ReadFile(second); string(data) != second {
		t.Errorf("a refused open again truncated the other file: %q", data)
	}
	if f, err := openAgain(first, os.O_WRONLY|os.O_TRUNC, 0, was); err != nil {
		t.Errorf("openAgain for a truncate on the same file: %v", err)
	} else {
		f.Close()
	}
	if data, _ := os.ReadFile(first); len(data) != 0 {
		t.Errorf("the same file was not truncated as asked: %q", data)
	}
	// Nor does the open again create: a name gone by then is gone.
	gone := filepath.Join(d, "gone")
	if f, err := openAgain(gone, os.O_WRONLY|os.O_CREATE, 0o600, was); err == nil {
		f.Close()
		t.Error("openAgain made a file that was not there")
	}
	if _, err := os.Lstat(gone); !os.IsNotExist(err) {
		t.Errorf("openAgain made %s: %v", gone, err)
	}

	// NotALink, for the Windows lock: a link is refused by the link's
	// sentence and a regular file is not.
	if err := NotALink("x", fakeInfo{mode: fs.ModeSymlink}); err == nil || !strings.Contains(err.Error(), "is a symbolic link") {
		t.Errorf("NotALink of a link: %v", err)
	}
	if err := NotALink("x", fakeInfo{mode: 0o644}); err != nil {
		t.Errorf("NotALink of a regular file: %v", err)
	}
}

// fakeInfo is a FileInfo with a mode and nothing else.
type fakeInfo struct{ mode fs.FileMode }

func (f fakeInfo) Name() string       { return "x" }
func (f fakeInfo) Size() int64        { return 0 }
func (f fakeInfo) Mode() fs.FileMode  { return f.mode }
func (f fakeInfo) ModTime() time.Time { return time.Time{} }
func (f fakeInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeInfo) Sys() any           { return nil }
