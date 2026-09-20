package regular

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

// TestARegularFileOpensAndReads: the ordinary case on every platform, and
// Create writes a file that Open then reads back.
func TestARegularFileOpensAndReads(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.txt")
	f, err := Create(path, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("hello"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	g, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	g.Close()
	data, err := ReadFile(path)
	if err != nil || string(data) != "hello" {
		t.Fatalf("ReadFile: %q, %v", data, err)
	}
	d, err := Dir(dir)
	if err != nil {
		t.Fatal(err)
	}
	d.Close()
	f, err = OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(" again")
	f.Close()
	if data, _ := ReadFile(path); string(data) != "hello again" {
		t.Errorf("after an append: %q", data)
	}
}

// TestADirectoryIsRefusedByItsHandle: a directory under a valid name is
// not a regular file, and Dir refuses a regular file the same way. An
// exclusive create over the directory is refused by the platform, which
// says so in one of two ways: Linux and macOS answer EEXIST, as open(2)
// with O_CREAT|O_EXCL does for any entry under the name, and Windows
// answers EISDIR, since CreateFile with CREATE_NEW opened for writing
// refuses a directory as access denied and Go's syscall.Open reports
// that as EISDIR when the attributes say directory (the first Windows
// run, on windows-2025-vs2026 with go1.27.0, is where this was learned).
// Either passes through unwrapped, and a caller that asks whether a
// name stands asks for both.
func TestADirectoryIsRefusedByItsHandle(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	f, err := Open(sub)
	var me *ModeError
	if !errors.As(err, &me) || !strings.Contains(err.Error(), "is a directory, not a regular file") {
		t.Errorf("Open on a directory: %v, want the mode sentence", err)
	}
	if f != nil {
		f.Close()
		t.Errorf("Open on a directory returned a file")
	}
	// For writing, the platform refuses a directory itself (EISDIR), and
	// that error passes through; either way there is no file.
	if f, err := OpenFile(sub, os.O_WRONLY, 0); err == nil || f != nil {
		if f != nil {
			f.Close()
		}
		t.Errorf("OpenFile for writing on a directory: %v", err)
	}
	if _, err := ReadFile(sub); err == nil || !strings.Contains(err.Error(), "is a directory, not a regular file") {
		t.Errorf("ReadFile on a directory: %v", err)
	}
	_, err = Create(sub, 0o600)
	switch {
	case runtime.GOOS == "windows" && errors.Is(err, syscall.EISDIR):
		t.Logf("Create over a directory: %v (Windows answers EISDIR)", err)
	case errors.Is(err, os.ErrExist):
		t.Logf("Create over a directory: %v", err)
	default:
		t.Errorf("Create over a directory: %v, want ErrExist, or EISDIR on Windows", err)
	}
	if _, err := os.Stat(sub); err != nil {
		t.Errorf("the directory is gone after the refusals: %v", err)
	}
	file := filepath.Join(dir, "f")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Dir(file); err == nil || !strings.Contains(err.Error(), "is a regular file, not a directory") {
		t.Errorf("Dir on a file: %v", err)
	}
}

// TestTheOpenErrorPassesThroughUnwrapped: the maintainer's question — a file that
// is not there, and one that is, are reported exactly as os reports
// them, so that a caller's errors.Is against os.ErrNotExist and
// os.ErrExist holds; a missing parent directory passes through the same
// way. The mode refusal is the only error of the package's own.
func TestTheOpenErrorPassesThroughUnwrapped(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing")
	for _, try := range []struct {
		name string
		err  func() error
	}{
		{"Open", func() error { _, err := Open(missing); return err }},
		{"ReadFile", func() error { _, err := ReadFile(missing); return err }},
		{"Dir", func() error { _, err := Dir(missing); return err }},
		{"OpenFile for append", func() error { _, err := OpenFile(missing, os.O_WRONLY|os.O_APPEND, 0); return err }},
		{"Create under a missing parent", func() error { _, err := Create(filepath.Join(missing, "child"), 0o600); return err }},
		{"Open under a missing parent", func() error { _, err := Open(filepath.Join(missing, "child")); return err }},
	} {
		err := try.err()
		if !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s: %v; want errors.Is os.ErrNotExist", try.name, err)
		}
		var pe *os.PathError
		if !errors.As(err, &pe) {
			t.Errorf("%s: %T is not the *os.PathError os gives", try.name, err)
		}
	}
	existing := filepath.Join(dir, "there")
	if err := os.WriteFile(existing, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Create(existing, 0o600); !errors.Is(err, os.ErrExist) || !os.IsExist(err) {
		t.Errorf("Create on an existing name: %v; want errors.Is os.ErrExist", err)
	}
	if data, _ := os.ReadFile(existing); string(data) != "x" {
		t.Errorf("the existing file was touched: %q", data)
	}
}

// TestLimitADeviceIsRefusedByItsHandle (Windows): CON, NUL, nul.txt and
// com1.txt under a temporary directory, through Open and Create, each
// answer one of three ways, and the test logs which: the handle check's
// sentence, when the platform hands back the device under the name; the
// platform's own refusal, passed through, with nothing made; or, since
// Windows versions differ in which names are devices under a directory,
// an ordinary name, which Open finds nothing under and Create makes a
// regular file under, which the test removes. What never happens is a
// device handed back as a regular file: a handle that came back is asked
// its mode here, the claim being the test's own and not the helper's.
// The first run, on windows-2025-vs2026 (Windows Server 2025, go1.27.0
// windows/amd64): NUL was the device — Open's handle check refused it
// as a device, and Create's exclusive create succeeded and handed the
// device back, the Handed sentence — while CON, nul.txt and com1.txt
// were ordinary names, not found by Open and made as regular files by
// Create. Older Windows resolves more of them, and the hand list in
// internal/channels stays wider than any one Windows for that reason.
func TestLimitADeviceIsRefusedByItsHandle(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows device names; the Unix plants are TestLimitAPlantedEntryIsRefusedByItsHandle's, in plants_unix_test.go")
	}
	dir := t.TempDir()
	for _, name := range []string{"CON", "NUL", "nul.txt", "com1.txt"} {
		path := filepath.Join(dir, name)
		for _, try := range []struct {
			name string
			call func() (*os.File, error)
		}{
			{"Open", func() (*os.File, error) { return Open(path) }},
			{"Create", func() (*os.File, error) { return Create(path, 0o600) }},
		} {
			f, err := try.call()
			var me *ModeError
			switch {
			case err == nil:
				info, serr := f.Stat()
				f.Close()
				if serr != nil || !info.Mode().IsRegular() {
					t.Errorf("%s of %s handed back %v, %v; want a regular file or a refusal", try.name, name, info, serr)
					continue
				}
				t.Logf("%s of %s: an ordinary name on this Windows; a regular file", try.name, name)
				if try.name == "Create" {
					if err := os.Remove(path); err != nil {
						t.Errorf("removing the file made under %s: %v", name, err)
					}
				}
			case errors.As(err, &me):
				if f != nil {
					f.Close()
					t.Errorf("%s of %s: a file came back with the refusal %v", try.name, name, err)
				}
				t.Logf("%s of %s: the handle check refused it: %v", try.name, name, err)
			default:
				if f != nil {
					f.Close()
					t.Errorf("%s of %s: a file came back with the refusal %v", try.name, name, err)
				}
				t.Logf("%s of %s: the platform refused it: %v", try.name, name, err)
			}
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		t.Errorf("%q stands under the directory", e.Name())
	}
}
