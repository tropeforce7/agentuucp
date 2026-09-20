package channels

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/regular"
)

// listedStems is every stem the hand list holds, and nearMisses the names
// beside them that are not devices anywhere.
var (
	listedStems = []string{"CON", "PRN", "AUX", "NUL",
		"COM0", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
		"LPT0", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
		"COM¹", "COM²", "COM³", "LPT¹", "LPT²", "LPT³"}
	consoleStems = []string{"CONIN$", "CONOUT$"}
	nearMisses   = []string{"console", "com10", "lpt", "conin", "nul2", "con-", "prn_", "aux1", "com", "co"}
)

// TestLimitTheDeviceListAgreesWithWindows: the hand list is not the
// source; Windows is. On Windows the test resolves every listed stem —
// bare, with an extension, upper and lower case, with a trailing space —
// and every near-miss through filepath.Abs, which is GetFullPathNameW,
// and holds the list one way, the way the pki host rule is held to x509:
// every name the OS resolves to a device must be in the list, so a
// near-miss the OS rewrites is the failure that matters, and the list may
// be wider, since Windows versions differ in what they resolve and a
// name nobody can use on some Windows is a name nobody needs. What each
// listed name resolved to is logged, with a count, for channels.go's
// package comment. CONIN$ and CONOUT$ are console names CreateFile
// understands and the resolver may not rewrite, so they are held to the
// OS the way the OS exposes them: an exclusive create under a temporary
// directory is refused by the handle as a device, or by the platform
// itself, or makes a regular file, which the test removes; never a
// device opened as a regular file. On every other platform the same
// names run against the list alone, which is the regression for the
// list's shape.
//
// The first run, on windows-2025-vs2026 (Windows Server 2025, build
// 10.0.26100, go1.27.0 windows/amd64): the resolver rewrote NUL alone —
// "NUL", "nul" and "NUL " — and left every other listed name in every
// form, NUL.txt among them, as a path under the directory; every
// near-miss was a path; and CreateFile made a regular file under CONIN$,
// CONOUT$, CONIN$.txt and CONOUT$.txt. Older Windows resolves more of
// the list, which is why the list stays wider than that OS.
func TestLimitTheDeviceListAgreesWithWindows(t *testing.T) {
	forms := func(stem string) []string {
		return []string{stem, strings.ToLower(stem), stem + ".txt", strings.ToLower(stem) + ".TXT", stem + " ", stem + " .txt"}
	}
	stemOf := func(name string) string {
		stem, _, _ := strings.Cut(name, ".")
		return stem
	}
	for _, stem := range append(append([]string{}, listedStems...), consoleStems...) {
		for _, name := range forms(stem) {
			if !WindowsDevice(stemOf(name)) {
				t.Errorf("the list does not hold %q to a device", name)
			}
		}
	}
	for _, miss := range nearMisses {
		for _, name := range forms(miss) {
			if WindowsDevice(stemOf(name)) {
				t.Errorf("the list calls %q a device", name)
			}
		}
	}
	if runtime.GOOS != "windows" {
		return
	}
	dir := t.TempDir()
	var resolved, paths []string
	for _, stem := range listedStems {
		for _, name := range forms(stem) {
			abs, err := filepath.Abs(filepath.Join(dir, name))
			if err != nil {
				t.Errorf("filepath.Abs of %q: %v", name, err)
				continue
			}
			if strings.HasPrefix(abs, `\\.\`) {
				resolved = append(resolved, name)
				t.Logf("Windows resolves %q to the device %q", name, abs)
			} else {
				paths = append(paths, name)
			}
		}
	}
	t.Logf("of the %d listed names, Windows resolved %d to a device and left %d as paths under the directory: %q", len(resolved)+len(paths), len(resolved), len(paths), paths)
	for _, miss := range nearMisses {
		for _, name := range forms(miss) {
			abs, err := filepath.Abs(filepath.Join(dir, name))
			if err != nil || strings.HasPrefix(abs, `\\.\`) {
				t.Errorf("Windows resolves the near-miss %q to a device, which the list does not hold: %q, %v", name, abs, err)
			}
		}
	}
	for _, stem := range consoleStems {
		for _, name := range []string{stem, stem + ".txt"} {
			path := filepath.Join(dir, name)
			abs, err := filepath.Abs(path)
			t.Logf("filepath.Abs of %q on Windows: %q, %v", name, abs, err)
			f, err := regular.Create(path, 0o600)
			var me *regular.ModeError
			switch {
			case err == nil:
				// regular.Create hands back a regular file or nothing; the
				// handle is asked once more here so the claim is the test's
				// own, and the file the platform made is removed.
				info, serr := f.Stat()
				f.Close()
				if serr != nil || !info.Mode().IsRegular() {
					t.Errorf("Create of %q handed back %v, %v; want a regular file or a refusal", name, info, serr)
				}
				t.Logf("regular.Create of %q on Windows: made a regular file", name)
				if err := os.Remove(path); err != nil {
					t.Errorf("removing the file made under %q: %v", name, err)
				}
			case errors.As(err, &me):
				t.Logf("regular.Create of %q on Windows: the handle check refused it: %v", name, err)
			default:
				t.Logf("regular.Create of %q on Windows: the platform refused it: %v", name, err)
			}
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		t.Errorf("%q stands under the directory after the console names", e.Name())
	}
}

// TestLimitTheForbiddenCharactersAgreeWithWindows: the characters
// Windows forbids in a file name beyond the separators and the colon,
// which have refusals of their own, and a trailing dot or space that it
// strips, are refused in a channel name on every platform; on Windows the
// test also creates a file under each and asserts the OS refuses the
// six, and that a name with a trailing dot or space is made under the
// stripped name, which is the fold the rule foresees. The first run, on
// windows-2025-vs2026 (Windows Server 2025, go1.27.0), refused each of
// the six with "The filename, directory name, or volume label syntax is
// incorrect" and made "bugs." and "bugs " as "bugs".
func TestLimitTheForbiddenCharactersAgreeWithWindows(t *testing.T) {
	for _, c := range WindowsForbidden {
		if err := ValidName("bug" + string(c) + "reports"); err == nil {
			t.Errorf("ValidName took %q", string(c))
		}
	}
	for _, name := range []string{"bugs.", "bugs "} {
		if err := ValidName(name); err == nil {
			t.Errorf("ValidName took %q", name)
		}
	}
	if runtime.GOOS != "windows" {
		return
	}
	dir := t.TempDir()
	for _, c := range WindowsForbidden {
		name := "bug" + string(c) + "reports"
		err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600)
		if err == nil {
			t.Errorf("Windows made a file named %q", name)
		} else {
			t.Logf("Windows refused %q: %v", name, err)
		}
	}
	for _, name := range []string{"bugs.", "bugs "} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Logf("Windows refused %q outright: %v", name, err)
			continue
		}
		if _, err := os.Stat(filepath.Join(dir, "bugs")); err != nil {
			t.Errorf("Windows did not fold %q to \"bugs\": %v", name, err)
		}
		os.Remove(filepath.Join(dir, "bugs"))
	}
}

// TestTheWindowsCharactersAreRefusedInNamesAlone: the seven characters
// are a rule for a name, which becomes a directory, and not for a
// description, which is prose: "what's new?" stays a description.
func TestTheWindowsCharactersAreRefusedInNamesAlone(t *testing.T) {
	for _, desc := range []string{"what's new?", `say "hi"`, "a | b", "<b>", "2 * 3", "a: b"} {
		if err := ValidDescription(desc); err != nil {
			t.Errorf("ValidDescription refused %q: %v", desc, err)
		}
	}
}
