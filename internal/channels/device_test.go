package channels

import (
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
// through filepath.Abs, which is GetFullPathNameW, and asserts each is a
// device to the OS, and that the near-misses are not: both directions,
// since a name the OS calls a device that the list does not is the
// failure that matters. CONIN$ and CONOUT$ are console names CreateFile
// understands but the resolver may not rewrite, so they are held to the
// OS the way the OS exposes them: an exclusive create under a temporary
// directory must leave no file there, and what the resolver answered is
// logged for channels' doc.go. On every other platform the same names run
// against the list alone, which is the regression for the list's shape.
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
	for _, stem := range listedStems {
		for _, name := range forms(stem) {
			abs, err := filepath.Abs(filepath.Join(dir, name))
			if err != nil || !strings.HasPrefix(abs, `\\.\`) {
				t.Errorf("Windows does not resolve %q to a device: %q, %v", name, abs, err)
			}
		}
	}
	for _, miss := range nearMisses {
		for _, name := range forms(miss) {
			abs, err := filepath.Abs(filepath.Join(dir, name))
			if err != nil || strings.HasPrefix(abs, `\\.\`) {
				t.Errorf("Windows resolves the near-miss %q to a device: %q, %v", name, abs, err)
			}
		}
	}
	for _, stem := range consoleStems {
		for _, name := range []string{stem, stem + ".txt"} {
			abs, err := filepath.Abs(filepath.Join(dir, name))
			t.Logf("filepath.Abs of %q on Windows: %q, %v", name, abs, err)
			f, err := regular.Create(filepath.Join(dir, name), 0o600)
			if f != nil {
				f.Close()
			}
			t.Logf("regular.Create of %q on Windows: %v", name, err)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		t.Errorf("%q was made under the directory by a console name", e.Name())
	}
}

// TestLimitTheForbiddenCharactersAgreeWithWindows: the seven characters
// Windows forbids in a file name, and a trailing dot or space that it
// strips, are refused in a channel name on every platform; on Windows the
// test also creates a file under each and asserts the OS refuses the
// seven, and that a name with a trailing dot or space is made under the
// stripped name, which is the fold the rule foresees.
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
