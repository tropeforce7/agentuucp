package main

import (
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/keyfile"
)

// runWithStdin is run with a passphrase piped in rather than named in a file,
// which is the path a script without a secret manager takes, and the only one
// a test can drive: the terminal path needs a terminal.
func runWithStdin(t *testing.T, dir, input string, args ...string) (string, error) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.WriteString(input); err != nil {
		t.Fatal(err)
	}
	w.Close()
	real := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = real; r.Close() })
	// An empty --passphrase-file keeps run from supplying one of its own, so
	// that standard input is what answers. show does not take the flag and
	// is not offered it.
	if needsPassphrase(args) {
		args = append(args, "--passphrase-file", "")
	}
	return run(t, dir, args...)
}

// quiet sends this test's stdout to nowhere, for a test that calls a command
// directly rather than through run.
func quiet(t *testing.T) {
	t.Helper()
	devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	real := os.Stdout
	os.Stdout = devnull
	t.Cleanup(func() { os.Stdout = real; devnull.Close() })
}

// TestInitWritesKeysAtTheShippedCost pays the real derivation once, because a
// default that nothing exercises is a default that drifts. Everything else in
// this package turns it down.
func TestInitWritesKeysAtTheShippedCost(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	// Not through run, which turns the derivation down: this test is about
	// what the shipped cost writes.
	t.Setenv("AUU_CA_HOME", dir)
	quiet(t)
	if err := cmdInit([]string{"--name", "Test", "--passphrase-file", passphraseFile(t)}); err != nil {
		t.Fatalf("init: %v", err)
	}
	for _, name := range []string{"ta.key", "server-ca.key", "client-ca.key"} {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode(raw)
		if block == nil || block.Type != keyfile.BlockType {
			t.Fatalf("%s is not an encrypted key file", name)
		}
		for _, want := range []struct {
			header string
			value  int
		}{
			{"Time", keyfile.DefaultTime},
			{"Memory", keyfile.DefaultMemory},
			{"Threads", keyfile.DefaultThreads},
			{"Iterations", keyfile.DefaultIterations},
		} {
			if got := block.Headers[want.header]; got != strconv.Itoa(want.value) {
				t.Errorf("%s: %s is %q, want %d", name, want.header, got, want.value)
			}
		}
	}
}

// TestRelayNeedsThePassphraseAndSaysSo. The command that costs an operator a
// trip to an offline machine must fail on the passphrase clearly.
func TestRelayNeedsThePassphraseAndSaysSo(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	if _, err := run(t, dir, "init", "--name", "Test"); err != nil {
		t.Fatal(err)
	}
	wrong := filepath.Join(t.TempDir(), "wrong")
	if err := os.WriteFile(wrong, []byte("not the passphrase\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "bundle.json")
	_, err := run(t, dir, "relay", "--host", "relay.example.com", "--out", out,
		"--passphrase-file", wrong)
	if err == nil {
		t.Fatal("a bundle was issued with the wrong passphrase")
	}
	if !strings.Contains(err.Error(), "wrong passphrase") {
		t.Errorf("error %q does not say the passphrase was wrong", err)
	}
	// And nothing was written where the bundle would have gone.
	if _, err := os.Stat(out); err == nil {
		t.Error("a bundle file was written by a failed run")
	}

	// The right one issues.
	if _, err := run(t, dir, "relay", "--host", "relay.example.com", "--out", out); err != nil {
		t.Fatalf("relay with the right passphrase: %v", err)
	}
}

// TestShowNeedsNoPassphrase: it reads no key, so it must never ask. An
// operator looking up the anchor hash to put in a token should not have to
// fetch the passphrase to do it.
func TestShowNeedsNoPassphrase(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	if _, err := run(t, dir, "init", "--name", "Test"); err != nil {
		t.Fatal(err)
	}
	// No passphrase anywhere: not a file, and standard input is a pipe with
	// nothing in it, so anything that asked would fail.
	out, err := runWithStdin(t, dir, "", "show")
	if err != nil {
		t.Fatalf("show asked for something: %v", err)
	}
	if !strings.Contains(out, "keys:         ML-DSA-65\n") {
		t.Errorf("show does not name the parameter set:\n%s", out)
	}
	// Every key file is encrypted, so there is no word for it and no
	// field: a field that is always true is a field for a state that
	// does not exist.
	if strings.Contains(strings.ToLower(out), "encrypted") {
		t.Errorf("show says something about encryption:\n%s", out)
	}
	asJSON, err := runWithStdin(t, dir, "", "show", "--json")
	if err != nil {
		t.Fatal(err)
	}
	var reported map[string]json.RawMessage
	if err := json.Unmarshal([]byte(asJSON), &reported); err != nil {
		t.Fatal(err)
	}
	if _, has := reported["keys_encrypted"]; has {
		t.Error("show --json carries keys_encrypted")
	}
}

func TestPassphraseChangesWhatOpensTheAuthority(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	if _, err := run(t, dir, "init", "--name", "Test"); err != nil {
		t.Fatal(err)
	}
	fresh := filepath.Join(t.TempDir(), "new")
	if err := os.WriteFile(fresh, []byte("a different passphrase\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := run(t, dir, "passphrase", "--new-passphrase-file", fresh)
	if err != nil {
		t.Fatalf("passphrase: %v", err)
	}
	if !strings.Contains(out, "changed the passphrase") {
		t.Errorf("passphrase does not say what it did:\n%s", out)
	}

	bundle := filepath.Join(t.TempDir(), "bundle.json")
	if _, err := run(t, dir, "relay", "--host", "relay.example.com", "--out", bundle); err == nil {
		t.Error("the old passphrase still issues")
	}
	if _, err := run(t, dir, "relay", "--host", "relay.example.com", "--out", bundle,
		"--passphrase-file", fresh); err != nil {
		t.Errorf("the new passphrase does not issue: %v", err)
	}
}

// TestAnAuthorityFromBeforeEncryptionIsRefused: every command that opens
// the directory, locked or not, refuses a plain key file by name and says
// to re-create the authority, before asking for any passphrase; there is
// no encrypting it in place, since passphrase opens it first.
func TestAnAuthorityFromBeforeEncryptionIsRefused(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	if _, err := run(t, dir, "init", "--name", "Test"); err != nil {
		t.Fatal(err)
	}
	unencrypt(t, dir, testSecret)
	want := filepath.Join(dir, "ta.key") + " holds an unencrypted private key, from before auu-ca encrypted its keys, " +
		"and there is no reading it: delete " + dir + " and re-create the authority with 'auu-ca init'"
	fresh := filepath.Join(t.TempDir(), "new")
	if err := os.WriteFile(fresh, []byte("a first passphrase\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"show"},
		{"show", "--json"},
		{"relay", "--host", "relay.example.com", "--out", filepath.Join(t.TempDir(), "b.json")},
		{"passphrase", "--new-passphrase-file", fresh},
	} {
		// Standard input empty: a command that asked for a passphrase
		// before refusing would fail on that instead.
		_, err := runWithStdin(t, dir, "", args...)
		if err == nil || err.Error() != want {
			t.Errorf("%s over an unencrypted authority: %v\nwant %s", strings.Join(args, " "), err, want)
		}
	}
	// The fix the sentence names, walked through: the directory gone, init
	// makes a new authority there.
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, dir, "init", "--name", "Test"); err != nil {
		t.Fatalf("init after the named fix: %v", err)
	}
}

// auu-ca version and --version say what this binary was built from, as
// `auu-ca vX`, with no directory opened and no passphrase asked; the
// version is whatever the tree the test binary was built from says, so
// the assertion is the name and that one is carried.
func TestVersionSaysWhatThisBinaryIs(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "never-made")
	out, err := runWithStdin(t, dir, "", "version")
	if err != nil {
		t.Fatalf("auu-ca version: %v", err)
	}
	if !strings.HasPrefix(out, "auu-ca ") || strings.TrimSpace(strings.TrimPrefix(out, "auu-ca ")) == "" {
		t.Fatalf("auu-ca version said %q", out)
	}
	flag, err := runWithStdin(t, dir, "", "--version")
	if err != nil || flag != out {
		t.Fatalf("auu-ca --version said %q (%v), auu-ca version %q", flag, err, out)
	}
	if _, err := os.Stat(dir); err == nil {
		t.Error("version made the authority's directory")
	}
	for _, spelling := range []string{"version", "--version"} {
		if _, err := runWithStdin(t, dir, "", spelling, "extra"); err == nil || !strings.Contains(err.Error(), `unexpected argument "extra"`) {
			t.Errorf("auu-ca %s extra: %v; want the usage error naming it", spelling, err)
		}
	}
}

// TestThePassphraseIsReadFromStandardInput drives the real path a script
// without a secret manager takes.
func TestThePassphraseIsReadFromStandardInput(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	if _, err := runWithStdin(t, dir, testSecret+"\n", "init", "--name", "Test"); err != nil {
		t.Fatalf("init from standard input: %v", err)
	}
	// And it is the passphrase that was piped in, not something else.
	if _, err := run(t, dir, "relay", "--host", "relay.example.com",
		"--out", filepath.Join(t.TempDir(), "b.json")); err != nil {
		t.Errorf("the piped passphrase is not what the keys are under: %v", err)
	}

	// Nothing on standard input, and no file: it says so rather than
	// hanging or writing an authority nobody can open.
	empty := filepath.Join(t.TempDir(), "ca2")
	_, err := runWithStdin(t, empty, "", "init", "--name", "Test")
	if err == nil {
		t.Fatal("an authority was created with no passphrase anywhere")
	}
	if !strings.Contains(err.Error(), "no passphrase on standard input") {
		t.Errorf("error %q does not say where a passphrase was expected", err)
	}
	if _, err := os.Stat(empty); err == nil {
		t.Error("a directory was created by a run that had no passphrase")
	}
}

// TestAShortPassphraseIsRefusedBeforeAnythingIsWritten. Nothing is generated
// until the passphrase has been settled, so a refusal leaves no directory.
func TestAShortPassphraseIsRefusedBeforeAnythingIsWritten(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{"one character short", strings.Repeat("x", MinPassphrase-1)},
		{"a single character", "x"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "ca")
			_, err := runWithStdin(t, dir, tc.body+"\n", "init", "--name", "Test")
			if err == nil {
				t.Fatalf("%s was accepted", tc.name)
			}
			if !strings.Contains(err.Error(), strconv.Itoa(MinPassphrase)) {
				t.Errorf("error %q does not name the minimum", err)
			}
			if _, err := os.Stat(dir); err == nil {
				t.Error("a directory was left behind by a refused passphrase")
			}
		})
	}
	// One character longer is accepted, which is the other side of the edge.
	dir := filepath.Join(t.TempDir(), "ca")
	if _, err := runWithStdin(t, dir, strings.Repeat("x", MinPassphrase)+"\n", "init", "--name", "Test"); err != nil {
		t.Errorf("a passphrase of exactly %d characters was refused: %v", MinPassphrase, err)
	}
}

// TestAPassphraseFileIsReadAsItsFirstLine: every editor and every echo leaves
// a trailing newline, and a passphrase with one appended opens nothing.
func TestAPassphraseFileIsReadAsItsFirstLine(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{"a trailing newline", "the passphrase\n", "the passphrase"},
		{"no trailing newline", "the passphrase", "the passphrase"},
		{"a file written on Windows", "the passphrase\r\n", "the passphrase"},
		{"more than one line", "the passphrase\nand a note\n", "the passphrase"},
		{"spaces, which are part of it", "  the passphrase  \n", "  the passphrase  "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "p")
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := fromFile(path)
			if err != nil {
				t.Fatalf("reading %q: %v", tc.body, err)
			}
			if string(got) != tc.want {
				t.Errorf("read %q, want %q", got, tc.want)
			}
		})
	}

	// An empty file is a mistake, not an empty passphrase.
	path := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := fromFile(path); err == nil || !strings.Contains(err.Error(), "is empty") {
		t.Errorf("an empty passphrase file gave %v", err)
	}
	// And a file that is not there names itself.
	if _, err := fromFile(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Error("a missing passphrase file was accepted")
	}
}

// unencrypt rewrites a store's key files the way they were written before
// they were encrypted, so a test can exercise the upgrade path.
func unencrypt(t *testing.T, dir, secret string) {
	t.Helper()
	for _, name := range []string{"ta.key", "server-ca.key", "client-ca.key"} {
		path := filepath.Join(dir, name)
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		der, err := keyfile.Decrypt(raw, []byte(secret))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		plain := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		if err := os.WriteFile(path, plain, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}
