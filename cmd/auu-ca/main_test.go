package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/keyfile"
)

// testSecret is what every authority a test builds is encrypted under. It is
// over MinPassphrase, because the commands enforce that.
const testSecret = "test passphrase"

// cheapCost turns the key derivation down for the duration of a test.
//
// The shipped cost is three passes over 64 MiB and 600,000 rounds of PBKDF2,
// about half a second a key and three keys an authority; a suite that paid it
// everywhere would take minutes. TestInitWritesKeysAtTheShippedCost pays it
// once, on purpose, and is what proves the default.
func cheapCost(t *testing.T) {
	t.Helper()
	was := cost
	cost = keyfile.TestPassphrase("")
	t.Cleanup(func() { cost = was })
}

// passphraseFile writes the test passphrase somewhere outside the authority's
// own directory, which several tests require to be empty.
func passphraseFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "passphrase")
	if err := os.WriteFile(path, []byte(testSecret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// run executes an auu-ca command with its own directory, capturing stdout.
//
// It supplies --passphrase-file for the commands that need one, so that a
// test says what it is testing rather than repeating the passphrase. A test
// that is about the passphrase passes its own flag, and this leaves it alone.
func run(t *testing.T, dir string, args ...string) (string, error) {
	t.Helper()
	stdout, _, err := runCapturing(t, dir, args...)
	return stdout, err
}

// runCapturing is run with standard error captured too, for a test about
// which stream something went to. Both are drained as they are written: a
// bundle on standard output is larger than a pipe, and a writer nobody is
// reading blocks for ever.
func runCapturing(t *testing.T, dir string, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	t.Setenv("AUU_CA_HOME", dir)
	cheapCost(t)
	if needsPassphrase(args) {
		args = append(args, "--passphrase-file", passphraseFile(t))
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	realOut, realErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = outW, errW
	var outBuf, errBuf bytes.Buffer
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); io.Copy(&outBuf, outR) }()
	go func() { defer wg.Done(); io.Copy(&errBuf, errR) }()

	// Through main's own switch, so a spelling main answers is one the
	// tests run.
	runErr := dispatch(args[0], args[1:])

	outW.Close()
	errW.Close()
	os.Stdout, os.Stderr = realOut, realErr
	wg.Wait()
	outR.Close()
	errR.Close()
	return outBuf.String(), errBuf.String(), runErr
}

// needsPassphrase says whether run should supply one: the command takes it,
// and the caller has not said anything about it itself.
func needsPassphrase(args []string) bool {
	switch args[0] {
	case "init", "relay", "passphrase":
	case "kit":
		// Without the bundle, kit asks for nothing.
		for _, a := range args[1:] {
			if a == "--without-bundle" || a == "-without-bundle" {
				return false
			}
		}
	default:
		return false
	}
	// Only the current passphrase. A test that names --new-passphrase-file
	// is changing one, and still needs the old one supplied.
	for _, a := range args[1:] {
		if a == "--passphrase-file" || a == "-passphrase-file" ||
			strings.HasPrefix(a, "--passphrase-file=") || strings.HasPrefix(a, "-passphrase-file=") {
			return false
		}
	}
	return true
}

func TestInitCreatesTheHierarchyAndRefusesASecond(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	out, err := run(t, dir, "init", "--name", "Test")
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	if !strings.Contains(out, "trust anchor") || !strings.Contains(out, "ML-DSA-65") {
		t.Errorf("init does not report what it made:\n%s", out)
	}
	// The next thing an operator needs is named.
	if !strings.Contains(out, "auu-ca relay") {
		t.Errorf("init does not say what to do next:\n%s", out)
	}

	for _, f := range []string{"ta.key", "ta.pem", "server-ca.key", "server-ca.pem",
		"client-ca.key", "client-ca.pem"} {
		info, err := os.Stat(filepath.Join(dir, f))
		if err != nil {
			t.Fatalf("%s was not created: %v", f, err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("%s is mode %04o, want 0600", f, perm)
		}
	}

	// A second one would be a different PKI entirely.
	if _, err := run(t, dir, "init", "--name", "Test"); err == nil {
		t.Fatal("a second init overwrote the first")
	}
}

func TestInitChecksItsArguments(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"no name", []string{"init"}, "--name is required"},
		{"a bad parameter set", []string{"init", "--name", "Test", "--mldsa", "50"}, "44, 65 or 87"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := run(t, filepath.Join(t.TempDir(), "ca"), tc.args...)
			if err == nil {
				t.Fatalf("%s was accepted", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not contain %q", err, tc.want)
			}
		})
	}
}

func TestRelayWritesABundleAndRotates(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	if _, err := run(t, dir, "init", "--name", "Test"); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "bundle.json")
	text, err := run(t, dir, "relay", "--host", "relay.example.com", "--out", out)
	if err != nil {
		t.Fatalf("relay: %v", err)
	}
	if !strings.Contains(text, "relay.example.com") || !strings.Contains(text, `"bundle"`) {
		t.Errorf("relay does not say what to do with the file:\n%s", text)
	}
	info, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("the bundle is mode %04o, want 0600; it holds signing keys", perm)
	}

	// Again is the rotation, and it says so, because an operator needs to
	// know nobody has to re-enrol.
	text, err = run(t, dir, "relay", "--host", "relay.example.com", "--out", out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "rotation") || !strings.Contains(text, "without re-enrolling") {
		t.Errorf("a rotation is not explained:\n%s", text)
	}
}

func TestRelayChecksItsArguments(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	if _, err := run(t, dir, "init", "--name", "Test"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"no host", []string{"relay", "--out", "x.json"}, "--host is required"},
		{"no out", []string{"relay", "--host", "a.example.com"}, "--out is required"},
		{"a host that is neither", []string{"relay", "--host", "not a host", "--out",
			filepath.Join(t.TempDir(), "b.json")}, "neither an IP address nor a DNS name"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := run(t, dir, tc.args...)
			if err == nil {
				t.Fatalf("%s was accepted", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not contain %q", err, tc.want)
			}
		})
	}
}

func TestShowReportsWhatIsHeldAndNothingSecret(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	initOut, err := run(t, dir, "init", "--name", "Test", "--json")
	if err != nil {
		t.Fatal(err)
	}
	var made struct {
		Anchor string `json:"anchor"`
	}
	if err := json.Unmarshal([]byte(initOut), &made); err != nil {
		t.Fatal(err)
	}

	out, err := run(t, dir, "show")
	if err != nil {
		t.Fatalf("show: %v", err)
	}
	if !strings.Contains(out, made.Anchor) {
		t.Error("show does not print the anchor an operator has to give out")
	}
	if !strings.Contains(out, "no relays issued yet") {
		t.Errorf("show does not say there is nothing issued:\n%s", out)
	}
	// Nothing secret: the key files are PEM, and none of that appears.
	for _, f := range []string{"ta.key", "server-ca.key", "client-ca.key"} {
		raw, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			t.Fatal(err)
		}
		body := strings.ReplaceAll(string(raw), "\n", "")
		body = strings.TrimPrefix(body, "-----BEGIN PRIVATE KEY-----")
		if len(body) > 20 && strings.Contains(out, body[:20]) {
			t.Errorf("show printed part of %s", f)
		}
	}

	// After issuing, it reports the relay and the retired count.
	bundle := filepath.Join(t.TempDir(), "bundle.json")
	if _, err := run(t, dir, "relay", "--host", "relay.example.com", "--out", bundle); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, dir, "relay", "--host", "relay.example.com", "--out", bundle); err != nil {
		t.Fatal(err)
	}
	out, err = run(t, dir, "show")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "relay.example.com") || !strings.Contains(out, "1 retired") {
		t.Errorf("show does not report the issued relay and its retired intermediate:\n%s", out)
	}
	// The date that matters is the intermediates', not only the anchor's:
	// it is the yearly one, and the one this machine has to be visited for.
	// The month is read in UTC, the zone show prints it in: the date is
	// the certificate's NotAfter as x509 parsed it, and on the local clock
	// the month turns hours apart from it, so a local month here failed
	// for the first ten hours of every month east of Greenwich.
	year := time.Now().UTC().AddDate(1, 0, 0).Format("2006-01")
	if !strings.Contains(out, "intermediates expire "+year) {
		t.Errorf("show does not say when the relay's intermediates expire:\n%s", out)
	}
}

func TestAuuCARefusesADirectoryOthersCanRead(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	if _, err := run(t, dir, "init", "--name", "Test"); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := run(t, dir, "show")
	if err == nil {
		t.Fatal("a world-readable authority was used")
	}
	for _, want := range []string{"0755", "must not be readable by group or others"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}
