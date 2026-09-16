package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/pki"
)

// caFiles is everything an authority's directory holds after issuing to one
// relay. Anything else found there was written by mistake.
var caFiles = map[string]bool{
	"ta.key": true, "ta.pem": true, "server-ca.key": true, "server-ca.pem": true,
	"client-ca.key": true, "client-ca.pem": true, "issued.json": true,
}

// listing is the names of the files under dir, recursively.
func listing(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestRelayToStandardOutputIsTheBundleAndNothingElse: with --out - the pipe
// carries exactly what a file would hold, everything for a person goes to
// standard error, and no file is written anywhere.
func TestRelayToStandardOutputIsTheBundleAndNothingElse(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	if _, err := run(t, dir, "init", "--name", "Test"); err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	t.Chdir(work)
	before := listing(t, work)

	stdout, stderr, err := runCapturing(t, dir, "relay", "--host", "relay.example.com", "--out", "-")
	if err != nil {
		t.Fatalf("relay --out -: %v", err)
	}
	if after := listing(t, work); len(after) != len(before) {
		t.Errorf("--out - wrote into the working directory: %v", after)
	}
	for _, path := range listing(t, dir) {
		if !caFiles[filepath.Base(path)] {
			t.Errorf("--out - left %s in the authority's directory", path)
		}
	}

	// The bytes are a bundle: they load through the same code a relay uses.
	tmp := filepath.Join(t.TempDir(), "piped.json")
	if err := os.WriteFile(tmp, []byte(stdout), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := pki.LoadBundle(tmp)
	if err != nil {
		t.Fatalf("what --out - wrote does not load as a bundle: %v", err)
	}
	// And nothing else: decoding and encoding again gives back every byte,
	// which a "wrote" line or a blank line on the wrong stream would break.
	var b pki.Bundle
	if err := json.Unmarshal([]byte(stdout), &b); err != nil {
		t.Fatal(err)
	}
	again, err := pki.EncodeBundle(&b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again, []byte(stdout)) {
		t.Errorf("standard output is not exactly the encoded bundle: %d bytes against %d", len(stdout), len(again))
	}
	for _, word := range []string{"wrote", "trust anchor", "Copy", "delete"} {
		if strings.Contains(stdout, word) {
			t.Errorf("standard output carries %q beside the bundle", word)
		}
	}
	for _, want := range []string{"wrote the bundle to standard output", loaded.AnchorSPKI, "relay.example.com"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("standard error lacks %q:\n%s", want, stderr)
		}
	}

	// A file written for the same store has the same shape and satisfies
	// the same identity; it cannot be the same bytes, since every issuance
	// makes fresh keys.
	file := filepath.Join(t.TempDir(), "bundle.json")
	if _, err := run(t, dir, "relay", "--host", "relay.example.com", "--out", file); err != nil {
		t.Fatal(err)
	}
	written, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var fromFile pki.Bundle
	if err := json.Unmarshal(written, &fromFile); err != nil {
		t.Fatal(err)
	}
	if fromFile.TrustAnchorSPKI != b.TrustAnchorSPKI || strings.Join(fromFile.Hosts, ",") != strings.Join(b.Hosts, ",") {
		t.Error("the file and the pipe describe different relays")
	}
	if again, _ := pki.EncodeBundle(&fromFile); !bytes.Equal(again, written) {
		t.Error("the file is not exactly the encoded bundle either")
	}
}

// TestRelayToAFileSaysToDeleteIt: the file is the operator's to delete and
// they are told so, in words that name what it holds, after a copy recipe
// that gives each prompt a terminal of its own — scp, then ssh -t for sudo,
// never auu-ca piped into ssh; with --out - there is nothing to copy and
// nothing to delete.
func TestRelayToAFileSaysToDeleteIt(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	if _, err := run(t, dir, "init", "--name", "Test"); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "relay-bundle.json")
	out, err := run(t, dir, "relay", "--host", "relay.example.com", "--out", file)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Then delete " + file + " from this machine",
		"backups",
		"scp " + file + " relay.example.com:",
		"ssh -t relay.example.com 'sudo systemd-creds encrypt --name=relay-bundle relay-bundle.json",
		"&& rm relay-bundle.json'",
		`"bundle_credential": "relay-bundle"`,
		`"bundle": "/etc/auu/relay-bundle.json"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the instructions lack %q:\n%s", want, out)
		}
	}
	// A pipe from auu-ca into ssh would put two prompts on one terminal.
	if strings.Contains(out, "--out - | ssh") {
		t.Errorf("the instructions pipe auu-ca into ssh:\n%s", out)
	}

	_, stderr, err := runCapturing(t, dir, "relay", "--host", "relay.example.com", "--out", "-")
	if err != nil {
		t.Fatal(err)
	}
	for _, absent := range []string{"Copy it", "delete", "install it", "systemd-creds"} {
		if strings.Contains(stderr, absent) {
			t.Errorf("with --out - the output still says %q:\n%s", absent, stderr)
		}
	}
}

// showJSON runs show --json and returns the relays it reports.
func showJSON(t *testing.T, dir string) []struct {
	Host         string `json:"host"`
	BundleOnDisk string `json:"bundle_on_disk"`
} {
	t.Helper()
	out, err := run(t, dir, "show", "--json")
	if err != nil {
		t.Fatalf("show --json: %v", err)
	}
	var got struct {
		Relays []struct {
			Host         string `json:"host"`
			BundleOnDisk string `json:"bundle_on_disk"`
		} `json:"relays"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("show --json: %v\n%s", err, out)
	}
	return got.Relays
}

// TestShowWarnsAboutABundleStillOnDisk: show is the command run at least
// yearly, so it is where the operator hears that a file of signing keys is
// still on this machine; once it is gone, or never existed, it says nothing.
func TestShowWarnsAboutABundleStillOnDisk(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	if _, err := run(t, dir, "init", "--name", "Test"); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "relay-bundle.json")
	if _, err := run(t, dir, "relay", "--host", "relay.example.com", "--out", file); err != nil {
		t.Fatal(err)
	}
	abs, err := filepath.Abs(file)
	if err != nil {
		t.Fatal(err)
	}

	stdout, stderr, err := runCapturing(t, dir, "show")
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("auu-ca: the bundle written for relay.example.com on %s is still at %s; "+
		"delete it once it is on the relay, or write the next one with --out -",
		time.Now().UTC().Format(time.DateOnly), abs)
	if !strings.Contains(stderr, want) {
		t.Errorf("show does not warn about the file:\n got %q\nwant %q", stderr, want)
	}
	if strings.Contains(stdout, "still at") {
		t.Error("the warning went to standard output")
	}
	if got := showJSON(t, dir); len(got) != 1 || got[0].BundleOnDisk != abs {
		t.Errorf("show --json reports %+v, want bundle_on_disk %q", got, abs)
	}

	// Deleted: nothing to say.
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if _, stderr, _ = runCapturing(t, dir, "show"); strings.Contains(stderr, "still at") {
		t.Errorf("show warns about a file that is gone:\n%s", stderr)
	}
	if got := showJSON(t, dir); got[0].BundleOnDisk != "" {
		t.Errorf("show --json reports a deleted file: %+v", got)
	}

	// Sent to standard output: nothing to say.
	if _, _, err := runCapturing(t, dir, "relay", "--host", "relay.example.com", "--out", "-"); err != nil {
		t.Fatal(err)
	}
	if _, stderr, _ = runCapturing(t, dir, "show"); strings.Contains(stderr, "still at") {
		t.Errorf("show warns after --out -:\n%s", stderr)
	}
	if got := showJSON(t, dir); got[0].BundleOnDisk != "" {
		t.Errorf("show --json reports a path after --out -: %+v", got)
	}

	// A record from before the path was kept, written out as it was then:
	// it loads, and there is nothing to say.
	record := filepath.Join(dir, "relays", "relay.example.com", "issued.json")
	raw, err := os.ReadFile(record)
	if err != nil {
		t.Fatal(err)
	}
	var current struct {
		ClientInts [][]byte `json:"client_intermediates"`
	}
	if err := json.Unmarshal(raw, &current); err != nil {
		t.Fatal(err)
	}
	old := fmt.Sprintf(`{
  "hosts": [
    "relay.example.com"
  ],
  "client_intermediates": [
    %q
  ],
  "updated": "2025-01-02T03:04:05Z"
}
`, base64.StdEncoding.EncodeToString(current.ClientInts[len(current.ClientInts)-1]))
	if err := os.WriteFile(record, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, err = runCapturing(t, dir, "show")
	if err != nil {
		t.Fatalf("show refuses a record from before bundle_path: %v", err)
	}
	if !strings.Contains(stdout, "relay.example.com") {
		t.Errorf("show does not list the relay from an old record:\n%s", stdout)
	}
	if strings.Contains(stderr, "still at") {
		t.Errorf("show warns from a record that holds no path:\n%s", stderr)
	}
}

// TestTheRecordedPathIsAbsolute: a relative --out is recorded as where it is
// on this machine, so that show finds it from any directory.
func TestTheRecordedPathIsAbsolute(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	if _, err := run(t, dir, "init", "--name", "Test"); err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	if err := os.Mkdir(filepath.Join(work, "relative"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(work)
	if _, err := run(t, dir, "relay", "--host", "relay.example.com", "--out", "relative/name.json"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "relays", "relay.example.com", "issued.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rec pki.RelayRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(rec.BundlePath) {
		t.Fatalf("recorded %q, which is not absolute", rec.BundlePath)
	}
	if filepath.Base(rec.BundlePath) != "name.json" || filepath.Base(filepath.Dir(rec.BundlePath)) != "relative" {
		t.Errorf("recorded %q, want .../relative/name.json", rec.BundlePath)
	}
	if _, err := os.Stat(rec.BundlePath); err != nil {
		t.Errorf("the recorded path does not name the file: %v", err)
	}

	// From somewhere else entirely, show still finds it.
	t.Chdir(t.TempDir())
	_, stderr, err := runCapturing(t, dir, "show")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr, "still at "+rec.BundlePath) {
		t.Errorf("show from another directory does not find the file:\n%s", stderr)
	}
	if got := showJSON(t, dir); got[0].BundleOnDisk != rec.BundlePath {
		t.Errorf("show --json reports %q, want %q", got[0].BundleOnDisk, rec.BundlePath)
	}
}
