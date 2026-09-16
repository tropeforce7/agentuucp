package main

import (
	"archive/zip"
	"bytes"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/kit"
	"github.com/tropeforce7/agentuucp/internal/pki"
)

// relayBinary writes the header of a static linux/amd64 executable, which
// is all the kit reads of the binary, and returns its path.
func relayBinary(t *testing.T) string {
	t.Helper()
	var b bytes.Buffer
	ident := [16]byte{0x7f, 'E', 'L', 'F', byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT), byte(elf.ELFOSABI_NONE)}
	b.Write(ident[:])
	for _, v := range []any{
		uint16(elf.ET_EXEC), uint16(elf.EM_X86_64), uint32(1), uint64(0), uint64(64), uint64(0), uint32(0),
		uint16(64), uint16(56), uint16(0), uint16(64), uint16(0), uint16(0),
	} {
		binary.Write(&b, binary.LittleEndian, v)
	}
	path := filepath.Join(t.TempDir(), "auu-relay")
	if err := os.WriteFile(path, b.Bytes(), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// anAdmin is an administrator's export line.
func anAdmin(t *testing.T, name string) string {
	t.Helper()
	id, err := identity.Generate(name)
	if err != nil {
		t.Fatal(err)
	}
	return id.Public().ExportLine()
}

// initialised is a test authority, and a kit path in another directory.
func initialised(t *testing.T) (dir, out string) {
	t.Helper()
	dir = filepath.Join(t.TempDir(), "ca")
	if _, err := run(t, dir, "init", "--name", "Test"); err != nil {
		t.Fatal(err)
	}
	return dir, filepath.Join(t.TempDir(), "relay.example.com.zip")
}

// kitEntries reads an archive back: entry name to its bytes.
func kitEntries(t *testing.T, path string) (map[string][]byte, []string) {
	t.Helper()
	r, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	files := map[string][]byte{}
	var order []string
	for _, f := range r.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		var b bytes.Buffer
		b.ReadFrom(rc)
		rc.Close()
		name := strings.TrimPrefix(f.Name, kit.Dir+"/")
		files[name] = b.Bytes()
		order = append(order, name)
	}
	return files, order
}

// printedRecipe is the recipe as auu-ca kit printed it: the lines from the
// one that introduces it to the line before the note that follows. Taken
// from the output rather than from what a test wrote, so an assertion over
// it is about the program.
func printedRecipe(t *testing.T, stdout string) string {
	t.Helper()
	const opens = "Copy it to the relay"
	i := strings.Index(stdout, opens)
	if i < 0 {
		t.Fatalf("no recipe in:\n%s", stdout)
	}
	rest := stdout[i:]
	if j := strings.Index(rest, "The host needs unzip"); j >= 0 {
		return rest[:j]
	}
	return rest
}

// The command against a test store writes a kit that internal/kit's format
// reads back: the table's entries, the bundle issued for the host under the
// store's anchor, the README naming that anchor, the settings for the host,
// the administrator's line in admins. The archive is 0600.
func TestKitWritesAnArchiveTheKitFormatReadsBack(t *testing.T) {
	dir, out := initialised(t)
	admin := anAdmin(t, "bunty")
	stdout, err := run(t, dir, "kit", "--host", "relay.example.com", "--host", "10.0.0.5",
		"--relay-binary", relayBinary(t), "--admin", admin, "--out", out)
	if err != nil {
		t.Fatalf("kit: %v", err)
	}
	info, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("the archive is mode %04o, want 0600", info.Mode().Perm())
	}
	files, order := kitEntries(t, out)
	if got := strings.Join(order, " "); got != "README MANIFEST install.sh auu-relay relay.json admins auu-relay.service relay-bundle.json" {
		t.Fatalf("the archive holds %s", got)
	}
	// The bundle is the store's, for the host, and the README names its
	// anchor, which is show's.
	bundlePath := filepath.Join(t.TempDir(), "relay-bundle.json")
	if err := os.WriteFile(bundlePath, files["relay-bundle.json"], 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := pki.LoadBundle(bundlePath)
	if err != nil {
		t.Fatalf("the kit's bundle does not load: %v", err)
	}
	if strings.Join(loaded.Hosts, ",") != "relay.example.com,10.0.0.5" {
		t.Fatalf("the bundle is for %v", loaded.Hosts)
	}
	showOut, err := run(t, dir, "show", "--json")
	if err != nil {
		t.Fatal(err)
	}
	var shown struct {
		Anchor string `json:"anchor"`
	}
	if err := json.Unmarshal([]byte(showOut), &shown); err != nil {
		t.Fatal(err)
	}
	if shown.Anchor != loaded.AnchorSPKI {
		t.Fatalf("the bundle's anchor %s is not the store's %s", loaded.AnchorSPKI, shown.Anchor)
	}
	if !bytes.Contains(files["README"], []byte("  trust anchor   "+shown.Anchor+"\n")) {
		t.Fatalf("the README does not name the anchor %s:\n%s", shown.Anchor, files["README"])
	}
	var settings struct {
		Listen       string `json:"listen"`
		PublicURL    string `json:"public_url"`
		Registration string `json:"registration"`
	}
	if err := json.Unmarshal(files["relay.json"], &settings); err != nil {
		t.Fatal(err)
	}
	if settings.Listen != ":9443" || settings.PublicURL != "https://relay.example.com:9443" || settings.Registration != "token" {
		t.Fatalf("the settings say %+v; want the defaults for the first host", settings)
	}
	if !bytes.Contains(files["admins"], []byte(admin+"\n")) {
		t.Fatalf("the admins file lacks the line:\n%s", files["admins"])
	}
	// What it printed: the wrote line with the architecture read from the
	// binary, the anchor, every file with its hash, the recipe.
	for _, want := range []string{
		"wrote " + out + " (",
		", amd64)\n", // the header the test builds carries no version
		"  for           relay.example.com, 10.0.0.5\n",
		"  trust anchor  " + shown.Anchor + "\n",
		"  README (",
		"  relay-bundle.json (",
		"The archive holds the relay's two signing keys in the clear",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("the output lacks %q:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, "rotation") {
		t.Errorf("a first kit was reported as a rotation:\n%s", stdout)
	}
}

// The printed recipe is scp, then unzip and the script under sudo over a
// terminal of its own, then the copies removed at both ends, never a change
// of directory; and for a host the store already holds a record for, the
// script's update form.
func TestKitPrintsTheRecipe(t *testing.T) {
	dir, out := initialised(t)
	bin := relayBinary(t)
	stdout, err := run(t, dir, "kit", "--host", "relay.example.com", "--relay-binary", bin,
		"--registration", "open", "--out", out)
	if err != nil {
		t.Fatal(err)
	}
	want := "Copy it to the relay, run the script there, and delete it at both ends:\n" +
		"  scp " + out + " relay.example.com:\n" +
		"  ssh -t relay.example.com 'unzip -oq relay.example.com.zip && sudo sh auu-relay-kit/install.sh'\n" +
		"  ssh relay.example.com 'rm -r relay.example.com.zip auu-relay-kit'\n" +
		"  rm " + out + "\n"
	if !strings.Contains(stdout, want) {
		t.Fatalf("the recipe is not:\n%s\nin:\n%s", want, stdout)
	}
	// The recipe alone, as it was printed, and not the whole of stdout:
	// the file list above it is eight hashes, and a hash ending in "cd"
	// before the two-space separator is the substring this forbids. Fresh
	// keys every run made that about one failure in thirty.
	recipe := printedRecipe(t, stdout)
	if strings.Contains(recipe, "cd ") || strings.Contains(recipe, "sh -c") {
		t.Fatalf("the recipe changes directory or runs a shell string:\n%s", recipe)
	}
	// The one thing the host needs that a minimal install lacks, said
	// beside the line that needs it.
	if !strings.Contains(stdout, want+"The host needs unzip, which a minimal install does not have: apt install unzip,\n"+
		"or dnf install unzip; python3 -m zipfile -e relay.example.com.zip . unpacks it too.\n") {
		t.Fatalf("the recipe does not say the host needs unzip:\n%s", stdout)
	}
	// The second kit for the host: a rotation, said as relay says it, and
	// the recipe's update form.
	stdout, err = run(t, dir, "kit", "--host", "relay.example.com", "--relay-binary", bin,
		"--registration", "open", "--out", out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "  rotation      2, keeping 1 earlier client intermediate(s) so existing\n") {
		t.Fatalf("the second kit was not reported as a rotation:\n%s", stdout)
	}
	if !strings.Contains(stdout, "sudo sh auu-relay-kit/install.sh update'\n") {
		t.Fatalf("the second kit's recipe does not say update:\n%s", stdout)
	}
	// And without a bundle, for a host with a record, the update form too.
	stdout, err = run(t, dir, "kit", "--host", "relay.example.com", "--relay-binary", bin,
		"--registration", "open", "--out", out, "--without-bundle")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "sudo sh auu-relay-kit/install.sh update'\n") {
		t.Fatalf("a kit without a bundle for a known host does not say update:\n%s", stdout)
	}
}

// show nags about a kit on disk as it nags about a bundle file, and its
// JSON names the path; deleting the kit silences it.
func TestShowNagsAboutAKitOnDisk(t *testing.T) {
	dir, out := initialised(t)
	if _, err := run(t, dir, "kit", "--host", "relay.example.com", "--relay-binary", relayBinary(t),
		"--registration", "open", "--out", out); err != nil {
		t.Fatal(err)
	}
	_, stderr, err := runCapturing(t, dir, "show")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr, "is still at "+out+";") {
		t.Fatalf("show did not nag about the kit:\n%s", stderr)
	}
	relays := showJSON(t, dir)
	if len(relays) != 1 || relays[0].BundleOnDisk != out {
		t.Fatalf("show --json says %+v, want bundle_on_disk %s", relays, out)
	}
	if err := os.Remove(out); err != nil {
		t.Fatal(err)
	}
	_, stderr, err = runCapturing(t, dir, "show")
	if err != nil {
		t.Fatal(err)
	}
	if stderr != "" {
		t.Fatalf("show still warns with the kit gone:\n%s", stderr)
	}
}

// --without-bundle issues nothing, asks for no passphrase, records nothing,
// and the archive has no bundle; the README still names the anchor, read
// as show reads it, and the output says what the script will ask for.
func TestKitWithoutBundleIssuesNothing(t *testing.T) {
	dir, out := initialised(t)
	// No --passphrase-file: run supplies none for --without-bundle, and a
	// command that asked would read an empty standard input and fail.
	stdout, err := run(t, dir, "kit", "--host", "relay.example.com", "--relay-binary", relayBinary(t),
		"--registration", "open", "--out", out, "--without-bundle")
	if err != nil {
		t.Fatalf("kit --without-bundle: %v", err)
	}
	files, order := kitEntries(t, out)
	if got := strings.Join(order, " "); got != "README MANIFEST install.sh auu-relay relay.json admins auu-relay.service" {
		t.Fatalf("the archive holds %s", got)
	}
	if relays := showJSON(t, dir); len(relays) != 0 {
		t.Fatalf("a kit without a bundle recorded a relay: %+v", relays)
	}
	showOut, _ := run(t, dir, "show", "--json")
	var shown struct {
		Anchor string `json:"anchor"`
	}
	json.Unmarshal([]byte(showOut), &shown)
	if !bytes.Contains(files["README"], []byte("  trust anchor   "+shown.Anchor+"\n")) {
		t.Fatalf("the README does not name the anchor:\n%s", files["README"])
	}
	if !bytes.Contains(files["README"], []byte("This kit carries no bundle.")) {
		t.Fatalf("the README does not say the kit has no bundle:\n%s", files["README"])
	}
	for _, want := range []string{
		"  bundle        none; install.sh will stop before starting the relay and print the\n",
		"                systemd-creds encrypt and systemctl enable lines to run once it is there\n",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("the output lacks %q:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, "signing keys in the clear") {
		t.Fatalf("a kit without a bundle was said to hold one:\n%s", stdout)
	}
	if _, _, err := runCapturing(t, dir, "show"); err != nil {
		t.Fatal(err)
	}
}

// --admin @FILE reads a file of lines, # and blank lines skipped, so an
// operator with an admins file has nothing to retype; a bad line is named
// by the file and its number.
func TestKitReadsAdminsFromAFile(t *testing.T) {
	dir, out := initialised(t)
	a, b := anAdmin(t, "bunty"), anAdmin(t, "boss")
	file := filepath.Join(t.TempDir(), "admins")
	if err := os.WriteFile(file, []byte("# who may administer\n\n"+a+"\n  \n"+b+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := anAdmin(t, "third")
	if _, err := run(t, dir, "kit", "--host", "relay.example.com", "--relay-binary", relayBinary(t),
		"--admin", "@"+file, "--admin", c, "--out", out); err != nil {
		t.Fatal(err)
	}
	files, _ := kitEntries(t, out)
	keys, err := identity.ParseExportLines("admins", files["admins"])
	if err != nil || len(keys) != 3 || keys[0].Name != "bunty" || keys[1].Name != "boss" || keys[2].Name != "third" {
		t.Fatalf("the kit's admins parse to %v, %v; want bunty, boss, third", keys, err)
	}
	if err := os.WriteFile(file, []byte(a+"\nssh-ed25519 AAAA nobody\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = run(t, dir, "kit", "--host", "relay.example.com", "--relay-binary", relayBinary(t),
		"--admin", "@"+file, "--out", out)
	if err == nil || !strings.HasPrefix(err.Error(), file+" line 2: ") {
		t.Fatalf("a bad line in the file: %v, want it named by file and line", err)
	}
	_, err = run(t, dir, "kit", "--host", "relay.example.com", "--relay-binary", relayBinary(t),
		"--admin", "@"+filepath.Join(t.TempDir(), "missing"), "--out", out)
	if err == nil || !strings.HasPrefix(err.Error(), "--admin: open ") {
		t.Fatalf("a missing file: %v", err)
	}
}

// Every refusal sentence, and that a refused kit is refused before the
// bundle is issued: the store's records are untouched, so no rotation is
// recorded for an archive that was never written.
func TestKitChecksItsArgumentsBeforeIssuing(t *testing.T) {
	dir, out := initialised(t)
	bin := relayBinary(t)
	macho := filepath.Join(t.TempDir(), "auu-relay")
	if err := os.WriteFile(macho, []byte{0xcf, 0xfa, 0xed, 0xfe, 0, 0, 0, 0}, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		args  []string
		want  string
		usage bool
	}{
		{[]string{"--relay-binary", bin, "--out", out, "--registration", "open"},
			"--host is required: it is what the relay's certificate will be valid for", true},
		{[]string{"--host", "relay.example.com", "--out", out, "--registration", "open"},
			"--relay-binary is required: the relay built for the host, CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build ./cmd/auu-relay", true},
		{[]string{"--host", "relay.example.com", "--relay-binary", bin, "--registration", "open"},
			"--out is required: the archive you copy to the relay", true},
		{[]string{"--host", "relay.example.com", "--relay-binary", bin, "--registration", "open", "--out", "-"},
			"--out - is not accepted: an archive with a binary in it is not a thing to pipe; name a file", true},
		{[]string{"--host", "relay.example.com", "--relay-binary", bin, "--registration", "open", "--out", out, "--without-bundle", "--years", "2"},
			"--years means nothing with --without-bundle: the bundle is issued by 'auu-ca relay' then", true},
		{[]string{"--host", "relay.example.com", "--relay-binary", bin, "--out", out, "extra"},
			`unexpected argument "extra"`, true},
		{[]string{"--host", "relay.example.com", "--relay-binary", bin, "--out", out},
			"a token relay needs an administrator: --admin LINE, or --registration open", false},
		{[]string{"--host", "relay.example.com", "--relay-binary", bin, "--out", out, "--registration", "invite"},
			`registration must be open, token or closed, not "invite"`, false},
		{[]string{"--host", "relay.example.com", "--relay-binary", bin, "--out", out, "--registration", "open", "--client-certs", "on"},
			`client_certs must be off or required, not "on"`, false},
		{[]string{"--host", "relay.example.com", "--relay-binary", bin, "--out", out, "--registration", "open", "--listen", "9443"},
			`listen must be host:port with a port, as :9443 is, not "9443"`, false},
		{[]string{"--host", "relay.example.com", "--relay-binary", bin, "--out", out, "--registration", "open", "--admin", "not a key"},
			`admin line 1: identity: unknown key type "not"`, false},
		{[]string{"--host", "relay.example.com", "--relay-binary", macho, "--out", out, "--registration", "open"},
			"the relay binary is not a static Linux executable for amd64 or arm64: a Mach-O executable, built for macOS", false},
		{[]string{"--host", "relay.example.com", "--relay-binary", filepath.Join(t.TempDir(), "none"), "--out", out, "--registration", "open"},
			"reading --relay-binary: open ", false},
	} {
		_, err := run(t, dir, append([]string{"kit"}, tc.args...)...)
		if err == nil {
			t.Fatalf("kit %v was accepted, want %q", tc.args, tc.want)
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("kit %v: %v, want %q", tc.args, err, tc.want)
		}
		var u *usageError
		if isUsage := errors.As(err, &u); isUsage != tc.usage {
			t.Fatalf("kit %v: usage error %v, want %v: %v", tc.args, isUsage, tc.usage, err)
		}
		if _, err := os.Stat(out); err == nil {
			t.Fatalf("kit %v wrote the archive before being refused", tc.args)
		}
	}
	// Nothing was issued for any of them: show lists no relay, and a kit
	// that now succeeds is the first, not a rotation.
	if relays := showJSON(t, dir); len(relays) != 0 {
		t.Fatalf("a refused kit recorded a relay: %+v", relays)
	}
	stdout, err := run(t, dir, "kit", "--host", "relay.example.com", "--relay-binary", bin, "--out", out, "--registration", "open")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stdout, "rotation") {
		t.Fatalf("the first kit that built was reported as a rotation, so a refused one issued:\n%s", stdout)
	}
}
