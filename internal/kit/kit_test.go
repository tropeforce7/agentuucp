package kit

import (
	"archive/zip"
	"bytes"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/keyfile"
	"github.com/tropeforce7/agentuucp/internal/pki"
)

// fakeELF is the smallest file debug/elf reads as an executable: a header
// and, when interp is set, one PT_INTERP program header, which is what a
// dynamically linked binary has and a static one does not. The tests build
// the binaries they refuse rather than ship them.
func fakeELF(class elf.Class, osabi elf.OSABI, machine elf.Machine, interp bool) []byte {
	var b bytes.Buffer
	ident := [16]byte{0x7f, 'E', 'L', 'F', byte(class), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT), byte(osabi)}
	b.Write(ident[:])
	if class == elf.ELFCLASS32 {
		// e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags,
		// e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx.
		binary.Write(&b, binary.LittleEndian, uint16(elf.ET_EXEC))
		binary.Write(&b, binary.LittleEndian, uint16(machine))
		binary.Write(&b, binary.LittleEndian, uint32(1))
		binary.Write(&b, binary.LittleEndian, uint32(0))
		binary.Write(&b, binary.LittleEndian, uint32(0))
		binary.Write(&b, binary.LittleEndian, uint32(0))
		binary.Write(&b, binary.LittleEndian, uint32(0))
		binary.Write(&b, binary.LittleEndian, uint16(52))
		binary.Write(&b, binary.LittleEndian, uint16(32))
		binary.Write(&b, binary.LittleEndian, uint16(0))
		binary.Write(&b, binary.LittleEndian, uint16(40))
		binary.Write(&b, binary.LittleEndian, uint16(0))
		binary.Write(&b, binary.LittleEndian, uint16(0))
		return b.Bytes()
	}
	phnum := uint16(0)
	if interp {
		phnum = 1
	}
	binary.Write(&b, binary.LittleEndian, uint16(elf.ET_EXEC))
	binary.Write(&b, binary.LittleEndian, uint16(machine))
	binary.Write(&b, binary.LittleEndian, uint32(1))
	binary.Write(&b, binary.LittleEndian, uint64(0))  // entry
	binary.Write(&b, binary.LittleEndian, uint64(64)) // phoff: right after the header
	binary.Write(&b, binary.LittleEndian, uint64(0))  // shoff
	binary.Write(&b, binary.LittleEndian, uint32(0))  // flags
	binary.Write(&b, binary.LittleEndian, uint16(64)) // ehsize
	binary.Write(&b, binary.LittleEndian, uint16(56)) // phentsize
	binary.Write(&b, binary.LittleEndian, phnum)
	binary.Write(&b, binary.LittleEndian, uint16(64)) // shentsize
	binary.Write(&b, binary.LittleEndian, uint16(0))  // shnum
	binary.Write(&b, binary.LittleEndian, uint16(0))  // shstrndx
	if interp {
		binary.Write(&b, binary.LittleEndian, uint32(elf.PT_INTERP))
		binary.Write(&b, binary.LittleEndian, uint32(elf.PF_R))
		for i := 0; i < 6; i++ {
			binary.Write(&b, binary.LittleEndian, uint64(0))
		}
	}
	return b.Bytes()
}

// staticAMD64 is what a relay built with CGO_ENABLED=0 GOOS=linux
// GOARCH=amd64 looks like to the check.
func staticAMD64() []byte { return fakeELF(elf.ELFCLASS64, elf.ELFOSABI_NONE, elf.EM_X86_64, false) }

// adminLine is one administrator's export line.
func adminLine(t *testing.T, name string) string {
	t.Helper()
	id, err := identity.Generate(name)
	if err != nil {
		t.Fatal(err)
	}
	return id.Public().ExportLine()
}

// authority is a test store and its anchor, for a bundle to come from.
func authority(t *testing.T) (*pki.Store, string) {
	t.Helper()
	params, err := pki.ParameterSet(pki.DefaultMLDSA)
	if err != nil {
		t.Fatal(err)
	}
	store, err := pki.Create(t.TempDir(), "Test", params, keyfile.TestPassphrase("test"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return store, pki.SPKI(store.Anchor.Cert)
}

// bundleFor is an encoded bundle issued for hosts, as auu-ca kit has it.
func bundleFor(t *testing.T, store *pki.Store, hosts []string) []byte {
	t.Helper()
	b, _, err := store.IssueRelay(hosts, pki.DefaultIntermediateYears, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	data, err := pki.EncodeBundle(b)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// aSpec is a kit that builds: one host, the guide's port, a token relay
// with one administrator, no bundle unless the test adds one.
func aSpec(t *testing.T) Spec {
	t.Helper()
	return Spec{
		Hosts:        []string{"relay.example.com"},
		Listen:       ":9443",
		Registration: "token",
		ClientCerts:  "off",
		Admins:       []string{adminLine(t, "bunty")},
		Anchor:       "sha256:" + strings.Repeat("0", 64),
		RelayBinary:  staticAMD64(),
		Now:          time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC),
	}
}

// build is Build into memory, failing the test on an error.
func build(t *testing.T, s Spec) ([]byte, Summary) {
	t.Helper()
	var out bytes.Buffer
	sum, err := Build(&out, s)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return out.Bytes(), sum
}

// refused is Build's error, which must be there and say what is asked.
func refused(t *testing.T, s Spec, want string) {
	t.Helper()
	_, err := Build(&bytes.Buffer{}, s)
	if err == nil {
		t.Fatalf("Build accepted a kit that should have been refused with %q", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("Build refused with %q, want %q", err, want)
	}
}

// entries reads a built kit back: name under the kit directory to the
// file, in archive order.
type kitFile struct {
	name string
	mode os.FileMode
	when time.Time
	data []byte
}

func entries(t *testing.T, archive []byte) []kitFile {
	t.Helper()
	r, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		t.Fatal(err)
	}
	var out []kitFile
	for _, f := range r.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		var data bytes.Buffer
		if _, err := data.ReadFrom(rc); err != nil {
			t.Fatal(err)
		}
		rc.Close()
		out = append(out, kitFile{name: f.Name, mode: f.Mode(), when: f.Modified, data: data.Bytes()})
	}
	return out
}

func fileIn(t *testing.T, archive []byte, name string) kitFile {
	t.Helper()
	for _, e := range entries(t, archive) {
		if e.name == Dir+"/"+name {
			return e
		}
	}
	t.Fatalf("no entry %s in the kit", name)
	return kitFile{}
}

func TestRegistrationMustBeOpenTokenOrClosed(t *testing.T) {
	for _, mode := range []string{"open", "token", "closed"} {
		s := aSpec(t)
		s.Registration = mode
		build(t, s)
	}
	s := aSpec(t)
	s.Registration = "invite"
	refused(t, s, `registration must be open, token or closed, not "invite"`)
	s.Registration = ""
	refused(t, s, `registration must be open, token or closed, not ""`)
}

func TestClientCertsMustBeOffOrRequired(t *testing.T) {
	for _, mode := range []string{"off", "required"} {
		s := aSpec(t)
		s.ClientCerts = mode
		build(t, s)
	}
	s := aSpec(t)
	s.ClientCerts = "on"
	refused(t, s, `client_certs must be off or required, not "on"`)
}

func TestListenMustBeHostPortWithAPort(t *testing.T) {
	for _, bad := range []string{"", "9443", ":", ":0", ":70000", ":https", "relay.example.com", "[::1]"} {
		s := aSpec(t)
		s.Listen = bad
		refused(t, s, `listen must be host:port with a port, as :9443 is, not "`+bad+`"`)
	}
	for _, good := range []string{":9443", ":443", "0.0.0.0:9443", "[::]:9443", "10.0.0.5:8443"} {
		s := aSpec(t)
		s.Listen = good
		build(t, s)
	}
}

// public_url is https://, the first host and the listen port, so the
// guide's rule that the two must agree is true by construction, and an
// IPv6 host is bracketed as a URL needs.
func TestPublicURLIsTheFirstHostAndTheListenPort(t *testing.T) {
	for _, tc := range []struct {
		hosts  []string
		listen string
		want   string
	}{
		{[]string{"relay.example.com"}, ":9443", "https://relay.example.com:9443"},
		{[]string{"relay.example.com", "10.0.0.5"}, "0.0.0.0:443", "https://relay.example.com:443"},
		{[]string{"10.0.0.5"}, ":8443", "https://10.0.0.5:8443"},
		{[]string{"2001:db8::1", "relay.example.com"}, ":9443", "https://[2001:db8::1]:9443"},
	} {
		s := aSpec(t)
		s.Hosts, s.Listen = tc.hosts, tc.listen
		archive, _ := build(t, s)
		var settings struct {
			Listen    string `json:"listen"`
			PublicURL string `json:"public_url"`
		}
		if err := json.Unmarshal(fileIn(t, archive, "relay.json").data, &settings); err != nil {
			t.Fatal(err)
		}
		if settings.PublicURL != tc.want || settings.Listen != tc.listen {
			t.Fatalf("hosts %v listen %q: settings say listen %q public_url %q, want %q",
				tc.hosts, tc.listen, settings.Listen, settings.PublicURL, tc.want)
		}
	}
	s := aSpec(t)
	s.Hosts = nil
	refused(t, s, "a kit needs a host: the first is what public_url names")
}

func TestATokenRelayNeedsAnAdministrator(t *testing.T) {
	s := aSpec(t)
	s.Admins = nil
	refused(t, s, "a token relay needs an administrator: --admin LINE, or --registration open")
	// Lines that are all blank or comments name nobody.
	s.Admins = []string{"# nobody", ""}
	refused(t, s, "a token relay needs an administrator: --admin LINE, or --registration open")
	s.Registration = "open"
	build(t, s)
	s.Registration = "closed"
	build(t, s)
}

// The admin lines go through the parser the relay's administrator file
// goes through, so a bad line is refused with the line number and the
// sentence the relay would use, and blank and comment lines are skipped.
func TestAdminLinesAreParsedAsTheRelayParsesThem(t *testing.T) {
	s := aSpec(t)
	s.Admins = []string{adminLine(t, "bunty"), "not a key line"}
	refused(t, s, `admin line 2: identity: unknown key type "not"`)
	s.Admins = []string{"# the boss", adminLine(t, "bunty"), "", adminLine(t, "boss")}
	archive, _ := build(t, s)
	keys, err := identity.ParseExportLines("admins", fileIn(t, archive, "admins").data)
	if err != nil || len(keys) != 2 || keys[0].Name != "bunty" || keys[1].Name != "boss" {
		t.Fatalf("the admins file parsed to %v, %v; want bunty and boss", keys, err)
	}
	// Byte for byte: a comment line saying what the file is, then the
	// lines as given.
	want := "# /etc/auu/admins: who may administer this relay, one export line each, as\n" +
		"# 'auu id export' prints it. The relay re-reads this file when it changes.\n" +
		strings.Join(s.Admins, "\n") + "\n"
	if got := string(fileIn(t, archive, "admins").data); got != want {
		t.Fatalf("the admins file is:\n%s\nwant:\n%s", got, want)
	}
}

func TestTheRelayBinaryMustBeAStaticLinuxExecutable(t *testing.T) {
	for _, tc := range []struct {
		what string
		bin  []byte
		want string
	}{
		{"empty", nil, "an empty file"},
		{"text", []byte("#!/bin/sh\n"), "not an executable at all"},
		{"Mach-O", []byte{0xcf, 0xfa, 0xed, 0xfe, 0, 0, 0, 0}, "a Mach-O executable, built for macOS; build it with CGO_ENABLED=0 GOOS=linux GOARCH=amd64 (or arm64)"},
		{"fat Mach-O", []byte{0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 2}, "a Mach-O executable"},
		{"Windows", []byte("MZ\x90\x00"), "a Windows executable"},
		{"ELF32", fakeELF(elf.ELFCLASS32, elf.ELFOSABI_NONE, elf.EM_386, false), "a 32-bit ELF"},
		{"FreeBSD", fakeELF(elf.ELFCLASS64, elf.ELFOSABI_FREEBSD, elf.EM_X86_64, false), "an ELF for another operating system (ELFOSABI_FREEBSD)"},
		{"riscv", fakeELF(elf.ELFCLASS64, elf.ELFOSABI_NONE, elf.EM_RISCV, false), "an ELF for EM_RISCV"},
		{"dynamic", fakeELF(elf.ELFCLASS64, elf.ELFOSABI_NONE, elf.EM_X86_64, true), "a dynamically linked Linux executable for amd64; build it with CGO_ENABLED=0"},
		{"dynamic arm64", fakeELF(elf.ELFCLASS64, elf.ELFOSABI_LINUX, elf.EM_AARCH64, true), "a dynamically linked Linux executable for arm64; build it with CGO_ENABLED=0"},
		{"truncated", []byte(elf.ELFMAG + "\x02\x01"), "not an executable this kit can read"},
	} {
		s := aSpec(t)
		s.RelayBinary = tc.bin
		refused(t, s, "the relay binary is not a static Linux executable for amd64 or arm64: "+tc.want)
	}
	for _, tc := range []struct {
		bin  []byte
		want string
	}{
		{fakeELF(elf.ELFCLASS64, elf.ELFOSABI_NONE, elf.EM_X86_64, false), "amd64"},
		{fakeELF(elf.ELFCLASS64, elf.ELFOSABI_LINUX, elf.EM_X86_64, false), "amd64"},
		{fakeELF(elf.ELFCLASS64, elf.ELFOSABI_NONE, elf.EM_AARCH64, false), "arm64"},
	} {
		s := aSpec(t)
		s.RelayBinary = tc.bin
		if _, sum := build(t, s); sum.Arch != tc.want {
			t.Fatalf("architecture %q, want %q", sum.Arch, tc.want)
		}
	}
}

// The test's own binary is what a maker who passed the wrong file would
// pass: on a Mac a Mach-O, on Windows a PE, and on Linux a dynamically
// linked ELF whenever cgo was on. Only a static Linux build is accepted,
// and then as what it is.
func TestTheTestsOwnBinaryIsRefusedUnlessItIsAStaticLinuxBuild(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	bin, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	s := aSpec(t)
	s.RelayBinary = bin
	_, err = Build(&bytes.Buffer{}, s)
	static := runtime.GOOS == "linux" && (runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64") && !hasInterp(t, bin)
	switch {
	case static && err != nil:
		t.Fatalf("a static Linux %s test binary was refused: %v", runtime.GOARCH, err)
	case !static && err == nil:
		t.Fatalf("the test binary for %s/%s was accepted as a static Linux relay", runtime.GOOS, runtime.GOARCH)
	case !static && !strings.HasPrefix(err.Error(), notStaticLinux):
		t.Fatalf("refused with %q, want the sentence beginning %q", err, notStaticLinux)
	}
	if runtime.GOOS == "darwin" && !strings.Contains(err.Error(), "a Mach-O executable, built for macOS") {
		t.Fatalf("on a Mac the refusal must name the Mach-O: %v", err)
	}
}

func hasInterp(t *testing.T, bin []byte) bool {
	t.Helper()
	f, err := elf.NewFile(bytes.NewReader(bin))
	if err != nil {
		return false
	}
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			return true
		}
	}
	return false
}

// A binary Go builds for linux/arm64 with cgo off is what the maker is told
// to build, and it is accepted as arm64. The program is the smallest one,
// since the check reads the header and nothing else; go on the path is
// what the test needs, and it is skipped without.
func TestABinaryBuiltForLinuxArm64IsAcceptedAsArm64(t *testing.T) {
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go is not on the path")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "main.go")
	if err := os.WriteFile(src, []byte("package main\n\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "relay")
	cmd := exec.Command(goTool, "build", "-o", out, src)
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=arm64", "CGO_ENABLED=0")
	if msg, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build for linux/arm64: %v\n%s", err, msg)
	}
	bin, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	s := aSpec(t)
	s.RelayBinary = bin
	_, sum := build(t, s)
	if sum.Arch != "arm64" {
		t.Fatalf("architecture %q, want arm64", sum.Arch)
	}
}

// The archive holds exactly the entries of the plan's table, in its order,
// under the one directory, at those modes, every one dated Now, and the
// bundle only when there is one.
func TestTheArchiveHoldsExactlyTheTableInOrderWithItsModes(t *testing.T) {
	store, anchor := authority(t)
	s := aSpec(t)
	s.Anchor = anchor
	s.Bundle = bundleFor(t, store, s.Hosts)
	want := []struct {
		name string
		mode os.FileMode
	}{
		{"README", 0o644}, {"MANIFEST", 0o644}, {"install.sh", 0o755}, {"auu-relay", 0o755},
		{"relay.json", 0o644}, {"admins", 0o644}, {"auu-relay.service", 0o644}, {"relay-bundle.json", 0o600},
	}
	for _, withBundle := range []bool{true, false} {
		if !withBundle {
			s.Bundle = nil
			want = want[:len(want)-1]
		}
		archive, sum := build(t, s)
		got := entries(t, archive)
		if len(got) != len(want) {
			t.Fatalf("bundle %v: %d entries, want %d: %v", withBundle, len(got), len(want), names(got))
		}
		for i, w := range want {
			e := got[i]
			if e.name != Dir+"/"+w.name {
				t.Fatalf("bundle %v: entry %d is %s, want %s/%s", withBundle, i, e.name, Dir, w.name)
			}
			if e.mode.Perm() != w.mode || !e.mode.IsRegular() {
				t.Fatalf("%s is mode %v, want %04o", e.name, e.mode, w.mode)
			}
			if !e.when.Equal(s.Now) {
				t.Fatalf("%s is dated %s, want Now, %s", e.name, e.when, s.Now)
			}
			if sum.Files[i].Name != w.name || sum.Files[i].Size != int64(len(e.data)) || sum.Files[i].SHA256 != hexSum(e.data) {
				t.Fatalf("the summary's entry %d is %+v, want %s of %d bytes", i, sum.Files[i], w.name, len(e.data))
			}
		}
		if sum.Bundle != withBundle || sum.Size != int64(len(archive)) || sum.Arch != "amd64" {
			t.Fatalf("summary %+v for a %d-byte kit with bundle %v", sum, len(archive), withBundle)
		}
		if withBundle && !bytes.Equal(fileIn(t, archive, "relay-bundle.json").data, s.Bundle) {
			t.Fatal("the bundle in the kit is not the bundle given")
		}
		if !bytes.Equal(fileIn(t, archive, "auu-relay").data, s.RelayBinary) {
			t.Fatal("the binary in the kit is not the binary given")
		}
	}
}

func names(files []kitFile) []string {
	var out []string
	for _, f := range files {
		out = append(out, f.name)
	}
	return out
}

// MANIFEST is sha256sum's format over every other entry, README included,
// in archive order, so `sha256sum -c MANIFEST` in the kit's directory
// checks the lot; the test recomputes every line.
func TestTheManifestCoversEveryOtherEntry(t *testing.T) {
	store, anchor := authority(t)
	s := aSpec(t)
	s.Anchor = anchor
	s.Bundle = bundleFor(t, store, s.Hosts)
	archive, _ := build(t, s)
	got := entries(t, archive)
	var want strings.Builder
	for _, e := range got {
		name := strings.TrimPrefix(e.name, Dir+"/")
		if name == "MANIFEST" {
			continue
		}
		want.WriteString(hexSum(e.data) + "  " + name + "\n")
	}
	if m := string(fileIn(t, archive, "MANIFEST").data); m != want.String() {
		t.Fatalf("MANIFEST is:\n%s\nwant:\n%s", m, want.String())
	}
	if !strings.Contains(want.String(), "  README\n") || !strings.Contains(want.String(), "  relay-bundle.json\n") {
		t.Fatal("the recomputed manifest does not name README and the bundle")
	}
}

// The unit and the settings template are copies of docs/systemd/'s, since
// go:embed cannot reach outside the package; this holds them equal, so an
// edit to one is caught unless made to both. The script is embedded
// verbatim, whatever it holds.
func TestTheEmbeddedFilesAreTheShippedOnes(t *testing.T) {
	for _, tc := range []struct {
		name     string
		embedded []byte
	}{
		{"auu-relay.service", unitFile},
		{"relay.json", settingsTemplate},
	} {
		shipped, err := os.ReadFile(filepath.Join("..", "..", "docs", "systemd", tc.name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(shipped, tc.embedded) {
			t.Fatalf("internal/kit/%s differs from docs/systemd/%s; edit both", tc.name, tc.name)
		}
	}
	archive, _ := build(t, aSpec(t))
	if !bytes.Equal(fileIn(t, archive, "auu-relay.service").data, unitFile) {
		t.Fatal("the unit in the kit is not the embedded unit")
	}
	script, err := os.ReadFile("install.sh")
	if err != nil {
		t.Fatal(err)
	}
	if got := fileIn(t, archive, "install.sh").data; !bytes.Equal(got, script) || !bytes.Equal(got, installScript) {
		t.Fatal("install.sh in the kit is not the file beside this package, verbatim")
	}
}

// The settings are the template with the four keys set and every other key
// as shipped: the same keys at every level, the four changed, nothing else
// touched, and nothing HTML-escaped.
func TestTheSettingsSetFourKeysAndCarryTheRestAsShipped(t *testing.T) {
	s := aSpec(t)
	s.Listen, s.Registration, s.ClientCerts = "0.0.0.0:8443", "open", "required"
	archive, _ := build(t, s)
	var got, shipped map[string]any
	if err := json.Unmarshal(fileIn(t, archive, "relay.json").data, &got); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(settingsTemplate, &shipped); err != nil {
		t.Fatal(err)
	}
	shipped["listen"] = "0.0.0.0:8443"
	shipped["public_url"] = "https://relay.example.com:8443"
	shipped["registration"] = "open"
	shipped["client_certs"].(map[string]any)["mode"] = "required"
	a, _ := json.Marshal(got)
	b, _ := json.Marshal(shipped)
	if !bytes.Equal(a, b) {
		t.Fatalf("the kit's settings are\n%s\nwant the template with the four keys set:\n%s", a, b)
	}
	if bytes.Contains(fileIn(t, archive, "relay.json").data, []byte(`&`)) {
		t.Fatal("the settings were HTML-escaped")
	}
}

// The README says what someone holding the archive and nothing else needs:
// the host, the architecture, the anchor, the systemd rule, the two ways to
// unpack and which keeps modes, the two commands, what update keeps and
// where the backup goes, the bundle warning word for word, that a sealed
// kit can be run again, and what to delete.
func TestTheREADMEStandsOnItsOwn(t *testing.T) {
	store, anchor := authority(t)
	s := aSpec(t)
	s.Anchor = anchor
	s.Bundle = bundleFor(t, store, s.Hosts)
	s.RelayBinary = fakeELF(elf.ELFCLASS64, elf.ELFOSABI_NONE, elf.EM_AARCH64, false)
	archive, _ := build(t, s)
	readme := string(fileIn(t, archive, "README").data)
	for _, want := range []string{
		"AgentUUCP relay kit for relay.example.com\n",
		"  host           relay.example.com\n",
		"  architecture   linux/arm64\n",
		"  public_url     https://relay.example.com:9443\n",
		"  registration   token\n",
		"  administrators 1\n",
		"  trust anchor   " + anchor + "\n",
		"It was made by auu-ca kit on 2026-09-14.",
		// The plan's paragraph, word for word, and written here rather
		// than taken from the constant, so the constant cannot drift.
		"relay-bundle.json holds the relay's two signing keys in the clear. install.sh\nseals it to this host and deletes it; delete this archive from every machine\nit touched once the relay is up.\n",
		"It needs systemd 250 or later running as PID 1: Debian 12 or 13, Ubuntu 24.04\nor later, Fedora, or RHEL 9 and its rebuilds. The script refuses anything else\nand names the reason.",
		"Unpacking needs `unzip`, which a minimal install does not have (`apt install\nunzip`, or `dnf install unzip`): `unzip -o FILE` keeps every file's mode and\nreplaces a kit already unpacked here without asking;\n`python3 -m zipfile -e FILE .` does not",
		"check every file here against MANIFEST, and it prints each command before\nrunning it.",
		"On a host with no relay:\n\n  sudo sh auu-relay-kit/install.sh\n",
		"On a host that has one, to bring it to what this kit holds, or to repair one\nwhose unit or binary has gone:\n\n  sudo sh auu-relay-kit/install.sh update\n",
		"update stops the relay and copies its database, binary, unit, settings,\nadministrators and credential into /var/lib/auu/backups/<time>/, with a RESTORE\nfile there that says how to put them back; it never puts them back itself.",
		"replaces the settings and the administrators only if\nthey have not been edited since the last kit: an edited file is kept, the kit's\ncopy is written beside it as /etc/auu/relay.json.kit or /etc/auu/admins.kit",
		"A kit whose bundle has already been sealed can be run\nagain; the credential on the host is kept.",
		"delete this directory and the archive it came from, here\nand on the machine that made it: they hold nothing the relay needs now.",
		"  curl https://relay.example.com:9443/v1/health\n",
		"and from an administrator's own machine, pointing it at the relay with the trust\nanchor above, then the check:\n\n  auu relay add https://relay.example.com:9443 --name NAME --anchor " + anchor + "\n  auu-admin status\n",
	} {
		if !strings.Contains(readme, want) {
			t.Fatalf("the README does not say %q; it says:\n%s", want, readme)
		}
	}
	if strings.Contains(readme, "This kit carries no bundle") {
		t.Fatal("a kit with a bundle has the without-bundle paragraph")
	}
}

// Without a bundle the README's bundle paragraph gives way to the two lines
// the operator runs when the bundle arrives.
func TestTheREADMEWithoutABundleGivesTheTwoLines(t *testing.T) {
	s := aSpec(t)
	archive, _ := build(t, s)
	readme := string(fileIn(t, archive, "README").data)
	want := "This kit carries no bundle. install.sh installs everything else and stops short\n" +
		"of starting the relay, printing the two lines that finish the job once the\n" +
		"bundle is on this host, run as root from the directory it landed in:\n\n" +
		"  systemd-creds encrypt --name=relay-bundle relay-bundle.json /etc/auu/relay-bundle.cred\n" +
		"  systemctl enable --now auu-relay\n"
	if !strings.Contains(readme, want) {
		t.Fatalf("the README without a bundle does not say:\n%s\nit says:\n%s", want, readme)
	}
	if strings.Contains(readme, "relay-bundle.json holds the relay's two signing keys") {
		t.Fatal("a kit without a bundle warns about one")
	}
}

// A bundle that is not for this kit is refused: issued for other hosts, or
// under another anchor. auu-ca kit makes both from one store, so this is
// for a caller that did not.
func TestTheBundleMustBeTheKits(t *testing.T) {
	store, anchor := authority(t)
	s := aSpec(t)
	s.Anchor = anchor
	s.Bundle = bundleFor(t, store, []string{"other.example.com"})
	refused(t, s, "the bundle was issued for other.example.com, not relay.example.com")
	s.Bundle = bundleFor(t, store, s.Hosts)
	s.Anchor = "sha256:" + strings.Repeat("1", 64)
	refused(t, s, "the bundle's trust anchor is "+anchor+", not the kit's sha256:"+strings.Repeat("1", 64))
	s.Bundle = []byte("{")
	refused(t, s, "the bundle does not parse")
	s.Anchor = anchor
	s.Bundle = bundleFor(t, store, s.Hosts)
	build(t, s)
}

// Build writes nothing it cannot finish: an error from the writer comes
// back rather than a half-written archive passed off as one.
func TestAWriterThatFailsFailsTheBuild(t *testing.T) {
	_, err := Build(failingWriter{}, aSpec(t))
	if err == nil || !errors.Is(err, errShort) {
		t.Fatalf("Build with a failing writer: %v, want the writer's error", err)
	}
}

var errShort = errors.New("disk full")

type failingWriter struct{}

func (failingWriter) Write(p []byte) (int, error) { return 0, errShort }

// The installer is POSIX sh a stranger is meant to read, and it is proven
// under a real systemd by scripts/kit-check.sh; here, cheaply and on every
// run, it at least parses as sh, and its first lines say what it is.
func TestTheInstallerParsesAsPOSIXSh(t *testing.T) {
	if !bytes.HasPrefix(installScript, []byte("#!/bin/sh\n")) {
		t.Fatalf("install.sh does not begin with #!/bin/sh:\n%.40s", installScript)
	}
	for _, want := range []string{
		"set -eu\n",
		`fail "usage: sh install.sh [update]"`,
		"sha256sum -c --quiet --ignore-missing MANIFEST",
		`fail "run as root: this installs a unit and seals a credential"`,
	} {
		if !bytes.Contains(installScript, []byte(want)) {
			t.Fatalf("install.sh lacks %q", want)
		}
	}
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh on this machine")
	}
	cmd := exec.Command(sh, "-n", "install.sh")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("sh -n install.sh: %v\n%s", err, out)
	}
}

// The kit says what relay it is carrying, read from the binary itself: the
// maker is handed whatever they built, and a hash alone tells an operator
// nothing about what it is. A binary with no build information — not a Go
// binary, or built from a copied tree — has no version, which is a state
// and not a failure: the summary and the README simply say nothing.
func TestTheKitReadsTheRelaysVersion(t *testing.T) {
	s := aSpec(t)
	_, sum := build(t, s)
	if sum.RelayVersion != "" {
		t.Fatalf("a header with no build information has version %q", sum.RelayVersion)
	}
	archive, _ := build(t, s)
	if bytes.Contains(fileIn(t, archive, "README").data, []byte("relay version")) {
		t.Fatal("the README names a version the binary does not carry")
	}

	// A real Go binary, built by the test: its version is carried into the
	// summary and the README. What it says depends on the tree it was
	// built from, so the assertion is that the two agree and neither is
	// empty.
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go is not on the path")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "main.go")
	if err := os.WriteFile(src, []byte("package main\n\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "relay")
	cmd := exec.Command(goTool, "build", "-o", out, "github.com/tropeforce7/agentuucp/cmd/auu-relay")
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")
	if msg, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("go build for linux/amd64: %v\n%s", err, msg)
	}
	bin, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	s.RelayBinary = bin
	archive, sum = build(t, s)
	if sum.RelayVersion == "" {
		t.Fatal("a Go binary's version was not read")
	}
	want := "  relay version  " + sum.RelayVersion + "\n"
	if !bytes.Contains(fileIn(t, archive, "README").data, []byte(want)) {
		t.Fatalf("the README does not say %q", want)
	}
}
