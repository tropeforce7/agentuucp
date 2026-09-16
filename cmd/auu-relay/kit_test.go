package main

import (
	"archive/zip"
	"bytes"
	"debug/elf"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/kit"
)

// A kit's relay.json is the shipped template with four keys set by a
// package that does not know this program's settings type: it decodes the
// template as a JSON object tree so a key the template gains later rides
// through untouched. The proof is on this side: the file the kit writes
// loads through Load with no error, carries the four fields, and carries
// the template's other keys, which the kit does not know, as shipped.
func TestAKitsSettingsLoad(t *testing.T) {
	admin, err := identity.Generate("bunty")
	if err != nil {
		t.Fatal(err)
	}
	var archive bytes.Buffer
	_, err = kit.Build(&archive, kit.Spec{
		Hosts:        []string{"relay.example.com", "10.0.0.5"},
		Listen:       "0.0.0.0:8443",
		Registration: "closed",
		ClientCerts:  "required",
		Admins:       []string{admin.Public().ExportLine()},
		Anchor:       "sha256:0000000000000000000000000000000000000000000000000000000000000000",
		RelayBinary:  staticLinuxELF(),
		Now:          time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	r, err := zip.NewReader(bytes.NewReader(archive.Bytes()), int64(archive.Len()))
	if err != nil {
		t.Fatal(err)
	}
	var settings []byte
	for _, f := range r.File {
		if f.Name == kit.Dir+"/relay.json" {
			rc, err := f.Open()
			if err != nil {
				t.Fatal(err)
			}
			var b bytes.Buffer
			b.ReadFrom(rc)
			rc.Close()
			settings = b.Bytes()
		}
	}
	if settings == nil {
		t.Fatal("no relay.json in the kit")
	}
	path := filepath.Join(t.TempDir(), "relay.json")
	if err := os.WriteFile(path, settings, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, warning, err := Load(path)
	if err != nil || warning != "" {
		t.Fatalf("Load of the kit's settings: %v, warning %q", err, warning)
	}
	if cfg.Listen != "0.0.0.0:8443" || cfg.PublicURL != "https://relay.example.com:8443" ||
		cfg.Registration != "closed" || cfg.ClientCerts.Mode != "required" {
		t.Fatalf("the four fields: listen %q public_url %q registration %q client_certs.mode %q",
			cfg.Listen, cfg.PublicURL, cfg.Registration, cfg.ClientCerts.Mode)
	}
	// The template's other keys, which the kit does not know, as shipped.
	shipped, _, err := Load(filepath.Join("..", "..", "docs", "systemd", "relay.json"))
	if err != nil {
		t.Fatal(err)
	}
	shipped.Listen, shipped.PublicURL, shipped.Registration, shipped.ClientCerts.Mode =
		cfg.Listen, cfg.PublicURL, cfg.Registration, cfg.ClientCerts.Mode
	var a, b bytes.Buffer
	if err := Encode(&a, cfg); err != nil {
		t.Fatal(err)
	}
	if err := Encode(&b, shipped); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Fatalf("the kit's settings loaded as:\n%s\nwant the template with the four fields set:\n%s", a.Bytes(), b.Bytes())
	}
	if cfg.AccessLog != "minimal" || cfg.Admin.TokenMaxAge != "720h" || cfg.TLS.BundleCredential != "relay-bundle" {
		t.Fatalf("a template key the kit does not know did not survive: access_log %q token_max_age %q bundle_credential %q",
			cfg.AccessLog, cfg.Admin.TokenMaxAge, cfg.TLS.BundleCredential)
	}
}

// staticLinuxELF is the header of a static linux/amd64 executable, which is
// all the kit reads of the binary.
func staticLinuxELF() []byte {
	var b bytes.Buffer
	ident := [16]byte{0x7f, 'E', 'L', 'F', byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT), byte(elf.ELFOSABI_NONE)}
	b.Write(ident[:])
	for _, v := range []any{
		uint16(elf.ET_EXEC), uint16(elf.EM_X86_64), uint32(1), uint64(0), uint64(64), uint64(0), uint32(0),
		uint16(64), uint16(56), uint16(0), uint16(64), uint16(0), uint16(0),
	} {
		binary.Write(&b, binary.LittleEndian, v)
	}
	return b.Bytes()
}
