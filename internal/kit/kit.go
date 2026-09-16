// Package kit builds the relay kit: one archive that installs a relay.
//
// A kit is the deployment guide's steps 2 to 7 packed for one host: the
// relay binary the maker cross-compiled, the settings and the administrator
// file written for that host, the systemd unit, the relay's signing bundle,
// and a script that puts them where the guide puts them. This package knows
// nothing about auu-ca's store: it takes a bundle already issued and the
// operator's choices, and writes the archive. The bundle is the relay's two
// signing keys in the clear, so a kit that holds one is a secret and is
// handled as the bundle file is: copied, run, deleted at both ends.
package kit

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/tropeforce7/agentuucp/internal/buildinfo"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/pki"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// The unit and the settings template are copies of docs/systemd/'s, held
// equal to them byte for byte by a test: go:embed cannot reach outside the
// package, and the documents are what an operator reads.

//go:embed auu-relay.service
var unitFile []byte

//go:embed relay.json
var settingsTemplate []byte

//go:embed install.sh
var installScript []byte

// Dir is the one directory every entry of the archive is under.
const Dir = "auu-relay-kit"

// Spec is what a kit is made from.
type Spec struct {
	Hosts        []string  // the bundle's hosts; Hosts[0] is public_url's
	Listen       string    // ":9443"
	Registration string    // open, token, closed
	ClientCerts  string    // off, required
	Admins       []string  // export lines, validated
	Bundle       []byte    // the encoded bundle, or nil for a kit without one
	Anchor       string    // the trust anchor's SPKI hash, for the README
	RelayBinary  []byte    // a static Linux executable for amd64 or arm64
	Now          time.Time // every entry's modification time
}

// Summary is what Build found and wrote, for auu-ca kit to print.
type Summary struct {
	Arch string // amd64 or arm64, read from the binary
	// RelayVersion is what the relay binary was built from, read from the
	// binary itself, and empty for one that carries no build information:
	// not a Go binary, or built from a copied tree. The maker is handed
	// whatever they built, so this says what it is rather than asking.
	RelayVersion string
	Size         int64  // the archive's bytes
	Bundle       bool   // whether the bundle is inside
	Files        []File // every entry, in archive order
}

// File is one entry of the archive: its name under Dir, its size, and its
// SHA-256 as MANIFEST records it.
type File struct {
	Name   string
	Size   int64
	SHA256 string
}

// entry is one file of the kit before it is written.
type entry struct {
	name string
	mode uint32
	data []byte
}

// Check validates a spec without writing anything: every rule Build
// applies, in Build's order, so a caller can refuse a kit before issuing
// the bundle that would go into it. A bundle issued for a kit that was
// then refused would still be a rotation on the store's record.
func Check(s Spec) error {
	_, _, err := validate(s)
	return err
}

// validate is the rules, in order, and what the archive needs from them:
// the listen port and the binary's architecture.
func validate(s Spec) (port int, arch string, err error) {
	if len(s.Hosts) == 0 {
		return 0, "", errors.New("a kit needs a host: the first is what public_url names")
	}
	switch s.Registration {
	case relayapi.RegistrationOpen, relayapi.RegistrationToken, relayapi.RegistrationClosed:
	default:
		return 0, "", fmt.Errorf("registration must be open, token or closed, not %q", s.Registration)
	}
	switch s.ClientCerts {
	case relayapi.ClientCertsOff, relayapi.ClientCertsRequired:
	default:
		return 0, "", fmt.Errorf("client_certs must be off or required, not %q", s.ClientCerts)
	}
	if port, err = listenPort(s.Listen); err != nil {
		return 0, "", err
	}
	if s.Registration == relayapi.RegistrationToken && len(s.Admins) == 0 {
		return 0, "", errors.New("a token relay needs an administrator: --admin LINE, or --registration open")
	}
	admins, err := identity.ParseExportLines("admin", []byte(strings.Join(s.Admins, "\n")))
	if err != nil {
		return 0, "", err
	}
	if s.Registration == relayapi.RegistrationToken && len(admins) == 0 {
		// Every line given was blank or a comment.
		return 0, "", errors.New("a token relay needs an administrator: --admin LINE, or --registration open")
	}
	if arch, err = architecture(s.RelayBinary); err != nil {
		return 0, "", err
	}
	if s.Bundle != nil {
		if err := bundleMatches(s); err != nil {
			return 0, "", err
		}
	}
	return port, arch, nil
}

// Build validates the spec and writes the archive to w.
func Build(w io.Writer, s Spec) (Summary, error) {
	var sum Summary
	port, arch, err := validate(s)
	if err != nil {
		return sum, err
	}
	settings, err := renderSettings(s, port)
	if err != nil {
		return sum, err
	}

	entries := []entry{
		{"README", 0o644, readme(s, arch, port)},
		{"MANIFEST", 0o644, nil}, // filled once the others are known
		{"install.sh", 0o755, installScript},
		{"auu-relay", 0o755, s.RelayBinary},
		{"relay.json", 0o644, settings},
		{"admins", 0o644, adminsFile(s.Admins)},
		{"auu-relay.service", 0o644, unitFile},
	}
	if s.Bundle != nil {
		entries = append(entries, entry{"relay-bundle.json", 0o600, s.Bundle})
	}
	entries[1].data = manifest(entries)

	counted := &countingWriter{w: w}
	zw := zip.NewWriter(counted)
	for _, e := range entries {
		h := &zip.FileHeader{Name: Dir + "/" + e.name, Method: zip.Deflate, Modified: s.Now}
		h.SetMode(fs.FileMode(e.mode))
		f, err := zw.CreateHeader(h)
		if err != nil {
			return sum, err
		}
		if _, err := f.Write(e.data); err != nil {
			return sum, err
		}
		sum.Files = append(sum.Files, File{Name: e.name, Size: int64(len(e.data)), SHA256: hexSum(e.data)})
	}
	if err := zw.Close(); err != nil {
		return sum, err
	}
	sum.Arch, sum.Size, sum.Bundle = arch, counted.n, s.Bundle != nil
	sum.RelayVersion = buildinfo.Of(bytes.NewReader(s.RelayBinary))
	return sum, nil
}

// listenPort is the port of a listen address, which must be host:port with
// a port: the guide's rule that public_url must name the port listen does
// is made true by construction, and that needs the port.
func listenPort(listen string) (int, error) {
	_, portText, err := net.SplitHostPort(listen)
	if err != nil {
		return 0, fmt.Errorf("listen must be host:port with a port, as :9443 is, not %q", listen)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("listen must be host:port with a port, as :9443 is, not %q", listen)
	}
	return port, nil
}

// publicURL is https://, the first host, and the listen port. An IPv6
// address is bracketed, as a URL needs.
func publicURL(host string, port int) string {
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		host = "[" + host + "]"
	}
	return "https://" + host + ":" + strconv.Itoa(port)
}

// bundleMatches checks a bundle against the kit it is going into: issued
// for the kit's hosts, under the kit's anchor. auu-ca kit makes both from
// one store, so this catches a caller that did not.
func bundleMatches(s Spec) error {
	var b pki.Bundle
	if err := json.Unmarshal(s.Bundle, &b); err != nil {
		return fmt.Errorf("the bundle does not parse: %w", err)
	}
	if b.TrustAnchorSPKI != s.Anchor {
		return fmt.Errorf("the bundle's trust anchor is %s, not the kit's %s", b.TrustAnchorSPKI, s.Anchor)
	}
	if strings.Join(b.Hosts, ", ") != strings.Join(s.Hosts, ", ") {
		return fmt.Errorf("the bundle was issued for %s, not %s",
			strings.Join(b.Hosts, ", "), strings.Join(s.Hosts, ", "))
	}
	return nil
}

// renderSettings is the shipped template with listen, public_url,
// registration and client_certs.mode set and every other key as shipped.
// The template is decoded as a JSON object tree rather than into the
// relay's settings type, which is cmd/auu-relay's and stays there, so a
// key the template gains later is carried untouched. Keys come out in
// sorted order, which is the encoder's; the relay reads them in any.
func renderSettings(s Spec, port int) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(settingsTemplate))
	dec.UseNumber()
	var tree map[string]any
	if err := dec.Decode(&tree); err != nil {
		return nil, fmt.Errorf("the settings template does not parse: %w", err)
	}
	tree["listen"] = s.Listen
	tree["public_url"] = publicURL(s.Hosts[0], port)
	tree["registration"] = s.Registration
	certs, ok := tree["client_certs"].(map[string]any)
	if !ok {
		certs = map[string]any{}
	}
	certs["mode"] = s.ClientCerts
	tree["client_certs"] = certs

	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(tree); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// adminsFile is the administrator file: a comment line saying what it is,
// then the lines as given, one per line.
func adminsFile(lines []string) []byte {
	var b strings.Builder
	b.WriteString("# /etc/auu/admins: who may administer this relay, one export line each, as\n")
	b.WriteString("# 'auu id export' prints it. The relay re-reads this file when it changes.\n")
	for _, l := range lines {
		b.WriteString(strings.TrimSpace(l))
		b.WriteString("\n")
	}
	return []byte(b.String())
}

// manifest is sha256sum's format over every entry but itself, in archive
// order, so `sha256sum -c MANIFEST` in the kit's directory checks the lot.
func manifest(entries []entry) []byte {
	var b strings.Builder
	for _, e := range entries {
		if e.name == "MANIFEST" {
			continue
		}
		fmt.Fprintf(&b, "%s  %s\n", hexSum(e.data), e.name)
	}
	return []byte(b.String())
}

func hexSum(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// countingWriter counts what passes through it, for the archive's size.
type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}
