package main

import (
	"bytes"
	"crypto/mldsa"
	"flag"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/pki"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// resolve runs the same pipeline main does: defaults, file, typed flags —
// with one thing added. A relay that says nothing about TLS is refused at
// validation, since TLS is the default and there is nothing to serve it
// from; the tests here are about every other setting, and want the plain
// relay a person testing on one machine runs. So a call whose args and
// file say nothing about TLS gets `--tls-mode off` put in front, exactly
// as that person types it. A test about TLS says what it means, and
// resolveBare is the same pipeline with nothing added.
func resolve(t *testing.T, file string, args ...string) (Config, error) {
	t.Helper()
	if !mentionsTLS(t, file, args) {
		args = append([]string{"--tls-mode", "off"}, args...)
	}
	return resolveBare(t, file, args...)
}

// resolveBare is resolve with nothing added: what main does, and nothing
// else.
func resolveBare(t *testing.T, file string, args ...string) (Config, error) {
	t.Helper()
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	f := registerFlags(fs)
	if file != "" {
		args = append([]string{"--config", file}, args...)
	}
	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}
	cfg, _, err := resolveConfig(fs, f)
	return cfg, err
}

// mentionsTLS says whether a test's args or file set anything under tls.
func mentionsTLS(t *testing.T, file string, args []string) bool {
	t.Helper()
	for _, a := range args {
		if strings.HasPrefix(a, "--tls-") {
			return true
		}
	}
	if file == "" {
		return false
	}
	data, err := os.ReadFile(file)
	if err != nil {
		// A file that is not there is the test's own point; the pipeline
		// says so, and nothing is added to what it says.
		return true
	}
	return strings.Contains(string(data), `"tls"`)
}

// merged runs the pipeline but stops before validation, for cases that are
// deliberately invalid.
func merged(t *testing.T, file string, args ...string) (Config, string, error) {
	t.Helper()
	if !mentionsTLS(t, file, args) {
		args = append([]string{"--tls-mode", "off"}, args...)
	}
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	f := registerFlags(fs)
	if file != "" {
		args = append([]string{"--config", file}, args...)
	}
	if err := fs.Parse(args); err != nil {
		return Config{}, "", err
	}
	cfg, warning, err := Load(f.config)
	if err != nil {
		return cfg, warning, err
	}
	cfg.Merge(fs, f)
	cfg.Resolve()
	return cfg, warning, nil
}

func writeFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "relay.json")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDefaultsAlone(t *testing.T) {
	cfg, err := resolve(t, "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != ":8080" {
		t.Fatalf("listen %q", cfg.Listen)
	}
	if cfg.DB != "relay.db" {
		t.Fatalf("db %q", cfg.DB)
	}
	if cfg.MaxBytes != relayapi.DefaultMaxBytes {
		t.Fatalf("max_bytes %d", cfg.MaxBytes)
	}
	if cfg.TLS.Mode != ModeOff {
		t.Fatalf("mode %q, expected off when the test helper said so", cfg.TLS.Mode)
	}
	if cfg.Registration != relayapi.RegistrationOpen {
		t.Fatalf("registration %q, want open by default", cfg.Registration)
	}
	// And with nothing said at all: TLS is the default, and there is
	// nothing to serve it from, so the relay refuses in the one sentence a
	// person who ran it bare will read.
	_, err = resolveBare(t, "")
	if err == nil || err.Error() != msgNoTLS {
		t.Fatalf("nothing configured gave %v, want %q", err, msgNoTLS)
	}
}

// The precedence rule that is easiest to get wrong: a flag the operator did
// not type must not clobber the file with its own default.
func TestUntypedFlagDoesNotOverrideFile(t *testing.T) {
	// knock_max_bytes beside a max_bytes under its default, as the
	// refusal of the pair asks.
	file := writeFile(t, `{"listen": ":8443", "db": "from-file.db", "max_bytes": 4096, "limits": {"knock_max_bytes": 0}}`)

	cfg, err := resolve(t, file)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != ":8443" {
		t.Fatalf("listen %q: the --listen default overwrote the file", cfg.Listen)
	}
	// A relative path in the file is resolved against the file's directory.
	if cfg.DB != filepath.Join(filepath.Dir(file), "from-file.db") {
		t.Fatalf("db %q: the --db default overwrote the file", cfg.DB)
	}
	if cfg.MaxBytes != 4096 {
		t.Fatalf("max_bytes %d: the --max-bytes default overwrote the file", cfg.MaxBytes)
	}

	// And a flag that IS typed wins.
	cfg, err = resolve(t, file, "--listen", ":9999")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != ":9999" {
		t.Fatalf("listen %q: typed flag did not win", cfg.Listen)
	}
	if cfg.DB != filepath.Join(filepath.Dir(file), "from-file.db") {
		t.Fatalf("db %q: an unrelated typed flag disturbed the file value", cfg.DB)
	}
}

func TestUnknownKeyIsAnError(t *testing.T) {
	file := writeFile(t, `{"lissen": ":8443"}`)
	_, _, err := merged(t, file)
	if err == nil {
		t.Fatal("an unknown key was accepted")
	}
	if !strings.Contains(err.Error(), "lissen") {
		t.Fatalf("error should name the unknown key, got: %v", err)
	}
}

func TestMalformedJSONNamesTheFile(t *testing.T) {
	file := writeFile(t, `{"listen": ":8443"`)
	_, _, err := merged(t, file)
	if err == nil {
		t.Fatal("malformed JSON was accepted")
	}
	if !strings.Contains(err.Error(), file) {
		t.Fatalf("error should name the file, got: %v", err)
	}
}

func TestMissingFileIsAnError(t *testing.T) {
	if _, _, err := merged(t, filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Fatal("a missing config file was accepted")
	}
}

func TestRedacted(t *testing.T) {
	// Nothing in the configuration is secret today: the static invite token
	// this test used to guard was replaced by signed enrolment tokens, which
	// the relay never holds. Redacted stays as the hook for the next one, and
	// what it prints must still round trip.
	cfg := Defaults()
	cfg.PublicURL = "https://relay.example.com"
	var buf bytes.Buffer
	if err := Encode(&buf, cfg.Redacted()); err != nil {
		t.Fatal(err)
	}
	round := writeFile(t, buf.String())
	back, _, err := Load(round)
	if err != nil {
		t.Fatalf("printed config does not load back: %v", err)
	}
	if back.PublicURL != cfg.PublicURL || back.Registration != cfg.Registration {
		t.Fatalf("printed config did not round trip: %+v", back)
	}
}

func TestWorldWritableConfigWarns(t *testing.T) {
	p := filepath.Join(t.TempDir(), "relay.json")
	if err := os.WriteFile(p, []byte(`{"registration":"closed"}`), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o666); err != nil {
		t.Fatal(err)
	}
	_, warning, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if warning == "" || !strings.Contains(warning, p) {
		t.Fatalf("expected a permissions warning naming the file, got %q", warning)
	}

	// A file only its owner can write warns about nothing.
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, warning, _ := Load(p); warning != "" {
		t.Fatalf("unexpected warning for a 0644 file: %q", warning)
	}
}

// TestFileAloneSetsEveryKey pins that a configuration file, with no flags at
// all, reaches every setting. A key that silently did nothing would be worse
// than one that was rejected.
func TestFileAloneSetsEveryKey(t *testing.T) {
	dir := t.TempDir()
	bundle := testBundlePath(t, dir)
	path := filepath.Join(dir, "relay.json")
	body := `{
	  "listen": ":9443",
	  "db": "` + filepath.Join(dir, "relay.db") + `",
	  "max_bytes": 1048576,
	  "registration": "token",
	  "public_url": "https://relay.example.com",
	  "access_log": "minimal",
	  "admin": {"authorized_file": "` + adminFilePath(t, dir) + `", "token_max_age": "24h"},
	  "client_certs": {"mode": "required", "lifetime": "720h"},
	  "tls": {"mode": "files", "bundle": "` + bundle + `"}
	}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	f := registerFlags(fs)
	if err := fs.Parse([]string{"--config", path}); err != nil {
		t.Fatal(err)
	}
	cfg, _, err := resolveConfig(fs, f)
	if err != nil {
		t.Fatalf("resolving: %v", err)
	}
	for _, tc := range []struct{ name, got, want string }{
		{"listen", cfg.Listen, ":9443"},
		{"registration", cfg.Registration, "token"},
		{"public_url", cfg.PublicURL, "https://relay.example.com"},
		{"access_log", cfg.AccessLog, "minimal"},
		{"tls mode", cfg.TLS.Mode, ModeFiles},
		{"tls bundle", cfg.TLS.Bundle, bundle},
		{"client certs", cfg.ClientCerts.Mode, "required"},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %q, want %q", tc.name, tc.got, tc.want)
		}
	}
	if cfg.MaxBytes != 1<<20 {
		t.Errorf("max_bytes = %d, want 1 MiB", cfg.MaxBytes)
	}
}

// TestFlagsAlone is the same for the command line.
func TestFlagsAlone(t *testing.T) {
	dir := t.TempDir()
	bundle := testBundlePath(t, dir)
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	f := registerFlags(fs)
	if err := fs.Parse([]string{
		"--listen", ":9443",
		"--db", filepath.Join(dir, "relay.db"),
		"--registration", "closed",
		"--access-log", "minimal",
		"--tls-bundle", bundle,
		"--client-certs", "required",
	}); err != nil {
		t.Fatal(err)
	}
	cfg, _, err := resolveConfig(fs, f)
	if err != nil {
		t.Fatalf("resolving: %v", err)
	}
	if cfg.Listen != ":9443" || cfg.Registration != "closed" || cfg.AccessLog != "minimal" {
		t.Errorf("flags not applied: %+v", cfg)
	}
	if cfg.TLS.Bundle != bundle || cfg.TLS.Mode != ModeFiles {
		t.Errorf("a bundle did not imply files mode: %q %q", cfg.TLS.Bundle, cfg.TLS.Mode)
	}
	if cfg.ClientCerts.Mode != "required" {
		t.Errorf("client_certs mode = %q, want required", cfg.ClientCerts.Mode)
	}
}

// TestModeInference pins what an unset tls.mode becomes: files, whatever
// else is set, because a relay serves TLS unless somebody writes down that
// it does not. Nothing is inferred from a bundle or a certificate any more;
// what they decide is whether files has something to serve from, which is
// TestValidation's. Off is off only when said, on the command line or in
// the file, and a flag over a file that says nothing is the flag.
func TestModeInference(t *testing.T) {
	dir := t.TempDir()
	bundle := testBundlePath(t, dir)
	for _, tc := range []struct {
		name string
		file string
		args []string
		want string
	}{
		{"nothing", "", nil, ModeFiles},
		{"a bundle", "", []string{"--tls-bundle", bundle}, ModeFiles},
		{"a certificate", "", []string{"--tls-cert", "c.pem", "--tls-key", "k.pem"}, ModeFiles},
		{"explicit off", "", []string{"--tls-mode", "off"}, ModeOff},
		{"off in the file", `{"tls": {"mode": "off"}}`, nil, ModeOff},
		{"off on the line over a file that says nothing", `{"listen": ":9"}`, []string{"--tls-mode", "off"}, ModeOff},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := flag.NewFlagSet("test", flag.ContinueOnError)
			f := registerFlags(fs)
			args := append([]string{"--db", filepath.Join(t.TempDir(), "relay.db")}, tc.args...)
			if tc.file != "" {
				args = append([]string{"--config", writeFile(t, tc.file)}, args...)
			}
			if err := fs.Parse(args); err != nil {
				t.Fatal(err)
			}
			cfg, _, err := Load(f.config)
			if err != nil {
				t.Fatal(err)
			}
			cfg.Merge(fs, f)
			cfg.Resolve()
			if cfg.TLS.Mode != tc.want {
				t.Errorf("mode = %q, want %q", cfg.TLS.Mode, tc.want)
			}
		})
	}
}

// TestValidation is the refusals an operator can actually hit, each with the
// words they will read.
func TestValidation(t *testing.T) {
	dir := t.TempDir()
	bundle := testBundlePath(t, dir)
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"files with neither", []string{"--tls-mode", "files"}, msgNoTLS},
		{"nothing at all", nil, msgNoTLS},
		{"files with a certificate and no key", []string{"--tls-cert", "c.pem"}, "both a certificate file and a key file"},
		{"off with a bundle", []string{"--tls-mode", "off", "--tls-bundle", bundle}, "off but tls.bundle names a bundle"},
		{"a bundle and a certificate", []string{"--tls-bundle", bundle, "--tls-cert", "c.pem", "--tls-key", "k.pem"},
			"not both"},
		{"off with a certificate", []string{"--tls-mode", "off", "--tls-cert", "c.pem"}, "off but a certificate"},
		{"an unknown mode", []string{"--tls-mode", "acme"}, "must be"},
		{"client certs with no bundle", []string{"--client-certs", "required", "--tls-cert", "c.pem", "--tls-key", "k.pem"},
			"tls.bundle"},
		{"bad registration", []string{"--registration", "sometimes"}, "registration must be"},
		{"bad access log", []string{"--access-log", "loud"}, "access_log must be"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := flag.NewFlagSet("test", flag.ContinueOnError)
			f := registerFlags(fs)
			args := append([]string{"--db", filepath.Join(t.TempDir(), "relay.db")}, tc.args...)
			if err := fs.Parse(args); err != nil {
				t.Fatal(err)
			}
			_, _, err := resolveConfig(fs, f)
			if err == nil {
				t.Fatalf("%s was accepted", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not contain %q", err, tc.want)
			}
		})
	}
}

// testBundlePath writes a real auu-ca bundle for relay.example.com and
// returns its path. Tests use the same thing a relay is given, so a bundle
// that would not load fails here rather than in a way that looks like a
// configuration bug.
func testBundlePath(t *testing.T, dir string) string {
	t.Helper()
	return testBundleFor(t, dir, "relay.example.com")
}

// testBundleFor writes a real auu-ca bundle issued for the given hosts.
func testBundleFor(t *testing.T, dir string, hosts ...string) string {
	t.Helper()
	store := pki.TestStore(t, mldsa.MLDSA65())
	b, err := store.IssueRelay(hosts, 1, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "bundle.json")
	if err := pki.WriteBundle(path, b); err != nil {
		t.Fatal(err)
	}
	return path
}

// A bundle is issued for the hosts the relay answers to, and its certificate
// is minted for them; public_url is the name tokens carry and machines
// connect by. When the two disagree the relay would start and every machine
// would then be refused with Go's hostname error, so the disagreement is a
// refusal at start, and --print-config, which runs the same validation,
// refuses the same way.
func TestABundleForAnotherHostIsRefused(t *testing.T) {
	const refusal = "public_url names relay.example.com but the bundle was issued for other.example.com: " +
		"run 'auu-ca relay --host relay.example.com' on the offline machine and deliver that bundle, or fix public_url"
	other := testBundleFor(t, t.TempDir(), "other.example.com")
	two := testBundleFor(t, t.TempDir(), "a.example.com", "b.example.com")
	v4 := testBundleFor(t, t.TempDir(), "127.0.0.1")
	v6 := testBundleFor(t, t.TempDir(), "::1")
	for _, tc := range []struct {
		name   string
		bundle string
		public string
		want   string // "" accepts; otherwise the error must contain it
	}{
		{"another host", other, "https://relay.example.com", refusal},
		{"another host with a port", other, "https://relay.example.com:9443", refusal},
		{"the bundle's host", other, "https://other.example.com", ""},
		{"the bundle's host with a port", other, "https://other.example.com:9443", ""},
		{"no public_url", other, "", ""},
		// The verifier compares names without regard to case or a trailing dot.
		{"the bundle's host in another case", other, "https://OTHER.Example.COM", ""},
		{"the bundle's host with a trailing dot", other, "https://other.example.com.", ""},
		{"another host with a trailing dot", other, "https://relay.example.com.", refusal},
		{"a subdomain of the bundle's host", other, "https://www.other.example.com",
			"public_url names www.other.example.com but the bundle was issued for other.example.com"},
		{"one of two hosts", two, "https://b.example.com", ""},
		{"neither of two hosts", two, "https://c.example.com",
			"public_url names c.example.com but the bundle was issued for a.example.com, b.example.com: " +
				"run 'auu-ca relay --host c.example.com'"},
		// Addresses are compared as addresses, so the form does not matter.
		{"the bundle's address", v4, "https://127.0.0.1:9443", ""},
		{"the bundle's address, IPv4-mapped", v4, "https://[::ffff:127.0.0.1]:9443", ""},
		{"another address", v4, "https://127.0.0.2:9443",
			"public_url names 127.0.0.2 but the bundle was issued for 127.0.0.1"},
		{"a name against an address", v4, "https://relay.example.com",
			"public_url names relay.example.com but the bundle was issued for 127.0.0.1"},
		{"the bundle's IPv6 address", v6, "https://[::1]:9443", ""},
		{"the bundle's IPv6 address, written long", v6, "https://[0:0:0:0:0:0:0:1]:9443", ""},
		{"another IPv6 address", v6, "https://[::2]:9443",
			"public_url names ::2 but the bundle was issued for ::1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := []string{"--db", filepath.Join(t.TempDir(), "relay.db"), "--tls-bundle", tc.bundle}
			if tc.public != "" {
				args = append(args, "--public-url", tc.public)
			}
			_, err := resolve(t, "", args...)
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("refused: %v", err)
			case tc.want != "" && err == nil:
				t.Fatalf("accepted public_url %q with a bundle for another host", tc.public)
			case tc.want != "" && !strings.Contains(err.Error(), tc.want):
				t.Fatalf("error %q does not contain %q", err, tc.want)
			}
			if tc.want == refusal && err.Error() != refusal {
				t.Fatalf("the sentence is %q, want it exactly", err)
			}
		})
	}
}

// adminFilePath writes a file with one administrator in it.
func adminFilePath(t *testing.T, dir string) string {
	t.Helper()
	id, err := identity.Generate("boss")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "admins")
	if err := os.WriteFile(path, []byte(id.Public().ExportLine()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// An editor that saves "as UTF-8" may put a byte order mark at the front,
// which JSON has no place for. Go names it as the character it is, \ufeff,
// which tells a person nothing; the relay names what happened and what to
// do. The container suite's R03 found the \ufeff.
func TestABOMIsNamed(t *testing.T) {
	path := writeFile(t, "\xef\xbb\xbf{\"listen\": \":9443\"}")
	_, _, err := Load(path)
	if err == nil {
		t.Fatal("a file beginning with a byte order mark was accepted")
	}
	want := path + " begins with a byte order mark, three invisible bytes an editor put there; save it as plain UTF-8"
	if err.Error() != want {
		t.Fatalf("error %q, want %q", err, want)
	}
	// Without the mark the same file loads.
	if _, _, err := Load(writeFile(t, "{\"listen\": \":9443\"}")); err != nil {
		t.Fatalf("the file without the mark was refused: %v", err)
	}
}

// A comma after the last item is the commonest thing a person types wrong
// in a settings file, and Go reports the brace that followed it. The relay
// keeps Go's reason and adds the mistake. The container suite's R03c found
// the brace.
func TestATrailingCommaIsNamed(t *testing.T) {
	const hint = ": the comma after the last item is one too many"
	for _, tc := range []struct {
		name, body string
		hinted     bool
	}{
		{"a comma before the closing brace", "{\"listen\": \":9443\",\n}", true},
		{"a comma and spaces before the brace", "{\"listen\": \":9443\", }", true},
		{"a comma before a closing bracket", "{\"limits\": {\"requests_per_minute\": 1,}}", true},
		{"a comma with CRLF before the brace", "{\"listen\": \":9443\",\r\n}", true},
		// The same character stopped the decoder, but no comma put it there.
		{"a brace after a key", "{\"listen\" }", false},
		{"a brace after a colon", "{\"listen\": }", false},
		{"a double comma", "{\"listen\": \":9443\",,}", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := Load(writeFile(t, tc.body))
			if err == nil {
				t.Fatalf("%q was accepted", tc.body)
			}
			if !strings.Contains(err.Error(), "malformed JSON at byte") {
				t.Fatalf("error %q is not the syntax refusal", err)
			}
			if got := strings.HasSuffix(err.Error(), hint); got != tc.hinted {
				t.Fatalf("error %q: hinted %v, want %v", err, got, tc.hinted)
			}
		})
	}
}
