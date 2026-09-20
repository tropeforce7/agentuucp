package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/buildinfo"
	"github.com/tropeforce7/agentuucp/internal/relay"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// credentialConfig is a configuration whose bundle is a systemd credential:
// the bundle sits in a directory under the credential's name, read-only, and
// CREDENTIALS_DIRECTORY names the directory, which is exactly what a unit
// with LoadCredentialEncrypted= gives the relay.
func credentialConfig(t *testing.T, name string) (Config, string) {
	t.Helper()
	dir := t.TempDir()
	creds := t.TempDir()
	written := testBundlePath(t, dir)
	raw, err := os.ReadFile(written)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(creds, name)
	if err := os.WriteFile(path, raw, 0o400); err != nil {
		t.Fatal(err)
	}
	t.Setenv(credentialsDirectoryEnv, creds)
	c := Defaults()
	c.DB = filepath.Join(dir, "relay.db")
	c.TLS.BundleCredential = name
	c.Resolve()
	return c, path
}

// TestBundlePathResolvesACredential: the one place a credential name becomes
// a path, and everything downstream of it — validation, the bundle, the
// listener — works from the file systemd placed.
func TestBundlePathResolvesACredential(t *testing.T) {
	c, want := credentialConfig(t, "relay-bundle")
	if c.TLS.Mode != ModeFiles {
		t.Fatalf("a credential did not imply files mode: %q", c.TLS.Mode)
	}
	got, ok, err := c.BundlePath()
	if err != nil || !ok {
		t.Fatalf("BundlePath = %q, %v, %v", got, ok, err)
	}
	if got != want {
		t.Fatalf("BundlePath = %q, want %q", got, want)
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("a relay with its bundle as a credential does not validate: %v", err)
	}
	parts, err := openBundle(c)
	if err != nil {
		t.Fatal(err)
	}
	if parts == nil {
		t.Fatal("openBundle read nothing from the credential")
	}

	// End to end: the relay serves TLS under the credential's bundle, and a
	// client that pins the bundle's anchor completes a request.
	rcfg, err := relayConfig(c, parts, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	tlsCfg, err := buildTLS(c, parts)
	if err != nil {
		t.Fatal(err)
	}
	st, err := relay.OpenStore(c.DB, c.MessagesDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	srv := httptest.NewUnstartedServer(relay.NewServer(st, rcfg))
	srv.TLS = tlsCfg
	srv.StartTLS()
	t.Cleanup(srv.Close)

	pool := x509.NewCertPool()
	pool.AddCert(parts.loaded.Anchor)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs:    pool,
		ServerName: "relay.example.com",
		MinVersion: tls.VersionTLS13,
	}}}
	resp, err := client.Get(srv.URL + "/v1/trust-anchor")
	if err != nil {
		t.Fatalf("a request over the credential's certificate failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	var anchor relayapi.TrustAnchorResponse
	if err := json.Unmarshal(body, &anchor); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(anchor.TrustAnchor, parts.loaded.Anchor.Raw) {
		t.Fatal("the anchor served is not the credential's")
	}
}

// TestACredentialWithoutACredentialsDirectoryIsRefusedByName: the failure an
// operator will actually hit is a relay started outside its unit, or a unit
// missing the directive, and the message names the directive to add.
func TestACredentialWithoutACredentialsDirectoryIsRefusedByName(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(t *testing.T)
		want string
	}{
		{"unset", func(t *testing.T) {
			t.Setenv(credentialsDirectoryEnv, "")
			os.Unsetenv(credentialsDirectoryEnv)
		}, `tls.bundle_credential is "relay-bundle" but CREDENTIALS_DIRECTORY is not set: ` +
			`the relay is not running under a unit with LoadCredentialEncrypted=relay-bundle:... in it`},
		{"empty", func(t *testing.T) { t.Setenv(credentialsDirectoryEnv, "") },
			`tls.bundle_credential is "relay-bundle" but CREDENTIALS_DIRECTORY is not set: ` +
				`the relay is not running under a unit with LoadCredentialEncrypted=relay-bundle:... in it`},
		{"relative", func(t *testing.T) { t.Setenv(credentialsDirectoryEnv, "run/credentials") },
			`CREDENTIALS_DIRECTORY is "run/credentials", not an absolute path`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.set(t)
			c := Defaults()
			c.DB = filepath.Join(t.TempDir(), "relay.db")
			c.TLS.BundleCredential = "relay-bundle"
			c.Resolve()
			_, _, err := c.BundlePath()
			if err == nil {
				t.Fatal("BundlePath resolved a credential with nowhere to find it")
			}
			if err.Error() != tc.want {
				t.Errorf("BundlePath error is\n %q\nwant\n %q", err, tc.want)
			}
			// And Validate is where the relay hits it.
			if err := c.Validate(); err == nil || err.Error() != tc.want {
				t.Errorf("Validate error is\n %v\nwant\n %q", err, tc.want)
			}
		})
	}
}

// TestAMissingCredentialNamesTheDirectory: the directory is there and the
// credential is not, which is a unit whose LoadCredentialEncrypted= names
// something else. The error names the setting, the credential and the
// directory systemd was supposed to fill.
func TestAMissingCredentialNamesTheDirectory(t *testing.T) {
	creds := t.TempDir()
	t.Setenv(credentialsDirectoryEnv, creds)
	c := Defaults()
	c.DB = filepath.Join(t.TempDir(), "relay.db")
	c.TLS.BundleCredential = "relay-bundle"
	c.Resolve()
	err := c.Validate()
	if err == nil {
		t.Fatal("a credential systemd did not provide was accepted")
	}
	for _, want := range []string{`tls.bundle_credential "relay-bundle"`, creds,
		filepath.Join(creds, "relay-bundle"), "no such file"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
}

func TestBundleAndCredentialTogetherAreRefused(t *testing.T) {
	c, _ := credentialConfig(t, "relay-bundle")
	c.TLS.Bundle = testBundlePath(t, t.TempDir())
	const want = "tls.bundle and tls.bundle_credential both name a bundle; use one"
	if _, _, err := c.BundlePath(); err == nil || err.Error() != want {
		t.Errorf("BundlePath error is\n %v\nwant\n %q", err, want)
	}
	if err := c.Validate(); err == nil || err.Error() != want {
		t.Errorf("Validate error is\n %v\nwant\n %q", err, want)
	}
	// With client certificates required the same message, not "no bundle".
	c.ClientCerts.Mode = relayapi.ClientCertsRequired
	if err := c.Validate(); err == nil || err.Error() != want {
		t.Errorf("with client certificates, Validate error is\n %v\nwant\n %q", err, want)
	}
}

// TestCredentialNameBoundaries: one step either side of the length limit, and
// each character systemd or a unit file would choke on, all through Validate
// with a real bundle behind the accepted names so an acceptance is one.
func TestCredentialNameBoundaries(t *testing.T) {
	const message = "is not a credential name: 1 to 255 printable ASCII characters, no space, slash or colon"
	for _, tc := range []struct {
		label string
		name  string
		ok    bool
	}{
		{"empty", "", false},
		{"one byte", "r", true},
		{"255 bytes", strings.Repeat("r", 255), true},
		{"256 bytes", strings.Repeat("r", 256), false},
		{"a slash", "auu/bundle", false},
		{"dot", ".", false},
		{"dot dot", "..", false},
		{"a space", "relay bundle", false},
		{"a colon", "relay:bundle", false},
		{"a byte over 0x7e", "relay\x7fbundle", false},
		{"a byte outside ASCII", "relay\xc3\xa9", false},
		{"a control character", "relay\tbundle", false},
		{"dots inside a name", "relay.bundle.v2", true},
	} {
		t.Run(tc.label, func(t *testing.T) {
			var c Config
			if tc.ok {
				c, _ = credentialConfig(t, tc.name)
			} else {
				// The refusal must come from the name, not from a missing
				// file, so the directory exists and is otherwise usable.
				t.Setenv(credentialsDirectoryEnv, t.TempDir())
				c = Defaults()
				c.DB = filepath.Join(t.TempDir(), "relay.db")
				c.TLS.BundleCredential = tc.name
				// An empty name is the setting left unset, and files is
				// the mode whether said or not; the refusal is then files
				// with nothing to serve from.
				c.Resolve()
			}
			err := c.Validate()
			if tc.ok && err != nil {
				t.Fatalf("%s was refused: %v", tc.label, err)
			}
			if tc.ok {
				return
			}
			if err == nil {
				t.Fatalf("%s was accepted", tc.label)
			}
			if tc.name == "" {
				// An empty name is no credential at all, and with no bundle
				// either files mode has nothing to serve: the one sentence
				// a bare relay gets.
				if err.Error() != msgNoTLS {
					t.Errorf("error %q, want %q", err, msgNoTLS)
				}
				return
			}
			if !strings.Contains(err.Error(), message) || !strings.Contains(err.Error(), "tls.bundle_credential") {
				t.Errorf("error is\n %q\nwant one containing\n %q", err, message)
			}
		})
	}
}

// TestClientCertsNeedABundleFromEitherSetting: the signing intermediate can
// come from a credential as well as a file, and the refusal names both.
func TestClientCertsNeedABundleFromEitherSetting(t *testing.T) {
	c, _ := credentialConfig(t, "relay-bundle")
	c.Registration = relayapi.RegistrationClosed
	c.ClientCerts.Mode = relayapi.ClientCertsRequired
	if err := c.Validate(); err != nil {
		t.Fatalf("client certificates from a credential were refused: %v", err)
	}
	parts, err := openBundle(c)
	if err != nil {
		t.Fatal(err)
	}
	if parts == nil || parts.policy == nil {
		t.Fatal("no client certificate policy came out of the credential")
	}

	c.TLS.BundleCredential = ""
	c.TLS.CertFile, c.TLS.KeyFile, _ = selfSigned(t, t.TempDir())
	err = c.Validate()
	if err == nil {
		t.Fatal("client certificates were required with no bundle from either setting")
	}
	for _, want := range []string{"tls.bundle", "tls.bundle_credential"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %s", err, want)
		}
	}
}

func TestTheCredentialConfigurationRoundTripsThroughPrintConfig(t *testing.T) {
	c, _ := credentialConfig(t, "relay-bundle")
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	var printed bytes.Buffer
	if err := Encode(&printed, c.Redacted()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(printed.String(), `"bundle_credential": "relay-bundle"`) {
		t.Fatalf("--print-config does not show the credential:\n%s", printed.String())
	}
	path := filepath.Join(t.TempDir(), "relay.json")
	if err := os.WriteFile(path, printed.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	back, err := resolve(t, path)
	if err != nil {
		t.Fatalf("a printed configuration does not load again: %v", err)
	}
	if back.TLS != c.TLS {
		t.Errorf("tls did not survive:\n got %+v\nwant %+v", back.TLS, c.TLS)
	}
	// And the flag reaches the setting, without disturbing a file's value
	// when it is not typed.
	flagged, err := resolve(t, "", "--db", filepath.Join(t.TempDir(), "relay.db"),
		"--tls-bundle-credential", "relay-bundle")
	if err != nil {
		t.Fatalf("--tls-bundle-credential: %v", err)
	}
	if flagged.TLS.BundleCredential != "relay-bundle" || flagged.TLS.Mode != ModeFiles {
		t.Errorf("the flag gave %+v", flagged.TLS)
	}
}

// TestTheShippedUnitAndSettingsNameTheSameCredential is the test that fails
// when somebody renames the credential in one file and not the other.
func TestTheShippedUnitAndSettingsNameTheSameCredential(t *testing.T) {
	unit, err := os.ReadFile(filepath.Join("..", "..", "docs", "systemd", "auu-relay.service"))
	if err != nil {
		t.Fatal(err)
	}
	var loaded []string
	for _, line := range strings.Split(string(unit), "\n") {
		if after, ok := strings.CutPrefix(strings.TrimSpace(line), "LoadCredentialEncrypted="); ok {
			id, _, _ := strings.Cut(after, ":")
			loaded = append(loaded, id)
		}
	}
	if len(loaded) != 1 {
		t.Fatalf("the shipped unit has %d LoadCredentialEncrypted= lines, want 1: %v", len(loaded), loaded)
	}
	cfg, _, err := Load(filepath.Join("..", "..", "docs", "systemd", "relay.json"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TLS.BundleCredential != loaded[0] {
		t.Fatalf("relay.json names credential %q and auu-relay.service loads %q",
			cfg.TLS.BundleCredential, loaded[0])
	}
	if !validCredentialName(loaded[0]) {
		t.Fatalf("the shipped credential name %q would be refused", loaded[0])
	}
}

// TestStartupLogsWhereTheBundleCameFrom: an operator checking that the
// credential is in use greps the journal for bundle_source; and the same
// line leads with the version the binary was built from and the schema
// it speaks, before the address, since a journal is what an operator has
// when asking which relay is running.
func TestStartupLogsWhereTheBundleCameFrom(t *testing.T) {
	fromCredential, credPath := credentialConfig(t, "relay-bundle")
	fromFile := Defaults()
	fromFile.DB = filepath.Join(t.TempDir(), "relay.db")
	fromFile.TLS.Bundle = testBundlePath(t, t.TempDir())
	fromFile.Resolve()
	for _, tc := range []struct {
		name string
		cfg  Config
		want string
		path string
	}{
		{"credential", fromCredential, "bundle_source=credential", credPath},
		{"file", fromFile, "bundle_source=file", fromFile.TLS.Bundle},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			logStartup(tc.cfg, nil, slog.New(slog.NewTextHandler(&logs, nil)))
			if !strings.Contains(logs.String(), tc.want) {
				t.Errorf("startup log does not say %s:\n%s", tc.want, logs.String())
			}
			if !strings.Contains(logs.String(), "cert="+tc.path) {
				t.Errorf("startup log does not name the bundle's path %s:\n%s", tc.path, logs.String())
			}
			assertStartingLine(t, logs.String(), "tls=files")
		})
	}
}

// assertStartingLine holds the "relay starting" line to its first fields:
// the version, which is whatever the tree this test binary was built from
// says and never empty, then the schema, then the address, then the TLS
// mode given.
func assertStartingLine(t *testing.T, logs, tls string) {
	t.Helper()
	line := regexp.MustCompile(`msg="relay starting" version=(\S+) schema=(\d+) addr=\S+ ` + regexp.QuoteMeta(tls) + ` `).FindStringSubmatch(logs)
	if line == nil {
		t.Fatalf("the starting line does not lead with version, schema, addr and %s:\n%s", tls, logs)
	}
	if line[1] != buildinfo.Version() {
		t.Errorf("the starting line says version %s, want %s", line[1], buildinfo.Version())
	}
	if line[2] != strconv.Itoa(relay.SchemaVersion) {
		t.Errorf("the starting line says schema %s, want %d", line[2], relay.SchemaVersion)
	}
}

// TestStartupLogsTheVersionWithTLSOff: the other branch of the starting
// line, for a relay serving plain HTTP, leads with the same two fields.
func TestStartupLogsTheVersionWithTLSOff(t *testing.T) {
	cfg := Defaults()
	cfg.DB = filepath.Join(t.TempDir(), "relay.db")
	cfg.TLS.Mode = ModeOff
	cfg.Resolve()
	var logs bytes.Buffer
	logStartup(cfg, nil, slog.New(slog.NewTextHandler(&logs, nil)))
	assertStartingLine(t, logs.String(), "tls=off")
}
