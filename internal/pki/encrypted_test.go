package pki

import (
	"bytes"
	"crypto/mldsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/keyfile"
)

// keyFiles is every private key file in a store.
var keyFiles = []string{anchorKeyFile, serverKeyFile, clientKeyFile}

// needle is how much of a key's base64 a leak test searches for. A PEM line
// is 64 characters, so anything longer than that spans a newline and would
// not be found in the control either.
const needle = 48

// TestTheKeyFilesHoldNoKey is the point of the whole change: what a backup or
// a stolen disk yields.
//
// It asserts an absence, so it first proves the search can find the key when
// it is there. Without that, a search comparing the wrong encodings would
// pass however badly the files leaked, which is a mistake this project has
// made once already.
func TestTheKeyFilesHoldNoKey(t *testing.T) {
	dir := t.TempDir()
	s, err := Create(dir, "Test", mldsa.MLDSA65(), keyfile.TestPassphrase(testSecret), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for i, name := range keyFiles {
		key := []*Key{s.Anchor, s.Server, s.Client}[i].Key
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		// The control: this is what the file used to be. The needle is a
		// prefix of the base64 short enough to sit inside one PEM line,
		// because PEM breaks every 64 characters and a longer needle would
		// never be found however badly a file leaked.
		plain := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		body := pemBody(t, plain)
		if len(body) < needle {
			t.Fatalf("%s: the key's base64 is only %d characters", name, len(body))
		}
		start := []byte(body[:needle])
		if !bytes.Contains(plain, start) {
			t.Fatalf("%s: the control is not searchable, so this test could not fail", name)
		}

		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if !keyfile.IsEncrypted(raw) {
			t.Errorf("%s is not encrypted", name)
		}
		if bytes.Contains(raw, der) {
			t.Errorf("%s holds the raw key", name)
		}
		if bytes.Contains(raw, start) {
			t.Errorf("%s holds the start of the key's base64", name)
		}
		if bytes.Contains(raw, []byte(testSecret)) {
			t.Errorf("%s holds the passphrase", name)
		}
	}
}

func pemBody(t *testing.T, encoded []byte) string {
	t.Helper()
	body := strings.ReplaceAll(string(encoded), "\n", "")
	body = strings.TrimPrefix(body, "-----BEGIN PRIVATE KEY-----")
	return strings.TrimSuffix(body, "-----END PRIVATE KEY-----")
}

func TestCreateRefusesAnEmptyPassphrase(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	_, err := Create(dir, "Test", mldsa.MLDSA65(), keyfile.Passphrase{}, time.Now())
	if !errors.Is(err, keyfile.ErrEmptyPassphrase) {
		t.Fatalf("Create with no passphrase gave %v, want ErrEmptyPassphrase", err)
	}
	// And it wrote nothing: an authority whose keys nobody can open is
	// worse than no authority.
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a directory was left behind: %v", err)
	}
}

func TestOpenRefusesTheWrongPassphrase(t *testing.T) {
	dir := t.TempDir()
	if _, err := Create(dir, "Test", mldsa.MLDSA65(), keyfile.TestPassphrase(testSecret), time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		secret []byte
		want   error
	}{
		{"a wrong one", []byte("not the passphrase"), keyfile.ErrPassphrase},
		{"one character short", []byte(testSecret[:len(testSecret)-1]), keyfile.ErrPassphrase},
		{"none at all", nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Open(dir, tc.secret)
			if err == nil {
				t.Fatal("an encrypted authority opened")
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("error is %v, want %v", err, tc.want)
			}
			// Whichever it was, it names the file, so an operator with a
			// half-converted directory knows which one refused them.
			if !strings.Contains(err.Error(), anchorKeyFile) {
				t.Errorf("error %q does not name the file", err)
			}
		})
	}
	// And the right one works.
	if _, err := Open(dir, []byte(testSecret)); err != nil {
		t.Fatalf("the right passphrase was refused: %v", err)
	}
}

// TestOpenLockedReadsCertificatesAndNoKey is what lets show run without ever
// asking for a passphrase.
func TestOpenLockedReadsCertificatesAndNoKey(t *testing.T) {
	dir := t.TempDir()
	made, err := Create(dir, "Test", mldsa.MLDSA65(), keyfile.TestPassphrase(testSecret), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	s, err := OpenLocked(dir)
	if err != nil {
		t.Fatalf("OpenLocked: %v", err)
	}
	if !s.Locked() {
		t.Error("the store does not report itself locked")
	}
	for i, k := range []*Key{s.Anchor, s.Server, s.Client} {
		if k.Key != nil {
			t.Errorf("%s came back with a private key", keyFiles[i])
		}
		if k.Cert == nil {
			t.Fatalf("%s came back with no certificate", keyFiles[i])
		}
	}
	// Everything show prints is there.
	if SPKI(s.Anchor.Cert) != SPKI(made.Anchor.Cert) {
		t.Error("the anchor's hash is not the one that was made")
	}
	if ParameterNumberOf(s.Params) != 65 {
		t.Errorf("the parameter set came back %d; it must come from the certificate", ParameterNumberOf(s.Params))
	}
	// And it can issue nothing, rather than panicking on a nil key.
	_, err = s.IssueRelay([]string{"relay.example.com"}, 1, time.Now())
	if err == nil {
		t.Fatal("a locked authority issued a bundle")
	}
	if !strings.Contains(err.Error(), "without its passphrase") {
		t.Errorf("error %q does not say why", err)
	}
}

func TestSetPassphraseChangesWhatOpensIt(t *testing.T) {
	dir := t.TempDir()
	if _, err := Create(dir, "Test", mldsa.MLDSA65(), keyfile.TestPassphrase(testSecret), time.Now()); err != nil {
		t.Fatal(err)
	}
	certsBefore := readAll(t, dir, anchorCertFile, serverCertFile, clientCertFile)
	keysBefore := readAll(t, dir, keyFiles...)

	const fresh = "a different passphrase"
	if err := SetPassphrase(dir, []byte(testSecret), keyfile.TestPassphrase(fresh)); err != nil {
		t.Fatalf("SetPassphrase: %v", err)
	}
	if _, err := Open(dir, []byte(testSecret)); !errors.Is(err, keyfile.ErrPassphrase) {
		t.Errorf("the old passphrase still opens it: %v", err)
	}
	s, err := Open(dir, []byte(fresh))
	if err != nil {
		t.Fatalf("the new passphrase does not open it: %v", err)
	}
	if s.Locked() {
		t.Error("the store reports itself locked")
	}
	// The certificates are untouched, byte for byte: only the keys were
	// rewritten, and a hash somebody pinned must not move.
	for name, was := range certsBefore {
		if now := readAll(t, dir, name)[name]; !bytes.Equal(was, now) {
			t.Errorf("%s changed", name)
		}
	}
	// Every key file is different, because each has a fresh salt.
	for name, was := range keysBefore {
		if now := readAll(t, dir, name)[name]; bytes.Equal(was, now) {
			t.Errorf("%s was not rewritten", name)
		}
	}
	// And it still works: the keys inside are the same ones.
	if _, err := s.IssueRelay([]string{"relay.example.com"}, 1, time.Now()); err != nil {
		t.Errorf("issuing after a passphrase change: %v", err)
	}
	// Nothing was left staged.
	for _, name := range keyFiles {
		if _, err := os.Stat(filepath.Join(dir, name+".new")); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s.new was left behind", name)
		}
	}
}

func TestSetPassphraseRefusesAnEmptyOne(t *testing.T) {
	dir := t.TempDir()
	if _, err := Create(dir, "Test", mldsa.MLDSA65(), keyfile.TestPassphrase(testSecret), time.Now()); err != nil {
		t.Fatal(err)
	}
	before := readAll(t, dir, keyFiles...)
	if err := SetPassphrase(dir, []byte(testSecret), keyfile.Passphrase{}); !errors.Is(err, keyfile.ErrEmptyPassphrase) {
		t.Fatalf("SetPassphrase to nothing gave %v", err)
	}
	for name, was := range before {
		if now := readAll(t, dir, name)[name]; !bytes.Equal(was, now) {
			t.Errorf("%s was rewritten by a refused change", name)
		}
	}
}

// TestADirectoryFromBeforeEncryptionIsRefusedByName: a key file written
// before auu-ca encrypted them is a plain "PRIVATE KEY" block, and nothing
// on this machine is from before. Open and OpenLocked refuse it naming the
// file and saying to re-create the authority, whether all three files are
// plain or one is — the one being what an interrupted change to the
// encrypted form would once have left — and with any passphrase or none;
// SetPassphrase, which opens first, refuses the same way, so there is no
// encrypting it in place; and the files are not touched.
func TestADirectoryFromBeforeEncryptionIsRefusedByName(t *testing.T) {
	made := t.TempDir()
	s, err := Create(made, "Test", mldsa.MLDSA65(), keyfile.TestPassphrase(testSecret), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		plain []string
		named string
	}{
		{"all three", keyFiles, anchorKeyFile},
		{"the server CA alone", []string{serverKeyFile}, serverKeyFile},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "ca")
			if err := copyDir(t, made, dir); err != nil {
				t.Fatal(err)
			}
			writePlainKeys(t, dir, s, tc.plain...)
			before := readAll(t, dir, keyFiles...)
			want := filepath.Join(dir, tc.named) + " holds an unencrypted private key, from before auu-ca encrypted its keys, " +
				"and there is no reading it: delete " + dir + " and re-create the authority with 'auu-ca init'"
			opens := []struct {
				name string
				fn   func() error
			}{
				{"Open with the passphrase", func() error { _, err := Open(dir, []byte(testSecret)); return err }},
				{"OpenLocked", func() error { _, err := OpenLocked(dir); return err }},
				{"SetPassphrase", func() error { return SetPassphrase(dir, []byte(testSecret), keyfile.TestPassphrase("another")) }},
			}
			if len(tc.plain) == len(keyFiles) {
				// With an encrypted file before the plain one, no
				// passphrase is refused first, for that file; with
				// none encrypted, the plain file is the refusal.
				opens = append(opens, struct {
					name string
					fn   func() error
				}{"Open with none", func() error { _, err := Open(dir, nil); return err }})
			}
			for _, open := range opens {
				err := open.fn()
				if err == nil || err.Error() != want {
					t.Errorf("%s: %v\nwant %s", open.name, err, want)
				}
			}
			for name, was := range before {
				if now := readAll(t, dir, name)[name]; !bytes.Equal(was, now) {
					t.Errorf("%s was rewritten by a refusal", name)
				}
			}
		})
	}
}

// TestAKeyFileThatIsNeitherIsRefusedByName.
func TestAKeyFileThatIsNeitherIsRefusedByName(t *testing.T) {
	dir := t.TempDir()
	if _, err := Create(dir, "Test", mldsa.MLDSA65(), keyfile.TestPassphrase(testSecret), time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, body, want string }{
		{"another kind of block", string(pem.EncodeToMemory(&pem.Block{
			Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte("PBES2, from openssl")})), "want"},
		{"not PEM at all", "just some bytes", "no PEM block"},
		{"two blocks", string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("a")})) +
			string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("b")})), "more than one PEM block"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "ca")
			if err := copyDir(t, dir, path); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(path, clientKeyFile), []byte(tc.body), keyMode); err != nil {
				t.Fatal(err)
			}
			_, err := Open(path, []byte(testSecret))
			if err == nil {
				t.Fatalf("%s was accepted", tc.name)
			}
			if !strings.Contains(err.Error(), clientKeyFile) || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not name the file and what was wrong", err)
			}
		})
	}
}

// writePlainKeys writes the named key files the way they were written before
// they were encrypted.
func writePlainKeys(t *testing.T, dir string, s *Store, names ...string) {
	t.Helper()
	for i, name := range keyFiles {
		if !slices.Contains(names, name) {
			continue
		}
		key := []*Key{s.Anchor, s.Server, s.Client}[i].Key
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		body := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		if err := os.WriteFile(filepath.Join(dir, name), body, keyMode); err != nil {
			t.Fatal(err)
		}
	}
}

func readAll(t *testing.T, dir string, names ...string) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	for _, n := range names {
		raw, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			t.Fatal(err)
		}
		out[n] = raw
	}
	return out
}

func copyDir(t *testing.T, from, to string) error {
	t.Helper()
	if err := os.MkdirAll(to, dirMode); err != nil {
		return err
	}
	entries, err := os.ReadDir(from)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() {
			if err := copyDir(t, filepath.Join(from, e.Name()), filepath.Join(to, e.Name())); err != nil {
				return err
			}
			continue
		}
		raw, err := os.ReadFile(filepath.Join(from, e.Name()))
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(to, e.Name()), raw, keyMode); err != nil {
			return err
		}
	}
	return nil
}

// A key file whose header names Argon2 memory at the old ceiling, 4 GiB,
// which only an edit by hand makes, is refused before anything is
// derived, with its path, the value and the ceiling (S58): auu-ca used to
// set out to allocate it before it could find the passphrase wrong.
func TestOpenRefusesAKeyFileAtTheOldMemoryCeiling(t *testing.T) {
	dir := t.TempDir()
	if _, err := Create(dir, "Test", mldsa.MLDSA65(), keyfile.TestPassphrase(testSecret), time.Now()); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, anchorKeyFile)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatal("no PEM block")
	}
	block.Headers["Threads"] = "1"
	block.Headers["Memory"] = "4194304"
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = Open(dir, []byte(testSecret))
	if err == nil || !strings.Contains(err.Error(), path+": keyfile: Memory must be between 8 and 1048576 KiB with 1 threads, got 4194304") {
		t.Fatalf("an authority whose anchor key names 4 GiB: %v; want the file and the bounds", err)
	}
}
