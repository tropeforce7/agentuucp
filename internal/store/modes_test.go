package store

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/keyfile"
)

// auu writes every key file 0600 and the home 0700 itself, so a wider mode
// means somebody changed it, and the refusal names the file, its mode, and
// the chmod that puts it back — as a damaged file, so the exit is 5. The
// container suite's K19 found no check at all, where the relay, auu-ca and
// the admin file all have one.
func TestPermissiveKeyFilesAreRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Go's FileMode on Windows says nothing about who can read a file; the check is Unix's")
	}
	// A plain home with a certificate, and an encrypted one, so that every
	// key file exists somewhere.
	plain := newStore(t)
	id, err := identity.Generate("ada")
	if err != nil {
		t.Fatal(err)
	}
	if err := plain.SaveIdentity(id); err != nil {
		t.Fatal(err)
	}
	r, err := plain.AddRelay("work", "https://work.example:9443")
	if err != nil {
		t.Fatal(err)
	}
	if err := plain.SaveCertFor(r, &CertRecord{Relay: r.URL, Serial: "aaa"}); err != nil {
		t.Fatal(err)
	}
	encrypted := newStore(t)
	if err := encrypted.SaveIdentity(id); err != nil {
		t.Fatal(err)
	}
	if err := encrypted.EncryptHome(keyfile.TestPassphrase("correct horse battery staple")); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		path string
		read func() error
	}{
		{"identity.json in its plain form", plain.path(identityFile), func() error { _, err := plain.Identity(); return err }},
		{"cert.json, read by CertFor", plain.relayPath(r, certFile), func() error { _, err := plain.CertFor(r); return err }},
		{"cert.json, read by the home's state", plain.relayPath(r, certFile), func() error { _, err := plain.Identity(); return err }},
		{"home.key", encrypted.path(homeKeyFile), func() error { _, err := encrypted.HomeKey(); return err }},
		{"identity.key", encrypted.path(identityKeyFile), func() error { _, _, err := encrypted.IdentityKey(); return err }},
	} {
		// The plan's three, and one for each half of the mask on its own:
		// group alone, and others alone, which the three do not tell apart.
		for _, mode := range []os.FileMode{0o644, 0o660, 0o666, 0o640, 0o604} {
			t.Run(fmt.Sprintf("%s at %04o", tc.name, mode), func(t *testing.T) {
				if err := os.Chmod(tc.path, mode); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { os.Chmod(tc.path, 0o600) })
				err := tc.read()
				if err == nil {
					t.Fatal("a key file anyone can read was accepted")
				}
				want := fmt.Sprintf("%s is mode %04o: anyone on this machine can read your keys. Run: chmod 600 %s", tc.path, mode, tc.path)
				if err.Error() != want {
					t.Fatalf("sentence\n  %q\nwant\n  %q", err, want)
				}
				if !errors.Is(err, ErrDamaged) {
					t.Fatalf("not ErrDamaged: %v", err)
				}
			})
		}
		t.Run(tc.name+" at 0600", func(t *testing.T) {
			if err := os.Chmod(tc.path, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := tc.read(); err != nil {
				t.Fatalf("the mode auu writes was refused: %v", err)
			}
		})
	}

	// The encrypted form of identity.json holds only the public half, and
	// its mode is not checked: the keys are in identity.key.
	t.Run("identity.json in its encrypted form at 0644", func(t *testing.T) {
		if err := os.Chmod(encrypted.path(identityFile), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(encrypted.path(identityFile), 0o600) })
		if _, err := encrypted.Self(); err != nil {
			t.Fatalf("the public half was refused for its mode: %v", err)
		}
	})
}

// The home itself is refused when group or others can write it, since that
// lets them replace what is in it whatever the files' own modes say; one
// they can only list exposes no key, and is what a home made by hand under
// the usual umask looks like.
func TestAWritableHomeIsRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the check is Unix's")
	}
	for _, tc := range []struct {
		mode    os.FileMode
		refused bool
	}{
		{0o775, true}, {0o777, true}, {0o707, true},
		{0o755, false}, {0o700, false},
	} {
		t.Run(fmt.Sprintf("%04o", tc.mode), func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "home")
			if err := os.Mkdir(root, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(root, tc.mode); err != nil {
				t.Fatal(err)
			}
			_, err := Open(root)
			if !tc.refused {
				if err != nil {
					t.Fatalf("a home at %04o was refused: %v", tc.mode, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("a home at %04o was accepted", tc.mode)
			}
			want := fmt.Sprintf("%s is mode %04o: anyone on this machine can write into your home and replace what is in it. Run: chmod 700 %s", root, tc.mode, root)
			if err.Error() != want {
				t.Fatalf("sentence\n  %q\nwant\n  %q", err, want)
			}
			if !errors.Is(err, ErrDamaged) {
				t.Fatalf("not ErrDamaged: %v", err)
			}
		})
	}
}

// The peer list and the spool hold nothing secret, so a permissive mode on
// them is a warning — once, however often the home is opened — and the
// command goes on.
func TestPermissivePeersAndSpoolAreWarnedAboutOnce(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the check is Unix's")
	}
	root := t.TempDir()
	s, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddPeer(peer(t, "bob")); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{s.path(peersFile), s.path(inboxDir)} {
		if err := os.Chmod(p, 0o777); err != nil {
			t.Fatal(err)
		}
	}
	// Readable and not writable is not warned about: nothing here is secret.
	if err := os.Chmod(s.path(sentDir), 0o755); err != nil {
		t.Fatal(err)
	}

	stderr := captureStderr(t, func() {
		for i := 0; i < 3; i++ {
			if _, err := Open(root); err != nil {
				t.Fatalf("a home with a writable peer list was refused: %v", err)
			}
		}
	})
	wantPeers := fmt.Sprintf("warning: %s is mode 0777: anyone on this machine can change who you trust; run chmod 600 %s\n",
		s.path(peersFile), s.path(peersFile))
	wantInbox := fmt.Sprintf("warning: %s is mode 0777: anyone on this machine can change your mail; run chmod 700 %s\n",
		s.path(inboxDir), s.path(inboxDir))
	if strings.Count(stderr, wantPeers) != 1 || strings.Count(stderr, wantInbox) != 1 {
		t.Fatalf("three opens did not warn once each:\n%s", stderr)
	}
	if strings.Contains(stderr, s.path(sentDir)) {
		t.Fatalf("a spool directory that is only readable was warned about:\n%s", stderr)
	}
}

// captureStderr runs fn with stderr redirected, and returns what it wrote.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	real := os.Stderr
	os.Stderr = w
	fn()
	w.Close()
	os.Stderr = real
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
	return string(data)
}
