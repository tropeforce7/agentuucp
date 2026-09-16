package main

import (
	"bytes"
	"io"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// adminFile writes an authorized administrator file and returns its path.
func adminFile(t *testing.T, names ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "admins")
	var b strings.Builder
	for _, n := range names {
		id, err := identity.Generate(n)
		if err != nil {
			t.Fatal(err)
		}
		b.WriteString(id.Public().ExportLine() + "\n")
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestAdminDefaults(t *testing.T) {
	cfg, err := resolve(t, "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Registration != relayapi.RegistrationOpen {
		t.Fatalf("registration %q, want open", cfg.Registration)
	}
	if cfg.Admin.AuthorizedFile != "" {
		t.Fatalf("a relay with no admin file configured has %q", cfg.Admin.AuthorizedFile)
	}
	if d, err := cfg.TokenMaxAge(); err != nil || d != defaultTokenMaxAge {
		t.Fatalf("token max age %v (%v), want %v", d, err, defaultTokenMaxAge)
	}
	if cfg.PublicURL != "" {
		t.Fatalf("public url %q, want empty", cfg.PublicURL)
	}
}

func TestAdminSettingsFromFile(t *testing.T) {
	admins := adminFile(t, "boss")
	file := writeFile(t, `{
	  "registration": "token",
	  "public_url": "https://relay.example.com",
	  "admin": {
	    "authorized_file": "`+admins+`",
	    "token_max_age": "24h"
	  }
	}`)
	cfg, err := resolve(t, file)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Registration != relayapi.RegistrationToken {
		t.Fatalf("registration %q", cfg.Registration)
	}
	if cfg.PublicURL != "https://relay.example.com" {
		t.Fatalf("public url %q", cfg.PublicURL)
	}
	if cfg.Admin.AuthorizedFile != admins {
		t.Fatalf("admin file %q", cfg.Admin.AuthorizedFile)
	}
	if d, _ := cfg.TokenMaxAge(); d != 24*time.Hour {
		t.Fatalf("token max age %v", d)
	}
}

func TestAdminFlagsOverrideTheFile(t *testing.T) {
	fromFile := adminFile(t, "boss")
	fromFlag := adminFile(t, "deputy")
	file := writeFile(t, `{
	  "registration": "closed",
	  "public_url": "https://old.example.com",
	  "admin": {"authorized_file": "`+fromFile+`", "token_max_age": "1h"}
	}`)
	cfg, err := resolve(t, file,
		"--registration", "token",
		"--public-url", "https://new.example.com",
		"--admin-file", fromFlag,
		"--token-max-age", "12h")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Registration != relayapi.RegistrationToken || cfg.PublicURL != "https://new.example.com" ||
		cfg.Admin.AuthorizedFile != fromFlag {
		t.Fatalf("flags did not win: %+v", cfg)
	}
	if d, _ := cfg.TokenMaxAge(); d != 12*time.Hour {
		t.Fatalf("token max age %v", d)
	}
}

func TestBadAdminSettingsAreRefused(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "not-there")
	badLines := filepath.Join(t.TempDir(), "admins")
	if err := os.WriteFile(badLines, []byte("ccx1 nonsense bob\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	writable := adminFile(t, "boss")
	if err := os.Chmod(writable, 0o666); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		args []string
		want string
	}{
		{"unknown mode", []string{"--registration", "sometimes"}, "registration must be"},
		{"token mode with no administrators", []string{"--registration", "token"}, "admin.authorized_file"},
		{"public url with a path", []string{"--public-url", "https://relay.example.com/v1"}, "public_url"},
		{"public url with no scheme", []string{"--public-url", "relay.example.com"}, "public_url"},
		{"admin file missing", []string{"--admin-file", missing}, "admin file"},
		{"admin file malformed", []string{"--admin-file", badLines}, "line 1"},
		{"admin file writable", []string{"--admin-file", writable}, "0666"},
		{"token max age not a duration", []string{"--token-max-age", "soon"}, "token_max_age"},
		{"token max age zero", []string{"--token-max-age", "0s"}, "token_max_age"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := resolve(t, "", c.args...)
			if err == nil {
				t.Fatalf("%v was accepted", c.args)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %q does not mention %q", err, c.want)
			}
		})
	}
}

func TestPrintedConfigCarriesTheAdminBlock(t *testing.T) {
	admins := adminFile(t, "boss")
	cfg, err := resolve(t, "", "--registration", "token", "--admin-file", admins,
		"--public-url", "https://relay.example.com")
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := Encode(&out, cfg.Redacted()); err != nil {
		t.Fatal(err)
	}
	printed := out.String()
	for _, key := range []string{"registration", "public_url", "authorized_file", "token_max_age"} {
		if !strings.Contains(printed, key) {
			t.Errorf("--print-config output is missing %q", key)
		}
	}
	back, err := resolve(t, writeFile(t, printed))
	if err != nil {
		t.Fatalf("the printed configuration does not load again: %v", err)
	}
	if back.Registration != relayapi.RegistrationToken || back.Admin.AuthorizedFile != admins ||
		back.PublicURL != "https://relay.example.com" {
		t.Fatalf("the printed configuration did not round trip: %+v", back)
	}
}

// The message directory holds stored mail, so it is created at startup and
// refused if anyone but the owner can write it.
func TestMessagesDirConfig(t *testing.T) {
	t.Run("derived from the database path", func(t *testing.T) {
		db := filepath.Join(t.TempDir(), "sub", "relay.db")
		cfg, err := resolve(t, "", "--db", db)
		if err != nil {
			t.Fatal(err)
		}
		want := filepath.Join(filepath.Dir(db), "messages")
		if cfg.MessagesDir != want {
			t.Fatalf("messages dir %q, want %q", cfg.MessagesDir, want)
		}
		if info, err := os.Stat(want); err != nil {
			t.Fatalf("the directory was not created: %v", err)
		} else if perm := info.Mode().Perm(); perm != 0o700 {
			t.Fatalf("mode %04o, want 0700", perm)
		}
	})

	t.Run("from the file and from the flag", func(t *testing.T) {
		fromFile := filepath.Join(t.TempDir(), "from-file")
		fromFlag := filepath.Join(t.TempDir(), "from-flag")
		file := writeFile(t, `{"messages_dir": "`+fromFile+`"}`)
		cfg, err := resolve(t, file)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.MessagesDir != fromFile {
			t.Fatalf("messages dir %q", cfg.MessagesDir)
		}
		cfg, err = resolve(t, file, "--messages-dir", fromFlag)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.MessagesDir != fromFlag {
			t.Fatalf("the flag did not win: %q", cfg.MessagesDir)
		}
	})

	t.Run("group or world writable is refused", func(t *testing.T) {
		for _, mode := range []os.FileMode{0o777, 0o770, 0o702} {
			dir := filepath.Join(t.TempDir(), "loose")
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(dir, mode); err != nil {
				t.Fatal(err)
			}
			_, err := resolve(t, "", "--messages-dir", dir)
			if err == nil {
				t.Fatalf("mode %04o was accepted", mode)
			}
			if !strings.Contains(err.Error(), "messages directory") {
				t.Fatalf("error %q does not name the directory", err)
			}
		}
		// The tight modes are fine.
		for _, mode := range []os.FileMode{0o700, 0o755, 0o750} {
			dir := filepath.Join(t.TempDir(), "tight")
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(dir, mode); err != nil {
				t.Fatal(err)
			}
			if _, err := resolve(t, "", "--messages-dir", dir); err != nil {
				t.Fatalf("mode %04o was refused: %v", mode, err)
			}
		}
	})

	t.Run("printed and round trips", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "m")
		cfg, err := resolve(t, "", "--messages-dir", dir)
		if err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		if err := Encode(&out, cfg.Redacted()); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), "messages_dir") {
			t.Fatalf("--print-config omits messages_dir:\n%s", out.String())
		}
		back, err := resolve(t, writeFile(t, out.String()))
		if err != nil {
			t.Fatal(err)
		}
		if back.MessagesDir != dir {
			t.Fatalf("messages_dir did not round trip: %q", back.MessagesDir)
		}
	})
}

// The three stream settings, each from the file and from the flag, with the
// edges of their ranges. An operator who turns streams off, or bounds them,
// has to be able to trust that the setting took.
func TestStreamConfig(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		cfg, err := resolve(t, "")
		if err != nil {
			t.Fatal(err)
		}
		if !cfg.Streams {
			t.Fatal("streams is off by default; auu-relay is meant to ask for it")
		}
		if cfg.MaxStreamBytes != defaultMaxStreamBytes {
			t.Fatalf("max_stream_bytes %d, want %d", cfg.MaxStreamBytes, defaultMaxStreamBytes)
		}
		ttl, err := cfg.ParsedUploadTTL()
		if err != nil || ttl != defaultUploadTTL {
			t.Fatalf("upload_ttl %v, %v; want %v", ttl, err, defaultUploadTTL)
		}
	})

	t.Run("streams off from the file and the flag", func(t *testing.T) {
		cfg, err := resolve(t, writeFile(t, `{"streams": false}`))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Streams {
			t.Fatal(`{"streams": false} was ignored`)
		}
		cfg, err = resolve(t, "", "--streams=false")
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Streams {
			t.Fatal("--streams=false was ignored")
		}
		// And the flag beats the file, in both directions.
		cfg, err = resolve(t, writeFile(t, `{"streams": false}`), "--streams=true")
		if err != nil {
			t.Fatal(err)
		}
		if !cfg.Streams {
			t.Fatal("--streams=true did not beat the file")
		}
	})

	t.Run("max_stream_bytes edges", func(t *testing.T) {
		for _, n := range []int64{0, 1, math.MaxInt64} {
			cfg, err := resolve(t, "", "--max-stream-bytes", strconv.FormatInt(n, 10))
			if err != nil {
				t.Fatalf("max_stream_bytes %d was refused: %v", n, err)
			}
			if cfg.MaxStreamBytes != n {
				t.Fatalf("max_stream_bytes %d, want %d", cfg.MaxStreamBytes, n)
			}
		}
		// One below zero is the first value that is not a size.
		for _, n := range []int64{-1, math.MinInt64} {
			if _, err := resolve(t, "", "--max-stream-bytes", strconv.FormatInt(n, 10)); err == nil {
				t.Fatalf("max_stream_bytes %d was accepted", n)
			} else if !strings.Contains(err.Error(), "max_stream_bytes") {
				t.Fatalf("error %q does not name the setting", err)
			}
		}
	})

	t.Run("upload_ttl edges", func(t *testing.T) {
		for _, d := range []string{"1ns", "1s", "720h", "2562047h"} {
			if _, err := resolve(t, "", "--upload-ttl", d); err != nil {
				t.Fatalf("upload_ttl %q was refused: %v", d, err)
			}
		}
		for _, d := range []string{"0s", "-1ns", "-720h", "soon", "24"} {
			if _, err := resolve(t, "", "--upload-ttl", d); err == nil {
				t.Fatalf("upload_ttl %q was accepted", d)
			} else if !strings.Contains(err.Error(), "upload_ttl") {
				t.Fatalf("error %q does not name the setting", err)
			}
		}
	})

	t.Run("printed and round trips", func(t *testing.T) {
		cfg, err := resolve(t, "", "--streams=false", "--max-stream-bytes", "123", "--upload-ttl", "90m")
		if err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		if err := Encode(&out, cfg.Redacted()); err != nil {
			t.Fatal(err)
		}
		for _, key := range []string{"streams", "max_stream_bytes", "upload_ttl"} {
			if !strings.Contains(out.String(), key) {
				t.Fatalf("--print-config omits %s:\n%s", key, out.String())
			}
		}
		back, err := resolve(t, writeFile(t, out.String()))
		if err != nil {
			t.Fatal(err)
		}
		// The duration round trips as the operator wrote it, not normalised.
		if back.Streams || back.MaxStreamBytes != 123 || back.UploadTTL != "90m" {
			t.Fatalf("the stream settings did not round trip: streams=%v max=%d ttl=%q",
				back.Streams, back.MaxStreamBytes, back.UploadTTL)
		}
	})
}

// The administrators are loaded once at start: the set the relay is handed is
// the set the startup line counts, so an operator reading "administrators
// loaded count=1" can rely on the first request being served from it. A file
// that cannot be loaded there is a startup failure, as it is at validation.
func TestTheRelayIsHandedTheAdministratorsStartLoaded(t *testing.T) {
	admins := adminFile(t, "boss")
	cfg, err := resolve(t, "", "--admin-file", admins)
	if err != nil {
		t.Fatal(err)
	}
	rcfg, err := relayConfig(cfg, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if rcfg.Admins == nil || len(rcfg.Admins.Keys) != 1 {
		t.Fatalf("the relay was handed %+v, want the one administrator loaded at start", rcfg.Admins)
	}
	var logs bytes.Buffer
	logStartup(cfg, rcfg.Admins, slog.New(slog.NewTextHandler(&logs, nil)))
	if want := `msg="administrators loaded" count=1 path=` + admins; !strings.Contains(logs.String(), want) {
		t.Fatalf("startup does not log %q:\n%s", want, logs.String())
	}

	if err := os.Remove(admins); err != nil {
		t.Fatal(err)
	}
	if _, err := relayConfig(cfg, nil, slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil ||
		!strings.Contains(err.Error(), "admin file") {
		t.Fatalf("a file gone before the relay was built was not a startup failure naming it: %v", err)
	}

	none, err := resolve(t, "")
	if err != nil {
		t.Fatal(err)
	}
	rcfg, err = relayConfig(none, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if rcfg.Admins != nil {
		t.Fatalf("a relay with no admin file was handed administrators: %+v", rcfg.Admins)
	}
}
