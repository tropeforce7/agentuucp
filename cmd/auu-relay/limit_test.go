package main

import (
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// TestLimitRelaySettings: every integer setting of the relay, from the
// file and from its flag. max_bytes is within [1, MaxBytesCeiling]
// (TestLimitMaxBytesBoundaries walks its edges); max_stream_bytes and
// eleven of the twelve limits are zero or more, zero meaning unlimited:
// a negative and the type's minimum are refused naming the setting, and
// zero and the type's maximum are taken; max_open_uploads, the twelfth,
// is zero or within [1, 1000], the one limit with a ceiling: one over it
// and the type's maximum are refused naming it, the two edges and zero
// taken. A flag is read as text: the text one past the type's maximum, a
// sign inside the digits, a leading space and a digit outside ASCII are
// the flag package's refusals, a minus before zero is zero, and a plus
// sign is the number.
func TestLimitRelaySettings(t *testing.T) {
	settings := []struct{ key, flag string }{
		{"max_stream_bytes", "--max-stream-bytes"},
		{"limits.requests_per_minute", "--limit-requests"},
		{"limits.posts_per_minute", "--limit-posts"},
		{"limits.post_bytes_per_hour", "--limit-post-bytes"},
		{"limits.unauthenticated_per_minute", "--limit-unauthenticated"},
		{"limits.registrations_per_hour", "--limit-registrations"},
		{"limits.max_mailboxes", "--max-mailboxes"},
		{"limits.mailbox_max_messages", "--mailbox-max-messages"},
		{"limits.mailbox_max_bytes", "--mailbox-max-bytes"},
		{"limits.relay_max_bytes", "--relay-max-bytes"},
		{"limits.max_inflight", "--max-inflight"},
		{"limits.max_waiting", "--max-waiting"},
	}
	// max_waiting must sit under max_inflight when both are set, so each
	// is taken to its extremes with the other unlimited.
	alone := map[string]string{"limits.max_inflight": "limits.max_waiting", "limits.max_waiting": "limits.max_inflight"}
	aloneFlag := map[string]string{"--max-inflight": "--max-waiting", "--max-waiting": "--max-inflight"}

	fileWith := func(key string, value string) string {
		name := key
		if strings.HasPrefix(key, "limits.") {
			name = strings.TrimPrefix(key, "limits.")
			other := ""
			if o, ok := alone[key]; ok {
				other = `, "` + strings.TrimPrefix(o, "limits.") + `": 0`
			}
			return writeFile(t, `{"limits": {"`+name+`": `+value+other+`}}`)
		}
		return writeFile(t, `{"`+name+`": `+value+`}`)
	}
	flagsWith := func(flag, value string) []string {
		args := []string{flag, value}
		if o, ok := aloneFlag[flag]; ok {
			args = append(args, o, "0")
		}
		return args
	}
	short := func(key string) string { return strings.TrimPrefix(key, "limits.") }

	for _, s := range settings {
		t.Run(s.key, func(t *testing.T) {
			for _, v := range []int64{-1, math.MinInt64} {
				text := strconv.FormatInt(v, 10)
				if _, err := resolve(t, fileWith(s.key, text)); err == nil || !strings.Contains(err.Error(), short(s.key)) {
					t.Errorf("%s %d in the file: %v; want the refusal naming it", s.key, v, err)
				}
				if _, err := resolve(t, "", flagsWith(s.flag, text)...); err == nil || !strings.Contains(err.Error(), short(s.key)) {
					t.Errorf("%s %d: %v; want the refusal naming the setting", s.flag, v, err)
				}
			}
			for _, v := range []int64{0, math.MaxInt64} {
				text := strconv.FormatInt(v, 10)
				if _, err := resolve(t, fileWith(s.key, text)); err != nil {
					t.Errorf("%s %d in the file: %v; want it taken", s.key, v, err)
				}
				if _, err := resolve(t, "", flagsWith(s.flag, text)...); err != nil {
					t.Errorf("%s %d: %v; want it taken", s.flag, v, err)
				}
			}
			for _, text := range []string{"9223372036854775808", "1-2", " 1", "\u0661", "1.0", ""} {
				if _, err := resolve(t, "", flagsWith(s.flag, text)...); err == nil || !strings.Contains(err.Error(), `invalid value "`+text+`" for flag -`+strings.TrimPrefix(s.flag, "--")) {
					t.Errorf("%s %q: %v; want the flag package's refusal", s.flag, text, err)
				}
			}
			for _, text := range []string{"-0", "+1"} {
				if _, err := resolve(t, "", flagsWith(s.flag, text)...); err != nil {
					t.Errorf("%s %q: %v; want it taken", s.flag, text, err)
				}
			}
			// The file is JSON: a number the type cannot hold is the
			// decoder's refusal, naming the field.
			if _, err := resolve(t, fileWith(s.key, "9223372036854775808")); err == nil {
				t.Errorf("%s one past the type's maximum in the file was taken", s.key)
			}
		})
	}

	t.Run("limits.max_open_uploads", func(t *testing.T) {
		ceiling := strconv.FormatInt(maxOpenUploadsCeiling, 10)
		over := strconv.FormatInt(maxOpenUploadsCeiling+1, 10)
		for _, text := range []string{"-1", strconv.FormatInt(math.MinInt64, 10), over, strconv.FormatInt(math.MaxInt64, 10)} {
			if _, err := resolve(t, fileWith("limits.max_open_uploads", text)); err == nil || !strings.Contains(err.Error(), "max_open_uploads") {
				t.Errorf("max_open_uploads %s in the file: %v; want the refusal naming it", text, err)
			}
			if _, err := resolve(t, "", "--max-open-uploads", text); err == nil || !strings.Contains(err.Error(), "max_open_uploads") {
				t.Errorf("--max-open-uploads %s: %v; want the refusal naming the setting", text, err)
			}
		}
		for _, text := range []string{"0", "1", ceiling} {
			if _, err := resolve(t, fileWith("limits.max_open_uploads", text)); err != nil {
				t.Errorf("max_open_uploads %s in the file: %v; want it taken", text, err)
			}
			if _, err := resolve(t, "", "--max-open-uploads", text); err != nil {
				t.Errorf("--max-open-uploads %s: %v; want it taken", text, err)
			}
		}
		if _, err := resolve(t, "", "--max-open-uploads", over); err == nil || !strings.Contains(err.Error(), "must be at most "+ceiling) {
			t.Errorf("--max-open-uploads %s: %v; want the ceiling in the sentence", over, err)
		}
		for _, text := range []string{"9223372036854775808", "1-2", " 1", "\u0661", "1.0", ""} {
			if _, err := resolve(t, "", "--max-open-uploads", text); err == nil || !strings.Contains(err.Error(), `invalid value "`+text+`" for flag -max-open-uploads`) {
				t.Errorf("--max-open-uploads %q: %v; want the flag package's refusal", text, err)
			}
		}
		for _, text := range []string{"-0", "+1"} {
			if _, err := resolve(t, "", "--max-open-uploads", text); err != nil {
				t.Errorf("--max-open-uploads %q: %v; want it taken", text, err)
			}
		}
		if _, err := resolve(t, fileWith("limits.max_open_uploads", "9223372036854775808")); err == nil {
			t.Error("max_open_uploads one past the type's maximum in the file was taken")
		}
	})

	t.Run("max_bytes", func(t *testing.T) {
		ceiling := strconv.FormatInt(relayapi.MaxBytesCeiling, 10)
		for _, text := range []string{"0", "-1", strconv.FormatInt(math.MinInt64, 10), strconv.FormatInt(relayapi.MaxBytesCeiling+1, 10), strconv.FormatInt(math.MaxInt64, 10)} {
			if _, err := resolve(t, fileWith("max_bytes", text)); err == nil || !strings.Contains(err.Error(), "max_bytes") {
				t.Errorf("max_bytes %s in the file: %v; want the refusal naming it", text, err)
			}
		}
		for _, text := range []string{"1", ceiling} {
			if _, err := resolve(t, fileWith("max_bytes", text)); err != nil {
				t.Errorf("max_bytes %s in the file: %v; want it taken", text, err)
			}
		}
		for _, text := range []string{"9223372036854775808", "1-2", " 1", "\u0661", ""} {
			if _, err := resolve(t, "", "--max-bytes", text); err == nil || !strings.Contains(err.Error(), `invalid value "`+text+`" for flag -max-bytes`) {
				t.Errorf("--max-bytes %q: %v; want the flag package's refusal", text, err)
			}
		}
		if _, err := resolve(t, "", "--max-bytes", "-0"); err == nil || !strings.Contains(err.Error(), "max_bytes must be positive") {
			t.Errorf("--max-bytes -0: %v; want zero refused", err)
		}
		if _, err := resolve(t, "", "--max-bytes", "+1"); err != nil {
			t.Errorf("--max-bytes +1: %v; want it taken", err)
		}
	})
}

// TestLimitDurationSettings: the two durations the relay's file carries
// as text, read by time.ParseDuration. client_certs.lifetime is within
// [an hour, ten years]; admin.token_max_age is more than
// nothing. One under and one over a bound, zero, a negative, the text one
// past the type's maximum, a bare number, "inf", a unit alone and a digit
// outside ASCII are each refused naming the setting; the bounds, a plus
// sign and an empty setting (the default) are taken.
func TestLimitDurationSettings(t *testing.T) {
	file := func(key, value string) string {
		switch key {
		case "client_certs.lifetime":
			return writeFile(t, `{"client_certs": {"mode": "off", "lifetime": "`+value+`"}}`)
		case "admin.token_max_age":
			return writeFile(t, `{"admin": {"token_max_age": "`+value+`"}}`)
		}
		return writeFile(t, `{"`+key+`": "`+value+`"}`)
	}
	forms := []string{"9223372037s", "1", "inf", "s", "-1h", "\u0661h", "1.5", "1h "}
	t.Run("client_certs.lifetime", func(t *testing.T) {
		for _, v := range append([]string{"59m59s", "87601h", "0s", "-1s"}, forms...) {
			if _, err := resolve(t, file("client_certs.lifetime", v)); err == nil || !strings.Contains(err.Error(), "client_certs.lifetime") {
				t.Errorf("lifetime %q: %v; want the refusal naming it", v, err)
			}
		}
		for _, v := range []string{"1h", "+1h", "87600h", ""} {
			if _, err := resolve(t, file("client_certs.lifetime", v)); err != nil {
				t.Errorf("lifetime %q: %v; want it taken", v, err)
			}
		}
	})
	for _, key := range []string{"admin.token_max_age"} {
		t.Run(key, func(t *testing.T) {
			for _, v := range append([]string{"0s", "-1s", "-9223372036854775808ns"}, forms...) {
				if _, err := resolve(t, file(key, v)); err == nil || !strings.Contains(err.Error(), key) {
					t.Errorf("%s %q: %v; want the refusal naming it", key, v, err)
				}
			}
			for _, v := range []string{"1ns", "+1s", "9223372036854775807ns", ""} {
				if _, err := resolve(t, file(key, v)); err != nil {
					t.Errorf("%s %q: %v; want it taken", key, v, err)
				}
			}
		})
	}
}

// TestLimitConfigPathsResolveAgainstTheirFile: a relative path in the
// relay's settings file — db, messages_dir, admin.authorized_file,
// tls.cert_file, tls.key_file, tls.bundle — is resolved against the
// file's own directory, never the working directory a supervisor started
// the relay in; an absolute one and an empty one are left as they are,
// and a flag keeps the working directory as a path typed at a shell does.
func TestLimitConfigPathsResolveAgainstTheirFile(t *testing.T) {
	fileDir := t.TempDir()
	elsewhere := t.TempDir()
	t.Chdir(elsewhere)
	file := filepath.Join(fileDir, "relay.json")
	if err := os.WriteFile(file, []byte(`{"tls": {"mode": "off"}, "db": "relay.db", "messages_dir": "bodies", "admin": {"authorized_file": "admins"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	// The administrators' file is looked for where the setting resolves
	// to: beside the settings, not in the working directory.
	if err := os.WriteFile(filepath.Join(fileDir, "admins"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := resolveBare(t, file)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, got, want string }{
		{"db", cfg.DB, filepath.Join(fileDir, "relay.db")},
		{"messages_dir", cfg.MessagesDir, filepath.Join(fileDir, "bodies")},
		{"admin.authorized_file", cfg.Admin.AuthorizedFile, filepath.Join(fileDir, "admins")},
	} {
		if tc.got != tc.want {
			t.Errorf("%s resolved to %q, want %q", tc.name, tc.got, tc.want)
		}
		if rel, err := filepath.Rel(elsewhere, tc.got); err == nil && !strings.HasPrefix(rel, "..") {
			t.Errorf("%s resolved under the working directory: %q", tc.name, tc.got)
		}
	}
	// TLS files, when the mode wants them, and an absolute path kept.
	abs := filepath.Join(t.TempDir(), "elsewhere.db")
	if err := os.WriteFile(file, []byte(`{"tls": {"mode": "files", "cert_file": "certs/relay.pem", "key_file": "certs/relay.key", "bundle": "bundle.json"}, "db": `+strconv.Quote(abs)+`}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, _, err = Load(file)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, got, want string }{
		{"tls.cert_file", cfg.TLS.CertFile, filepath.Join(fileDir, "certs", "relay.pem")},
		{"tls.key_file", cfg.TLS.KeyFile, filepath.Join(fileDir, "certs", "relay.key")},
		{"tls.bundle", cfg.TLS.Bundle, filepath.Join(fileDir, "bundle.json")},
		{"db, absolute", cfg.DB, abs},
		{"messages_dir, empty", cfg.MessagesDir, ""},
	} {
		if tc.got != tc.want {
			t.Errorf("%s resolved to %q, want %q", tc.name, tc.got, tc.want)
		}
	}
	// The defaults are settings the file left out, and land beside the
	// file too: a relay under a unit with a file that names no db keeps
	// its database beside its settings, not in the unit's working
	// directory.
	if err := os.WriteFile(file, []byte(`{"tls": {"mode": "off"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err = resolveBare(t, file)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DB != filepath.Join(fileDir, "relay.db") || cfg.MessagesDir != filepath.Join(fileDir, "messages") {
		t.Errorf("with db and messages_dir left out: db %q, messages_dir %q; want both beside the file", cfg.DB, cfg.MessagesDir)
	}
	// A flag is the shell's: relative to the working directory.
	cfg, err = resolve(t, "", "--db", "flag.db")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DB != "flag.db" {
		t.Errorf("--db flag.db became %q; a flag keeps the working directory", cfg.DB)
	}
}
