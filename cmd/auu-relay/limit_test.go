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
// twelve of the fifteen limits are zero or more, zero meaning unlimited:
// a negative and the type's minimum are refused naming the setting, and
// zero and the type's maximum are taken; max_open_uploads and
// max_knocks_waiting are zero or within [1, 1000], the two limits with a
// ceiling: one over it and the type's maximum are refused naming the
// setting, the two edges and zero taken; knock_max_bytes is zero, which
// means max_bytes, or within [1, max_bytes]: one over max_bytes and the
// type's maximum are refused naming both, the two edges and zero taken.
// A flag is read as text: the text one past the type's maximum, a
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
		{"limits.knocks_per_hour", "--knocks-per-hour"},
	}
	// max_waiting must sit under max_inflight when both are set, and
	// knock_max_bytes at or under max_bytes, so each is taken to its
	// extremes with the other unlimited (for max_bytes, the knock cap
	// unset, since its default is over a small max_bytes).
	alone := map[string]string{"limits.max_inflight": "limits.max_waiting", "limits.max_waiting": "limits.max_inflight", "max_bytes": "limits.knock_max_bytes"}
	aloneFlag := map[string]string{"--max-inflight": "--max-waiting", "--max-waiting": "--max-inflight", "--max-bytes": "--knock-max-bytes"}

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
		if o, ok := alone[key]; ok {
			return writeFile(t, `{"`+name+`": `+value+`, "limits": {"`+strings.TrimPrefix(o, "limits.")+`": 0}}`)
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

	// The three with a ceiling: the two counts at 1000, and the knock cap
	// at max_bytes, which is the default 16 MiB here and named in the
	// refusal beside the knock cap.
	for _, c := range []struct {
		key, flag string
		ceiling   int64
		sentence  string
	}{
		{"limits.max_open_uploads", "--max-open-uploads", maxOpenUploadsCeiling, "must be at most 1000"},
		{"limits.max_knocks_waiting", "--max-knocks-waiting", maxKnocksWaitingCeiling, "must be at most 1000"},
		{"limits.knock_max_bytes", "--knock-max-bytes", relayapi.DefaultMaxBytes, "must be at most max_bytes (" + strconv.FormatInt(relayapi.DefaultMaxBytes, 10) + ")"},
	} {
		t.Run(c.key, func(t *testing.T) {
			name := short(c.key)
			ceiling := strconv.FormatInt(c.ceiling, 10)
			over := strconv.FormatInt(c.ceiling+1, 10)
			for _, text := range []string{"-1", strconv.FormatInt(math.MinInt64, 10), over, strconv.FormatInt(math.MaxInt64, 10)} {
				if _, err := resolve(t, fileWith(c.key, text)); err == nil || !strings.Contains(err.Error(), name) {
					t.Errorf("%s %s in the file: %v; want the refusal naming it", name, text, err)
				}
				if _, err := resolve(t, "", c.flag, text); err == nil || !strings.Contains(err.Error(), name) {
					t.Errorf("%s %s: %v; want the refusal naming the setting", c.flag, text, err)
				}
			}
			for _, text := range []string{"0", "1", ceiling} {
				if _, err := resolve(t, fileWith(c.key, text)); err != nil {
					t.Errorf("%s %s in the file: %v; want it taken", name, text, err)
				}
				if _, err := resolve(t, "", c.flag, text); err != nil {
					t.Errorf("%s %s: %v; want it taken", c.flag, text, err)
				}
			}
			if _, err := resolve(t, "", c.flag, over); err == nil || !strings.Contains(err.Error(), c.sentence) {
				t.Errorf("%s %s: %v; want the ceiling in the sentence", c.flag, over, err)
			}
			for _, text := range []string{"9223372036854775808", "1-2", " 1", "\u0661", "1.0", ""} {
				if _, err := resolve(t, "", c.flag, text); err == nil || !strings.Contains(err.Error(), `invalid value "`+text+`" for flag -`+strings.TrimPrefix(c.flag, "--")) {
					t.Errorf("%s %q: %v; want the flag package's refusal", c.flag, text, err)
				}
			}
			for _, text := range []string{"-0", "+1"} {
				if _, err := resolve(t, "", c.flag, text); err != nil {
					t.Errorf("%s %q: %v; want it taken", c.flag, text, err)
				}
			}
			if _, err := resolve(t, fileWith(c.key, "9223372036854775808")); err == nil {
				t.Errorf("%s one past the type's maximum in the file was taken", name)
			}
		})
	}

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
		if _, err := resolve(t, "", flagsWith("--max-bytes", "+1")...); err != nil {
			t.Errorf("--max-bytes +1: %v; want it taken", err)
		}
	})
}

// TestKnockMaxBytesMustBeUnderMaxBytes: the knock route's cap sits at or
// under the post's, or the pair is refused naming both and the zero that
// means max_bytes; zero beside any max_bytes is taken, and the default
// knock cap beside a max_bytes under it is the same refusal, as
// max_waiting's default is beside a small max_inflight. The file is
// checked the same way as the flags.
func TestKnockMaxBytesMustBeUnderMaxBytes(t *testing.T) {
	for _, tc := range []struct {
		knock, max string
		ok         bool
	}{
		{"8191", "8192", true},
		{"8192", "8192", true},
		{"8193", "8192", false},
		{"0", "8192", true},
		{"0", "1", true},
		{"1", "1", true},
		{"2", "1", false},
	} {
		_, err := resolve(t, "", "--knock-max-bytes", tc.knock, "--max-bytes", tc.max)
		if tc.ok && err != nil {
			t.Errorf("knock_max_bytes %s under max_bytes %s was refused: %v", tc.knock, tc.max, err)
		}
		if !tc.ok {
			want := "knock_max_bytes (" + tc.knock + ") must be at most max_bytes (" + tc.max + "): a knock is a post, " +
				"and its cap cannot be over the post's (use 0 for max_bytes)"
			if err == nil || err.Error() != want {
				t.Errorf("knock_max_bytes %s with max_bytes %s: %v, want %q", tc.knock, tc.max, err, want)
			}
		}
	}
	// The default knock cap over a max_bytes set under it.
	if _, err := resolve(t, "", "--max-bytes", "4096"); err == nil ||
		!strings.Contains(err.Error(), "knock_max_bytes (8192) must be at most max_bytes (4096)") {
		t.Errorf("max_bytes under the default knock cap: %v", err)
	}
	// A negative is said as a negative first.
	if _, err := resolve(t, "", "--knock-max-bytes", "-1", "--max-bytes", "1"); err == nil ||
		!strings.Contains(err.Error(), "knock_max_bytes must not be negative") {
		t.Errorf("a negative knock_max_bytes beside a max_bytes: %v", err)
	}
	file := writeFile(t, `{"max_bytes": 4096, "limits": {"knock_max_bytes": 4097}}`)
	if _, err := resolve(t, file); err == nil || !strings.Contains(err.Error(), "knock_max_bytes (4097) must be at most max_bytes (4096)") {
		t.Errorf("the file's knock_max_bytes over max_bytes: %v", err)
	}
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
// courier.home, courier.authorized_file, tls.cert_file, tls.key_file,
// tls.bundle — is resolved against the
// file's own directory, never the working directory a supervisor started
// the relay in; an absolute one and an empty one are left as they are,
// and a flag keeps the working directory as a path typed at a shell does.
func TestLimitConfigPathsResolveAgainstTheirFile(t *testing.T) {
	fileDir := t.TempDir()
	elsewhere := t.TempDir()
	t.Chdir(elsewhere)
	file := filepath.Join(fileDir, "relay.json")
	if err := os.WriteFile(file, []byte(`{"tls": {"mode": "off"}, "db": "relay.db", "messages_dir": "bodies", "admin": {"authorized_file": "admins"}, "courier": {"home": "courier", "authorized_file": "couriers"}, "registration": "closed"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	// The administrators' file is looked for where the setting resolves
	// to: beside the settings, not in the working directory.
	if err := os.WriteFile(filepath.Join(fileDir, "admins"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	// And so is the couriers file, which is read at validation for the same
	// reason: a typo in it is a relay that does not start. An empty one is
	// a relay that accepts from nobody yet, which is valid.
	if err := os.WriteFile(filepath.Join(fileDir, "couriers"), nil, 0o600); err != nil {
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
		{"courier.home", cfg.Courier.Home, filepath.Join(fileDir, "courier")},
		{"courier.authorized_file", cfg.Courier.AuthorizedFile, filepath.Join(fileDir, "couriers")},
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
