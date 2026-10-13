package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relay"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// couriersFile writes a couriers file — export lines, one per neighbouring
// relay this one accepts forwarded mail from — and returns its path.
func couriersFile(t *testing.T, names ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "couriers")
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

// courierHome is an auu home as the relay's user would leave it.
func courierHome(t *testing.T, neighbour, url string) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "courier")
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	id, err := identity.Generate("relay-a")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SaveIdentity(id); err != nil {
		t.Fatal(err)
	}
	if neighbour != "" {
		if _, err := s.AddRelay(neighbour, url); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// resolvePeered is resolve with no file and a peering in front of args: an
// empty couriers file given by --courier-file, which accepts from nobody
// yet is a peering, so the courier numbers in args are bounds on something
// and are judged on their own edges rather than refused as numbers alone.
func resolvePeered(t *testing.T, args ...string) (Config, error) {
	t.Helper()
	return resolve(t, "", append([]string{"--courier-file", couriersFile(t)}, args...)...)
}

// TestARelayPeersWithNobodyByDefault: forwarding is something an operator
// asks for. A relay with no courier block dials nobody, accepts nothing
// forwarded, and hands the library a nil courier, which is what every relay
// was before any of this existed.
func TestARelayPeersWithNobodyByDefault(t *testing.T) {
	cfg, err := resolve(t, "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Courier.Home != "" || cfg.Courier.AuthorizedFile != "" {
		t.Fatalf("a relay with no courier block has %+v", cfg.Courier)
	}
	if cfg.Courier.set() {
		t.Error("an empty courier block reads as set")
	}
	rc, err := relayConfig(cfg, nil, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	if rc.Courier != nil {
		t.Error("a relay with no courier block was given one")
	}
}

// TestAnEmptyCourierBlockIsRefused: an operator who wrote "courier": {} meant
// something and got nothing. After the strict decode an empty object and an
// absent key are one thing, so the refusal reads the raw bytes, where the
// difference still exists — and a relay with no block at all, the ordinary
// case, is not refused.
func TestAnEmptyCourierBlockIsRefused(t *testing.T) {
	file := writeFile(t, `{"tls": {"mode": "off"}, "courier": {}}`)
	_, err := resolve(t, file)
	if err == nil {
		t.Fatal("an empty courier block was accepted")
	}
	for _, want := range []string{"empty block", "courier.home", "courier.authorized_file", "remove the block"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%v does not say %q", err, want)
		}
	}
	// A block with either key is not empty.
	for _, body := range []string{
		`{"tls": {"mode": "off"}, "courier": {"home": "home"}}`,
		`{"tls": {"mode": "off"}, "courier": {"authorized_file": "couriers"}}`,
	} {
		if err := checkEmptyCourier([]byte(body)); err != nil {
			t.Errorf("%s: %v", body, err)
		}
	}
	// And a typo inside the block is a typo, reported by the strict decode
	// rather than as an empty block.
	typo := writeFile(t, `{"tls": {"mode": "off"}, "courier": {"hme": "home"}}`)
	_, err = resolve(t, typo)
	if err == nil || strings.Contains(err.Error(), "empty block") {
		t.Errorf("a misspelled key inside the block: %v; want the unknown-field error", err)
	}
}

// TestACouriersFileWithABadLineIsAStartupFailure: the file is parsed at the
// start rather than at the first forwarded message, so a typo in it is a relay
// that does not start, with the line number in the sentence.
func TestACouriersFileWithABadLineIsAStartupFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "couriers")
	if err := os.WriteFile(path, []byte("ccx2.not-a-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := resolve(t, "", "--courier-file", path)
	if err == nil {
		t.Fatal("a couriers file with a bad line started")
	}
	if !strings.Contains(err.Error(), "line 1") {
		t.Errorf("%v does not name the line", err)
	}
}

// TestPrintedConfigCarriesTheCourierBlock: every setting is in the printed
// configuration and loads again from it, since that output is the record of
// what the relay is doing and an operator pastes it back.
func TestPrintedConfigCarriesTheCourierBlock(t *testing.T) {
	home := courierHome(t, "bar", "https://bar.example")
	file := couriersFile(t, "bar")
	cfg, err := resolve(t, "", "--registration", "closed", "--courier-home", home, "--courier-file", file)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := Encode(&out, cfg.Redacted()); err != nil {
		t.Fatal(err)
	}
	printed := out.String()
	for _, key := range []string{"courier", "home", "authorized_file"} {
		if !strings.Contains(printed, key) {
			t.Errorf("--print-config output is missing %q", key)
		}
	}
	back, err := resolve(t, writeFile(t, printed))
	if err != nil {
		t.Fatalf("the printed configuration does not load again: %v", err)
	}
	if back.Courier.Home != home || back.Courier.AuthorizedFile != file {
		t.Fatalf("the courier block did not round trip: %+v", back.Courier)
	}
}

// TestTheCourierFlagsWinOverTheFile: a flag typed at a shell beats a file, and
// a flag left off never overwrites a file value with its own default.
func TestTheCourierFlagsWinOverTheFile(t *testing.T) {
	fromFile := couriersFile(t, "bar")
	fromFlag := couriersFile(t, "baz")
	home := courierHome(t, "bar", "https://bar.example")
	file := writeFile(t, `{"tls": {"mode": "off"}, "courier": {"authorized_file": `+strconv.Quote(fromFile)+`}}`)

	kept, err := resolve(t, file)
	if err != nil {
		t.Fatal(err)
	}
	if kept.Courier.AuthorizedFile != fromFile {
		t.Errorf("the file's value became %q, want %q", kept.Courier.AuthorizedFile, fromFile)
	}
	if kept.Courier.Home != "" {
		t.Errorf("a flag nobody typed set the home to %q", kept.Courier.Home)
	}

	over, err := resolve(t, file, "--registration", "closed", "--courier-file", fromFlag, "--courier-home", home)
	if err != nil {
		t.Fatal(err)
	}
	if over.Courier.AuthorizedFile != fromFlag || over.Courier.Home != home {
		t.Errorf("the flags did not win: %+v", over.Courier)
	}
}

// TestAStartWithAPeeringBuildsTheCourier: the relay is handed a courier built
// once, before the listener opens, so that a peering which cannot work is a
// relay that does not start.
func TestAStartWithAPeeringBuildsTheCourier(t *testing.T) {
	home := courierHome(t, "bar", "https://bar.example")
	cfg, err := resolve(t, "", "--registration", "closed", "--courier-home", home, "--courier-file", couriersFile(t, "bar"))
	if err != nil {
		t.Fatal(err)
	}
	rc, err := relayConfig(cfg, nil, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	if rc.Courier == nil {
		t.Fatal("a relay with a peering was given no courier")
	}
	if r, ok := rc.Courier.Neighbour("bar"); !ok || r.URL != "https://bar.example" {
		t.Errorf("the courier does not know bar: %v, %v", r, ok)
	}
	if rc.Courier.Identity() == nil {
		t.Error("the courier has no identity")
	}
}

// TestAPeeringThatCannotWorkStopsTheStart: what needs the home is refused
// where the home is opened, which is the start and not the settings file's
// validation, and it is still before the listener opens.
func TestAPeeringThatCannotWorkStopsTheStart(t *testing.T) {
	// A home with no identity: the settings are valid, the start is not.
	root := filepath.Join(t.TempDir(), "empty")
	if _, err := store.Open(root); err != nil {
		t.Fatal(err)
	}
	cfg, err := resolve(t, "", "--registration", "closed", "--courier-home", root)
	if err != nil {
		t.Fatalf("the settings themselves are fine and were refused: %v", err)
	}
	if _, err := relayConfig(cfg, nil, slog.Default()); err == nil {
		t.Fatal("a home with no identity started")
	} else if !strings.Contains(err.Error(), "holds no identity") {
		t.Errorf("%v; want the refusal naming what the home lacks", err)
	}
}

// TestValidatingTheSettingsDoesNotMakeAHome: validation runs on every start
// and whenever somebody prints the configuration, and store.Open creates the
// directories a home has, so validation that opened the home would leave one
// wherever it ran — including under a --print-config that was only ever meant
// to print.
func TestValidatingTheSettingsDoesNotMakeAHome(t *testing.T) {
	home := filepath.Join(t.TempDir(), "not-made-yet")
	cfg, err := resolve(t, "", "--registration", "closed", "--courier-home", home)
	if err != nil {
		t.Fatalf("settings naming a home that does not exist: %v; the start is what refuses that", err)
	}
	if cfg.Courier.Home != home {
		t.Fatalf("home %q, want %q", cfg.Courier.Home, home)
	}
	if _, err := os.Stat(home); err == nil {
		t.Error("validating the settings created the courier home")
	}
	var buf bytes.Buffer
	if err := Encode(&buf, cfg.Redacted()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(home); err == nil {
		t.Error("printing the configuration created the courier home")
	}
	// It is the start that refuses it, by name.
	_, err = relay.NewCourier(relay.CourierConfig{Home: home}, slog.Default())
	if err == nil {
		t.Error("a home that does not exist started")
	}
}

// TestTheCourierDefaultsMatchTheLibrarys: operator defaults live in the
// library and the command populates itself from them, so the two cannot drift
// without this failing. Comparing field by field rather than with one
// equality is deliberate: a field added to the library and forgotten here is
// what the test is for, and the compiler does not notice one.
func TestTheCourierDefaultsMatchTheLibrarys(t *testing.T) {
	cfg, err := resolve(t, "")
	if err != nil {
		t.Fatal(err)
	}
	got, err := cfg.Courier.Relay()
	if err != nil {
		t.Fatal(err)
	}
	want := relay.DefaultCourierLimits()
	if got.MaxHops != want.MaxHops ||
		got.ForwardTTL != want.ForwardTTL ||
		got.QueueMaxBytes != want.QueueMaxBytes ||
		got.QueueMaxMessages != want.QueueMaxMessages ||
		got.QueueMaxMessagesPerPoster != want.QueueMaxMessagesPerPoster ||
		got.QueueMaxBytesPerPoster != want.QueueMaxBytesPerPoster ||
		got.QueueMaxMessagesPerCourier != want.QueueMaxMessagesPerCourier ||
		got.PostsPerMinute != want.PostsPerMinute ||
		got.ReportsPerMinute != want.ReportsPerMinute ||
		got.PostBytesPerHour != want.PostBytesPerHour ||
		got.CarriedMaxRows != want.CarriedMaxRows {
		t.Fatalf("the command's courier defaults have drifted from the relay's:\n got %+v\nwant %+v", got, want)
	}
	// A relay with no peering still has these numbers: what it would allow
	// if it were asked is a setting, and only the two paths decide whether
	// anybody asks.
	if cfg.Courier.set() {
		t.Error("the defaults alone made this relay peer with somebody")
	}
}

// TestLimitCourierSettingRanges: every courier number an operator can set,
// at both sides of both edges and at the type's own, with the sentence each
// refusal gives. max_hops and forward_ttl have no honest zero and say so;
// the rest take zero as unlimited.
func TestLimitCourierSettingRanges(t *testing.T) {
	t.Run("max_hops", func(t *testing.T) {
		for _, tc := range []struct {
			hops int64
			ok   bool
		}{
			{0, false}, {-1, false}, {math.MinInt64, false},
			{1, true}, {8, true}, {relayapi.MaxHops, true},
			{relayapi.MaxHops + 1, false}, {math.MaxInt64, false},
		} {
			_, err := resolvePeered(t, "--courier-max-hops", strconv.FormatInt(tc.hops, 10))
			if tc.ok && err != nil {
				t.Errorf("max_hops %d: %v; want it taken", tc.hops, err)
			}
			if !tc.ok {
				if err == nil {
					t.Errorf("max_hops %d was taken", tc.hops)
				} else if !strings.Contains(err.Error(), fmt.Sprintf("between 1 and %d", relayapi.MaxHops)) {
					t.Errorf("max_hops %d: %v; want the range in the sentence", tc.hops, err)
				}
			}
		}
	})
	t.Run("forward_ttl", func(t *testing.T) {
		for _, tc := range []struct {
			ttl string
			ok  bool
		}{
			{"59s", false}, {"0", false}, {"0s", false}, {"-1h", false},
			{"1m", true}, {"72h", true}, {"720h", true},
			{"721h", false}, {"9223372037s", false}, {"inf", false}, {"", true},
		} {
			args := []string{}
			if tc.ttl != "" {
				args = []string{"--courier-forward-ttl", tc.ttl}
			}
			_, err := resolvePeered(t, args...)
			if tc.ok && err != nil {
				t.Errorf("forward_ttl %q: %v; want it taken", tc.ttl, err)
			}
			if !tc.ok && err == nil {
				t.Errorf("forward_ttl %q was taken", tc.ttl)
			}
		}
	})
	t.Run("the counts and the bytes", func(t *testing.T) {
		for _, f := range []string{
			"--courier-queue-max-bytes", "--courier-queue-max-bytes-per-poster",
			"--courier-posts-per-minute", "--courier-post-bytes-per-hour",
			"--courier-carried-max-rows", "--courier-queue-max-messages",
			"--courier-queue-max-messages-per-poster",
			"--courier-queue-max-messages-per-courier",
			"--courier-reports-per-minute",
			"--courier-carried-rows-per-poster", "--courier-carried-rows-per-courier",
		} {
			// Zero is unlimited and is taken; a negative one is refused with
			// the sentence that says what zero means.
			if _, err := resolvePeered(t, f, "0"); err != nil {
				t.Errorf("%s 0: %v; want unlimited", f, err)
			}
			_, err := resolvePeered(t, f, "-1")
			if err == nil {
				t.Errorf("%s -1 was taken", f)
			} else if !strings.Contains(err.Error(), "use 0 for unlimited") {
				t.Errorf("%s -1: %v; want the sentence naming what zero means", f, err)
			}
			if _, err := resolvePeered(t, f, strconv.FormatInt(math.MinInt64, 10)); err == nil {
				t.Errorf("%s MinInt64 was taken", f)
			}
		}
		// The three with a ceiling, each at it and one over. They are
		// counts of rows and of files the relay holds, which is why each
		// has one, and a neighbour's is larger than a person's, which is
		// why it is not the same number.
		for _, tc := range []struct {
			flag    string
			ceiling int
		}{
			{"--courier-queue-max-messages", maxQueueMessagesCeiling},
			{"--courier-queue-max-messages-per-poster", maxQueueMessagesCeiling},
			{"--courier-queue-max-messages-per-courier", maxQueuePerCourierCeiling},
		} {
			f := tc.flag
			if _, err := resolvePeered(t, f, strconv.Itoa(tc.ceiling)); err != nil {
				t.Errorf("%s at its ceiling: %v", f, err)
			}
			_, err := resolvePeered(t, f, strconv.Itoa(tc.ceiling+1))
			if err == nil || !strings.Contains(err.Error(), "at most") {
				t.Errorf("%s one over its ceiling: %v; want the refusal", f, err)
			}
			if _, err := resolvePeered(t, f, strconv.FormatInt(math.MaxInt64, 10)); err == nil {
				t.Errorf("%s MaxInt64 was taken", f)
			}
		}
	})
	// The carried shares are bounded below by relay.CarriedShareFloor,
	// the least share whose bucket pays for a hash on the longest path, and
	// above by a nonzero carried_max_rows, which a larger share could never
	// reach.
	t.Run("the carried shares", func(t *testing.T) {
		hops := relay.DefaultCourierLimits().MaxHops
		ceiling := relay.DefaultCourierLimits().CarriedMaxRows
		if hops != 8 || ceiling != 1_000_000 {
			t.Fatalf("the defaults moved: max_hops %d, carried_max_rows %d", hops, ceiling)
		}
		floor := relay.CarriedShareFloor(int64(hops))
		// The docs say 30 at max_hops 8, ceil(8 × (1 + H(8))); this pins it.
		if floor != 30 {
			t.Fatalf("CarriedShareFloor(8) is %d; the guides say 30", floor)
		}
		atLeast := func(name string, got int64) string {
			return fmt.Sprintf("%s must be at least %d, got %d: a hash costs one for each "+
				"forward_ttl it is kept, one on the longest path is kept courier.max_hops (8) of "+
				"them, and a poster may spend at most the share over 1 + H(max_hops) at once "+
				"(use 0 for unlimited)", name, floor, got)
		}
		for _, f := range []string{"--courier-carried-rows-per-poster", "--courier-carried-rows-per-courier"} {
			name := "courier.carried_rows_per_poster"
			if f == "--courier-carried-rows-per-courier" {
				name = "courier.carried_rows_per_courier"
			}
			for _, tc := range []struct {
				share int64
				want  string // "" for taken
			}{
				{floor, ""},
				{floor - 1, atLeast(name, floor-1)},
				{int64(hops), atLeast(name, int64(hops))},
				{ceiling, ""},
				{ceiling + 1, "at most courier.carried_max_rows (1000000), got 1000001"},
				{math.MaxInt64, "at most courier.carried_max_rows (1000000)"},
			} {
				_, err := resolvePeered(t, f, strconv.FormatInt(tc.share, 10))
				switch {
				case tc.want == "" && err != nil:
					t.Errorf("%s %d: %v; want it taken", f, tc.share, err)
				case tc.want != "" && err == nil:
					t.Errorf("%s %d was taken; want %q", f, tc.share, tc.want)
				case tc.want != "" && !strings.Contains(err.Error(), tc.want):
					t.Errorf("%s %d: %v; want %q", f, tc.share, err, tc.want)
				}
			}
			// An unlimited ceiling has no top for a share to pass.
			if _, err := resolvePeered(t, f, strconv.FormatInt(math.MaxInt64, 10),
				"--courier-carried-max-rows", "0"); err != nil {
				t.Errorf("%s MaxInt64 under an unlimited ceiling: %v; want it taken", f, err)
			}
			// A ceiling below the floor is the floor itself: a share at it,
			// or 0, is taken, and anything smaller is refused with the
			// sentence that says why a share must be the ceiling itself.
			want := fmt.Sprintf("%s must be courier.carried_max_rows (5) or 0, got 3: the ceiling "+
				"is below %d, the least share that pays for a path of courier.max_hops (8) relays, "+
				"so a share must be the ceiling itself", name, floor)
			_, err := resolvePeered(t, "--courier-carried-max-rows", "5", f, "3")
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("%s 3 under a ceiling of 5: %v; want %q", f, err, want)
			}
			for _, share := range []string{"5", "0"} {
				if _, err := resolvePeered(t, "--courier-carried-max-rows", "5", f, share); err != nil {
					t.Errorf("%s %s under a ceiling of 5: %v; want it taken", f, share, err)
				}
			}
		}
		// A share a settings file sets is the file's and is held to the
		// same bounds, not derived over: one under the floor is refused
		// where a derived share would have been the default sixteenth.
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "couriers"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		file := filepath.Join(dir, "relay.json")
		for _, tc := range []struct {
			key   string
			share int64
			want  string
		}{
			{"carried_rows_per_poster", floor - 1, atLeast("courier.carried_rows_per_poster", floor-1)},
			{"carried_rows_per_courier", floor - 1, atLeast("courier.carried_rows_per_courier", floor-1)},
			{"carried_rows_per_poster", 1_000_001, "courier.carried_rows_per_poster must be at most courier.carried_max_rows (1000000)"},
			{"carried_rows_per_courier", 1_000_001, "courier.carried_rows_per_courier must be at most courier.carried_max_rows (1000000)"},
			{"carried_rows_per_poster", floor, ""},
			{"carried_rows_per_courier", floor, ""},
		} {
			body := fmt.Sprintf(`{"tls": {"mode": "off"}, "registration": "closed", "courier": {
				"authorized_file": "couriers", %q: %d}}`, tc.key, tc.share)
			if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := resolve(t, file)
			if tc.want != "" {
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Errorf("file %s %d: %v; want %q", tc.key, tc.share, err, tc.want)
				}
				continue
			}
			if err != nil {
				t.Errorf("file %s %d: %v; want it taken", tc.key, tc.share, err)
				continue
			}
			got := cfg.Courier.CarriedRowsPerPoster
			if tc.key == "carried_rows_per_courier" {
				got = cfg.Courier.CarriedRowsPerCourier
			}
			if got != tc.share {
				t.Errorf("file %s %d resolved to %d; want the file's own value", tc.key, tc.share, got)
			}
		}
	})
}

// printedShares is the two carried shares as --print-config prints them.
func printedShares(t *testing.T, cfg Config) (poster, courier int64, printed string) {
	t.Helper()
	var out bytes.Buffer
	if err := Encode(&out, cfg.Redacted()); err != nil {
		t.Fatal(err)
	}
	var probe struct {
		Courier map[string]json.RawMessage `json:"courier"`
	}
	if err := json.Unmarshal(out.Bytes(), &probe); err != nil {
		t.Fatalf("the printed configuration is not JSON: %v", err)
	}
	read := func(key string) int64 {
		raw, ok := probe.Courier[key]
		if !ok {
			t.Fatalf("--print-config output has no courier.%s:\n%s", key, out.String())
		}
		var n int64
		if err := json.Unmarshal(raw, &n); err != nil {
			t.Fatalf("courier.%s printed as %s: %v", key, raw, err)
		}
		return n
	}
	return read("carried_rows_per_poster"), read("carried_rows_per_courier"), out.String()
}

// TestTheCarriedSharesFollowTheCeiling: a share nobody set is a sixteenth
// and a quarter of carried_max_rows as configured, so an operator who
// lowers the ceiling lowers the shares with it; an unlimited ceiling uses
// the default one's; a derived share is raised to relay.CarriedShareFloor
// and no further than a nonzero ceiling; a share somebody set is kept; and
// the printed configuration, loaded again, gives the same numbers.
func TestTheCarriedSharesFollowTheCeiling(t *testing.T) {
	floor := relay.CarriedShareFloor(relay.DefaultCourierLimits().MaxHops)
	for _, tc := range []struct {
		name            string
		args            []string
		poster, courier int64
	}{
		{"the defaults", nil, 62_500, 250_000},
		{"a ceiling of 1600", []string{"--courier-carried-max-rows", "1600"}, 100, 400},
		{"a ceiling of 127, the sixteenth under the floor",
			[]string{"--courier-carried-max-rows", "127"}, floor, 31},
		{"a ceiling below the floor", []string{"--courier-carried-max-rows", "5"}, 5, 5},
		{"an unlimited ceiling", []string{"--courier-carried-max-rows", "0"}, 62_500, 250_000},
		{"a poster share set", []string{"--courier-carried-max-rows", "1600",
			"--courier-carried-rows-per-poster", strconv.FormatInt(floor+1, 10)}, floor + 1, 400},
		{"a courier share set", []string{"--courier-carried-max-rows", "1600",
			"--courier-carried-rows-per-courier", "1600"}, 100, 1600},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := resolvePeered(t, tc.args...)
			if err != nil {
				t.Fatalf("%v: %v; want the derived shares to validate", tc.args, err)
			}
			poster, courier, printed := printedShares(t, cfg)
			if poster != tc.poster || courier != tc.courier {
				t.Fatalf("%v printed per poster %d, per courier %d; want %d and %d",
					tc.args, poster, courier, tc.poster, tc.courier)
			}
			limits, err := cfg.Courier.Relay()
			if err != nil {
				t.Fatal(err)
			}
			if limits.CarriedRowsPerPoster != tc.poster || limits.CarriedRowsPerCourier != tc.courier {
				t.Errorf("the library is handed %d and %d; want what is printed, %d and %d",
					limits.CarriedRowsPerPoster, limits.CarriedRowsPerCourier, tc.poster, tc.courier)
			}
			back, err := resolve(t, writeFile(t, printed))
			if err != nil {
				t.Fatalf("the printed configuration does not load again: %v", err)
			}
			bp, bc, _ := printedShares(t, back)
			if bp != tc.poster || bc != tc.courier {
				t.Errorf("loaded again, per poster %d, per courier %d; want %d and %d",
					bp, bc, tc.poster, tc.courier)
			}
		})
	}
}

// TestPrintedConfigCarriesTheCourierNumbers: the printed configuration is the
// record of what the relay is doing, so every bound is in it and loads again.
func TestPrintedConfigCarriesTheCourierNumbers(t *testing.T) {
	cfg, err := resolvePeered(t, "--courier-max-hops", "3", "--courier-forward-ttl", "5h",
		"--courier-carried-max-rows", "7")
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := Encode(&out, cfg.Redacted()); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"max_hops", "forward_ttl", "queue_max_bytes", "queue_max_messages",
		"queue_max_messages_per_poster", "queue_max_messages_per_courier",
		"queue_max_bytes_per_poster", "posts_per_minute",
		"post_bytes_per_hour", "carried_max_rows",
		"carried_rows_per_poster", "carried_rows_per_courier"} {
		if !strings.Contains(out.String(), key) {
			t.Errorf("--print-config output is missing %q", key)
		}
	}
	back, err := resolve(t, writeFile(t, out.String()))
	if err != nil {
		t.Fatalf("the printed configuration does not load again: %v", err)
	}
	// The duration round trips as the operator wrote it, not as Go would
	// print it: the printed configuration is their file back again.
	if back.Courier.MaxHops != 3 || back.Courier.ForwardTTL != "5h" || back.Courier.CarriedMaxRows != 7 {
		t.Fatalf("the courier's numbers did not round trip: %+v", back.Courier)
	}
	// A ceiling of 7 has a sixteenth of 0 and a quarter of 1, each under
	// the floor at max_hops 3, which is itself above the ceiling, so each
	// share stops at the ceiling, 7; and 7 is what comes back.
	if f := relay.CarriedShareFloor(3); f <= 7 {
		t.Fatalf("CarriedShareFloor(3) is %d; this case wants it above the ceiling of 7", f)
	}
	if cfg.Courier.CarriedRowsPerPoster != 7 || cfg.Courier.CarriedRowsPerCourier != 7 {
		t.Errorf("the derived shares are %d and %d; want the ceiling, 7 and 7",
			cfg.Courier.CarriedRowsPerPoster, cfg.Courier.CarriedRowsPerCourier)
	}
	if back.Courier.CarriedRowsPerPoster != 7 || back.Courier.CarriedRowsPerCourier != 7 {
		t.Errorf("the shares loaded again are %d and %d; want 7 and 7",
			back.Courier.CarriedRowsPerPoster, back.Courier.CarriedRowsPerCourier)
	}
}

// TestANullCarriedShareIsAbsent: a share key the file gives as null is a
// share the file did not set, so it is derived from the file's ceiling and
// does not keep the default ceiling's fraction the decode left in place.
func TestANullCarriedShareIsAbsent(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "couriers"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "relay.json")
	body := `{"tls": {"mode": "off"}, "registration": "closed", "courier": {
		"authorized_file": "couriers", "carried_max_rows": 1600,
		"carried_rows_per_poster": null, "carried_rows_per_courier": null}}`
	if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := resolve(t, file)
	if err != nil {
		t.Fatalf("a null share under a ceiling of 1600: %v; want it read as absent", err)
	}
	poster, courier, _ := printedShares(t, cfg)
	if poster != 100 || courier != 400 {
		t.Errorf("null shares under a ceiling of 1600 printed %d and %d; want the derived 100 and 400",
			poster, courier)
	}
}

// TestTheCarriedShareFlagsDefaultToZero: a share's default is worked out
// from the ceiling, so the flag set's own default is 0 and the help says
// derived rather than printing a number that holds only at the default
// ceiling.
func TestTheCarriedShareFlagsDefaultToZero(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	registerFlags(fs)
	for _, name := range []string{"courier-carried-rows-per-poster", "courier-carried-rows-per-courier"} {
		fl := fs.Lookup(name)
		if fl == nil {
			t.Fatalf("--%s is not a flag", name)
		}
		if fl.DefValue != "0" {
			t.Errorf("--%s defaults to %q; want \"0\"", name, fl.DefValue)
		}
		if !strings.Contains(fl.Usage, "derived") {
			t.Errorf("--%s help %q does not say the share is derived", name, fl.Usage)
		}
	}
}

// TestOpenRegistrationBesideACourierHomeIsRefused: a pair that cancels a
// guarantee is refused at the start and not written down somewhere hopeful.
//
// The forward route is open to every identity with a mailbox on this relay,
// because forwarding is what this relay's own users do. With registration
// open, anybody can become one of those users in a single request and post
// through this relay to its neighbours, arriving there under this relay's own
// courier identity. Nothing of it is delivered — the recipient's allow list
// runs at the relay that delivers — but the neighbour's queue and the budget
// they gave this relay are spent, and their only remedy is to stop accepting
// from an operator who did nothing wrong.
func TestOpenRegistrationBesideACourierHomeIsRefused(t *testing.T) {
	home := courierHome(t, "bar", "https://bar.example")
	_, err := resolve(t, "", "--courier-home", home)
	if err == nil {
		t.Fatal("open registration beside a courier home started")
	}
	for _, want := range []string{"registration is open", "courier.home",
		"under this relay's own courier", "token or closed"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%v does not say %q", err, want)
		}
	}
	// Either repair is taken.
	if _, err := resolve(t, "", "--registration", "closed", "--courier-home", home); err != nil {
		t.Errorf("registration closed beside a home: %v", err)
	}
	// And accepting from neighbours under open registration is not the
	// pair: what arrives that way is bounded by the couriers file, and
	// nothing leaves this relay on a stranger's account.
	if _, err := resolve(t, "", "--courier-file", couriersFile(t, "bar")); err != nil {
		t.Errorf("open registration beside a couriers file: %v; that is not the pair", err)
	}
}

// TestACourierBlockWithoutTheNewKeyKeepsItsDefault: a settings file written
// before a setting existed gets that setting's default and not its zero.
//
// Zero means unlimited for every bound here, so the difference is the whole
// difference: an operator who upgrades and restarts would otherwise find the
// bound they never asked to turn off silently off. The file is read into the
// defaults rather than into an empty struct, which is what makes that true,
// and this holds it there — the key can be added to the file later, and a
// value in the file still wins.
func TestACourierBlockWithoutTheNewKeyKeepsItsDefault(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "relay.json")
	// A couriers file beside it, since a courier block naming one is
	// validated against the file on disk.
	if err := os.WriteFile(filepath.Join(dir, "couriers"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	// A courier block as an operator would have written it before this
	// setting existed: the other queue bounds set, this one absent.
	write := func(body string) {
		t.Helper()
		if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(`{"tls": {"mode": "off"}, "registration": "closed", "courier": {
		"authorized_file": "couriers",
		"queue_max_messages": 500,
		"queue_max_messages_per_poster": 7,
		"queue_max_bytes_per_poster": 1024
	}}`)
	cfg, err := resolve(t, file)
	if err != nil {
		t.Fatal(err)
	}
	limits, err := cfg.Courier.Relay()
	if err != nil {
		t.Fatal(err)
	}
	want := relay.DefaultCourierLimits().QueueMaxMessagesPerCourier
	if limits.QueueMaxMessagesPerCourier != want {
		t.Errorf("a file that predates the setting gives %d; want the default %d, since zero is "+
			"unlimited and an operator who upgrades did not ask to turn a bound off",
			limits.QueueMaxMessagesPerCourier, want)
	}
	// The keys the file does set are the file's, so this is not the
	// defaults winning over everything.
	if limits.QueueMaxMessagesPerPoster != 7 || limits.QueueMaxMessages != 500 {
		t.Errorf("the file's own values were not read: per poster %d, relay-wide %d",
			limits.QueueMaxMessagesPerPoster, limits.QueueMaxMessages)
	}

	// And when the file does set it, the file wins — including at zero,
	// which is an operator turning it off on purpose.
	write(`{"tls": {"mode": "off"}, "registration": "closed", "courier": {
		"authorized_file": "couriers", "queue_max_messages_per_courier": 0
	}}`)
	cfg, err = resolve(t, file)
	if err != nil {
		t.Fatal(err)
	}
	if limits, err = cfg.Courier.Relay(); err != nil {
		t.Fatal(err)
	}
	if limits.QueueMaxMessagesPerCourier != 0 {
		t.Errorf("an explicit 0 gives %d; unlimited is a value an operator may choose",
			limits.QueueMaxMessagesPerCourier)
	}
}
