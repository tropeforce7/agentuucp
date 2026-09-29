package main

import (
	"bytes"
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
			_, err := resolve(t, "", "--courier-max-hops", strconv.FormatInt(tc.hops, 10))
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
			_, err := resolve(t, "", args...)
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
		} {
			// Zero is unlimited and is taken; a negative one is refused with
			// the sentence that says what zero means.
			if _, err := resolve(t, "", f, "0"); err != nil {
				t.Errorf("%s 0: %v; want unlimited", f, err)
			}
			_, err := resolve(t, "", f, "-1")
			if err == nil {
				t.Errorf("%s -1 was taken", f)
			} else if !strings.Contains(err.Error(), "use 0 for unlimited") {
				t.Errorf("%s -1: %v; want the sentence naming what zero means", f, err)
			}
			if _, err := resolve(t, "", f, strconv.FormatInt(math.MinInt64, 10)); err == nil {
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
			if _, err := resolve(t, "", f, strconv.Itoa(tc.ceiling)); err != nil {
				t.Errorf("%s at its ceiling: %v", f, err)
			}
			_, err := resolve(t, "", f, strconv.Itoa(tc.ceiling+1))
			if err == nil || !strings.Contains(err.Error(), "at most") {
				t.Errorf("%s one over its ceiling: %v; want the refusal", f, err)
			}
			if _, err := resolve(t, "", f, strconv.FormatInt(math.MaxInt64, 10)); err == nil {
				t.Errorf("%s MaxInt64 was taken", f)
			}
		}
	})
}

// TestPrintedConfigCarriesTheCourierNumbers: the printed configuration is the
// record of what the relay is doing, so every bound is in it and loads again.
func TestPrintedConfigCarriesTheCourierNumbers(t *testing.T) {
	cfg, err := resolve(t, "", "--courier-max-hops", "3", "--courier-forward-ttl", "5h",
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
		"post_bytes_per_hour", "carried_max_rows"} {
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
