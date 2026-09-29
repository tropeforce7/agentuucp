package main

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relay"
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
	cfg, err := resolve(t, "", "--courier-home", home, "--courier-file", file)
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

	over, err := resolve(t, file, "--courier-file", fromFlag, "--courier-home", home)
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
	cfg, err := resolve(t, "", "--courier-home", home, "--courier-file", couriersFile(t, "bar"))
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
	cfg, err := resolve(t, "", "--courier-home", root)
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
	cfg, err := resolve(t, "", "--courier-home", home)
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
