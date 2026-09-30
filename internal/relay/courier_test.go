package relay

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/keyfile"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// courierHome is an auu home as the relay's user would leave it: an identity
// and one entry per neighbour, named as a sender would write the name.
func courierHome(t *testing.T, neighbours map[string]string) string {
	t.Helper()
	id, err := identity.Generate("relay-a")
	if err != nil {
		t.Fatal(err)
	}
	return courierHomeAs(t, id, neighbours)
}

// courierHomeAs is courierHome with the identity given rather than generated,
// for a test where another relay has to admit this one: a courier is admitted
// by an export line, so the neighbour's file and this home must hold the same
// key. A test that peers two relays and lets each generate its own would have
// each signing as a key the other never admitted, and every hand-over would
// be unauthorized.
func courierHomeAs(t *testing.T, id *identity.Identity, neighbours map[string]string) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "courier")
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SaveIdentity(id); err != nil {
		t.Fatal(err)
	}
	for name, url := range neighbours {
		if _, err := s.AddRelay(name, url); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// writeCouriers writes a couriers file: export lines, each name this relay's
// name for that neighbour.
func writeCouriers(t *testing.T, path string, ids ...*identity.Identity) {
	t.Helper()
	var b strings.Builder
	b.WriteString("# the relays this one accepts forwarded mail from\n\n")
	for _, id := range ids {
		b.WriteString(id.Public().ExportLine() + "\n")
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	// A distinct modification time, so a reload does not depend on the
	// filesystem's timestamp resolution.
	future := time.Now().Add(time.Duration(len(ids)+1) * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}
}

// couriersFile writes one and returns its path.
func couriersFile(t *testing.T, ids ...*identity.Identity) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "couriers")
	writeCouriers(t, path, ids...)
	return path
}

// neighbourID is an identity under a name a relay would be known by.
func neighbourID(t *testing.T, name string) *identity.Identity {
	t.Helper()
	id, err := identity.Generate(name)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// logTo is a logger writing into a buffer the test reads.
func logTo(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, nil))
}

// TestACourierBlockThatDoesNothingIsRefused: a block with neither key would
// forward nothing and accept nothing, which is what a relay without one
// already does, so an operator who wrote it meant something and got nothing.
// auu-relay refuses it at the settings file, where the operator can see the
// line; this is the library's own refusal, for an embedder that builds the
// configuration itself.
func TestACourierBlockThatDoesNothingIsRefused(t *testing.T) {
	_, err := NewCourier(CourierConfig{}, slog.Default())
	if err == nil {
		t.Fatal("a courier with neither home nor file was accepted")
	}
	for _, want := range []string{"neither home nor authorized_file", "courier.home", "courier.authorized_file"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%v does not say %q", err, want)
		}
	}
}

// TestACourierHomeWithNoIdentityIsRefusedByName: the home is where the
// relay's second signing key lives, and a home without one cannot post
// anywhere. The sentence names the home and what to run in it.
func TestACourierHomeWithNoIdentityIsRefusedByName(t *testing.T) {
	root := filepath.Join(t.TempDir(), "empty")
	if _, err := store.Open(root); err != nil {
		t.Fatal(err)
	}
	_, err := NewCourier(CourierConfig{Home: root}, slog.Default())
	if err == nil {
		t.Fatal("a home with no identity was accepted")
	}
	for _, want := range []string{root, "holds no identity", "auu init", "no passphrase set", "auu enrol"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%v does not say %q", err, want)
		}
	}
}

// TestACourierHomeWithAnEncryptedIdentityIsRefusedByName: an encrypted home
// needs a passphrase and an agent, and a relay can be asked for neither. The
// refusal says so and says what to make instead, rather than failing later
// with whatever the agent's absence looks like.
func TestACourierHomeWithAnEncryptedIdentityIsRefusedByName(t *testing.T) {
	root := filepath.Join(t.TempDir(), "encrypted")
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
	if err := s.EncryptHome(keyfile.TestPassphrase("passphrase")); err != nil {
		t.Fatal(err)
	}
	_, err = NewCourier(CourierConfig{Home: root}, slog.Default())
	if err == nil {
		t.Fatal("a home with an encrypted identity was accepted")
	}
	if !strings.Contains(err.Error(), root) {
		t.Errorf("%v does not name the home", err)
	}
	// Whichever way the encrypted home fails — the identity comes back
	// remote, or the agent it needs is not there — the operator is told the
	// same thing, because the repair is the same.
	if !strings.Contains(err.Error(), "encrypted") && !strings.Contains(err.Error(), "agent") {
		t.Errorf("%v says neither that the home is encrypted nor that an agent is wanted", err)
	}
}

// TestANeighbourAtThisRelaysOwnURLIsRefused: a relay that is its own
// neighbour would hand an envelope out and take it straight back, which the
// carried table refuses and nobody is told about, so it is refused at the
// start with the name to remove.
func TestANeighbourAtThisRelaysOwnURLIsRefused(t *testing.T) {
	const mine = "https://relay.example"
	// The spellings a person produces: the URL as written, a trailing
	// slash, the scheme's own port typed out, and the case a host name
	// folds. The store refuses to add one relay twice under any of them,
	// so a relay that compared them its own way would take as a neighbour
	// something the home would have called itself.
	for _, theirs := range []string{mine, mine + "/", mine + ":443", strings.ToUpper(mine)} {
		root := courierHome(t, map[string]string{"loop": theirs})
		_, err := NewCourier(CourierConfig{Home: root, PublicURL: mine}, slog.Default())
		if err == nil {
			t.Fatalf("%s: a neighbour at this relay's own URL was accepted", theirs)
		}
		for _, want := range []string{"loop", "public_url", "cannot be its own neighbour", "auu relay rm loop"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%s: %v does not say %q", theirs, err, want)
			}
		}
	}
}

// TestACouriersFileNamingThisRelaysOwnCourierIsRefused: a relay that accepted
// mail from itself would take its own envelopes back.
func TestACouriersFileNamingThisRelaysOwnCourierIsRefused(t *testing.T) {
	root := courierHome(t, nil)
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	self, err := s.Identity()
	if err != nil {
		t.Fatal(err)
	}
	// The line carries this relay's own courier under a neighbour's name.
	path := filepath.Join(t.TempDir(), "couriers")
	line := strings.Replace(self.Public().ExportLine(), "relay-a", "myself", 1)
	if err := os.WriteFile(path, []byte(line+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = NewCourier(CourierConfig{Home: root, AuthorizedFile: path}, slog.Default())
	if err == nil {
		t.Fatal("a couriers file naming this relay's own courier was accepted")
	}
	for _, want := range []string{"own courier identity", "myself", "remove that line"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%v does not say %q", err, want)
		}
	}
}

// TestACouriersFileWithADuplicateIsRefused: one fingerprint is one relay and
// takes one name, and one name is one relay or a path could not say which.
func TestACouriersFileWithADuplicateIsRefused(t *testing.T) {
	twice := neighbourID(t, "bar")
	t.Run("a fingerprint twice", func(t *testing.T) {
		path := couriersFile(t, twice, twice)
		_, err := LoadCouriers(path)
		if err == nil || !strings.Contains(err.Error(), "one neighbour twice") {
			t.Fatalf("%v; want the refusal naming the repeat", err)
		}
	})
	t.Run("a name twice", func(t *testing.T) {
		path := couriersFile(t, neighbourID(t, "bar"), neighbourID(t, "bar"))
		_, err := LoadCouriers(path)
		if err == nil || !strings.Contains(err.Error(), "two neighbours as \"bar\"") {
			t.Fatalf("%v; want the refusal naming the name", err)
		}
	})
	t.Run("a name twice, folded", func(t *testing.T) {
		// The name is a directory in a courier home, and two filesystems
		// spell Bar and bar as one.
		path := couriersFile(t, neighbourID(t, "bar"), neighbourID(t, "Bar"))
		_, err := LoadCouriers(path)
		if err == nil || !strings.Contains(err.Error(), "two neighbours as") {
			t.Fatalf("%v; want the refusal", err)
		}
	})
}

// TestACouriersFileIsHeldToMaxCouriers: at the cap it loads, one over it is
// refused with both numbers.
func TestACouriersFileIsHeldToMaxCouriers(t *testing.T) {
	ids := make([]*identity.Identity, 0, relayapi.MaxCouriers+1)
	for i := range relayapi.MaxCouriers + 1 {
		ids = append(ids, neighbourID(t, fmt.Sprintf("n%d", i)))
	}
	atCap := couriersFile(t, ids[:relayapi.MaxCouriers]...)
	if _, err := LoadCouriers(atCap); err != nil {
		t.Fatalf("%d neighbours: %v; want the cap taken", relayapi.MaxCouriers, err)
	}
	over := couriersFile(t, ids...)
	_, err := LoadCouriers(over)
	if err == nil || !strings.Contains(err.Error(),
		fmt.Sprintf("holds %d neighbours; at most %d", relayapi.MaxCouriers+1, relayapi.MaxCouriers)) {
		t.Fatalf("%d neighbours: %v; want the refusal with both numbers", relayapi.MaxCouriers+1, err)
	}
}

// TestACouriersFileWritableByOthersIsRefused: whoever can write it decides
// which relays may put mail into this one's mailboxes, which is the
// administrators file's rule for the administrators file's reason.
func TestACouriersFileWritableByOthersIsRefused(t *testing.T) {
	if os.Getenv("GOOS") == "windows" {
		t.Skip("a Go FileMode on Windows is made from the read-only attribute and says nothing about who may write")
	}
	for _, mode := range []os.FileMode{0o666, 0o646, 0o622} {
		path := couriersFile(t, neighbourID(t, "bar"))
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		_, err := LoadCouriers(path)
		if err == nil || !strings.Contains(err.Error(), "must not be writable by group or others") {
			t.Errorf("mode %04o: %v; want the refusal", mode, err)
		}
		if err != nil && !strings.Contains(err.Error(), "which relays may forward mail here") {
			t.Errorf("mode %04o: %v does not say what the file decides", mode, err)
		}
	}
	// And the mode a person is told to use is taken.
	path := couriersFile(t, neighbourID(t, "bar"))
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCouriers(path); err != nil {
		t.Errorf("mode 0644: %v; want it taken", err)
	}
}

// TestACourierNameIsHeldToTheRelayNameRule: a neighbour's name is a path
// element a sender writes and a directory in a courier home, so it is held to
// store.ValidRelayName and not merely to the export line's own rule. The
// values here pass identity.ValidName and would be a device on Windows.
func TestACourierNameIsHeldToTheRelayNameRule(t *testing.T) {
	for _, name := range []string{"con", "nul", "com1", "CON", "lpt9.bar"} {
		id := neighbourID(t, name)
		if err := identity.ValidName(name); err != nil {
			t.Fatalf("%q does not pass the export line's own rule, so it proves nothing: %v", name, err)
		}
		path := couriersFile(t, id)
		_, err := LoadCouriers(path)
		if err == nil || !strings.Contains(err.Error(), "device name on Windows") {
			t.Errorf("%q: %v; want the relay name rule's refusal", name, err)
		}
	}
}

// TestTheCouriersReloadWithoutARestart: adding or removing a neighbour is an
// edit, as appointing an administrator is, and a file that cannot be read
// keeps the neighbours loaded earlier rather than locking every one of them
// out of a relay that may be under attack.
func TestTheCouriersReloadWithoutARestart(t *testing.T) {
	bar, baz := neighbourID(t, "bar"), neighbourID(t, "baz")
	path := filepath.Join(t.TempDir(), "couriers")
	writeCouriers(t, path, bar)

	var buf bytes.Buffer
	loaded, err := LoadCouriers(path)
	if err != nil {
		t.Fatal(err)
	}
	set := newCourierSet(path, loaded, "", logTo(&buf))

	if name, ok := set.lookup(bar.Public().Fingerprint()); !ok || name != "bar" {
		t.Fatalf("bar is %q, %v; want bar", name, ok)
	}
	if _, ok := set.lookup(baz.Public().Fingerprint()); ok {
		t.Fatal("baz is a neighbour before the file names it")
	}

	writeCouriers(t, path, bar, baz)
	if name, ok := set.lookup(baz.Public().Fingerprint()); !ok || name != "baz" {
		t.Fatalf("after the edit baz is %q, %v; want baz", name, ok)
	}
	if set.count() != 2 {
		t.Errorf("%d neighbours after the edit, want 2", set.count())
	}
	if !strings.Contains(buf.String(), "couriers reloaded") {
		t.Errorf("the reload was silent: %s", buf.String())
	}

	// A file that has gone keeps what was loaded, and says so once.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	buf.Reset()
	if name, ok := set.lookup(bar.Public().Fingerprint()); !ok || name != "bar" {
		t.Errorf("with the file gone bar is %q, %v; want the set loaded earlier", name, ok)
	}
	if !strings.Contains(buf.String(), "keeping the neighbours loaded earlier") {
		t.Errorf("the missing file was silent: %s", buf.String())
	}
	// Once per run of failures, not once per message.
	buf.Reset()
	set.lookup(bar.Public().Fingerprint())
	if buf.Len() != 0 {
		t.Errorf("a second look said it again: %s", buf.String())
	}
}

// TestAcceptsAnswersThisRelaysNameForANeighbour: what Accepts answers is the
// name that goes into the return path, so a reply travels back along a name
// the relay that wrote it reads.
func TestAcceptsAnswersThisRelaysNameForANeighbour(t *testing.T) {
	bar := neighbourID(t, "bar")
	stranger := neighbourID(t, "nobody")
	root := courierHome(t, map[string]string{"bar": "http://127.0.0.1:1"})
	c, err := NewCourier(CourierConfig{
		Home: root, AuthorizedFile: couriersFile(t, bar), PublicURL: "https://a.example",
	}, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	if name, ok := c.Accepts(bar.Public().Fingerprint()); !ok || name != "bar" {
		t.Errorf("Accepts(bar) = %q, %v; want bar", name, ok)
	}
	if name, ok := c.Accepts(stranger.Public().Fingerprint()); ok {
		t.Errorf("Accepts(a stranger) = %q, %v; want none", name, ok)
	}
	if r, ok := c.Neighbour("bar"); !ok || r.URL != "http://127.0.0.1:1" {
		t.Errorf("Neighbour(bar) = %v, %v; want the entry from the home", r, ok)
	}
	if _, ok := c.Neighbour("baz"); ok {
		t.Error("Neighbour(baz) answers for a name the home does not have")
	}
	// A nil courier is a relay that forwards nothing and accepts nothing,
	// and both answers are no rather than a panic.
	var none *Courier
	if _, ok := none.Accepts(bar.Public().Fingerprint()); ok {
		t.Error("a relay with no courier accepts one")
	}
	if _, ok := none.Neighbour("bar"); ok {
		t.Error("a relay with no courier has a neighbour")
	}
}

// TestTheStartSaysWhichPeeringsAreOneWay: one-way peering is allowed, and a
// name in one of the two places and not the other is also what a typo looks
// like, so the start says it and the operator decides which it is.
func TestTheStartSaysWhichPeeringsAreOneWay(t *testing.T) {
	// bar is on both sides; baz is dialled and not accepted; qux is
	// accepted and not dialled.
	bar := neighbourID(t, "bar")
	qux := neighbourID(t, "qux")
	root := courierHome(t, map[string]string{
		"bar": "http://127.0.0.1:1",
		"baz": "http://127.0.0.1:2",
	})
	var buf bytes.Buffer
	if _, err := NewCourier(CourierConfig{
		Home: root, AuthorizedFile: couriersFile(t, bar, qux), PublicURL: "https://a.example",
	}, logTo(&buf)); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "accepts mail from a neighbour it cannot dial") || !strings.Contains(out, "qux") {
		t.Errorf("nothing said about qux, accepted and not dialled: %s", out)
	}
	if !strings.Contains(out, "dials a neighbour it accepts no mail from") || !strings.Contains(out, "baz") {
		t.Errorf("nothing said about baz, dialled and not accepted: %s", out)
	}
	if strings.Contains(out, "name=bar") {
		t.Errorf("bar is on both sides and was mentioned: %s", out)
	}
}

// TestOneWayByConfigurationIsNotRemarkedOn: a relay given a home and no file,
// or a file and no home, meant one-way, and saying so at every start would be
// noise rather than news.
func TestOneWayByConfigurationIsNotRemarkedOn(t *testing.T) {
	root := courierHome(t, map[string]string{"bar": "http://127.0.0.1:1"})
	var buf bytes.Buffer
	if _, err := NewCourier(CourierConfig{Home: root}, logTo(&buf)); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "accepts no mail from") {
		t.Errorf("a relay with no couriers file was told about it: %s", buf.String())
	}

	buf.Reset()
	if _, err := NewCourier(CourierConfig{
		AuthorizedFile: couriersFile(t, neighbourID(t, "bar")),
	}, logTo(&buf)); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "cannot dial") {
		t.Errorf("a relay with no home was told about it: %s", buf.String())
	}
}

// TestTheStartSaysWhenACourierCertificateCannotBeRead: the relay's own
// sentence, since internal/dial's says to run a command without saying which
// home to run it in, and the courier's home is not the operator's own. It is
// a warning and not a refusal: the file can be repaired while the relay runs,
// and one damaged certificate must not take the relay away from everybody it
// serves.
func TestTheStartSaysWhenACourierCertificateCannotBeRead(t *testing.T) {
	root := courierHome(t, map[string]string{"bar": "http://127.0.0.1:1"})
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.Relay("bar")
	if err != nil {
		t.Fatal(err)
	}
	// A certificate record whose PEM is not a certificate: there, and
	// unreadable, which is the state the sentence is for.
	rec := &store.CertRecord{
		Relay:     r.URL,
		Serial:    strings.Repeat("0", 31) + "1",
		Label:     "relay",
		Key:       "-----BEGIN PRIVATE KEY-----\nbm90IGEga2V5\n-----END PRIVATE KEY-----\n",
		Cert:      "-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydA==\n-----END CERTIFICATE-----\n",
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour),
	}
	if err := s.SaveCertFor(r, rec); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := NewCourier(CourierConfig{Home: root}, logTo(&buf)); err != nil {
		t.Fatalf("a damaged certificate refused the start: %v; it is a warning", err)
	}
	out := buf.String()
	for _, want := range []string{"cannot be read", "bar", root, "auu register"} {
		if !strings.Contains(out, want) {
			t.Errorf("the warning does not say %q: %s", want, out)
		}
	}
	// A neighbour with no certificate at all is a state, not a fault.
	quiet := courierHome(t, map[string]string{"baz": "http://127.0.0.1:2"})
	buf.Reset()
	if _, err := NewCourier(CourierConfig{Home: quiet}, logTo(&buf)); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "cannot be read") {
		t.Errorf("a neighbour with no certificate was reported: %s", buf.String())
	}
}

// Nothing in this commit is on the wire, and the test that says so is
// TestTheClassifierAgreesWithTheRelay in scope_test.go: it holds every
// pattern the relay registers against a table and fails on one the table
// does not name, whatever the route is called. A test of my own grepping the
// route list for "forward" or "courier" would pass a route named anything
// else, so it is not here. What is below is the other half — that the
// couriers are not served through an answer that already exists.

// TestTheCourierSetIsNotServedInTheStatusAnswer: the administrators' count is
// in the admin status answer; the couriers' is not, since no route reads it
// yet and a field on the wire is a field an end must always send.
func TestTheCourierSetIsNotServedInTheStatusAnswer(t *testing.T) {
	h := newHarness(t, Config{})
	admin := neighbourID(t, "boss")
	path := adminFile(t, admin)
	h.server.admins = newAdminSet(path, nil, h.server.log)
	status, body := h.do(admin, "GET", "/v1/admin/status", nil, nil)
	if status != 200 {
		t.Fatalf("status %d: %s", status, body)
	}
	var answer map[string]json.RawMessage
	if err := json.Unmarshal(body, &answer); err != nil {
		t.Fatal(err)
	}
	for field := range answer {
		if strings.Contains(field, "courier") {
			t.Errorf("the status answer carries %q, and nothing in this commit is on the wire", field)
		}
	}
}

// TestAReloadWillNotAdmitThisRelaysOwnCourier: the start refuses a couriers
// file that admits this relay's own courier, and an edit is the other way the
// same line arrives. The reload refuses the file rather than dropping the
// line, so what is loaded is always a file that was whole, and the relay goes
// on with the neighbours it had.
func TestAReloadWillNotAdmitThisRelaysOwnCourier(t *testing.T) {
	root := courierHome(t, map[string]string{"bar": "http://127.0.0.1:1"})
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	self, err := s.Identity()
	if err != nil {
		t.Fatal(err)
	}
	bar := neighbourID(t, "bar")
	path := filepath.Join(t.TempDir(), "couriers")
	writeCouriers(t, path, bar)

	var buf bytes.Buffer
	c, err := NewCourier(CourierConfig{
		Home: root, AuthorizedFile: path, PublicURL: "https://a.example",
	}, logTo(&buf))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Accepts(bar.Public().Fingerprint()); !ok {
		t.Fatal("bar is not admitted to begin with")
	}

	// Somebody adds this relay's own courier to the file while it runs.
	line := strings.Replace(self.Public().ExportLine(), "relay-a", "myself", 1)
	body := "# neighbours\n" + bar.Public().ExportLine() + "\n" + line + "\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Minute)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}

	buf.Reset()
	if _, ok := c.Accepts(self.Public().Fingerprint()); ok {
		t.Error("an edit admitted this relay's own courier, which the start refuses")
	}
	if _, ok := c.Accepts(bar.Public().Fingerprint()); !ok {
		t.Error("the refused reload lost the neighbours loaded earlier")
	}
	out := buf.String()
	for _, want := range []string{"own courier", "myself", "keeping the neighbours loaded earlier"} {
		if !strings.Contains(out, want) {
			t.Errorf("the warning does not say %q: %s", want, out)
		}
	}
}

// TestAPeeringIsOneNeighbourWhateverTheCase: each half of a peering folds
// internally — the home refuses two relays whose names differ only in case,
// and so does the couriers file, each name being a directory — so the two
// halves are matched folded as well. Unfolded, a file saying Bar against a
// home saying bar is one correctly configured neighbour reported as one-way
// in both directions, and a path naming Bar would find no neighbour at all.
func TestAPeeringIsOneNeighbourWhateverTheCase(t *testing.T) {
	root := courierHome(t, map[string]string{"bar": "http://127.0.0.1:1"})
	var buf bytes.Buffer
	c, err := NewCourier(CourierConfig{
		Home:           root,
		AuthorizedFile: couriersFile(t, neighbourID(t, "Bar")),
		PublicURL:      "https://a.example",
	}, logTo(&buf))
	if err != nil {
		t.Fatal(err)
	}
	if out := buf.String(); strings.Contains(out, "cannot dial") || strings.Contains(out, "accepts no mail from") {
		t.Errorf("one neighbour under two spellings was reported as one-way: %s", out)
	}
	for _, name := range []string{"bar", "Bar", "BAR"} {
		if _, ok := c.Neighbour(name); !ok {
			t.Errorf("Neighbour(%q) found nothing", name)
		}
	}
}

// TestNeighbourHandsOutACopy: the dialling writes the trust anchor's ratchet
// back into the Relay it was given, so a shared pointer would be an
// unsynchronised write the first time a neighbour's authority rotated, and
// the callers are the next commit's workers, one per neighbour.
func TestNeighbourHandsOutACopy(t *testing.T) {
	root := courierHome(t, map[string]string{"bar": "http://127.0.0.1:1"})
	c, err := NewCourier(CourierConfig{Home: root}, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	first, ok := c.Neighbour("bar")
	if !ok {
		t.Fatal("bar is not a neighbour")
	}
	second, _ := c.Neighbour("bar")
	if first == second {
		t.Fatal("two callers were handed the same Relay")
	}
	// What the dialling does to it: the ratchet records what it last saw.
	first.ServerIntSPKI = "changed"
	if second.ServerIntSPKI != "" {
		t.Error("one caller's write reached another's copy")
	}
	third, _ := c.Neighbour("bar")
	if third.ServerIntSPKI != "" {
		t.Error("one caller's write reached the courier's own entry")
	}
}

// TestTheStartSaysWhenAPinnedAnchorCannotBeRead: the dialling needs the
// certificate and the anchor, and a damaged anchor is the same fault for the
// same operator, so the start says it in the same shape.
func TestTheStartSaysWhenAPinnedAnchorCannotBeRead(t *testing.T) {
	root := courierHome(t, map[string]string{"bar": "http://127.0.0.1:1"})
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.Relay("bar")
	if err != nil {
		t.Fatal(err)
	}
	// A relay record that says an anchor was pinned, with no file beside
	// it: what an operator gets by removing the file and leaving the
	// record, which the store names as a home that has been edited.
	r.TrustAnchorSPKI = strings.Repeat("a", 64)
	if err := s.SaveRelay(r); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := NewCourier(CourierConfig{Home: root}, logTo(&buf)); err != nil {
		t.Fatalf("a damaged anchor refused the start: %v; it is a warning", err)
	}
	out := buf.String()
	for _, want := range []string{"anchor", "cannot be read", "bar", root} {
		if !strings.Contains(out, want) {
			t.Errorf("the warning does not say %q: %s", want, out)
		}
	}
}

// TestTheStartSaysThePeeringIsOn: an operator reading a start sees the
// administrators counted, and wants to see the neighbours counted the same
// way; without it the only count is the one a reload prints, which is to say
// only after somebody has edited the file.
func TestTheStartSaysThePeeringIsOn(t *testing.T) {
	root := courierHome(t, map[string]string{
		"bar": "http://127.0.0.1:1",
		"baz": "http://127.0.0.1:2",
	})
	var buf bytes.Buffer
	if _, err := NewCourier(CourierConfig{
		Home:           root,
		AuthorizedFile: couriersFile(t, neighbourID(t, "bar")),
		PublicURL:      "https://a.example",
	}, logTo(&buf)); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"couriers loaded", "neighbours=2", "accepted=1", root} {
		if !strings.Contains(out, want) {
			t.Errorf("the start does not say %q: %s", want, out)
		}
	}
}

// TestTheCourierLogsNameNoFingerprint: every line the peering writes names a
// neighbour by the name this relay's operator gave it, which is theirs and
// not an identity, and never a fingerprint. The relay's own log is read by
// whoever runs it and shipped to whatever collects it, and a fingerprint in
// it is a fact about somebody that nothing there needs.
func TestTheCourierLogsNameNoFingerprint(t *testing.T) {
	bar, qux := neighbourID(t, "bar"), neighbourID(t, "qux")
	root := courierHome(t, map[string]string{
		"bar": "http://127.0.0.1:1",
		"baz": "http://127.0.0.1:2",
	})
	path := filepath.Join(t.TempDir(), "couriers")
	writeCouriers(t, path, bar, qux)

	var buf bytes.Buffer
	c, err := NewCourier(CourierConfig{
		Home: root, AuthorizedFile: path, PublicURL: "https://a.example",
	}, logTo(&buf))
	if err != nil {
		t.Fatal(err)
	}
	// And the lines a reload and a failure write, which are the others.
	writeCouriers(t, path, bar)
	c.Accepts(bar.Public().Fingerprint())
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	c.Accepts(bar.Public().Fingerprint())

	out := buf.String()
	if out == "" {
		t.Fatal("nothing was logged, so this test proves nothing")
	}
	for _, id := range []*identity.Identity{bar, qux} {
		fp := id.Public().Fingerprint()
		if strings.Contains(out, fp) {
			t.Errorf("a fingerprint is in the log: %s", out)
		}
		if strings.Contains(out, fp[:16]) {
			t.Errorf("a short fingerprint is in the log: %s", out)
		}
	}
	// The names that should be there are there, which is what proves the
	// absence above is the rule and not an empty log. bar is not among
	// them: it is on both sides of the peering, and a neighbour that is
	// configured correctly is deliberately not remarked on.
	for _, want := range []string{"qux", "baz", "couriers loaded"} {
		if !strings.Contains(out, want) {
			t.Errorf("the log does not name %q: %s", want, out)
		}
	}
}
