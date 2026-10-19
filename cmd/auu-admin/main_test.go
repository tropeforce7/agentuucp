package main

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/agent"
	"github.com/tropeforce7/agentuucp/internal/allowlist"
	"github.com/tropeforce7/agentuucp/internal/card"
	"github.com/tropeforce7/agentuucp/internal/channels"
	"github.com/tropeforce7/agentuucp/internal/client"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/keyfile"
	"github.com/tropeforce7/agentuucp/internal/recipients"
	"github.com/tropeforce7/agentuucp/internal/relay"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/store"
	"github.com/tropeforce7/agentuucp/internal/token"
	"github.com/tropeforce7/agentuucp/internal/wire"
)

// fixture is a relay with one administrator, plus homes for whoever a test
// needs to be.
type fixture struct {
	t     *testing.T
	url   string
	store *relay.Store
	// dbPath is the relay's database, for a test that edits a row the
	// way an intruder on the host would.
	dbPath string
	boss   *persona
}

// persona is one AUU_HOME with an identity in it.
type persona struct {
	t    *testing.T
	home string
	id   *identity.Identity
}

func newPersona(t *testing.T, name, relayURL string) *persona {
	t.Helper()
	home := t.TempDir()
	s, err := store.Open(home)
	if err != nil {
		t.Fatal(err)
	}
	id, err := identity.Generate(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SaveIdentity(id); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveConfig(store.Config{Name: name}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddRelay("", relayURL); err != nil {
		t.Fatal(err)
	}
	return &persona{t: t, home: home, id: id}
}

// run executes a auu-admin command as this persona, capturing stdout.
func (p *persona) run(args ...string) string {
	p.t.Helper()
	out, err := p.tryRun(args...)
	if err != nil {
		p.t.Fatalf("auu-admin %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

func (p *persona) tryRun(args ...string) (string, error) {
	p.t.Helper()
	p.t.Setenv("AUU_HOME", p.home)

	realStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		p.t.Fatal(err)
	}
	os.Stdout = w
	runErr := run(args)
	w.Close()
	os.Stdout = realStdout

	data, _ := io.ReadAll(r)
	r.Close()
	return string(data), runErr
}

func newFixture(t *testing.T, cfg relay.Config) *fixture {
	t.Helper()
	boss, err := identity.Generate("boss")
	if err != nil {
		t.Fatal(err)
	}
	adminPath := filepath.Join(t.TempDir(), "admins")
	if err := os.WriteFile(adminPath, []byte(boss.Public().ExportLine()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	st, err := relay.OpenStore(filepath.Join(dir, "relay.db"), filepath.Join(dir, "messages"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	cfg.AdminFile = adminPath
	cfg.Streams = true
	cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	if cfg.TokenMaxAge == 0 {
		cfg.TokenMaxAge = 720 * time.Hour
	}
	srv := httptest.NewServer(relay.NewServer(st, cfg))
	t.Cleanup(srv.Close)

	// The administrator's home carries the identity the file names.
	f := &fixture{t: t, url: srv.URL, store: st, dbPath: filepath.Join(dir, "relay.db")}
	f.boss = &persona{t: t, home: t.TempDir(), id: boss}
	s, err := store.Open(f.boss.home)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SaveIdentity(boss); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveConfig(store.Config{Name: "boss"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddRelay("", srv.URL); err != nil {
		t.Fatal(err)
	}
	return f
}

// enroll registers an identity directly, for tests setting the scene.
func (f *fixture) enroll(ids ...*identity.Identity) {
	f.t.Helper()
	for _, id := range ids {
		if err := f.store.Register(id.Fingerprint(), id.Public().Bundle(), id.Name,
			relay.RegisterOptions{}); err != nil {
			f.t.Fatal(err)
		}
	}
}

func TestStatus(t *testing.T) {
	f := newFixture(t, relay.Config{Registration: relayapi.RegistrationToken})
	out := f.boss.run("status", "--json")
	var st relayapi.AdminStatusResponse
	if err := json.Unmarshal([]byte(out), &st); err != nil {
		t.Fatalf("status --json unparseable: %v\n%s", err, out)
	}
	if st.Administrators != 1 || st.Registration != relayapi.RegistrationToken {
		t.Fatalf("unexpected status: %+v", st)
	}
	// And the human form says the same things.
	plain := f.boss.run("status")
	for _, want := range []string{"registration:", "administrators:", "mailboxes:", "max recipients: 32\n"} {
		if !strings.Contains(plain, want) {
			t.Fatalf("status output is missing %q:\n%s", want, plain)
		}
	}
}

// The relay's max_recipients is said when the status answer carries its
// section, and nothing is said from a relay from before the setting, whose
// answer carries none.
func TestTheStatusSaysMaxRecipientsWhenTheRelayDoes(t *testing.T) {
	f := newFixture(t, relay.Config{Limits: relay.Limits{MaxRecipients: 7}})
	if plain := f.boss.run("status"); !strings.Contains(plain, "max recipients: 7\n") {
		t.Fatalf("status from a relay set to 7 does not say so:\n%s", plain)
	}
	if got := maxRecipientsLine(nil); got != "" {
		t.Errorf("an answer with no section: %q; want nothing said", got)
	}
	section := []wire.Section{{Name: recipients.MaxName, Data: json.RawMessage(`{"max":12}`)}}
	if got := maxRecipientsLine(section); got != "max recipients: 12\n" {
		t.Errorf("an answer saying 12: %q", got)
	}
}

// The likeliest reason to be refused is simply not being an administrator, and
// the message has to say so rather than showing a bare 401.
func TestNotAnAdministrator(t *testing.T) {
	f := newFixture(t, relay.Config{})
	outsider := newPersona(t, "outsider", f.url)

	_, err := outsider.tryRun("status")
	if err == nil {
		t.Fatal("a non-administrator got a status report")
	}
	msg := err.Error()
	if !strings.Contains(msg, "not an administrator") {
		t.Fatalf("error %q does not explain what is wrong", msg)
	}
	if !strings.Contains(msg, "auu id export") {
		t.Fatalf("error %q does not say how to fix it", msg)
	}
	var e *exitError
	if !asExit(err, &e) || e.code != exitTransport {
		t.Fatalf("expected exit code %d, got %v", exitTransport, err)
	}
}

func TestTokenIssueListRevoke(t *testing.T) {
	f := newFixture(t, relay.Config{Registration: relayapi.RegistrationToken})

	out := f.boss.run("token", "issue", "--note", "Bob, protocol review", "--expires", "168h")
	lines := strings.Split(strings.TrimSpace(out), "\n")
	raw := lines[len(lines)-1]
	// The token is the last line and nothing else, so it can be piped.
	if !strings.HasPrefix(raw, token.Prefix+".") {
		t.Fatalf("the last line is not a token:\n%s", out)
	}
	if !strings.Contains(out, "Bob, protocol review") {
		t.Fatalf("issue did not show the note:\n%s", out)
	}
	if !strings.Contains(out, "signature: checked") {
		t.Fatalf("issue did not confirm it signed the token:\n%s", out)
	}

	// It is registered, live, and usable.
	listed := f.boss.run("token", "ls", "--json")
	var tokens []relayapi.TokenRecord
	if err := json.Unmarshal([]byte(listed), &tokens); err != nil {
		t.Fatal(err)
	}
	if len(tokens) != 1 || tokens[0].State != relayapi.TokenLive {
		t.Fatalf("unexpected token list: %+v", tokens)
	}
	if strings.Contains(listed, raw) {
		t.Fatal("token ls returned the token string")
	}

	// Revoking takes it out of the live list but not out of the record.
	f.boss.run("token", "revoke", tokens[0].ID)
	if out := f.boss.run("token", "ls"); !strings.Contains(out, "no tokens") {
		t.Fatalf("a revoked token is still listed as live:\n%s", out)
	}
	all := f.boss.run("token", "ls", "--all", "--json")
	if err := json.Unmarshal([]byte(all), &tokens); err != nil {
		t.Fatal(err)
	}
	if len(tokens) != 1 || tokens[0].State != relayapi.TokenRevoked {
		t.Fatalf("--all did not show the revoked token: %+v", tokens)
	}

	// Revoking something that does not exist says how to look it up.
	_, err := f.boss.tryRun("token", "revoke", strings.Repeat("a", 32))
	if err == nil || !strings.Contains(err.Error(), "token ls --all") {
		t.Fatalf("error %v does not help", err)
	}
}

func TestTokenIssueRequiresANote(t *testing.T) {
	f := newFixture(t, relay.Config{})
	_, err := f.boss.tryRun("token", "issue")
	if err == nil {
		t.Fatal("a token was issued with no note")
	}
	if !strings.Contains(err.Error(), "shared secret with extra steps") {
		t.Fatalf("error %q does not explain why", err)
	}
}

func TestTokenShowOffline(t *testing.T) {
	f := newFixture(t, relay.Config{})
	out := f.boss.run("token", "issue", "--note", "for a colleague")
	lines := strings.Split(strings.TrimSpace(out), "\n")
	raw := lines[len(lines)-1]

	// The issuer reads their own token back, and the signature checks out.
	shown := f.boss.run("token", "show", raw)
	if !strings.Contains(shown, "for a colleague") {
		t.Fatalf("token show lost the note:\n%s", shown)
	}
	if !strings.Contains(shown, "signature: checked") {
		t.Fatalf("an administrator could not verify their own token:\n%s", shown)
	}

	// Somebody who does not know the issuer is told the signature is unchecked
	// rather than being shown something that looks verified.
	stranger := newPersona(t, "stranger", f.url)
	shown = stranger.run("token", "show", raw)
	if !strings.Contains(shown, "NOT checked") {
		t.Fatalf("an unknown issuer's token looked verified:\n%s", shown)
	}
}

// auu-admin version and --version say what this binary was built from,
// as `auu-admin vX`, asking no relay anything; what the version is depends
// on the tree the test binary was built from, so the assertion is the
// name and that a version is carried.
func TestVersionSaysWhatThisBinaryIs(t *testing.T) {
	stranger := newPersona(t, "stranger", "https://relay.invalid")
	out := stranger.run("version")
	if !strings.HasPrefix(out, "auu-admin ") || strings.TrimSpace(strings.TrimPrefix(out, "auu-admin ")) == "" {
		t.Fatalf("auu-admin version said %q", out)
	}
	if flag := stranger.run("--version"); flag != out {
		t.Fatalf("auu-admin --version said %q, auu-admin version %q", flag, out)
	}
	// An argument it does not take is refused by name, as auu and auu-ca
	// refuse it.
	for _, spelling := range []string{"version", "--version"} {
		if _, err := stranger.tryRun(spelling, "extra"); err == nil || !strings.Contains(err.Error(), `unexpected argument "extra"`) {
			t.Errorf("auu-admin %s extra: %v; want the usage error naming it", spelling, err)
		}
	}
}

func TestMailboxesAndBlocks(t *testing.T) {
	f := newFixture(t, relay.Config{})
	alice, err := identity.Generate("alice")
	if err != nil {
		t.Fatal(err)
	}
	f.enroll(alice)

	if out := f.boss.run("mailboxes", "ls"); !strings.Contains(out, alice.Fingerprint()[:16]) {
		t.Fatalf("alice is not listed:\n%s", out)
	}
	if out := f.boss.run("mailboxes", "show", alice.Fingerprint()); !strings.Contains(out, "alice") {
		t.Fatalf("mailboxes show:\n%s", out)
	}
	// The channel count, zero with no directory and the number of rows
	// once one is pushed; the names are the owner's and never shown. The
	// directory's own word stands beside the count: none until one is
	// pushed, and "-" in the listing, as the allow list and the card are.
	if out := f.boss.run("mailboxes", "show", alice.Fingerprint()); !strings.Contains(out, "channels:    0\n") ||
		!strings.Contains(out, "directory:   none\n") {
		t.Fatalf("mailboxes show does not count channels:\n%s", out)
	}
	d := &channels.Directory{Issued: time.Now(), Channels: []channels.Channel{
		{Name: "default"}, {Name: "xylophone lessons"}, {Name: "bugs"}}}
	doc, sig, err := channels.Sign(alice, d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.SetDirectory(alice.Fingerprint(), d, doc, sig); err != nil {
		t.Fatal(err)
	}
	out := f.boss.run("mailboxes", "show", alice.Fingerprint())
	if !strings.Contains(out, "channels:    3\n") || !strings.Contains(out, "directory:   signed\n") ||
		strings.Contains(out, "xylophone") {
		t.Fatalf("mailboxes show after a directory:\n%s", out)
	}
	if out := f.boss.run("mailboxes", "show", alice.Fingerprint(), "--json"); !strings.Contains(out, `"channels": 3`) ||
		!strings.Contains(out, `"directory": "signed"`) || strings.Contains(out, "xylophone") {
		t.Fatalf("mailboxes show --json:\n%s", out)
	}
	// The listing's whole row, the columns' padding collapsed to one
	// space: the directory's word has a column of its own between the
	// card's and the block state, and the two documents alice has not
	// pushed read "-".
	for _, want := range []string{
		"FINGERPRINT NAME QUEUED BYTES ALLOW CARD DIRECTORY STATE",
		alice.Fingerprint()[:16] + " alice 0 0 B - - signed -",
	} {
		found := false
		ls := f.boss.run("mailboxes", "ls")
		for _, l := range strings.Split(ls, "\n") {
			if strings.Join(strings.Fields(l), " ") == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("no row %q in mailboxes ls:\n%s", want, ls)
		}
	}

	// The allow list: none until one is pushed, then the count and the
	// state word, which is what an operator looks for after an upgrade
	// (broken, from a row without a signature) or an incident (broken). Never the senders.
	if out := f.boss.run("mailboxes", "show", alice.Fingerprint()); !strings.Contains(out, "allowlist:   none\n") {
		t.Fatalf("mailboxes show with no allow list:\n%s", out)
	}
	if out := f.boss.run("mailboxes", "ls"); !strings.Contains(out, "  -  ") {
		t.Fatalf("mailboxes ls with no allow list:\n%s", out)
	}
	bob, _ := identity.Generate("bob")
	l := &allowlist.Document{Issued: time.Now(), Senders: []string{bob.Fingerprint()}}
	ldoc, lsig, err := allowlist.Sign(alice, l)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.SetAllowlist(alice.Fingerprint(), l, ldoc, lsig); err != nil {
		t.Fatal(err)
	}
	if out := f.boss.run("mailboxes", "show", alice.Fingerprint()); !strings.Contains(out, "allowlist:   1 senders, signed\n") ||
		strings.Contains(out, bob.Fingerprint()) {
		t.Fatalf("mailboxes show with a signed list:\n%s", out)
	}
	if out := f.boss.run("mailboxes", "ls"); !strings.Contains(out, "  1 signed  ") {
		t.Fatalf("mailboxes ls with a signed list:\n%s", out)
	}
	if out := f.boss.run("mailboxes", "show", alice.Fingerprint(), "--json"); !strings.Contains(out, `"allowlist_size": 1`) ||
		!strings.Contains(out, `"allow": "signed"`) {
		t.Fatalf("mailboxes show --json with a signed list:\n%s", out)
	}
	db, err := sql.Open("sqlite", f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`UPDATE allowlists SET sig = X'00' WHERE fp = ?`, alice.Fingerprint()); err != nil {
		t.Fatal(err)
	}
	if out := f.boss.run("mailboxes", "ls"); !strings.Contains(out, "  1 broken  ") {
		t.Fatalf("mailboxes ls with a broken list:\n%s", out)
	}

	// The card: none until one is pushed, then the two words the relay
	// parsed from it, "neither" for a signed card that says neither, and
	// broken for a row that no longer verifies; the name is never printed,
	// since the relay does not keep it.
	if out := f.boss.run("mailboxes", "show", alice.Fingerprint()); !strings.Contains(out, "card:        none\n") {
		t.Fatalf("mailboxes show with no card:\n%s", out)
	}
	pushCard := func(listed, knocks bool) {
		t.Helper()
		c := &card.Document{Issued: time.Now(), Name: "alice", Listed: listed, Knocks: knocks}
		cdoc, csig, err := card.Sign(alice, c)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.SetCard(alice.Fingerprint(), c, cdoc, csig); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		listed, knocks bool
		want           string
	}{
		{true, true, "listed, knocks"}, {true, false, "listed"}, {false, true, "knocks"}, {false, false, "neither"},
	} {
		pushCard(tc.listed, tc.knocks)
		if out := f.boss.run("mailboxes", "show", alice.Fingerprint()); !strings.Contains(out, "card:        "+tc.want+"\n") {
			t.Fatalf("mailboxes show with a card listed %v knocks %v:\n%s", tc.listed, tc.knocks, out)
		}
		if out := f.boss.run("mailboxes", "ls"); !strings.Contains(out, "  "+tc.want+"  ") {
			t.Fatalf("mailboxes ls with a card listed %v knocks %v:\n%s", tc.listed, tc.knocks, out)
		}
	}
	if out := f.boss.run("mailboxes", "show", alice.Fingerprint(), "--json"); !strings.Contains(out, `"card": "signed"`) ||
		!strings.Contains(out, `"card_listed": false`) || !strings.Contains(out, `"card_knocks": false`) {
		t.Fatalf("mailboxes show --json with a card:\n%s", out)
	}
	if _, err := db.Exec(`UPDATE cards SET sig = X'00' WHERE fp = ?`, alice.Fingerprint()); err != nil {
		t.Fatal(err)
	}
	if out := f.boss.run("mailboxes", "show", alice.Fingerprint()); !strings.Contains(out, "card:        broken\n") {
		t.Fatalf("mailboxes show with a broken card:\n%s", out)
	}
	if out := f.boss.run("mailboxes", "ls"); !strings.Contains(out, "  broken  ") {
		t.Fatalf("mailboxes ls with a broken card:\n%s", out)
	}

	// The directory, once its row no longer verifies: the count stands
	// and the word says none of those channels routes, which is the pair
	// an operator reads together.
	if _, err := db.Exec(`UPDATE directories SET sig = X'00' WHERE fp = ?`, alice.Fingerprint()); err != nil {
		t.Fatal(err)
	}
	if out := f.boss.run("mailboxes", "show", alice.Fingerprint()); !strings.Contains(out, "directory:   broken\n") ||
		!strings.Contains(out, "channels:    3\n") {
		t.Fatalf("mailboxes show with a broken directory:\n%s", out)
	}
	if out := f.boss.run("mailboxes", "show", alice.Fingerprint(), "--json"); !strings.Contains(out, `"directory": "broken"`) {
		t.Fatalf("mailboxes show --json with a broken directory:\n%s", out)
	}

	// Blocking, listing, and lifting it.
	f.boss.run("blocks", "add", alice.Fingerprint(), "--reason", "flooding", "--yes")
	if out := f.boss.run("blocks", "ls"); !strings.Contains(out, "flooding") {
		t.Fatalf("blocks ls:\n%s", out)
	}
	if out := f.boss.run("mailboxes", "ls"); !strings.Contains(out, "blocked") {
		t.Fatalf("a blocked mailbox is not marked as such:\n%s", out)
	}
	f.boss.run("blocks", "rm", alice.Fingerprint())
	if out := f.boss.run("blocks", "ls"); !strings.Contains(out, "no blocks") {
		t.Fatalf("the block was not lifted:\n%s", out)
	}

	// A block with no reason is refused before it reaches the relay.
	if _, err := f.boss.tryRun("blocks", "add", alice.Fingerprint(), "--yes"); err == nil {
		t.Fatal("a block with no reason was accepted")
	}

	// Removing a mailbox says what will go, and then goes.
	f.boss.run("mailboxes", "rm", alice.Fingerprint(), "--yes")
	if out := f.boss.run("mailboxes", "ls"); !strings.Contains(out, "no mailboxes") {
		t.Fatalf("the mailbox survived:\n%s", out)
	}
}

func TestFingerprintArgumentsMustBeComplete(t *testing.T) {
	f := newFixture(t, relay.Config{})
	for _, args := range [][]string{
		{"mailboxes", "show", "abc"},
		{"blocks", "add", "abc", "--reason", "x"},
		{"blocks", "rm", "abc"},
	} {
		if _, err := f.boss.tryRun(args...); err == nil {
			t.Fatalf("%v accepted a partial fingerprint", args)
		} else if !strings.Contains(err.Error(), "all 64 characters") {
			t.Fatalf("%v: error %q does not say what is needed", args, err)
		}
	}
}

func asExit(err error, target **exitError) bool {
	e, ok := err.(*exitError)
	if ok {
		*target = e
	}
	return ok
}

// answer feeds a line to a command that prompts, so the confirmation is
// exercised rather than skipped with --yes. A declined prompt must change
// nothing.
func (p *persona) answer(reply string, args ...string) (string, error) {
	p.t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		p.t.Fatal(err)
	}
	if _, err := w.WriteString(reply + "\n"); err != nil {
		p.t.Fatal(err)
	}
	w.Close()
	realStdin := os.Stdin
	os.Stdin = r
	defer func() {
		os.Stdin = realStdin
		r.Close()
	}()
	return p.tryRun(args...)
}

func TestDeclinedPromptsChangeNothing(t *testing.T) {
	f := newFixture(t, relay.Config{})
	alice, err := identity.Generate("alice")
	if err != nil {
		t.Fatal(err)
	}
	f.enroll(alice)

	t.Run("mailboxes rm", func(t *testing.T) {
		if _, err := f.boss.answer("n", "mailboxes", "rm", alice.Fingerprint()); err == nil {
			t.Fatal("declining reported success")
		}
		if out := f.boss.run("mailboxes", "ls"); !strings.Contains(out, alice.Fingerprint()[:16]) {
			t.Fatalf("a declined removal took the mailbox:\n%s", out)
		}
	})

	t.Run("mailboxes purge", func(t *testing.T) {
		if _, err := f.boss.answer("n", "mailboxes", "purge", alice.Fingerprint()); err == nil {
			t.Fatal("declining reported success")
		}
		if out := f.boss.run("mailboxes", "ls"); !strings.Contains(out, alice.Fingerprint()[:16]) {
			t.Fatalf("a declined purge took the mailbox:\n%s", out)
		}
	})

	t.Run("blocks add", func(t *testing.T) {
		if _, err := f.boss.answer("n", "blocks", "add", alice.Fingerprint(), "--reason", "testing"); err == nil {
			t.Fatal("declining reported success")
		}
		if out := f.boss.run("blocks", "ls"); !strings.Contains(out, "no blocks") {
			t.Fatalf("a declined block was placed:\n%s", out)
		}
	})

	// And accepting does what it says, so the prompt is not simply ignored.
	t.Run("accepted", func(t *testing.T) {
		if _, err := f.boss.answer("y", "blocks", "add", alice.Fingerprint(), "--reason", "testing"); err != nil {
			t.Fatalf("accepting failed: %v", err)
		}
		if out := f.boss.run("blocks", "ls"); !strings.Contains(out, "testing") {
			t.Fatalf("accepting the prompt did nothing:\n%s", out)
		}
	})
}

// Flags placed after a positional argument must still be seen.
func TestAdminFlagsAfterPositionalArguments(t *testing.T) {
	f := newFixture(t, relay.Config{})
	alice, err := identity.Generate("alice")
	if err != nil {
		t.Fatal(err)
	}
	f.enroll(alice)

	out := f.boss.run("mailboxes", "show", alice.Fingerprint(), "--json")
	if !strings.HasPrefix(strings.TrimSpace(out), "{") {
		t.Fatalf("mailboxes show ignored --json after the positional:\n%s", out)
	}

	issued := f.boss.run("token", "issue", "--note", "for a flag test")
	lines := strings.Split(strings.TrimSpace(issued), "\n")
	raw := strings.TrimSpace(lines[len(lines)-1])
	shown := f.boss.run("token", "show", raw, "--json")
	if !strings.HasPrefix(strings.TrimSpace(shown), "{") {
		t.Fatalf("token show ignored --json after the positional:\n%s", shown)
	}
}

// --uses and --expires are numbers from an administrator's shell.
func TestTokenIssueArgumentExtremes(t *testing.T) {
	f := newFixture(t, relay.Config{})

	for _, args := range [][]string{
		{"token", "issue", "--note", "x", "--uses", "0"},
		{"token", "issue", "--note", "x", "--uses", "-1"},
		{"token", "issue", "--note", "x", "--uses", "1001"},
		{"token", "issue", "--note", "x", "--uses", "9223372036854775807"},
		{"token", "issue", "--note", "x", "--expires", "-1h"},
		{"token", "issue", "--note", "x", "--expires", "0s"},
		{"token", "issue", "--note", "x", "--expires", "1ns"}, // rounds to the same second
		{"token", "issue", "--note", "x", "--not-after", "1999-01-01T00:00:00Z"},
		{"token", "issue", "--note", "x", "--for", "short"},
		{"token", "issue", "--note", strings.Repeat("n", 201)},
	} {
		if _, err := f.boss.tryRun(args...); err == nil {
			t.Errorf("%v was accepted", args[2:])
		}
	}

	// The accepted edges. --expires is a minute rather than the one second
	// that is its real edge: a one-second token has at most one second of
	// life and often far less, because the window is truncated to whole
	// seconds, and it still has to survive a TLS handshake and a round trip
	// to the relay before the relay checks whether it has expired. That made
	// this test fail about one race run in four under load. The edge itself
	// is TestLimitTheTokenWindowIsWholeSecondsFromNow, which walks it
	// without a relay.
	for _, args := range [][]string{
		{"token", "issue", "--note", "x", "--uses", "1"},
		{"token", "issue", "--note", "x", "--uses", "1000"},
		{"token", "issue", "--note", strings.Repeat("n", 200)},
		{"token", "issue", "--note", "x", "--expires", "1m"},
	} {
		if _, err := f.boss.tryRun(args...); err != nil {
			t.Errorf("%v was refused: %v", args[2:], err)
		}
	}
}

// TestLimitTheTokenWindowIsWholeSecondsFromNow walks the boundary the
// command enforces on --expires and --not-after, in the arithmetic the
// token actually carries, and at every phase of the second now might fall
// in: the ledger's test for --expires, since a round trip cannot show a
// one-second token taken without racing the clock (TestLimitAdminFlags
// carries the flag's text forms, with hours of slack).
//
// A token records two whole seconds, so a sub-second duration left to the
// truncation would be accepted or refused according to where in the current
// second now fell — --expires 1ns is a full second of life at phase .999 and
// none at phase .001. It is refused at every phase instead, and the phases
// below are what proves that, since no end-to-end test can choose when now
// is. This is what TestTokenIssueArgumentExtremes used to reach for with a
// one-second token and a round trip, and lose about one race run in four,
// and what TestLimitAdminFlags reached for again and lost once.
func TestLimitTheTokenWindowIsWholeSecondsFromNow(t *testing.T) {
	// A whole second, so the phase below is the only thing varying.
	base := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)

	for _, tc := range []struct {
		name    string
		expires time.Duration
		ok      bool
	}{
		{"a week, the default", 168 * time.Hour, true},
		{"a second, the shortest there is", MinTokenLife, true},
		{"a second and a nanosecond", MinTokenLife + 1, true},
		{"a nanosecond under a second", MinTokenLife - 1, false},
		{"half a second", 500 * time.Millisecond, false},
		{"a nanosecond", 1, false},
		{"nothing", 0, false},
		{"a nanosecond in the past", -1, false},
		{"an hour in the past", -time.Hour, false},
		{"the largest duration there is", time.Duration(math.MaxInt64), true},
		{"the smallest duration there is", time.Duration(math.MinInt64), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Every phase of the second, because the truncation is what
			// decides and a test that only ever starts on a whole second
			// would never see the case that made this flake.
			for _, phase := range []time.Duration{
				0, time.Nanosecond, time.Millisecond, 500 * time.Millisecond,
				999 * time.Millisecond, time.Second - time.Nanosecond,
			} {
				now := base.Add(phase)
				notBefore, notAfter, err := tokenWindow(now, tc.expires, "")
				if tc.ok {
					if err != nil {
						t.Fatalf("phase %v: %v was refused: %v", phase, tc.expires, err)
					}
					if notBefore != now.Unix() {
						t.Errorf("phase %v: not_before is %d, want %d", phase, notBefore, now.Unix())
					}
					if notAfter <= notBefore {
						t.Errorf("phase %v: the window is %d seconds wide", phase, notAfter-notBefore)
					}
					continue
				}
				if err == nil {
					t.Fatalf("phase %v: %v was accepted, giving a window of %d seconds",
						phase, tc.expires, notAfter-notBefore)
				}
				if !strings.Contains(err.Error(), "--expires") {
					t.Errorf("phase %v: error %q does not name the flag that was wrong", phase, err)
				}
			}
		})
	}
}

// TestNotAfterOverridesExpiresAndIsCheckedTheSameWay.
func TestNotAfterOverridesExpiresAndIsCheckedTheSameWay(t *testing.T) {
	now := time.Date(2026, 9, 10, 12, 0, 0, 500_000_000, time.UTC)
	for _, tc := range []struct {
		name  string
		value string
		ok    bool
	}{
		{"next year", "2027-09-10T12:00:00Z", true},
		{"the next whole second", "2026-09-10T12:00:01Z", true},
		{"the second now is in", "2026-09-10T12:00:00Z", false},
		{"the second before", "2026-09-10T11:59:59Z", false},
		{"long ago", "1999-01-01T00:00:00Z", false},
		{"not a timestamp", "next Tuesday", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// A --expires that would be fine on its own, to prove the
			// absolute value is what is used.
			notBefore, notAfter, err := tokenWindow(now, 168*time.Hour, tc.value)
			if tc.ok {
				if err != nil {
					t.Fatalf("%s was refused: %v", tc.value, err)
				}
				want, perr := time.Parse(time.RFC3339, tc.value)
				if perr != nil {
					t.Fatal(perr)
				}
				if notAfter != want.Unix() {
					t.Errorf("not_after is %d, want %d: --expires won", notAfter, want.Unix())
				}
				if notBefore != now.Unix() {
					t.Errorf("not_before is %d, want %d", notBefore, now.Unix())
				}
				return
			}
			if err == nil {
				t.Fatalf("%s was accepted", tc.value)
			}
			if !strings.Contains(err.Error(), "--not-after") {
				t.Errorf("error %q does not name --not-after", err)
			}
		})
	}
}

// An administrator's home may know several relays, so auu-admin picks one the
// same way auu does: the flag, then the environment, then the default.
func TestTheRelayIsChosenByNameEnvironmentOrDefault(t *testing.T) {
	work := newFixture(t, relay.Config{})
	boss := work.boss

	// A second relay that answers to the same administrator, so that both
	// are hers and only the selection differs.
	admins := filepath.Join(t.TempDir(), "admins")
	if err := os.WriteFile(admins, []byte(boss.id.Public().ExportLine()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	st, err := relay.OpenStore(filepath.Join(dir, "relay.db"), filepath.Join(dir, "messages"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	second := httptest.NewServer(relay.NewServer(st, relay.Config{
		AdminFile:   admins,
		TokenMaxAge: 720 * time.Hour,
		Streams:     true,
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}))
	t.Cleanup(second.Close)

	s, err := store.Open(boss.home)
	if err != nil {
		t.Fatal(err)
	}
	def, err := s.DefaultRelay()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RenameRelay(def.Name, "work"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddRelay("personal", second.URL); err != nil {
		t.Fatal(err)
	}

	// The status line names the relay the command acted on, which is the
	// only thing this test is about.
	relayOf := func(args ...string) string {
		t.Helper()
		out := boss.run(args...)
		for _, line := range strings.Split(out, "\n") {
			if strings.HasPrefix(line, "relay:") {
				return strings.TrimSpace(strings.TrimPrefix(line, "relay:"))
			}
		}
		t.Fatalf("no relay line in:\n%s", out)
		return ""
	}

	if got := relayOf("status"); got != work.url {
		t.Errorf("with nothing set the relay is %q, want %q", got, work.url)
	}
	if got := relayOf("status", "--relay", "personal"); got != second.URL {
		t.Errorf("--relay personal gave %q, want %q", got, second.URL)
	}
	if got := relayOf("status", "--relay", second.URL); got != second.URL {
		t.Errorf("--relay by URL gave %q, want %q", got, second.URL)
	}
	t.Setenv("AUU_RELAY", "personal")
	if got := relayOf("status"); got != second.URL {
		t.Errorf("AUU_RELAY=personal gave %q, want %q", got, second.URL)
	}
	if got := relayOf("status", "--relay", "work"); got != work.url {
		t.Errorf("--relay work under AUU_RELAY=personal gave %q, want %q", got, work.url)
	}
	t.Setenv("AUU_RELAY", "")

	// A URL the home does not know is still administered: that is how the
	// first administrator's machine starts, before anybody has joined.
	if got := relayOf("status", "--relay", second.URL+"/"); got != second.URL {
		t.Errorf("--relay by an unknown-shaped URL gave %q", got)
	}
	// A name nothing matches is refused rather than guessed at.
	if _, err := boss.tryRun("status", "--relay", "nowhere"); err == nil {
		t.Error("an unknown relay name was accepted")
	}
}

// TestAnAdministratorsEncryptedHomeGoesThroughTheAgent: an administrator's
// identity is an auu identity in an auu home, so an encrypted one is
// loaded the same way and signs through the same agent; locked, the
// program says what auu says, with the same exit code.
func TestAnAdministratorsEncryptedHomeGoesThroughTheAgent(t *testing.T) {
	f := newFixture(t, relay.Config{Registration: relayapi.RegistrationToken})
	dir, err := os.MkdirTemp("", "auu")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	t.Setenv("XDG_RUNTIME_DIR", dir)
	s, err := store.Open(f.boss.home)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.EncryptHome(keyfile.TestPassphrase("correct horse battery staple")); err != nil {
		t.Fatal(err)
	}
	// Locked: no agent at all.
	_, err = f.boss.tryRun("status")
	if err == nil {
		t.Fatal("status with the identity locked succeeded")
	}
	advised := adviseLocked(err)
	var e *exitError
	if !errors.As(advised, &e) || e.code != exitLocked {
		t.Fatalf("a locked identity gave %v, want exit %d", advised, exitLocked)
	}
	if e.Error() != "your identity is locked: run 'auu unlock' in your own terminal" {
		t.Errorf("the advice is %q", e.Error())
	}
	// Unlocked to receive: an in-process agent on the socket, and every
	// administrative route originates, so status is refused with the
	// agent's own sentence and the same code.
	srv := agent.NewServer(s, agent.Options{})
	l, err := agent.Listen(f.boss.home)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(l) }()
	t.Cleanup(func() { srv.Stop(); <-done; l.Close() })
	if err := srv.Unlock([]byte("correct horse battery staple"), 0, agent.ScopeReceive); err != nil {
		t.Fatal(err)
	}
	_, err = f.boss.tryRun("status")
	advised = adviseLocked(err)
	if !errors.As(advised, &e) || e.code != exitLocked || e.Error() != agent.ReceiveOnlyMessage {
		t.Fatalf("status in receive scope gave %v, want exit %d and %q", advised, exitLocked, agent.ReceiveOnlyMessage)
	}
	// Unlocked to send, and status works.
	if err := srv.Unlock([]byte("correct horse battery staple"), 0, agent.ScopeSend); err != nil {
		t.Fatal(err)
	}
	out := f.boss.run("status", "--json")
	var st relayapi.AdminStatusResponse
	if err := json.Unmarshal([]byte(out), &st); err != nil {
		t.Fatalf("status --json unparseable: %v\n%s", err, out)
	}
	if st.Administrators != 1 {
		t.Errorf("status through the agent: %+v", st)
	}
}

// An administrator's home is an auu home, and a damaged file in it exits 5
// here as it does from auu: the sentence names the file, the code says a
// person has to look.
func TestADamagedFileInAnAdministratorsHomeExitsFive(t *testing.T) {
	f := newFixture(t, relay.Config{Registration: relayapi.RegistrationToken})
	if err := os.WriteFile(filepath.Join(f.boss.home, "config.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := f.boss.tryRun("status")
	if err == nil {
		t.Fatal("status with config.json damaged succeeded")
	}
	advised := adviseLocked(err)
	var e *exitError
	if !errors.As(advised, &e) || e.code != exitDamaged {
		t.Fatalf("a damaged file gave %v, want exit %d", advised, exitDamaged)
	}
	if !strings.Contains(e.Error(), filepath.Join(f.boss.home, "config.json")+" is not valid JSON (") {
		t.Errorf("the sentence does not name the file: %q", e.Error())
	}
}

// TestMailboxesPrintAHostileNameEscaped: a relay that is not ours can
// answer a name with a terminal escape in it, and it reaches
// the operator's terminal through the mailbox listing and the one-mailbox
// view. Both print it with every byte outside the printable set escaped.
func TestMailboxesPrintAHostileNameEscaped(t *testing.T) {
	f := newFixture(t, relay.Config{})
	alice, err := identity.Generate("alice")
	if err != nil {
		t.Fatal(err)
	}
	f.enroll(alice)
	db, err := sql.Open("sqlite", f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	hostile := "alice\x1b[2K\x1b[1;31mowned\nccx2.evil"
	if _, err := db.Exec(`UPDATE mailboxes SET name = ? WHERE fp = ?`, hostile, alice.Fingerprint()); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"mailboxes", "ls"}, {"mailboxes", "show", alice.Fingerprint()}} {
		out := f.boss.run(args...)
		for i := 0; i < len(out); i++ {
			if c := out[i]; c == 0x1b || (c < 0x20 && c != '\n' && c != '\t') {
				t.Fatalf("%v printed byte %#x from the relay's name:\n%q", args, c, out)
			}
		}
		if !strings.Contains(out, `alice\x1b[2K`) {
			t.Fatalf("%v does not show the name escaped:\n%s", args, out)
		}
	}
}

// TestTheRemovalPromptPrintsAHostileNameEscaped: the mailbox listing and
// the one-mailbox view pass the relay's name through identity.Printable,
// whose comment says every place a name from the network reaches a
// terminal goes through it; the confirmation that 'mailboxes rm' and
// 'mailboxes purge' print before asking did not, and put a relay's escape
// sequence on the administrator's terminal at the one moment they are
// reading carefully. Now it is escaped as the listing escapes it.
func TestTheRemovalPromptPrintsAHostileNameEscaped(t *testing.T) {
	f := newFixture(t, relay.Config{})
	alice, err := identity.Generate("alice")
	if err != nil {
		t.Fatal(err)
	}
	f.enroll(alice)
	db, err := sql.Open("sqlite", f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	hostile := "alice\x1b[2K\x1b[1;31mowned\nccx2.evil"
	if _, err := db.Exec(`UPDATE mailboxes SET name = ? WHERE fp = ?`, hostile, alice.Fingerprint()); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"mailboxes", "purge", alice.Fingerprint()},
		{"mailboxes", "rm", alice.Fingerprint()},
	} {
		// Declined, so nothing changes; the prompt is what is under test.
		out, _ := f.boss.answer("n", args...)
		for i := 0; i < len(out); i++ {
			if c := out[i]; c == 0x1b || (c < 0x20 && c != '\n' && c != '\t') {
				t.Errorf("%v printed byte %#x from the relay's name in its confirmation prompt; expected the name escaped as the listing escapes it:\n%q",
					strings.Join(args[:2], " "), c, out)
				break
			}
		}
		if !strings.Contains(out, `(alice\x1b[2K`) {
			t.Errorf("%v does not show the name escaped:\n%s", args[:2], out)
		}
	}
}

// fakeRelay answers each path with the JSON it is given and 404 otherwise:
// a relay that says what a test wants said, however wrong.
func fakeRelay(t *testing.T, answers map[string]any) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := answers[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestAShortFieldInAnAnswerIsRefusedNotSliced: every command that prints an
// id from a relay's answer prints its first sixteen characters, and a Go
// slice past the end of a string is a panic; a relay answering a two-byte
// fingerprint, serial or token id crashed the tool. The client refuses
// such an answer before the command sees it, and the command prints the
// malformed-answer sentence, naming the field and the relay, and exits 2.
// A panic would fail the test on its own.
func TestAShortFieldInAnAnswerIsRefusedNotSliced(t *testing.T) {
	boss, err := identity.Generate("boss")
	if err != nil {
		t.Fatal(err)
	}
	fp := boss.Fingerprint()
	const serial = "0123456789abcdef0123456789abcdef"
	for _, tc := range []struct {
		args   []string
		path   string
		field  string
		answer any
	}{
		{[]string{"status"}, "/v1/admin/status", "ca_fingerprint", relayapi.AdminStatusResponse{CAFingerprint: "ab", Registration: relayapi.RegistrationOpen, ClientCerts: relayapi.ClientCertsOff}},
		{[]string{"status"}, "/v1/admin/status", "token_max_age_seconds", relayapi.AdminStatusResponse{TokenMaxAgeSecs: relayapi.MaxDurationSeconds + 1, Registration: relayapi.RegistrationOpen, ClientCerts: relayapi.ClientCertsOff}},
		{[]string{"mailboxes", "ls"}, "/v1/admin/mailboxes", "fp", relayapi.MailboxListResponse{Mailboxes: []relayapi.MailboxRecord{{FP: "ab"}}}},
		{[]string{"mailboxes", "show", fp}, "/v1/admin/mailboxes/" + fp, "fp", relayapi.MailboxAnswer{Mailbox: relayapi.MailboxRecord{FP: "ab"}}},
		{[]string{"blocks", "ls"}, "/v1/admin/blocks", "by_fp", relayapi.BlocksResponse{Blocks: []relayapi.BlockRecord{{FP: fp, ByFP: "ab"}}}},
		{[]string{"token", "ls"}, "/v1/admin/tokens", "id", relayapi.TokenListResponse{Tokens: []relayapi.TokenRecord{{ID: "ab", Issuer: fp}}}},
		{[]string{"token", "ls"}, "/v1/admin/tokens", "subject", relayapi.TokenListResponse{Tokens: []relayapi.TokenRecord{{ID: strings.Repeat("7", 32), Issuer: fp, Subject: "ab"}}}},
		{[]string{"certs", "ls"}, "/v1/admin/certs", "serial", relayapi.CertsResponse{Certs: []relayapi.CertRecord{{Serial: "ab", FP: fp}}}},
		{[]string{"certs", "ls"}, "/v1/admin/certs", "fp", relayapi.CertsResponse{Certs: []relayapi.CertRecord{{Serial: serial, FP: "ab"}}}},
	} {
		srv := fakeRelay(t, map[string]any{tc.path: tc.answer})
		p := newPersona(t, "boss", srv.URL)
		out, err := p.tryRun(tc.args...)
		var exit *exitError
		if !asExit(err, &exit) || exit.code != exitTransport {
			t.Errorf("auu-admin %v with a bad %s: %v (exit %+v), want exit %d\n%s", tc.args, tc.field, err, exit, exitTransport, out)
			continue
		}
		if !strings.Contains(err.Error(), "malformed answer") || !strings.Contains(err.Error(), tc.field+" is not") || !strings.Contains(err.Error(), srv.URL) {
			t.Errorf("auu-admin %v with a bad %s: %q does not say the answer is malformed, naming the field and the relay", tc.args, tc.field, err)
		}
	}
}

// TestStatusRendersAPebibyte: auu-admin's own humanBytes indexed "KMGT"
// past its end at a pebibyte, and a relay reporting queued_bytes at that
// scale panicked status; the one HumanBytes in term renders it. And a
// pasted token with a short issuer is refused by token show as malformed,
// naming the field, rather than sliced.
func TestStatusRendersAPebibyteAndAShortIssuerIsRefused(t *testing.T) {
	srv := fakeRelay(t, map[string]any{
		"/v1/admin/status": relayapi.AdminStatusResponse{QueuedBytes: 1 << 50, TokenMaxAgeSecs: 3600, Registration: relayapi.RegistrationOpen, ClientCerts: relayapi.ClientCertsOff},
	})
	p := newPersona(t, "boss", srv.URL)
	out := p.run("status")
	if !strings.Contains(out, "1.0 PiB") {
		t.Errorf("status with queued_bytes 2^50 printed:\n%s", out)
	}
	payload, err := json.Marshal(token.Claims{
		ID: strings.Repeat("7", 32), Issuer: "ab", Relay: "https://relay.example.com", Use: token.UseRegister,
		NotBefore: 1, NotAfter: 2, Uses: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	raw := strings.Join([]string{
		token.Prefix,
		base64.RawURLEncoding.EncodeToString(payload),
		base64.RawURLEncoding.EncodeToString(make([]byte, 64)),
	}, ".")
	out, err = p.tryRun("token", "show", raw)
	var exit *exitError
	if !asExit(err, &exit) || exit.code != exitUsage {
		t.Fatalf("token show with a two-character issuer: %v, want a usage error\n%s", err, out)
	}
	if !strings.Contains(err.Error(), "malformed token: issuer is not a fingerprint; nothing was described") {
		t.Errorf("token show: %q does not say the token is malformed and name the field", err)
	}
}

// The string review at af0d96e: auu-admin printed nine strings of the
// relay's raw. Now the enumerated fields — registration, client_certs, the
// allow word, a token's use and state — are held to the protocol's set when
// the answer is read, so a word outside it is a malformed answer, and the
// free text — public_url, uptime, access_log, a block's reason — goes
// through the escaper at the print.

// escapeSeq is a terminal command as a relay would send it: OSC 0 sets
// the window title; the BEL ends it.
const escapeSeq = "\x1b]0;owned\a"

// controlBytes says which byte, if any, in out would drive a terminal.
func controlBytes(out string) (byte, bool) {
	for i := 0; i < len(out); i++ {
		c := out[i]
		if (c < 0x20 && c != '\n' && c != '\t') || c == 0x7f {
			return c, true
		}
	}
	return 0, false
}

func TestStatusEscapesTheRelaysWordsAndHoldsItsEnums(t *testing.T) {
	boss, err := identity.Generate("boss")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		field  string
		enum   bool
		answer relayapi.AdminStatusResponse
	}{
		{"public_url", false, relayapi.AdminStatusResponse{PublicURL: "https://r" + escapeSeq}},
		{"uptime", false, relayapi.AdminStatusResponse{Uptime: "1h" + escapeSeq}},
		{"access_log", false, relayapi.AdminStatusResponse{AccessLog: "full" + escapeSeq}},
		{"registration", true, relayapi.AdminStatusResponse{Registration: "open" + escapeSeq}},
		{"client_certs", true, relayapi.AdminStatusResponse{ClientCerts: "off" + escapeSeq}},
	} {
		tc.answer.CAFingerprint = boss.Fingerprint()
		// The two words the relay always sends, unless the case is about
		// one of them.
		if tc.answer.Registration == "" {
			tc.answer.Registration = relayapi.RegistrationOpen
		}
		if tc.answer.ClientCerts == "" {
			tc.answer.ClientCerts = relayapi.ClientCertsOff
		}
		srv := fakeRelay(t, map[string]any{"/v1/admin/status": tc.answer})
		p := newPersona(t, "boss", srv.URL)
		out, err := p.tryRun("status")
		if c, found := controlBytes(out); found {
			t.Errorf("status printed byte %#x from the relay's %s:\n%q", c, tc.field, out)
		}
		switch {
		case tc.enum && (err == nil || !strings.Contains(err.Error(), tc.field+" is not one of")):
			t.Errorf("status with a %s outside the protocol's set: %v, want the malformed-answer sentence naming it\n%s", tc.field, err, out)
		case !tc.enum && err != nil:
			t.Errorf("status with an escape in %s: %v\n%s", tc.field, err, out)
		case !tc.enum && !strings.Contains(out, `\x1b]0;owned\a`):
			t.Errorf("status does not show the relay's %s escaped:\n%s", tc.field, out)
		}
	}
}

func TestMailboxListingHoldsTheCardWordToItsSet(t *testing.T) {
	boss, err := identity.Generate("boss")
	if err != nil {
		t.Fatal(err)
	}
	fp := boss.Fingerprint()
	rec := relayapi.MailboxRecord{FP: fp, Name: "alice", Card: "signed" + escapeSeq, CardListed: true}
	srv := fakeRelay(t, map[string]any{
		"/v1/admin/mailboxes":       relayapi.MailboxListResponse{Mailboxes: []relayapi.MailboxRecord{rec}},
		"/v1/admin/mailboxes/" + fp: relayapi.MailboxAnswer{Mailbox: rec},
	})
	p := newPersona(t, "boss", srv.URL)
	for _, args := range [][]string{{"mailboxes", "ls"}, {"mailboxes", "show", fp}} {
		out, err := p.tryRun(args...)
		if c, found := controlBytes(out); found {
			t.Errorf("auu-admin %s printed byte %#x from the relay's card field:\n%q", strings.Join(args, " "), c, out)
		}
		if err == nil || !strings.Contains(err.Error(), "card is not one of signed, none, broken") {
			t.Errorf("auu-admin %s with a card word outside the set: %v, want the malformed-answer sentence", strings.Join(args, " "), err)
		}
	}
}

func TestMailboxListingHoldsTheDirectoryWordToItsSet(t *testing.T) {
	boss, err := identity.Generate("boss")
	if err != nil {
		t.Fatal(err)
	}
	fp := boss.Fingerprint()
	rec := relayapi.MailboxRecord{FP: fp, Name: "alice", Directory: "signed" + escapeSeq, Channels: 3}
	srv := fakeRelay(t, map[string]any{
		"/v1/admin/mailboxes":       relayapi.MailboxListResponse{Mailboxes: []relayapi.MailboxRecord{rec}},
		"/v1/admin/mailboxes/" + fp: relayapi.MailboxAnswer{Mailbox: rec},
	})
	p := newPersona(t, "boss", srv.URL)
	for _, args := range [][]string{{"mailboxes", "ls"}, {"mailboxes", "show", fp}} {
		out, err := p.tryRun(args...)
		if c, found := controlBytes(out); found {
			t.Errorf("auu-admin %s printed byte %#x from the relay's directory field:\n%q", strings.Join(args, " "), c, out)
		}
		if err == nil || !strings.Contains(err.Error(), "directory is not one of signed, none, broken") {
			t.Errorf("auu-admin %s with a directory word outside the set: %v, want the malformed-answer sentence", strings.Join(args, " "), err)
		}
	}
}

func TestMailboxListingHoldsTheAllowWordToItsSet(t *testing.T) {
	boss, err := identity.Generate("boss")
	if err != nil {
		t.Fatal(err)
	}
	fp := boss.Fingerprint()
	rec := relayapi.MailboxRecord{FP: fp, Name: "alice", Allow: "signed" + escapeSeq, AllowlistSize: 2}
	srv := fakeRelay(t, map[string]any{
		"/v1/admin/mailboxes":       relayapi.MailboxListResponse{Mailboxes: []relayapi.MailboxRecord{rec}},
		"/v1/admin/mailboxes/" + fp: relayapi.MailboxAnswer{Mailbox: rec},
	})
	p := newPersona(t, "boss", srv.URL)
	for _, args := range [][]string{{"mailboxes", "ls"}, {"mailboxes", "show", fp}} {
		out, err := p.tryRun(args...)
		if c, found := controlBytes(out); found {
			t.Errorf("auu-admin %s printed byte %#x from the relay's allow field:\n%q", strings.Join(args, " "), c, out)
		}
		if err == nil || !strings.Contains(err.Error(), "allow is not one of signed, none, broken") {
			t.Errorf("auu-admin %s with an allow word outside the set: %v, want the malformed-answer sentence", strings.Join(args, " "), err)
		}
	}
}

func TestBlockListingEscapesTheReason(t *testing.T) {
	boss, err := identity.Generate("boss")
	if err != nil {
		t.Fatal(err)
	}
	fp := boss.Fingerprint()
	srv := fakeRelay(t, map[string]any{
		"/v1/admin/blocks": relayapi.BlocksResponse{Blocks: []relayapi.BlockRecord{
			{FP: fp, ByFP: fp, Created: time.Now(), Reason: "spam" + escapeSeq},
		}},
	})
	p := newPersona(t, "boss", srv.URL)
	out, err := p.tryRun("blocks", "ls")
	if err != nil {
		t.Fatalf("blocks ls: %v\n%s", err, out)
	}
	if c, found := controlBytes(out); found {
		t.Errorf("blocks ls printed byte %#x from the relay's reason:\n%q", c, out)
	}
	if !strings.Contains(out, `spam\x1b]0;owned\a`) {
		t.Errorf("blocks ls does not show the reason escaped:\n%s", out)
	}
}

func TestTokenListingHoldsUseAndStateToTheirSets(t *testing.T) {
	boss, err := identity.Generate("boss")
	if err != nil {
		t.Fatal(err)
	}
	fp := boss.Fingerprint()
	id := strings.Repeat("7", 32)
	for _, tc := range []struct {
		field string
		rec   relayapi.TokenRecord
	}{
		{"use", relayapi.TokenRecord{ID: id, Issuer: fp, Use: "register" + escapeSeq, State: "live", Note: "x"}},
		{"state", relayapi.TokenRecord{ID: id, Issuer: fp, Use: "register", State: "live" + escapeSeq, Note: "x"}},
	} {
		srv := fakeRelay(t, map[string]any{
			"/v1/admin/tokens": relayapi.TokenListResponse{Tokens: []relayapi.TokenRecord{tc.rec}},
		})
		p := newPersona(t, "boss", srv.URL)
		out, err := p.tryRun("token", "ls")
		if c, found := controlBytes(out); found {
			t.Errorf("token ls printed byte %#x from the relay's %s:\n%q", c, tc.field, out)
		}
		if err == nil || !strings.Contains(err.Error(), tc.field+" is not one of") {
			t.Errorf("token ls with a %s outside the set: %v, want the malformed-answer sentence", tc.field, err)
		}
	}
}

// TestTokenRevokeHoldsTheIDToItsShape: the id given to token revoke was
// joined onto a URL with no rule, while every other id a command takes is
// checked first; a value with a '?' in it became a path and a query. Now
// it is refused as not a token id before any request, and the client
// refuses the same on its own.
func TestTokenRevokeHoldsTheIDToItsShape(t *testing.T) {
	var requests int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, "{}")
	}))
	t.Cleanup(srv.Close)
	p := newPersona(t, "boss", srv.URL)
	for _, id := range []string{"x?all=true", "a/b", "..", strings.Repeat("7", 31)} {
		out, err := p.tryRun("token", "revoke", id)
		var exit *exitError
		if !asExit(err, &exit) || exit.code != exitUsage || !strings.Contains(err.Error(), "is not a token id (32 lowercase hex characters)") {
			t.Errorf("token revoke %q: %v, want a usage error naming the shape\n%s", id, err, out)
		}
	}
	if requests != 0 {
		t.Errorf("%d requests reached the relay for ids that are not token ids; want none", requests)
	}
}

// TestTokenShowEscapesAnUnverifiedTokensWords: a pasted token's relay and
// note are the token's author's words, and Describe printed them as
// written; now they are escaped. A relay claim that is not a URL and a
// note with a control character in it are refused at Validate first, so
// the escape here is for what the rules let through: a format character.
func TestTokenShowEscapesAnUnverifiedTokensWords(t *testing.T) {
	boss, err := identity.Generate("boss")
	if err != nil {
		t.Fatal(err)
	}
	srv := fakeRelay(t, map[string]any{})
	p := newPersona(t, "boss", srv.URL)
	now := time.Now().Unix()
	payload, err := json.Marshal(map[string]any{
		"id": strings.Repeat("7", 32), "issuer": boss.Fingerprint(), "relay": srv.URL, "use": "register",
		"note": "for you\u202e", "not_before": now, "not_after": now + 3600, "uses": 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	raw := token.Prefix + "." + base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(make([]byte, 64))
	out, err := p.tryRun("token", "show", raw)
	if err != nil {
		t.Fatalf("token show: %v\n%s", err, out)
	}
	if strings.Contains(out, "\u202e") || !strings.Contains(out, `for:     for you\u202e`) {
		t.Errorf("token show printed the note's bidi override, or not its escape:\n%q", out)
	}
	// And a note with a terminal command is refused at Validate, not
	// described.
	payload, _ = json.Marshal(map[string]any{
		"id": strings.Repeat("7", 32), "issuer": boss.Fingerprint(), "relay": srv.URL, "use": "register",
		"note": "for you" + escapeSeq, "not_before": now, "not_after": now + 3600, "uses": 1,
	})
	raw = token.Prefix + "." + base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(make([]byte, 64))
	out, err = p.tryRun("token", "show", raw)
	if err == nil || !strings.Contains(err.Error(), "malformed token: note") {
		t.Errorf("token show with a control character in the note: %v\n%s", err, out)
	}
	if c, found := controlBytes(out); found {
		t.Errorf("token show printed byte %#x:\n%q", c, out)
	}
}

// no-administrators is known by its code (ruling 68): a 403 under it is
// advice to be made an administrator, and the same sentence under a code
// this build does not know is said as it came.
func TestTheNoAdministratorsCodeIsAdvised(t *testing.T) {
	t.Setenv("AUU_HOME", t.TempDir())
	relayName := ""
	asJSON := false
	c := &common{relay: &relayName, asJSON: &asJSON}
	coded := &client.HTTPError{Status: http.StatusForbidden, Code: relayapi.CodeNoAdministrators, Message: relayapi.MsgNoAdministrators}
	if got := adminErr(c, coded); !strings.Contains(got.Error(), "not an administrator") {
		t.Errorf("no-administrators: %v; want the advice", got)
	}
	later := &client.HTTPError{Status: http.StatusForbidden, Code: "later-kind", Message: relayapi.MsgNoAdministrators}
	if got := adminErr(c, later); strings.Contains(got.Error(), "not an administrator") || !errors.Is(got, later) {
		t.Errorf("another code with the same sentence: %v; want it as it came", got)
	}
}
