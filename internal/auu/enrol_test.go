package auu

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relay"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/store"
	"github.com/tropeforce7/agentuucp/internal/token"
)

// tokenRelay starts a relay that only admits people holding a token from the
// one administrator it knows about, and returns its address plus a function
// that issues and registers tokens for it.
func tokenRelay(t *testing.T) (string, func(mutate func(*token.Claims)) string) {
	t.Helper()
	boss, err := identity.Generate("boss")
	if err != nil {
		t.Fatal(err)
	}
	admins := filepath.Join(t.TempDir(), "admins")
	if err := os.WriteFile(admins, []byte(boss.Public().ExportLine()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	url, st := startRelayConfig(t, relay.Config{
		AdminFile:    admins,
		Registration: relayapi.RegistrationToken,
		TokenMaxAge:  720 * time.Hour,
	})

	issue := func(mutate func(*token.Claims)) string {
		t.Helper()
		now := time.Now()
		c := token.Claims{
			Relay:     token.NormaliseRelay(url),
			Use:       token.UseRegister,
			Note:      "a colleague, for the protocol review",
			NotBefore: now.Unix(),
			NotAfter:  now.Add(24 * time.Hour).Unix(),
			Uses:      1,
		}
		if mutate != nil {
			mutate(&c)
		}
		raw, err := token.Issue(boss, c)
		if err != nil {
			t.Fatal(err)
		}
		u, err := token.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if err := st.AddToken(u.Claims, now); err != nil {
			t.Fatal(err)
		}
		return raw
	}
	return url, issue
}

// answer feeds a line to a command that prompts, so the confirmation can be
// exercised rather than skipped with --yes.
func (u *user) answer(reply string, args ...string) (string, error) {
	u.t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		u.t.Fatal(err)
	}
	if _, err := w.WriteString(reply + "\n"); err != nil {
		u.t.Fatal(err)
	}
	w.Close()
	realStdin := os.Stdin
	os.Stdin = r
	defer func() {
		os.Stdin = realStdin
		r.Close()
	}()
	return u.tryRun(args...)
}

// A person with a token and no identity should get from nothing to registered
// in one command.
func TestEnrolCreatesAnIdentityAndRegisters(t *testing.T) {
	relayURL, issue := tokenRelay(t)
	tok := issue(nil)

	bob := &user{t: t, home: t.TempDir()}
	out := bob.run("enrol", "--name", "bob", "--yes", tok)

	// It shows what the token is before acting on it.
	for _, want := range []string{"for:", "a colleague, for the protocol review", relayURL, "expires:"} {
		if !strings.Contains(out, want) {
			t.Fatalf("enrol did not show the token (%q missing):\n%s", want, out)
		}
	}
	if !strings.Contains(out, "registered") {
		t.Fatalf("enrol did not report registering:\n%s", out)
	}

	// The identity exists, and the relay came from the token.
	s, err := store.Open(bob.home)
	if err != nil {
		t.Fatal(err)
	}
	def, err := s.DefaultRelay()
	if err != nil {
		t.Fatal(err)
	}
	if def.URL != token.NormaliseRelay(relayURL) {
		t.Fatalf("relay %q, want the one from the token", def.URL)
	}
	id, err := s.Identity()
	if err != nil {
		t.Fatalf("no identity was created: %v", err)
	}
	if id.Name != "bob" {
		t.Fatalf("name %q", id.Name)
	}

	// Bob running it again is a harmless re-registration: he already has a
	// mailbox, and changing your display name never needs a token.
	bob.run("enrol", "--name", "bob", "--yes", tok)

	// Somebody else with the same, now spent, token gets nowhere.
	carol := &user{t: t, home: t.TempDir()}
	_, err = carol.tryRun("enrol", "--name", "carol", "--yes", tok)
	if err == nil {
		t.Fatal("a spent token enrolled a second person")
	}
	var e *exitError
	if !asExit(err, &e) || e.code != exitTransport {
		t.Fatalf("expected exit code %d, got %v", exitTransport, err)
	}
	if !strings.Contains(err.Error(), "already been used") {
		t.Fatalf("error %q does not say the token is spent", err)
	}
	// The failed enrolment still created carol's identity, and says so, so she
	// can ask for another token without starting over.
	s2, err := store.Open(carol.home)
	if err != nil {
		t.Fatal(err)
	}
	if !s2.HasIdentity() {
		t.Fatal("a refused enrolment left no identity, so a second token could not be used")
	}
}

// Declining the prompt must leave the home exactly as it was.
func TestEnrolDeclinedLeavesNothingBehind(t *testing.T) {
	_, issue := tokenRelay(t)
	tok := issue(nil)

	bob := &user{t: t, home: t.TempDir()}
	if _, err := bob.answer("n", "enrol", "--name", "bob", tok); err == nil {
		t.Fatal("declining the prompt reported success")
	}
	s, err := store.Open(bob.home)
	if err != nil {
		t.Fatal(err)
	}
	if s.HasIdentity() {
		t.Fatal("declining the prompt created an identity anyway")
	}
	cfg, err := s.Config()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DefaultRelay != "" || cfg.Name != "" {
		t.Fatalf("declining the prompt wrote configuration: %+v", cfg)
	}
	relays, err := s.Relays()
	if err != nil {
		t.Fatal(err)
	}
	if len(relays) != 0 {
		t.Fatalf("declining the prompt added %d relay(s)", len(relays))
	}
}

func TestEnrolAcceptedAtThePrompt(t *testing.T) {
	_, issue := tokenRelay(t)
	bob := &user{t: t, home: t.TempDir()}
	out, err := bob.answer("y", "enrol", "--name", "bob", issue(nil))
	if err != nil {
		t.Fatalf("enrol: %v\n%s", err, out)
	}
	s, err := store.Open(bob.home)
	if err != nil {
		t.Fatal(err)
	}
	if !s.HasIdentity() {
		t.Fatal("accepting the prompt did not create an identity")
	}
}

// Somebody who already has an identity uses register, with a token.
func TestRegisterWithAToken(t *testing.T) {
	relayURL, issue := tokenRelay(t)

	bob := &user{t: t, home: t.TempDir()}
	bob.run("init", "--name", "bob", "--relay", relayURL)
	if _, err := bob.tryRun("register"); err == nil {
		t.Fatal("a token relay accepted a registration without one")
	}
	bob.run("register", "--token", issue(nil))
}

// A holder can read a token before acting on it, and is told plainly when the
// signature has not been checked.
func TestTokenShow(t *testing.T) {
	_, issue := tokenRelay(t)
	tok := issue(nil)

	bob := &user{t: t, home: t.TempDir()}
	bob.run("init", "--name", "bob")
	out := bob.run("token", "show", tok)
	if !strings.Contains(out, "a colleague, for the protocol review") {
		t.Fatalf("token show did not print the note:\n%s", out)
	}
	if !strings.Contains(out, "NOT checked") {
		t.Fatalf("token show did not say the signature was unchecked:\n%s", out)
	}
	if _, err := bob.tryRun("token", "show", "not-a-token"); err == nil {
		t.Fatal("token show accepted a non-token")
	}
}
