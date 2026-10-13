package relay

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/token"
)

// writeAdmins writes an authorized administrator file: export lines, exactly
// as a user keeps them in authorized_peers.
func writeAdmins(t *testing.T, path string, admins ...*identity.Identity) {
	t.Helper()
	var b strings.Builder
	b.WriteString("# administrators of this relay\n\n")
	for _, a := range admins {
		b.WriteString(a.Public().ExportLine() + "\n")
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	// Force a distinct modification time so the reload is not at the mercy of
	// the filesystem's timestamp resolution.
	future := time.Now().Add(time.Duration(len(admins)) * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}
}

func adminFile(t *testing.T, admins ...*identity.Identity) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "admins")
	writeAdmins(t, path, admins...)
	return path
}

// issue signs a token for this harness's relay.
func (h *harness) issue(admin *identity.Identity, mutate func(*token.Claims)) string {
	h.t.Helper()
	now := time.Now()
	c := token.Claims{
		Relay:     token.NormaliseRelay(h.srv.URL),
		Use:       token.UseRegister,
		Note:      "a colleague, for review work",
		NotBefore: now.Unix(),
		NotAfter:  now.Add(24 * time.Hour).Unix(),
		Uses:      1,
	}
	if mutate != nil {
		mutate(&c)
	}
	raw, err := token.Issue(admin, c)
	if err != nil {
		h.t.Fatal(err)
	}
	return raw
}

// addToken issues a token and registers it, which is what auu-admin does.
func (h *harness) addToken(admin *identity.Identity, mutate func(*token.Claims)) string {
	h.t.Helper()
	raw := h.issue(admin, mutate)
	status, body, _ := h.send(admin, "POST", "/v1/admin/tokens",
		relayapi.RegisterTokenRequest{Token: raw}, nil)
	if status != http.StatusCreated {
		h.t.Fatalf("registering a token: %d %s", status, body)
	}
	return raw
}

// enrol registers an identity with an enrolment token, which travels inside
// the certificate request where the signature covers it.
func (h *harness) enrol(id *identity.Identity, tok string) (int, []byte) {
	h.t.Helper()
	return h.registerWith(id, tok)
}

// An outsider must not learn who administers a relay by watching which
// fingerprints are told they are not one.
func TestAdminRoutesRefuseNonAdministrators(t *testing.T) {
	people := ids(t, "boss", "user")
	boss, user := people[0], people[1]
	h := newHarness(t, Config{AdminFile: adminFile(t, boss)})
	h.register(user)

	status, _, _ := h.send(user, "GET", "/v1/admin/status", nil, nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("a registered non-administrator got %d, want 401", status)
	}
	if strings.Contains(h.logs.String(), "msg=admin") {
		t.Fatalf("a refused admin request produced an audit line:\n%s", h.logs.String())
	}
	// An unsigned request learns exactly as little.
	if status, _, _ := h.send(nil, "GET", "/v1/admin/status", nil, nil); status != http.StatusUnauthorized {
		t.Fatalf("an unsigned admin request got %d, want 401", status)
	}
}

// Admin authority comes from the file, so an administrator need not be a user
// of the relay at all. This is what makes bootstrapping work.
func TestAdministratorNeedsNoMailbox(t *testing.T) {
	boss := ids(t, "boss")[0]
	h := newHarness(t, Config{AdminFile: adminFile(t, boss)})

	status, body, _ := h.send(boss, "GET", "/v1/admin/status", nil, nil)
	if status != http.StatusOK {
		t.Fatalf("an administrator with no mailbox got %d: %s", status, body)
	}
	var st relayapi.AdminStatusResponse
	if err := json.Unmarshal(body, &st); err != nil {
		t.Fatal(err)
	}
	if st.Administrators != 1 || st.Mailboxes != 0 {
		t.Fatalf("unexpected status: %+v", st)
	}
	if st.Registration != relayapi.RegistrationOpen {
		t.Fatalf("registration %q, want open by default", st.Registration)
	}
}

func TestNoAdminFileClosesTheAdminAPI(t *testing.T) {
	boss := ids(t, "boss")[0]
	h := newHarness(t, Config{})

	status, body, _ := h.send(boss, "GET", "/v1/admin/status", nil, nil)
	if status != http.StatusForbidden {
		t.Fatalf("status %d, want 403", status)
	}
	if got := errorText(t, body); !strings.Contains(got, "no administrators") {
		t.Fatalf("error %q does not explain the refusal", got)
	}
}

// Appointing or removing an administrator is an edit, not a restart.
func TestAdminFileIsRereadWhenItChanges(t *testing.T) {
	people := ids(t, "boss", "deputy")
	boss, deputy := people[0], people[1]
	path := adminFile(t, boss)
	h := newHarness(t, Config{AdminFile: path})

	if status, _, _ := h.send(deputy, "GET", "/v1/admin/status", nil, nil); status != http.StatusUnauthorized {
		t.Fatal("the deputy was an administrator before being appointed")
	}
	writeAdmins(t, path, boss, deputy)
	if status, _, _ := h.send(deputy, "GET", "/v1/admin/status", nil, nil); status != http.StatusOK {
		t.Fatal("appointing an administrator needed a restart")
	}

	writeAdmins(t, path, boss)
	if status, _, _ := h.send(deputy, "GET", "/v1/admin/status", nil, nil); status != http.StatusUnauthorized {
		t.Fatal("removing an administrator needed a restart")
	}
	if status, _, _ := h.send(boss, "GET", "/v1/admin/status", nil, nil); status != http.StatusOK {
		t.Fatal("the remaining administrator was locked out")
	}
}

// A file that cannot be read must not lock every administrator out of a relay
// that may well be under attack.
func TestUnreadableAdminFileKeepsTheLastGoodSet(t *testing.T) {
	boss := ids(t, "boss")[0]
	path := adminFile(t, boss)
	h := newHarness(t, Config{AdminFile: path})

	if status, _, _ := h.send(boss, "GET", "/v1/admin/status", nil, nil); status != http.StatusOK {
		t.Fatal("the administrator was refused before anything went wrong")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if status, _, _ := h.send(boss, "GET", "/v1/admin/status", nil, nil); status != http.StatusOK {
		t.Fatal("deleting the admin file locked the administrator out")
	}
	if !strings.Contains(h.logs.String(), "admin file could not be read") {
		t.Fatalf("nothing was logged about the unreadable file:\n%s", h.logs.String())
	}
}

// The set the relay serves from is filled at start, not on the first admin
// request: a file that goes missing between the two loses nobody their
// access, and the warning counts the administrators it kept, truthfully.
// The container suite's R10 found the set was filled on first use, so the
// "administrators loaded earlier" it kept were none.
func TestAdministratorsAreThereBeforeTheFirstRequest(t *testing.T) {
	boss := ids(t, "boss")[0]
	path := adminFile(t, boss)
	h := newHarness(t, Config{AdminFile: path})
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}

	status, body, _ := h.send(boss, "GET", "/v1/admin/status", nil, nil)
	if status != http.StatusOK {
		t.Fatalf("the administrator loaded at start got %d before the first request: %s", status, body)
	}
	var st relayapi.AdminStatusResponse
	if err := json.Unmarshal(body, &st); err != nil {
		t.Fatal(err)
	}
	if st.Administrators != 1 {
		t.Fatalf("administrators = %d, want the one loaded at start", st.Administrators)
	}
	logs := h.logs.String()
	if !strings.Contains(logs, "keeping the administrators loaded earlier") || !strings.Contains(logs, "administrators=1") {
		t.Fatalf("the warning does not say it kept one administrator:\n%s", logs)
	}
	if strings.Contains(logs, "administrators=0") {
		t.Fatalf("the warning counts no administrators when one was loaded at start:\n%s", logs)
	}
}

// auu-relay loads the file once at start, logs the count, and hands the relay
// the set; the relay serves from that set rather than reading the file
// again, so what start logged is what the first request gets.
func TestTheSetGivenAtStartIsTheSetServed(t *testing.T) {
	boss := ids(t, "boss")[0]
	path := adminFile(t, boss)
	loaded, err := LoadAdmins(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	// The file is gone before the server is built: only the set it was
	// given can answer.
	h := newHarness(t, Config{AdminFile: path, Admins: loaded})
	if status, body, _ := h.send(boss, "GET", "/v1/admin/status", nil, nil); status != http.StatusOK {
		t.Fatalf("the set given at start was not served: %d %s", status, body)
	}
	if strings.Contains(h.logs.String(), "could not be read at start") {
		t.Fatalf("the relay read the file it was handed the contents of:\n%s", h.logs.String())
	}
}

// A relay built with the path alone, as an embedder or a test does, loads the
// file itself; one whose file cannot be loaded says so once and has no
// administrators, rather than claiming to keep a set it never had.
func TestAnAdminFileMissingAtStartIsSaidToBe(t *testing.T) {
	boss := ids(t, "boss")[0]
	path := filepath.Join(t.TempDir(), "admins")
	h := newHarness(t, Config{AdminFile: path})
	if status, _, _ := h.send(boss, "GET", "/v1/admin/status", nil, nil); status != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401 from a relay whose admin file never loaded", status)
	}
	logs := h.logs.String()
	if !strings.Contains(logs, "admin file could not be read at start; this relay has no administrators until it can be") {
		t.Fatalf("the failed load at start was not said:\n%s", logs)
	}
	if strings.Contains(logs, "loaded earlier") {
		t.Fatalf("the relay claims to keep administrators it never loaded:\n%s", logs)
	}
	// Written later, the file is taken up, as the reload rule says.
	writeAdmins(t, path, boss)
	if status, _, _ := h.send(boss, "GET", "/v1/admin/status", nil, nil); status != http.StatusOK {
		t.Fatal("the file written after start was not taken up")
	}
}

// An operator who edits the file wants to see that the relay took it, and one
// who did not wants to know that somebody did: a reload is one INFO line with
// the count and the path. The container suite's E07 found the reload silent.
func TestAReloadIsLogged(t *testing.T) {
	people := ids(t, "boss", "deputy")
	boss, deputy := people[0], people[1]
	path := adminFile(t, boss)
	h := newHarness(t, Config{AdminFile: path})

	if status, _, _ := h.send(boss, "GET", "/v1/admin/status", nil, nil); status != http.StatusOK {
		t.Fatal("the administrator was refused before anything changed")
	}
	if strings.Contains(h.logs.String(), "administrators reloaded") {
		t.Fatalf("a reload was logged when the file had not changed:\n%s", h.logs.String())
	}
	writeAdmins(t, path, boss, deputy)
	if status, _, _ := h.send(deputy, "GET", "/v1/admin/status", nil, nil); status != http.StatusOK {
		t.Fatal("the deputy was not taken up")
	}
	want := "msg=\"administrators reloaded\" count=2 path=" + path
	if !strings.Contains(h.logs.String(), want) {
		t.Fatalf("the reload was not logged as %q:\n%s", want, h.logs.String())
	}
	if strings.Count(h.logs.String(), "administrators reloaded") != 1 {
		t.Fatalf("one change, one line:\n%s", h.logs.String())
	}
	if strings.Contains(h.logs.String(), "level=WARN") {
		t.Fatalf("a reload is not a warning:\n%s", h.logs.String())
	}
}

// Whoever can write the file can appoint themselves.
func TestWorldWritableAdminFileIsRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Go's FileMode on Windows says nothing about who can write a file; the check is Unix's")
	}
	boss := ids(t, "boss")[0]
	path := adminFile(t, boss)
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	_, err := LoadAdmins(path)
	if err == nil {
		t.Fatal("a world-writable admin file was accepted")
	}
	if !strings.Contains(err.Error(), "0666") {
		t.Fatalf("error %q does not name the mode", err)
	}

	if err := os.Chmod(path, 0o664); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAdmins(path); err == nil {
		t.Fatal("a group-writable admin file was accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAdmins(path); err != nil {
		t.Fatalf("a private admin file was refused: %v", err)
	}
}

func TestMalformedAdminFileIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admins")
	if err := os.WriteFile(path, []byte("ccx1 not-base64 bob\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadAdmins(path)
	if err == nil {
		t.Fatal("a malformed admin file was accepted")
	}
	if !strings.Contains(err.Error(), "line 1") {
		t.Fatalf("error %q does not name the line", err)
	}
}

func TestTokenRegistrationRules(t *testing.T) {
	people := ids(t, "boss", "deputy")
	boss, deputy := people[0], people[1]
	h := newHarness(t, Config{
		AdminFile:   adminFile(t, boss, deputy),
		PublicURL:   "", // filled in below, once the test server has an address
		TokenMaxAge: 48 * time.Hour,
	})

	t.Run("another administrator's token is refused", func(t *testing.T) {
		raw := h.issue(deputy, nil)
		status, body, _ := h.send(boss, "POST", "/v1/admin/tokens",
			relayapi.RegisterTokenRequest{Token: raw}, nil)
		if status != http.StatusForbidden {
			t.Fatalf("status %d, want 403: %s", status, body)
		}
		if got := errorText(t, body); !strings.Contains(got, "who signed it") {
			t.Fatalf("error %q does not explain the rule", got)
		}
	})

	t.Run("a lifetime past token_max_age is refused", func(t *testing.T) {
		raw := h.issue(boss, func(c *token.Claims) {
			c.NotAfter = time.Now().Add(72 * time.Hour).Unix()
		})
		status, body, _ := h.send(boss, "POST", "/v1/admin/tokens",
			relayapi.RegisterTokenRequest{Token: raw}, nil)
		if status != http.StatusBadRequest {
			t.Fatalf("status %d, want 400: %s", status, body)
		}
		if got := errorText(t, body); !strings.Contains(got, "token_max_age") {
			t.Fatalf("error %q does not name the limit", got)
		}
	})

	t.Run("an expired token is refused", func(t *testing.T) {
		raw := h.issue(boss, func(c *token.Claims) {
			c.NotBefore = time.Now().Add(-2 * time.Hour).Unix()
			c.NotAfter = time.Now().Add(-time.Hour).Unix()
		})
		status, body, _ := h.send(boss, "POST", "/v1/admin/tokens",
			relayapi.RegisterTokenRequest{Token: raw}, nil)
		if status != http.StatusBadRequest {
			t.Fatalf("status %d, want 400: %s", status, body)
		}
	})

	t.Run("a duplicate id is a conflict", func(t *testing.T) {
		raw := h.addToken(boss, nil)
		status, body, _ := h.send(boss, "POST", "/v1/admin/tokens",
			relayapi.RegisterTokenRequest{Token: raw}, nil)
		if status != http.StatusConflict {
			t.Fatalf("status %d, want 409: %s", status, body)
		}
	})

	t.Run("a forged signature is refused", func(t *testing.T) {
		raw := h.issue(boss, nil)
		parts := strings.Split(raw, ".")
		forged := parts[0] + "." + parts[1] + "." + strings.Repeat("A", len(parts[2]))
		status, _, _ := h.send(boss, "POST", "/v1/admin/tokens",
			relayapi.RegisterTokenRequest{Token: forged}, nil)
		if status != http.StatusForbidden && status != http.StatusBadRequest {
			t.Fatalf("a forged token got %d", status)
		}
	})

	t.Run("a note with a control character is refused", func(t *testing.T) {
		// Issue refuses to make one, so the token has to be built by hand,
		// which is exactly the case the relay's own check exists for.
		raw := forgeToken(t, boss, func(m map[string]any) {
			m["note"] = "audit\nline injection"
		})
		status, body, _ := h.send(boss, "POST", "/v1/admin/tokens",
			relayapi.RegisterTokenRequest{Token: raw}, nil)
		if status != http.StatusBadRequest && status != http.StatusForbidden {
			t.Fatalf("status %d, want a refusal: %s", status, body)
		}
	})
}

// TestATokenDatedPastTheYear9999IsRefusedAtIssueAndOneAtTheEdgeIsListed
// (G26): a token whose not_before or not_after was one second past the
// last second of the year 9999 was stored, and then the issue answer and
// every listing failed with a 500, since a time past 9999 cannot be
// written. The issue route now answers 400 naming the field, the value
// and the bound, and nothing is stored; a token whose not_after is the
// last second is issued and listed.
func TestATokenDatedPastTheYear9999IsRefusedAtIssueAndOneAtTheEdgeIsListed(t *testing.T) {
	const last = 253402300799
	boss := ids(t, "boss")[0]
	h := newHarness(t, Config{AdminFile: adminFile(t, boss)})
	stored := func() int {
		t.Helper()
		all, err := h.store.Tokens(true, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return len(all)
	}

	for _, c := range []struct {
		field               string
		notBefore, notAfter int64
	}{
		{"not_after", time.Now().Unix(), last + 1},
		{"not_before", last + 1, last + 2},
	} {
		t.Run(c.field+" one second past", func(t *testing.T) {
			// Issue refuses to make one, so it is signed by hand, as an
			// older auu-admin or a hand-made token would have it.
			raw := forgeToken(t, boss, func(m map[string]any) {
				m["relay"] = token.NormaliseRelay(h.srv.URL)
				m["not_before"], m["not_after"] = c.notBefore, c.notAfter
			})
			before := stored()
			status, body, _ := h.send(boss, "POST", "/v1/admin/tokens",
				relayapi.RegisterTokenRequest{Token: raw}, nil)
			if status != http.StatusBadRequest {
				t.Fatalf("status %d, want 400: %s", status, body)
			}
			n := c.notAfter
			if c.field == "not_before" {
				n = c.notBefore
			}
			want := "malformed token: " + c.field + " is " + strconv.FormatInt(n, 10) + ", past 253402300799, the end of the year 9999"
			if got := errorText(t, body); got != want {
				t.Fatalf("error %q, want %q", got, want)
			}
			if after := stored(); after != before {
				t.Fatalf("%d tokens stored before, %d after; the refused one was kept", before, after)
			}
		})
	}

	t.Run("at the edge, issued and listed", func(t *testing.T) {
		// not_after at the edge, from now; not_before at its edge is shown
		// in the token package, since here it would be not yet valid.
		raw := h.addToken(boss, func(c *token.Claims) {
			c.NotAfter = last
		})
		u, err := token.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		status, body, _ := h.send(boss, "GET", "/v1/admin/tokens?all=1", nil, nil)
		if status != http.StatusOK {
			t.Fatalf("listing: status %d, want 200: %s", status, body)
		}
		var list relayapi.TokenListResponse
		if err := json.Unmarshal(body, &list); err != nil {
			t.Fatal(err)
		}
		for _, r := range list.Tokens {
			if r.ID != u.Claims.ID {
				continue
			}
			if r.NotBefore.Unix() != u.Claims.NotBefore || r.NotAfter.Unix() != last {
				t.Fatalf("listed as %v to %v, want %d to %d", r.NotBefore, r.NotAfter, u.Claims.NotBefore, int64(last))
			}
			return
		}
		t.Fatalf("the token at the edge is not in the listing: %s", body)
	})
}

// TestATokenThatStartsLaterIsRegisteredAndListed: the add-token route takes
// a token that is not yet valid, as its comment says, where it read the
// claims Verify had not given back and the handler panicked (G27).
func TestATokenThatStartsLaterIsRegisteredAndListed(t *testing.T) {
	boss := ids(t, "boss")[0]
	h := newHarness(t, Config{AdminFile: adminFile(t, boss)})
	later := time.Now().Add(time.Hour).Unix()
	raw := forgeToken(t, boss, func(m map[string]any) {
		m["relay"] = token.NormaliseRelay(h.srv.URL)
		m["not_before"], m["not_after"] = later, later+3600
	})
	status, body, _ := h.send(boss, "POST", "/v1/admin/tokens",
		relayapi.RegisterTokenRequest{Token: raw}, nil)
	if status != http.StatusCreated {
		t.Fatalf("a token starting in an hour: status %d, want 201: %s", status, body)
	}
	u, err := token.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	status, body, _ = h.send(boss, "GET", "/v1/admin/tokens?all=1", nil, nil)
	if status != http.StatusOK {
		t.Fatalf("listing: status %d, want 200: %s", status, body)
	}
	var list relayapi.TokenListResponse
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatal(err)
	}
	for _, r := range list.Tokens {
		if r.ID == u.Claims.ID {
			if r.NotBefore.Unix() != later {
				t.Fatalf("listed from %v, want %d", r.NotBefore, later)
			}
			return
		}
	}
	t.Fatalf("the token that starts later is not in the listing: %s", body)
}

// forgeToken builds a token whose payload Issue would never produce, signed
// for real, so the relay's own validation is what is being tested.
func forgeToken(t *testing.T, id *identity.Identity, mutate func(map[string]any)) string {
	t.Helper()
	good, err := token.Issue(id, token.Claims{
		Relay:     "https://relay.example.com",
		Use:       token.UseRegister,
		Note:      "placeholder",
		NotBefore: time.Now().Unix(),
		NotAfter:  time.Now().Add(time.Hour).Unix(),
		Uses:      1,
	})
	if err != nil {
		t.Fatal(err)
	}
	return resign(t, id, good, mutate)
}

func TestAdminMailboxLifecycle(t *testing.T) {
	people := ids(t, "boss", "alice", "bob")
	boss, alice, bob := people[0], people[1], people[2]
	h := newHarness(t, Config{AdminFile: adminFile(t, boss)})
	h.register(alice)
	h.register(bob)
	var lastEnvelope []byte
	for range 3 {
		lastEnvelope = sealed(t, alice, bob.Public(), "queued")
		if status, _, _ := h.send(alice, "POST", "/v1/mailbox/"+bob.Fingerprint(),
			lastEnvelope, nil); status != http.StatusOK {
			t.Fatal("post refused")
		}
	}

	// Listing shows what is there, without any message content.
	status, body, _ := h.send(boss, "GET", "/v1/admin/mailboxes", nil, nil)
	if status != http.StatusOK {
		t.Fatalf("mailboxes: %d %s", status, body)
	}
	var list relayapi.MailboxListResponse
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Mailboxes) != 2 {
		t.Fatalf("listed %d mailboxes, want 2", len(list.Mailboxes))
	}
	var bobs relayapi.MailboxRecord
	for _, m := range list.Mailboxes {
		if m.FP == bob.Fingerprint() {
			bobs = m
		}
	}
	if bobs.QueuedMessages != 3 || bobs.QueuedBytes == 0 {
		t.Fatalf("bob's mailbox reports %+v", bobs)
	}
	// An administrator sees the shape of what is queued and never the content.
	var envelope map[string]any
	if err := json.Unmarshal(lastEnvelope, &envelope); err != nil {
		t.Fatal(err)
	}
	ct, _ := envelope["ct"].(string)
	if ct == "" {
		t.Fatal("the test envelope has no ciphertext to look for")
	}
	if strings.Contains(string(body), ct) {
		t.Fatal("the admin listing carried a stored envelope")
	}

	// Purging keeps the mailbox and frees the quota.
	if status, _, _ := h.send(boss, "DELETE", "/v1/admin/mailboxes/"+bob.Fingerprint()+"/messages",
		nil, nil); status != http.StatusNoContent {
		t.Fatal("purge failed")
	}
	h.assertCountersAgree()
	if status, _, _ := h.send(bob, "GET", "/v1/mailbox/"+bob.Fingerprint(), nil, nil); status != http.StatusOK {
		t.Fatal("purging removed the mailbox as well as its messages")
	}

	// Removing takes the mailbox with it.
	if status, _, _ := h.send(alice, "POST", "/v1/mailbox/"+bob.Fingerprint(),
		sealed(t, alice, bob.Public(), "again"), nil); status != http.StatusOK {
		t.Fatal("post after purge refused")
	}
	if status, _, _ := h.send(boss, "DELETE", "/v1/admin/mailboxes/"+bob.Fingerprint(),
		nil, nil); status != http.StatusNoContent {
		t.Fatal("deregister failed")
	}
	h.assertCountersAgree()
	if status, _, _ := h.send(bob, "GET", "/v1/mailbox/"+bob.Fingerprint(), nil, nil); status != http.StatusUnauthorized {
		t.Fatal("a deregistered mailbox still authenticates")
	}
	if status, _, _ := h.send(boss, "DELETE", "/v1/admin/mailboxes/"+bob.Fingerprint(),
		nil, nil); status != http.StatusNotFound {
		t.Fatal("removing a mailbox twice was not a 404")
	}
}

func TestAdminMailboxPaging(t *testing.T) {
	boss := ids(t, "boss")[0]
	h := newHarness(t, Config{AdminFile: adminFile(t, boss)})
	people := ids(t, "a", "b", "c", "d", "e")
	for _, id := range people {
		h.enroll(id)
	}

	seen := map[string]bool{}
	after := ""
	for range 10 {
		path := "/v1/admin/mailboxes?limit=2"
		if after != "" {
			path += "&after=" + after
		}
		status, body, _ := h.send(boss, "GET", path, nil, nil)
		if status != http.StatusOK {
			t.Fatalf("page: %d %s", status, body)
		}
		var page relayapi.MailboxListResponse
		if err := json.Unmarshal(body, &page); err != nil {
			t.Fatal(err)
		}
		for _, m := range page.Mailboxes {
			if seen[m.FP] {
				t.Fatalf("mailbox %s came back on two pages", m.FP[:8])
			}
			seen[m.FP] = true
		}
		if page.Next == "" {
			break
		}
		after = page.Next
	}
	if len(seen) != len(people) {
		t.Fatalf("paging visited %d of %d mailboxes", len(seen), len(people))
	}
}

func TestBlocks(t *testing.T) {
	people := ids(t, "boss", "alice", "nuisance")
	boss, alice, nuisance := people[0], people[1], people[2]
	h := newHarness(t, Config{AdminFile: adminFile(t, boss)})
	h.register(alice)
	h.register(nuisance)

	block := func() (int, []byte) {
		status, body, _ := h.send(boss, "PUT", "/v1/admin/blocks/"+nuisance.Fingerprint(),
			relayapi.BlockRequest{Reason: "flooding the relay"}, nil)
		return status, body
	}
	if status, body := block(); status != http.StatusNoContent {
		t.Fatalf("block: %d %s", status, body)
	}

	// Cannot authenticate.
	status, body, _ := h.send(nuisance, "GET", "/v1/mailbox/"+nuisance.Fingerprint(), nil, nil)
	if status != http.StatusForbidden {
		t.Fatalf("a blocked identity listed its mailbox: %d %s", status, body)
	}
	if got := errorText(t, body); got != msgBlocked {
		t.Fatalf("error %q, want %q", got, msgBlocked)
	}
	// Cannot register.
	if status, _, _ := h.send(nuisance, "POST", "/v1/register",
		h.registerBody(nuisance, "nuisance", ""), nil); status != http.StatusForbidden {
		t.Fatalf("a blocked identity re-registered: %d", status)
	}
	// Cannot receive.
	if status, body, _ := h.send(alice, "POST", "/v1/mailbox/"+nuisance.Fingerprint(),
		sealed(t, alice, nuisance.Public(), "hello"), nil); status != http.StatusForbidden {
		t.Fatalf("mail was accepted for a blocked recipient: %d %s", status, body)
	}
	// An unauthenticated caller learns nothing from the block list.
	if status, _, _ := h.send(nil, "GET", "/v1/keys/"+nuisance.Fingerprint(), nil, nil); status != http.StatusOK {
		t.Fatal("a key lookup revealed the block")
	}

	// Blocking is idempotent and lists.
	if status, _ := block(); status != http.StatusNoContent {
		t.Fatal("blocking twice was not idempotent")
	}
	status, body, _ = h.send(boss, "GET", "/v1/admin/blocks", nil, nil)
	if status != http.StatusOK {
		t.Fatal("listing blocks failed")
	}
	var blocks relayapi.BlocksResponse
	if err := json.Unmarshal(body, &blocks); err != nil {
		t.Fatal(err)
	}
	if len(blocks.Blocks) != 1 || blocks.Blocks[0].ByFP != boss.Fingerprint() {
		t.Fatalf("blocks %+v", blocks.Blocks)
	}

	// Unblocking restores everything.
	if status, _, _ := h.send(boss, "DELETE", "/v1/admin/blocks/"+nuisance.Fingerprint(),
		nil, nil); status != http.StatusNoContent {
		t.Fatal("unblock failed")
	}
	if status, _, _ := h.send(nuisance, "GET", "/v1/mailbox/"+nuisance.Fingerprint(), nil, nil); status != http.StatusOK {
		t.Fatal("unblocking did not restore authentication")
	}
	if status, _, _ := h.send(alice, "POST", "/v1/mailbox/"+nuisance.Fingerprint(),
		sealed(t, alice, nuisance.Public(), "hello"), nil); status != http.StatusOK {
		t.Fatal("unblocking did not restore delivery")
	}
}

// An administrator's own authority never depends on the block list, so a
// mistake there cannot lock the relay's owner out of fixing it.
func TestBlockingAnAdministratorDoesNotRemoveTheirAuthority(t *testing.T) {
	boss := ids(t, "boss")[0]
	h := newHarness(t, Config{AdminFile: adminFile(t, boss)})
	h.register(boss)

	if status, _, _ := h.send(boss, "PUT", "/v1/admin/blocks/"+boss.Fingerprint(),
		relayapi.BlockRequest{Reason: "a mistake"}, nil); status != http.StatusNoContent {
		t.Fatal("block failed")
	}
	if status, _, _ := h.send(boss, "GET", "/v1/admin/status", nil, nil); status != http.StatusOK {
		t.Fatal("a blocked administrator lost admin access")
	}
	if status, _, _ := h.send(boss, "DELETE", "/v1/admin/blocks/"+boss.Fingerprint(),
		nil, nil); status != http.StatusNoContent {
		t.Fatal("the administrator could not undo it")
	}
}

func TestBlockReasonIsRequiredAndClean(t *testing.T) {
	people := ids(t, "boss", "someone")
	boss, someone := people[0], people[1]
	h := newHarness(t, Config{AdminFile: adminFile(t, boss)})

	for _, reason := range []string{"", "   ", "line\nbreak"} {
		status, _, _ := h.send(boss, "PUT", "/v1/admin/blocks/"+someone.Fingerprint(),
			relayapi.BlockRequest{Reason: reason}, nil)
		if status != http.StatusBadRequest {
			t.Fatalf("reason %q was accepted with status %d", reason, status)
		}
	}
}

// The audit log is the operator's record of their own administrators. It is
// written in both access log modes, and never carries a token string.
func TestAuditLog(t *testing.T) {
	for _, mode := range []string{AccessLogFull, AccessLogMinimal} {
		t.Run(mode, func(t *testing.T) {
			people := ids(t, "boss", "alice", "newcomer")
			boss, alice, newcomer := people[0], people[1], people[2]
			h := newHarness(t, Config{
				AdminFile:    adminFile(t, boss),
				AccessLog:    mode,
				Registration: relayapi.RegistrationToken,
			})
			// Alice is already a user; the relay is closed to new ones
			// without a token, which is what the newcomer is for.
			h.enroll(alice)

			tok := h.addToken(boss, nil)
			if status, body := h.enrol(newcomer, tok); status != http.StatusOK {
				t.Fatalf("enrolment: %d %s", status, body)
			}
			h.send(boss, "PUT", "/v1/admin/blocks/"+alice.Fingerprint(),
				relayapi.BlockRequest{Reason: "testing"}, nil)
			h.send(boss, "DELETE", "/v1/admin/mailboxes/"+alice.Fingerprint(), nil, nil)

			logged := h.logs.String()
			for _, want := range []string{
				`action=token.issue`,
				`action=enrol`,
				`action=block.add`,
				`action=mailbox.remove`,
				`admin=` + boss.Fingerprint()[:16],
				`target=` + newcomer.Fingerprint()[:16],
				`outcome=ok`,
			} {
				if !strings.Contains(logged, want) {
					t.Fatalf("the audit log is missing %q:\n%s", want, logged)
				}
			}
			if strings.Contains(logged, tok) {
				t.Fatal("the audit log contains the token string")
			}
			if strings.Contains(logged, "ccxt1.") {
				t.Fatalf("something token-shaped reached the log:\n%s", logged)
			}
		})
	}
}

// resign rewrites a token's payload and signs it again with the same key, so a
// test can build a payload token.Issue would refuse while keeping the
// signature genuine. The domain string is written out rather than imported: it
// is a wire constant, and pinning it from outside the package is the point.
func resign(t *testing.T, id *identity.Identity, tok string, mutate func(map[string]any)) string {
	t.Helper()
	parts := strings.Split(tok, ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(payload, &m); err != nil {
		t.Fatal(err)
	}
	mutate(m)
	next, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	sig := mustSign(t, id, append([]byte("ccx-token-v1"), next...))
	return parts[0] + "." +
		base64.RawURLEncoding.EncodeToString(next) + "." +
		base64.RawURLEncoding.EncodeToString(sig)
}
