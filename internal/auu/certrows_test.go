package auu

import (
	"crypto/mldsa"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/client"
	"github.com/tropeforce7/agentuucp/internal/clientca"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/pki"
	"github.com/tropeforce7/agentuucp/internal/relay"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/token"
)

// Each certificate refusal a client acts on, reached through a real relay
// with real handshakes, and the advice auu gives for it pinned whole. The
// client reads the refusal's code and never its sentence (ruling 68), so a
// relay that wrote any of these sentences without its code would leave the
// error as the relay's words and every test here would fail. The container
// suite's K09 and X07 produce the same states in four containers; these are
// their twins in one process.

// certRowRelay is certRelay that also hands back the relay's store and its
// administrator, so that a test can do to the relay's records what an
// operator, or time, would.
func certRowRelay(t *testing.T) (string, *relay.Store, *identity.Identity, func(use, subject string) string) {
	t.Helper()
	boss, err := identity.Generate("boss")
	if err != nil {
		t.Fatal(err)
	}
	admins := filepath.Join(t.TempDir(), "admins")
	if err := os.WriteFile(admins, []byte(boss.Public().ExportLine()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bundle := pki.TestHierarchy(t, []string{"127.0.0.1"}, mldsa.MLDSA65())
	url, st := startTLSRelay(t, relay.Config{
		AdminFile:    admins,
		Registration: relayapi.RegistrationToken,
		TokenMaxAge:  720 * time.Hour,
		ClientCerts: &relay.ClientCertPolicy{
			Issuer:   clientca.NewIssuer(bundle),
			Verifier: clientca.NewVerifier(bundle),
			Lifetime: 365 * 24 * time.Hour,
		},
	}, bundle)
	return url, st, boss, tokenIssuer(t, boss, url, st)
}

// certRowEnrolled is a machine enrolled on the relay, its first command
// shown to work so that what follows is the change and nothing else, and the
// serial of its certificate as the relay recorded it.
func certRowEnrolled(t *testing.T, st *relay.Store, name string, issue func(use, subject string) string) (*user, string) {
	t.Helper()
	u := &user{t: t, home: t.TempDir()}
	u.run("enrol", "--name", name, "--yes", issue(token.UseRegister, ""))
	u.run("inbox")
	serial := u.certRecord().Serial
	if _, err := st.CertBySerial(serial); err != nil {
		t.Fatalf("the relay has no row for %s's certificate %s: %v", name, serial, err)
	}
	return u, serial
}

// certRowAdvised runs inbox and holds the failure to the advice for state,
// with the exit status every certificate problem carries.
func certRowAdvised(t *testing.T, u *user, args []string, state string) {
	t.Helper()
	out, err := u.tryRun(args...)
	if err == nil {
		t.Fatalf("auu %v reached the relay with a certificate that is %s:\n%s", args, state, out)
	}
	var e *exitError
	if !errors.As(err, &e) || e.code != exitTransport {
		t.Errorf("auu %v: %v, want exit %d", args, err, exitTransport)
	}
	want := "this relay requires a client certificate and this machine's is " + state + ": " +
		"run 'auu register --token TOKEN' with a token from an administrator"
	if got := err.Error(); got != want {
		t.Errorf("error is\n %q\nwant\n %q", got, want)
	}
}

// An administrator revokes a machine's certificate. The relay resolves the
// serial on every request, so the very next one is refused, as revoked.
func TestARevokedCertificateIsAdvisedThroughTheRelay(t *testing.T) {
	_, st, boss, issue := certRowRelay(t)
	alice, serial := certRowEnrolled(t, st, "alice", issue)

	revoked, err := st.RevokeCert(serial, boss.Fingerprint(), "laptop lost", time.Now())
	if err != nil || !revoked {
		t.Fatalf("revoking %s: revoked %v, %v", serial, revoked, err)
	}
	certRowAdvised(t, alice, []string{"inbox"}, "revoked")
}

// The relay's record of a certificate runs out while the certificate the
// machine holds has not: the relay's clock and its record decide, as X07
// has it with an UPDATE in the container. The store has no way to rewrite a
// row's expiry, so the row is forgotten and recorded again as it was, with
// yesterday for its end; the certificate on the machine is untouched, and
// still verifies in the handshake.
func TestAnExpiredCertificateIsAdvisedThroughTheRelay(t *testing.T) {
	_, st, _, issue := certRowRelay(t)
	alice, serial := certRowEnrolled(t, st, "alice", issue)

	row, err := st.CertBySerial(serial)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := st.PurgeCerts(row.NotAfter.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	row.NotAfter = now.Add(-24 * time.Hour)
	if err := st.RenewCert(row.FP, "", *row, now); err != nil {
		t.Fatal(err)
	}
	if again, err := st.CertBySerial(serial); err != nil || !again.NotAfter.Before(now) || again.Revoked {
		t.Fatalf("the relay's row for %s is not expired and live: %+v, %v", serial, again, err)
	}
	certRowAdvised(t, alice, []string{"inbox"}, "expired")
}

// Bob's cert.json copied over alice's, as K09 does. The certificate is the
// relay's own and verifies; the relay's row says it is bob's, and the
// request is signed by alice.
func TestACertificateForAnotherIdentityIsAdvisedThroughTheRelay(t *testing.T) {
	_, st, _, issue := certRowRelay(t)
	alice, _ := certRowEnrolled(t, st, "alice", issue)
	bob, _ := certRowEnrolled(t, st, "bob", issue)

	if alice.certPath() == bob.certPath() {
		t.Fatal("alice and bob share a home")
	}
	raw, err := os.ReadFile(bob.certPath())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(alice.certPath(), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	certRowAdvised(t, alice, []string{"inbox"}, "for another identity")
	// Bob, whose certificate it is, is unaffected.
	bob.run("inbox")
}

// The relay no longer knows the serial: its row is gone, as it would be
// from a database restored from before the enrolment. The certificate still
// chains to the relay's authority, so the handshake carries it and the
// refusal is the relay's, at the lookup.
func TestAnUnknownCertificateIsAdvisedThroughTheRelay(t *testing.T) {
	_, st, _, issue := certRowRelay(t)
	alice, serial := certRowEnrolled(t, st, "alice", issue)

	row, err := st.CertBySerial(serial)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.PurgeCerts(row.NotAfter.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CertBySerial(serial); !errors.Is(err, relay.ErrNoCert) {
		t.Fatalf("the relay still has a row for %s: %v", serial, err)
	}
	certRowAdvised(t, alice, []string{"inbox"}, "not known")
}

// A machine enrolled on one relay that asks another, where it holds no
// certificate, is told its certificate is missing and the command that
// enrols it there: whether one is missing or not accepted is decided by
// the certificate this machine holds for the relay that refused, never by
// one it holds for another (ruling 70). A test pins what the advice should
// say, never what the code happens to say; the advice this replaced, "not
// accepted" for a relay that had never been offered anything, was the
// latter.
func TestAMachineEnrolledElsewhereIsToldToEnrolHere(t *testing.T) {
	_, st, _, issue := certRowRelay(t)
	other, _, _, _ := certRowRelay(t)
	alice, _ := certRowEnrolled(t, st, "alice", issue)

	alice.run("relay", "add", other, "--name", "other")
	_, err := alice.tryRun("inbox", "--relay", "other")
	var e *exitError
	if !errors.As(err, &e) || e.code != exitTransport {
		t.Fatalf("inbox on a relay with no certificate for it: %v, want exit %d", err, exitTransport)
	}
	want := "this relay requires a client certificate and this machine's is missing: " +
		"run 'auu register --relay other --token TOKEN' with a token from an administrator"
	if got := err.Error(); got != want {
		t.Errorf("error is\n %q\nwant\n %q", got, want)
	}
	// The relay alice enrolled on is unaffected.
	alice.run("inbox")
}

// A certificate held for the relay that refused and not presented is "not
// accepted". The shipped relay asks for a certificate without naming an
// authority, so a machine offers whatever it holds and this cannot happen
// against it: the refusal here is made by hand, a cert-required 401 from
// the relay alice holds a certificate for, and only the advice is real.
func TestACertificateHeldForTheRefusingRelayIsNotAccepted(t *testing.T) {
	relayURL, st, _, issue := certRowRelay(t)
	alice, _ := certRowEnrolled(t, st, "alice", issue)
	t.Setenv("AUU_HOME", alice.home)

	refused := &client.HTTPError{Status: http.StatusUnauthorized, Relay: relayURL,
		Code: relayapi.CodeCertRequired, Message: relayapi.MsgCertRequired}
	got := adviseCert(refused)
	want := "this relay requires a client certificate and this machine's is not accepted: " +
		"run 'auu register --token TOKEN' with a token from an administrator"
	if got == nil || got.Error() != want {
		t.Errorf("error is\n %v\nwant\n %q", got, want)
	}
	// The same refusal from a relay this home does not know is "missing":
	// nothing held for it could have been offered.
	refused.Relay = "https://elsewhere.example"
	if got := adviseCert(refused); got == nil || !strings.Contains(got.Error(), "machine's is missing") {
		t.Errorf("from an unknown relay: %v; want missing", got)
	}
}
