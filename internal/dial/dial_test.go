package dial

import (
	"crypto/mldsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// The bodies in this package are internal/auu's, moved unchanged, and the
// tests that prove what they do are still that package's: they run a command
// against a relay, which is the path a person takes and the only place the
// renewal's warning and the rotation's notice reach a terminal. What is new
// here is the Dialer — the program's name in the advice, and a remark handed
// to a caller instead of written to standard error — so that is what these
// tests are about.

// home is a home with an identity and one relay, as auu init and auu relay
// add leave it, and nothing pinned.
func home(t *testing.T) (*store.Store, *identity.Identity, *store.Relay) {
	t.Helper()
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id, err := identity.Generate("ada")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SaveIdentity(id); err != nil {
		t.Fatal(err)
	}
	r, err := s.AddRelay("work", "https://relay.example")
	if err != nil {
		t.Fatal(err)
	}
	return s, id, r
}

// selfSigned is a certificate for a key, enough to be pinned or read back.
func selfSigned(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(nil, tmpl, tmpl, key.PublicKey(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// TestTheAdviceNamesTheProgramThatIsRunning: the sentence for a certificate
// file that cannot be read tells the person what to run, and what to run is
// the program they typed. It was auu's prog when this code was auu's; two
// callers make it the Dialer's, and a hard-coded name would send a relay's
// operator to a command they do not have.
func TestTheAdviceNamesTheProgramThatIsRunning(t *testing.T) {
	for _, prog := range []string{"auu", "agentuucp", "courier"} {
		s, id, r := home(t)
		// A record whose PEM is not a certificate: there, and unreadable,
		// which is the state the sentence is for.
		rec := &store.CertRecord{
			Relay:     r.URL,
			Serial:    strings.Repeat("0", 31) + "1",
			Label:     "laptop",
			Key:       string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not a key")})),
			Cert:      string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not a certificate")})),
			NotBefore: time.Now(),
			NotAfter:  time.Now().Add(time.Hour),
		}
		if err := s.SaveCertFor(r, rec); err != nil {
			t.Fatal(err)
		}
		_, err := Dialer{Prog: prog}.NoRenew(s, id, r)
		if err == nil {
			t.Fatalf("%s: a certificate that cannot be read dialled anyway", prog)
		}
		want := "run '" + prog + " register --relay work --token TOKEN'"
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v; want the advice %q", prog, err, want)
		}
	}
}

// TestARemarkIsASentenceTheCallerPrefixes: the two remarks this package makes
// carry no program name and no newline, because the caller puts its own name
// in front and decides where the line goes — standard error for a command, a
// log for a relay. A package that wrote "auu: " into them would be one no
// relay could use.
func TestARemarkIsASentenceTheCallerPrefixes(t *testing.T) {
	s, _, r := home(t)
	if err := s.SaveAnchorFor(r, selfSigned(t)); err != nil {
		t.Fatal(err)
	}
	var said []string
	d := Dialer{Prog: "auu", Note: func(s string) { said = append(said, s) }}
	a, err := d.anchor(s, r)
	if err != nil {
		t.Fatal(err)
	}
	if a == nil {
		t.Fatal("no anchor for a relay with one pinned")
	}
	a.OnRotation(time.Now(), time.Now().Add(-24*time.Hour))
	if len(said) != 1 {
		t.Fatalf("%d remarks, want 1: %q", len(said), said)
	}
	switch got := said[0]; {
	case !strings.Contains(got, "was rotated"):
		t.Errorf("%q does not say what happened", got)
	case !strings.Contains(got, r.Name):
		t.Errorf("%q does not name the relay", got)
	case strings.Contains(got, "auu"):
		t.Errorf("%q carries the program's name; the caller adds it", got)
	case strings.HasSuffix(got, "\n"):
		t.Errorf("%q ends in a newline; the caller ends the line", got)
	}
}

// TestADialerWithNoNoteDropsTheRemark: a caller with nowhere to put a remark
// passes no Note, and neither remark is a failure, so nothing panics and
// nothing is returned. The same dialer with a Note records, so the nil is
// what the test is measuring and not the path being unreachable.
func TestADialerWithNoNoteDropsTheRemark(t *testing.T) {
	s, _, r := home(t)
	if err := s.SaveAnchorFor(r, selfSigned(t)); err != nil {
		t.Fatal(err)
	}
	quiet, err := Dialer{Prog: "auu"}.anchor(s, r)
	if err != nil {
		t.Fatal(err)
	}
	quiet.OnRotation(time.Now(), time.Now().Add(-24*time.Hour))

	var said int
	loud, err := Dialer{Prog: "auu", Note: func(string) { said++ }}.anchor(s, r)
	if err != nil {
		t.Fatal(err)
	}
	loud.OnRotation(time.Now(), time.Now().Add(-24*time.Hour))
	if said != 1 {
		t.Fatalf("the dialer with a Note said %d things, want 1; the nil case proves nothing", said)
	}
}

// TestAnchorIsNoneWhenThisMachinePinnedNone: a relay under a public authority
// has no anchor, which is a state and not a failure.
func TestAnchorIsNoneWhenThisMachinePinnedNone(t *testing.T) {
	s, _, r := home(t)
	a, err := Dialer{Prog: "auu"}.anchor(s, r)
	if err != nil {
		t.Fatalf("no anchor pinned: %v; want none and no error", err)
	}
	if a != nil {
		t.Errorf("an anchor for a relay with none pinned")
	}
}

// TestRenewIfExpiringDoesNothingWithoutACertificate: the renewal looks at the
// certificate this machine holds, and a machine with none has nothing to
// renew; it says so by doing nothing rather than by a remark, since there is
// no fault here to tell anybody about.
func TestRenewIfExpiringDoesNothingWithoutACertificate(t *testing.T) {
	s, id, r := home(t)
	var said int
	d := Dialer{Prog: "auu", Note: func(string) { said++ }}
	if d.RenewIfExpiring(s, id, nil, r, time.Now()) {
		t.Error("renewed a certificate this machine does not have")
	}
	if said != 0 {
		t.Errorf("%d remarks for a machine with no certificate, want 0", said)
	}
}

// TestMachineLabelPrefersWhatItWasGiven: an explicit label wins, and the
// hostname it falls back to is the short form, since "laptop" reads better in
// an administrator's listing than "laptop.corp.example.com".
//
// The second half is a smoke check and says so: the cut at the first dot runs
// only on a machine whose own hostname has one, which this one does and a
// runner may not, so on a runner the assertion holds without the branch
// having run. Driving the branch from outside means splitting the rule out of
// a body this commit is moving unchanged, which is not a trade worth making
// in a commit that is a move; it is written down here instead.
func TestMachineLabelPrefersWhatItWasGiven(t *testing.T) {
	if got := MachineLabel("desk"); got != "desk" {
		t.Errorf("MachineLabel(%q) = %q", "desk", got)
	}
	got := MachineLabel("")
	if got == "" {
		t.Error("no label at all for a machine that gave none")
	}
	if strings.Contains(got, ".") {
		t.Errorf("MachineLabel(\"\") = %q; want the hostname's short form", got)
	}
}
