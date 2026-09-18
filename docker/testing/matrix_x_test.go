//go:build e2e

package e2e

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Expiry and rotation. Nothing here can be told the time, so what runs
// out is either issued short or issued in the past by the forge.
var expiryRows = []matrixRow{
	{"X01", "token_expired", "an enrolment token used after it expired", x01},
	{"X02", "token_not_after_past", "a token issued with --not-after in the past", x02},
	{"X03", "token_revoked", "a token revoked, then used", x03},
	{"X04", "token_uses", "a token with two uses, used three times", x04},
	{"X05", "intermediate_runs_out", "the relay's signing intermediates run out while it serves", x05},
	{"X06", "anchor_expired", "a bundle from an authority created eleven years ago", x06},
	{"X07", "client_cert_expired_on_relay", "the relay's record of alice's certificate expires", x07},
	{"X09", "rotation_rolled_back", "the earlier bundle delivered again after a rotation", x09},
	{"X10", "unlock_ttl", "an unlock for two seconds, to receive and then to send", x10},
	{"X08", "short_cert_lifetime", "client certificates issued for one hour, the relay's minimum", x08},
	{"X11", "client_cert_expires_for_real", "a one-hour certificate, an hour later (AUU_E2E_SLOW=1)", x11},
}

func x01(t *testing.T) {
	tok := issueToken(t, "--note", "two seconds", "--expires", "2s")
	time.Sleep(3 * time.Second)
	c := newCarol(t)
	r := c.auu("enrol", "--name", "carol", "--yes", tok)
	// The client describes the token as expired a few seconds ago and says
	// the relay accepts it for five minutes past that, and the relay does.
	expectCode(t, r, 0)
	if !regexp.MustCompile(`\(expired [0-9]+s ago; a relay accepts it for 5 minutes past that\)`).MatchString(r.stdout) {
		t.Errorf("stdout does not describe the token as still accepted:\n%s", r.stdout)
	}
	expectSays(t, r, 0, `registered `, `as "carol"`)
	if !slow {
		verdict(t, "ok", "The client tells the person the token expired seconds ago and that a relay accepts it for five "+
			"minutes past that, and enrols them with it. AUU_E2E_SLOW=1 waits the five minutes for the refusal.")
		return
	}
	tok = issueToken(t, "--note", "six minutes ago", "--expires", "2s")
	time.Sleep(6 * time.Minute)
	c = newCarol(t)
	r = c.auu("enrol", "--name", "carol", "--yes", tok)
	// Plainly expired: minutes, and no word about a relay accepting it.
	expectSays(t, r, 2, "enrolment token has expired")
	if !regexp.MustCompile(`\(expired [0-9]+ minutes ago\)`).MatchString(r.stdout) {
		t.Errorf("stdout does not describe the token as plainly expired:\n%s", r.stdout)
	}
	expectNot(t, r, "a relay accepts it")
	verdict(t, "ok", "Inside the five minutes of clock skew the token is described as still accepted and is; past them "+
		"it is described as expired, plainly, and refused by name.")
}

func x02(t *testing.T) {
	past := time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
	before := operator.admin("token", "ls", "--all").stdout
	r := operator.admin("token", "issue", "--note", "already over", "--not-after", past)
	expectCode(t, r, 1)
	record(operator, "(observing)", "", r)
	after := operator.admin("token", "ls", "--all").stdout
	if strings.Count(after, "\n") != strings.Count(before, "\n") {
		t.Error("a token was registered")
	}
	verdict(t, "ok", "Refused on the administrator's machine before the relay is asked.")
}

func x03(t *testing.T) {
	r := operator.admin("token", "issue", "--note", "to be revoked", "--json")
	expectCode(t, r, 0)
	var issued struct {
		Token  string `json:"token"`
		Record struct {
			ID string `json:"id"`
		} `json:"record"`
	}
	jsonOf(t, r, &issued)
	expectSays(t, operator.admin("token", "revoke", issued.Record.ID), 0, "revoked "+issued.Record.ID)
	c := newCarol(t)
	r = c.auu("enrol", "--name", "carol", "--yes", issued.Token)
	expectSays(t, r, 2, "enrolment token has been revoked")
	verdict(t, "ok", "")
}

func x04(t *testing.T) {
	tok := issueToken(t, "--note", "two uses", "--uses", "2")
	for i := 1; i <= 2; i++ {
		c := newCarol(t)
		expectSays(t, c.auu("enrol", "--name", fmt.Sprintf("carol%d", i), "--yes", tok), 0, "registered")
	}
	c := newCarol(t)
	expectSays(t, c.auu("enrol", "--name", "carol3", "--yes", tok), 2, "enrolment token has already been used")
	expectSays(t, operator.admin("token", "ls", "--all"), 0, "two uses")
	verdict(t, "ok", "")
}

func x05(t *testing.T) {
	// Cleanups run last first: the administrator's anchor goes back after
	// the real bundle does, since pinning checks the relay.
	repin := false
	t.Cleanup(func() {
		if repin {
			operator.auu("anchor", "pin", state.anchor)
		}
	})
	_, undo := credBackup(t)
	t.Cleanup(undo)
	// An authority old enough to have issued a year ago, and a bundle from
	// it whose intermediates run out a hundred seconds from now. To the
	// machines enrolled on the real authority this relay has been rebuilt;
	// a newcomer with a token naming the aged anchor accepts it.
	operator.exec("", "rm", "-rf", "/home/you/aged-ca")
	created := time.Now().AddDate(-2, 0, 0)
	r := operator.exec("", "forge", "init", "--dir", "/home/you/aged-ca", "--name", "Aged", "--passphrase-file", operatorPass,
		"--at", created.UTC().Format(time.RFC3339))
	expectCode(t, r, 0)
	agedAnchor := find(t, reHex64, r.stdout)
	at := time.Now().AddDate(-1, 0, 0).Add(100 * time.Second)
	local := forgeBundle(t, "/home/you/aged-ca", at, relayName)
	m := deliverHostBundle(t, local)
	log := relayLogSince(m)
	if !strings.Contains(log, "this relay's server signing intermediate expires soon; run 'auu-ca relay' on the offline machine and replace the bundle") {
		t.Errorf("no warning at start:\n%s", log)
	}
	r = alice.auu("inbox")
	expectSays(t, r, 2, "the relay's certificate is not signed by the trust anchor this machine pinned",
		"if the relay was rebuilt, enrol again with a new token")
	// The administrator's machine pinned the real anchor too, and has to
	// pin the aged one before it can issue for this relay.
	r = operator.admin("token", "issue", "--anchor", agedAnchor, "--note", "on the aged authority")
	expectSays(t, r, 2, "x509: certificate signed by unknown authority")
	expectSays(t, operator.auu("anchor", "pin", agedAnchor), 0, "From now on this machine trusts that anchor")
	repin = true
	tok := issueToken(t, "--note", "on the aged authority")
	c := newCarol(t)
	expectSays(t, c.auu("enrol", "--name", "carol", "--yes", tok), 0, "registered")
	expectSays(t, c.auu("inbox"), 0)
	// And then it runs out.
	if d := time.Until(at.AddDate(1, 0, 0)); d > 0 {
		time.Sleep(d + 2*time.Second)
	}
	r = c.auu("inbox")
	expectCode(t, r, 2)
	stderrIs(t, r, "auu: the relay's certificate has expired; its operator needs to run 'auu-ca relay' on the offline "+
		"machine and replace the bundle. Nothing on this machine is wrong")
	verdict(t, "ok", "The relay warned its operator at start, in one sentence with the command to run. The user, when it "+
		"runs out, gets one line that says whose problem it is and that nothing here is wrong; the renewal that would "+
		"have warned first, with the same words in brackets, keeps quiet.")
}

func x06(t *testing.T) {
	_, undo := credBackup(t)
	t.Cleanup(undo)
	operator.exec("", "rm", "-rf", "/home/you/old-ca")
	at := time.Now().AddDate(-11, 0, 0)
	r := operator.exec("", "forge", "init", "--dir", "/home/you/old-ca", "--name", "Long Ago", "--passphrase-file", operatorPass,
		"--at", at.UTC().Format(time.RFC3339))
	expectCode(t, r, 0)
	local := forgeBundle(t, "/home/you/old-ca", at, relayName)
	if nofault {
		verdict(t, "observed", "")
		return
	}
	hostFile(t, local, relay, "/etc/auu/delivered/relay-bundle.json")
	log := relayRestartFails(t)
	if !strings.Contains(log, "server signing intermediate expired on ") || !strings.Contains(log, ": run 'auu-ca relay' again") {
		t.Errorf("log:\n%s", log)
	}
	verdict(t, "ok", "Refused at start with the date and the command.")
}

func x07(t *testing.T) {
	t.Cleanup(dbBackup(t))
	yesterday := time.Now().Add(-24 * time.Hour).Unix()
	if !nofault {
		relay.sql(t, fmt.Sprintf("UPDATE certs SET not_after=%d WHERE serial='%s'", yesterday, state.aliceSerial))
	}
	r := alice.auu("inbox")
	expectSays(t, r, 2, certExpired)
	verdict(t, "ok", "The relay's clock decides, and the sentence says what to do.")
}

func x09(t *testing.T) {
	if len(state.bundles) < 2 {
		t.Skip("the earlier bundle is only kept by the process that ran the cycle")
	}
	_, undo := credBackup(t)
	t.Cleanup(undo)
	deliverHostBundle(t, state.bundles[0])
	r := alice.auu("inbox")
	expectCode(t, r, 2)
	// Two issue times, to the second, since the two rotations were a minute
	// apart; and the two explanations, only one of which is the operator's.
	stamp := `[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}`
	want := regexp.MustCompile(`^auu: the relay presented an older signing authority than the one this machine accepted: ` +
		`issued ` + stamp + `, replacing one issued ` + stamp + `\. Either the relay's operator restored an earlier bundle, ` +
		`or somebody is replaying a retired one\. Ask the operator before doing anything; if it was theirs, enrol again ` +
		`with a new token, which accepts what the relay serves now\n$`)
	if !want.MatchString(r.stderr) {
		t.Errorf("stderr: %q", r.stderr)
	}
	expectNot(t, r, "refused this machine's certificate", "register --token")
	verdict(t, "ok", "The replay is caught and reported as what it is, with both issue times to the second: nothing is "+
		"probed without the certificate, alice is not told to get a new token, and the two explanations are put to "+
		"the one person who can tell them apart.")
}

func x10(t *testing.T) {
	defer encryptAlice(t)()
	expectSays(t, alice.auu("lock"), 0, "locked")
	// The receive TTL locks: a two-second unlock reads inside it and is
	// locked after it.
	r := alice.auu("unlock", "--ttl", "2s", "--passphrase-file", alicePass)
	expectSays(t, r, 0, "unlocked to receive until")
	expectCode(t, alice.auu("inbox"), 0)
	time.Sleep(3 * time.Second)
	r = alice.auu("inbox")
	expectCode(t, r, 4)
	stderrIs(t, r, locked)
	// The send TTL narrows: a two-second send window sends inside it and
	// is refused with the other sentence after it, with the agent still
	// unlocked to receive for its own eight hours.
	r = alice.auu("unlock", "--send", "--ttl", "2s", "--passphrase-file", alicePass)
	expectSays(t, r, 0, "unlocked to send until", "(receive until")
	expectSays(t, alice.auu("send", "--to", "bob", "inside the send ttl"), 0, "sent to bob")
	time.Sleep(3 * time.Second)
	r = alice.auu("send", "--to", "bob", "after the send ttl")
	expectCode(t, r, 4)
	stderrIs(t, r, receiveOnly)
	expectCode(t, alice.auu("inbox"), 0)
	drain(bob)
	verdict(t, "ok", "")
}

func x08(t *testing.T) {
	undoThenRestart(t, extraArgs(t, "--client-cert-lifetime 1h"))
	relayRestart(t)
	tok := issueToken(t, "--use", "cert", "--for", state.aliceFP, "--note", "one hour")
	expectSays(t, alice.auu("register", "--token", tok, "--label", "laptop"), 0, "client certificate for this machine (laptop): expires")
	st := alice.auu("cert", "status")
	expectSays(t, st, 0, "renews:  from")
	before := strings.Count(operator.admin("certs", "ls", "--all").stdout, "renewed")
	for i := 0; i < 3; i++ {
		expectSays(t, alice.auu("inbox"), 0)
	}
	after := strings.Count(operator.admin("certs", "ls", "--all").stdout, "renewed")
	record(operator, fmt.Sprintf("(renewed rows: %d before, %d after three commands)", before, after), "", result{})
	if after-before < 3 {
		t.Errorf("renewed rows went from %d to %d over three commands", before, after)
	}
	verdict(t, "observed", "A certificate shorter than the renewal window is renewed on every command, silently, and "+
		"each renewal is a row on the relay: an operator who sets a short lifetime gets a table that grows by one a "+
		"command.")
}

func x11(t *testing.T) {
	if !slow {
		t.Skip("set AUU_E2E_SLOW=1 to wait an hour for a certificate to expire")
	}
	undoThenRestart(t, extraArgs(t, "--client-cert-lifetime 1h"))
	relayRestart(t)
	tok := issueToken(t, "--use", "cert", "--for", state.bobFP, "--note", "one real hour")
	expectSays(t, bob.auu("register", "--token", tok, "--label", "laptop"), 0, "client certificate for this machine (laptop): expires")
	// A renewal would keep it alive, so the relay is put back to the
	// shipped lifetime now and bob is left alone for an hour.
	relay.root("rm -f /etc/auu/extra-args")
	relayRestart(t)
	time.Sleep(61 * time.Minute)
	r := bob.auu("inbox")
	expectSays(t, r, 2, certExpired)
	verdict(t, "ok", "")
}
