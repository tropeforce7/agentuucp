//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// state is what one step of the cycle leaves for the next.
var state struct {
	anchor             string   // the trust anchor's hash, as auu-ca printed it
	bundles            []string // host copies of every bundle issued, in order
	aliceFP, bobFP     string
	aliceLine, bobLine string
	// dave is family F's far end, on relay-c, and is set by that family's
	// setup rather than by the cycle: the cycle is the deployment guide's own
	// narrative, which is one relay.
	daveFP, daveLine string
	thread           string
	aliceSerial      string
	cycleFailed      bool
}

const (
	operatorPass = "/home/you/pass"
	bundleOut    = "/home/you/relay-bundle.json"
	alicePass    = "/home/alice/pass"
	bobDesktop   = "/home/bob/.auu-desktop"
)

// The deployment guide and the enrolling guide, in order, in containers:
// every step asserts the guide's own words.
func TestCycle(t *testing.T) {
	steps := []struct {
		id, what string
		run      func(t *testing.T)
	}{
		{"E01", "auu-ca init on the operator's machine", e01Init},
		{"E02", "auu-ca relay writes the bundle to a file", e02Bundle},
		{"E03", "the settings, the admin file, and the check the guide says to run before the credential exists", e03Settings},
		{"E04", "scp the bundle to the relay host, where it becomes the credential, and rm the local copy", e04Deliver},
		{"E05", "auu init for the administrator, pinning the anchor by its hash", e05AdminInit},
		{"E06", "auu-admin status before the administrator's line is in the admin file", e06NotAdmin},
		{"E07", "the export line goes into /etc/auu/admins; no restart", e07Admins},
		{"E08", "two enrolment tokens, one each", e08Tokens},
		{"E09", "alice and bob enrol", e09Enrol},
		{"E10", "bob writes to alice before she has added him: quarantine, then trust", e10Quarantine},
		{"E11", "the two exchange export lines and restrict their mailboxes", e11Peers},
		{"E12", "bob defines a channel for bug reports, and alice lists his channels", e12Channel},
		{"E13", "a message with an attachment, to that channel, read, extracted, replied to, waited for", e13Message},
		{"E14", "a 100 KiB attachment goes as a stream", e14Stream},
		{"E15", "the operator turns client certificates on", e15CertsOn},
		{"E16", "alice and bob get their machines certificates", e16Certs},
		{"E17", "bob's second machine", e17SecondMachine},
		{"E18", "the operator rotates the signing intermediates", e18Rotate},
		{"E19", "alice's laptop is revoked and enrolled again", e19Revoke},
		{"E20", "alice encrypts her keys: locked, unlocked, expired, then decrypted again", e20Passphrase},
		{"E21", "day two: what the operator runs, and a backup", e21DayTwo},
	}
	for _, s := range steps {
		s := s
		ok := t.Run(s.id, func(t *testing.T) {
			if state.cycleFailed {
				t.Skip("an earlier step failed")
			}
			begin(t, s.id, "E", s.what)
			s.run(t)
		})
		if !ok {
			state.cycleFailed = true
		}
	}
	if state.cycleFailed {
		t.Fatal("the cycle did not complete; the matrix has nothing to start from")
	}
	// The mail the cycle exchanged is read and, since a channel keeps its
	// mail, still on the relay. The matrix starts from an empty mailbox,
	// so the snapshot is taken with it removed: every row that leaves
	// mail behind is then its own to clear, and a row that counts what
	// the relay holds counts only its own.
	drain(bob)
	drain(alice)
	if left := queued(t, state.bobFP); len(left) != 0 {
		t.Fatalf("the cycle left %v queued for bob; the matrix starts from an empty mailbox", left)
	}
	snapshot(t)
}

func e01Init(t *testing.T) {
	r := operator.exec("", "sh", "-c", "umask 077 && printf 'operator passphrase\\n' > "+operatorPass)
	expectCode(t, r, 0)
	r = operator.ca("init", "--name", "Example", "--passphrase-file", operatorPass)
	expectSays(t, r, 0, "created /home/you/.auu-ca", "  trust anchor  ",
		"  keys          ML-DSA-65, encrypted under your passphrase")
	state.anchor = find(t, reHex64, r.stdout)
	ls := operator.exec("", "sh", "-c", "stat -c '%a %n' ~/.auu-ca ~/.auu-ca/*")
	expectSays(t, ls, 0, "700 /home/you/.auu-ca", "600 /home/you/.auu-ca/ta.key", "600 /home/you/.auu-ca/ta.pem",
		"600 /home/you/.auu-ca/server-ca.key", "600 /home/you/.auu-ca/client-ca.key")
	verdict(t, "ok", "")
}

func e02Bundle(t *testing.T) {
	r := operator.ca("relay", "--host", relayName, "--out", bundleOut, "--passphrase-file", operatorPass)
	expectSays(t, r, 0, "wrote "+bundleOut, "  for           "+relayName, "  trust anchor  "+state.anchor,
		"  scp "+bundleOut+" relay.example.com:", "Then delete "+bundleOut)
	if got := operator.stat(t, bundleOut); !strings.HasPrefix(got, "you:600 ") {
		t.Errorf("the bundle is %s, want you:600", got)
	}
	// The two signing keys and nothing else: the anchor's key and the
	// authorities' keys never leave the operator's directory.
	local := keepBundle(t)
	var b map[string]json.RawMessage
	raw, err := os.ReadFile(local)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatal(err)
	}
	var keys []string
	for k := range b {
		if strings.HasSuffix(k, "_key") {
			keys = append(keys, k)
		}
	}
	if len(keys) != 2 || b["server_int_key"] == nil || b["client_int_key"] == nil {
		t.Errorf("the bundle holds keys %v, want server_int_key and client_int_key only", keys)
	}
	if !strings.Contains(string(raw), `"hosts": [`) && !strings.Contains(string(raw), `"hosts":[`) {
		t.Errorf("the bundle names no hosts")
	}
	show := operator.ca("show")
	expectSays(t, show, 0, "trust anchor: "+state.anchor, "relays issued:", relayName)
	if !strings.Contains(show.stderr, bundleOut) {
		t.Errorf("auu-ca show did not warn that %s is still on disk; stderr: %q", bundleOut, show.stderr)
	}
	verdict(t, "ok", "")
}

// keepBundle copies the bundle the operator just wrote to the host, for a
// later rotation or rollback.
func keepBundle(t *testing.T) string {
	t.Helper()
	local := filepath.Join(workDir, fmt.Sprintf("bundle-%d.json", len(state.bundles)+1))
	tmp := fetch(t, operator, bundleOut)
	if err := os.Rename(tmp, local); err != nil {
		t.Fatal(err)
	}
	state.bundles = append(state.bundles, local)
	return local
}

func e03Settings(t *testing.T) {
	hostFile(t, filepath.Join("..", "..", "docs", "systemd", "relay.json"), relay, "/etc/auu/relay.json")
	relay.mustRoot(t, "chown root:root /etc/auu/relay.json && chmod 0644 /etc/auu/relay.json && "+
		"install -o root -g root -m 0644 /dev/null /etc/auu/admins")
	r := relayAuu.exec("", "auu-relay", "--config", "/etc/auu/relay.json", "--print-config")
	expectCode(t, r, 1)
	stderrIs(t, r, `auu-relay: tls.bundle_credential is "relay-bundle" but CREDENTIALS_DIRECTORY is not set: `+
		`the relay is not running under a unit with LoadCredentialEncrypted=relay-bundle:... in it`)
	if got := relay.stat(t, "/var/lib/auu/messages"); !strings.HasPrefix(got, "auu:700 ") {
		t.Errorf("the message directory is %s, want auu:700", got)
	}
	verdict(t, "ok", "The check refuses for the one reason the guide says it will, after making the message directory as auu.")
}

// deliverBundle is the guide's scp and rm: the file goes to the relay
// host, becomes the credential, and leaves the operator's disk.
func deliverBundle(t *testing.T) mark {
	t.Helper()
	m := logMark()
	copyFile(t, operator, bundleOut, relay, "/etc/auu/delivered/relay-bundle.json")
	expectCode(t, operator.exec("", "rm", bundleOut), 0)
	return m
}

func e04Deliver(t *testing.T) {
	m := deliverBundle(t)
	log := waitRelayLog(t, m, "serving from an auu-ca bundle", 60*time.Second)
	waitRelayReady(t)
	for _, want := range []string{"bundle_source=credential", "cert=/run/credentials/auu-relay/relay-bundle",
		"hosts=" + relayName, "installed the delivered bundle as the credential relay-bundle"} {
		if !strings.Contains(log, want) {
			t.Errorf("the relay log lacks %q:\n%s", want, log)
		}
	}
	if relay.exists("/etc/auu/delivered/relay-bundle.json") {
		t.Error("the delivered copy is still in /etc/auu/delivered")
	}
	if got := relay.stat(t, "/run/credentials/auu-relay/relay-bundle"); !strings.HasPrefix(got, "auu:400 ") {
		t.Errorf("the credential is %s, want auu:400", got)
	}
	show := operator.ca("show")
	expectCode(t, show, 0)
	if strings.TrimSpace(show.stderr) != "" {
		t.Errorf("auu-ca show warned after the bundle was deleted: %q", show.stderr)
	}
	verdict(t, "ok", "")
}

func e05AdminInit(t *testing.T) {
	r := operator.auu("init", "--name", "boss", "--relay", relayURL, "--anchor", state.anchor)
	expectSays(t, r, 0, "pinned the trust anchor of "+relayName+": "+state.anchor[:16],
		"identity created in /home/you/.auu", "Next: auu register --relay "+relayName)
	line := operator.auu("id", "export")
	expectCode(t, line, 0)
	if l := strings.TrimSpace(line.stdout); !strings.HasPrefix(l, "ccx2.") || !strings.HasSuffix(l, ".boss") {
		t.Errorf("export line %q", l)
	}
	verdict(t, "ok", "")
}

func e06NotAdmin(t *testing.T) {
	r := operator.admin("status")
	expectSays(t, r, 2, "you are not an administrator of "+relayURL+"; an administrator's export line "+
		"must be in that relay's authorized file. Print yours with: auu id export")
	verdict(t, "ok", "")
}

func e07Admins(t *testing.T) {
	m := logMark()
	line := strings.TrimSpace(operator.auu("id", "export").stdout)
	relay.mustRoot(t, "printf '%s\\n' "+shq(line)+" > /etc/auu/admins && chmod 0644 /etc/auu/admins")
	var r result
	for i := 0; i < 20; i++ {
		r = operator.admin("status")
		if r.code == 0 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	expectSays(t, r, 0, "administrators: 1", "registration:   token", "client certs:   off")
	if log := relayLogSince(m); !strings.Contains(log, `msg="administrators reloaded" count=1 path=/etc/auu/admins`) {
		t.Errorf("the relay did not log the reload:\n%s", log)
	}
	verdict(t, "ok", "The file is re-read on change and no restart is needed, and the reload is one line in the "+
		"journal with the count and the path.")
}

// issueToken has the administrator issue a token and returns it.
func issueToken(t *testing.T, args ...string) string {
	t.Helper()
	r := operator.admin(append([]string{"token", "issue"}, args...)...)
	expectSays(t, r, 0, "Send this to them. It is a bearer credential")
	tok := lastLine(r.stdout)
	if !strings.HasPrefix(tok, "ccxt2.") {
		t.Fatalf("the last line is not a token: %q", tok)
	}
	return tok
}

var tokens struct{ alice, bob string }

func e08Tokens(t *testing.T) {
	tokens.alice = issueToken(t, "--note", "Alice, protocol review", "--expires", "168h")
	tokens.bob = issueToken(t, "--note", "Bob, protocol review", "--expires", "168h")
	r := alice.auu("token", "show", tokens.alice)
	expectSays(t, r, 0, relayURL, "Alice, protocol review")
	ls := operator.admin("token", "ls")
	expectSays(t, ls, 0, "Alice, protocol review", "Bob, protocol review")
	expectNot(t, ls, tokens.alice)
	verdict(t, "ok", "The token is the last line of stdout and token ls never shows one.")
}

func e09Enrol(t *testing.T) {
	r := alice.auu("enrol", "--name", "alice", "--label", "laptop", "--yes", tokens.alice)
	expectSays(t, r, 0, "identity created in /home/alice/.auu", `as "alice" on `+relayName+" ("+relayURL+")",
		"this relay does not use client certificates")
	r = bob.auu("enrol", "--name", "bob", "--label", "laptop", "--yes", tokens.bob)
	expectSays(t, r, 0, `as "bob" on `+relayName)
	state.aliceLine = strings.TrimSpace(alice.auu("id", "export").stdout)
	state.bobLine = strings.TrimSpace(bob.auu("id", "export").stdout)
	var id struct {
		Fingerprint string `json:"fingerprint"`
	}
	jsonOf(t, alice.auu("id", "--json"), &id)
	state.aliceFP = id.Fingerprint
	jsonOf(t, bob.auu("id", "--json"), &id)
	state.bobFP = id.Fingerprint
	if len(state.aliceFP) != 64 || len(state.bobFP) != 64 {
		t.Fatalf("fingerprints %q %q", state.aliceFP, state.bobFP)
	}
	verdict(t, "ok", "")
}

func e10Quarantine(t *testing.T) {
	expectSays(t, bob.auu("peers", "add", state.aliceLine), 0, "added "+state.aliceFP[:16])
	r := bob.auu("send", "--to", "alice", "--subject", "hello", "first contact")
	expectSays(t, r, 0, "sent to alice via "+relayName)
	r = alice.auu("inbox")
	expectSays(t, r, 0, "1 quarantined from unknown senders", "Unknown senders are held back: auu quarantine ls")
	r = alice.auu("quarantine", "ls")
	expectSays(t, r, 0, "from "+state.bobFP[:16]+"  hello", "then run: auu quarantine trust <id>")
	id := strings.Fields(r.stdout)[0]
	r = alice.auu("quarantine", "show", id)
	expectSays(t, r, 0, "!! QUARANTINED: this sender is not in your peer list.", "first contact")
	r = alice.auuIn("bob\n", "quarantine", "trust", id)
	expectSays(t, r, 0, "Local name for "+state.bobFP[:16]+" [", "trusted "+state.bobFP[:16]+" and moved message "+id+" to the inbox",
		"run 'auu allow push' if your relay mailbox is restricted")
	expectSays(t, alice.auu("inbox", "--no-fetch"), 0, "hello")
	verdict(t, "ok", "")
}

func e11Peers(t *testing.T) {
	expectSays(t, alice.auu("peers", "add", state.bobLine), 0, "already known: "+state.bobFP[:16]+"  bob")
	expectSays(t, alice.auu("allow", "push"), 0, relayName+" will now accept mail for you from 1 peer(s) only")
	expectSays(t, bob.auu("allow", "push"), 0, "from 1 peer(s) only")
	expectSays(t, alice.auu("peers", "ls"), 0, state.bobFP)
	expectSays(t, bob.auu("peers", "ls"), 0, state.aliceFP)
	verdict(t, "ok", "")
}

// bugChannel is the channel bob defines in E12 and the first message
// goes to; every matrix row starts from a mailbox whose directory holds
// default and this.
const (
	bugChannel     = "bug reports"
	bugDescription = "One bug per message; attach the log"
)

// channelsJSON is auu channel ls --json.
type channelsJSON struct {
	Peer      string `json:"peer"`
	Directory bool   `json:"directory"`
	Channels  []struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		NotBefore   string `json:"not_before"`
		NotAfter    string `json:"not_after"`
		Open        bool   `json:"open"`
		Why         string `json:"why"`
	} `json:"channels"`
	Relays []struct {
		Name   string           `json:"name"`
		State  string           `json:"state"`
		Queued map[string]int64 `json:"queued"`
	} `json:"relays"`
}

func e12Channel(t *testing.T) {
	expectSays(t, bob.auu("channel", "create", bugChannel, "--description", bugDescription), 0,
		relayName+": directory pushed (2 channels)")
	// The owner's view: the table with counts, and what the relay holds.
	r := bob.auu("channel", "ls")
	expectSays(t, r, 0, "NAME", "DESCRIPTION", "PERIOD", "STATE", "QUEUED", "KEEP", "issued ", " by this machine",
		relayName+": holds this directory")
	// KEEP is the owner's own setting for what a fetch leaves on the
	// relay, on for every channel until they say otherwise.
	tableHas(t, r, "default - open 0 on", bugChannel+" "+bugDescription+" - open 0 on")
	// The sender's view: the same lines, no counts, verified against the
	// key alice holds for bob.
	r = alice.auu("channel", "ls", "bob")
	expectSays(t, r, 0, "issued ", " by bob")
	tableHas(t, r, "default - open", bugChannel+" "+bugDescription+" - open")
	expectNot(t, r, "QUEUED", "holds")
	var ls channelsJSON
	jsonOf(t, alice.auu("channel", "ls", "bob", "--json"), &ls)
	if ls.Peer != "bob" || !ls.Directory || len(ls.Channels) != 2 || ls.Channels[1].Name != bugChannel ||
		ls.Channels[1].Description != bugDescription || !ls.Channels[1].Open || ls.Channels[1].Why != "" || ls.Relays != nil {
		t.Errorf("alice's channel ls bob --json: %+v", ls)
	}
	verdict(t, "ok", "")
}

type sent struct {
	ID      string `json:"id"`
	Thread  string `json:"thread"`
	Kind    string `json:"kind"`
	Chunks  int    `json:"chunks"`
	Channel string `json:"channel"`
}

type inboxJSON struct {
	Fetch struct {
		Delivered, Quarantined, Unreadable int
		Gone                               map[string]int `json:"channels_gone"`
	} `json:"fetch"`
	// Relays is what each relay gave up, and what it still holds: with a
	// channel set to keep, which is the default, Queued is the mail read
	// and left there.
	Relays []struct {
		Relay  string `json:"relay"`
		Queued int64  `json:"queued"`
	} `json:"relays"`
	Messages []struct {
		ID          string `json:"id"`
		Thread      string `json:"thread"`
		InReplyTo   string `json:"in_reply_to"`
		Type        string `json:"type"`
		Subject     string `json:"subject"`
		From        string `json:"from"`
		FromName    string `json:"from_name"`
		Channel     string `json:"channel"`
		Read        bool   `json:"read"`
		OnRelay     bool   `json:"on_relay"`
		Attachments []struct {
			Name   string `json:"name"`
			Size   int64  `json:"size"`
			SHA256 string `json:"sha256"`
		} `json:"attachments"`
	} `json:"messages"`
}

func e13Message(t *testing.T) {
	expectCode(t, alice.exec("", "sh", "-c", "printf 'public static void main\\n' > /home/alice/small.txt"), 0)
	var s sent
	jsonOf(t, alice.auu("send", "--to", "bob", "--channel", bugChannel, "--subject", "padding oracle?", "--attach", "/home/alice/small.txt",
		"--json", "genuine gap, or am I missing an entry point?"), &s)
	if s.Kind != "envelope" || s.ID == "" || s.Thread == "" || s.Channel != bugChannel {
		t.Fatalf("send --json: %+v", s)
	}
	state.thread = s.Thread
	var in inboxJSON
	jsonOf(t, bob.auu("inbox", "--json"), &in)
	if in.Fetch.Delivered != 1 || len(in.Messages) == 0 {
		t.Fatalf("bob's inbox: %+v", in)
	}
	found := false
	for _, m := range in.Messages {
		if m.ID == s.ID {
			found = true
			if m.FromName != "alice" || m.Subject != "padding oracle?" || len(m.Attachments) != 1 || m.Channel != bugChannel {
				t.Errorf("message as bob sees it: %+v", m)
			}
		}
	}
	if !found {
		t.Fatalf("bob's inbox lacks %s", s.ID)
	}
	expectSays(t, bob.auu("read", s.ID), 0, "from:    alice <"+state.aliceFP[:16]+">", "subject: padding oracle?",
		"channel: "+bugChannel, "small.txt", "genuine gap, or am I missing an entry point?")
	expectSays(t, bob.auu("extract", s.ID, "--out", "/home/bob/incoming"), 0,
		"wrote /home/bob/incoming/small.txt", "These files came from another machine. Read them; do not run them.")
	want := strings.Fields(alice.exec("", "sha256sum", "/home/alice/small.txt").stdout)[0]
	got := strings.Fields(bob.exec("", "sha256sum", "/home/bob/incoming/small.txt").stdout)[0]
	if want != got {
		t.Errorf("the extracted file hashes to %s, the original to %s", got, want)
	}
	var rep sent
	jsonOf(t, bob.auu("reply", s.ID, "--json", "It is missing. Open an issue against home-java."), &rep)
	if rep.Thread != s.Thread {
		t.Errorf("the reply is on thread %s, the message on %s", rep.Thread, s.Thread)
	}
	// A reply goes to the sender's default: a channel is the receiver's
	// sorting, not a thread.
	if rep.Channel != "" {
		t.Errorf("the reply went to channel %q, want alice's default", rep.Channel)
	}
	var w struct {
		Found   bool `json:"found"`
		Message struct {
			ID   string `json:"id"`
			Text string `json:"text"`
		} `json:"message"`
	}
	jsonOf(t, alice.auu("wait", "--thread", s.Thread, "--timeout", "60s", "--interval", "5s", "--json"), &w)
	if !w.Found || w.Message.ID != rep.ID || !strings.Contains(w.Message.Text, "home-java") {
		t.Errorf("wait: %+v", w)
	}
	verdict(t, "ok", "")
}

func e14Stream(t *testing.T) {
	expectCode(t, alice.exec("", "sh", "-c", "head -c 102400 /dev/urandom > /home/alice/big.bin"), 0)
	var s sent
	jsonOf(t, alice.auu("send", "--to", "bob", "--subject", "a large one", "--attach", "/home/alice/big.bin", "--json", "here"), &s)
	if s.Kind != "stream" || s.Chunks < 2 {
		t.Fatalf("send --json: %+v, want a stream of at least 2 chunks", s)
	}
	var in inboxJSON
	jsonOf(t, bob.auu("inbox", "--json"), &in)
	if in.Fetch.Delivered != 1 {
		t.Fatalf("bob's fetch: %+v", in.Fetch)
	}
	expectSays(t, bob.auu("extract", s.ID, "--out", "/home/bob/incoming"), 0, "wrote /home/bob/incoming/big.bin")
	want := strings.Fields(alice.exec("", "sha256sum", "/home/alice/big.bin").stdout)[0]
	got := strings.Fields(bob.exec("", "sha256sum", "/home/bob/incoming/big.bin").stdout)[0]
	if want != got {
		t.Errorf("the extracted file hashes to %s, the original to %s", got, want)
	}
	verdict(t, "ok", "")
}

const (
	certMissing = "this relay requires a client certificate and this machine's is missing: " +
		"run 'auu register --token TOKEN' with a token from an administrator"
	certRevoked = "this relay requires a client certificate and this machine's is revoked: " +
		"run 'auu register --token TOKEN' with a token from an administrator"
	certExpired = "this relay requires a client certificate and this machine's is expired: " +
		"run 'auu register --token TOKEN' with a token from an administrator"
)

func e15CertsOn(t *testing.T) {
	// The guide's "Client certificates" section: the settings, then a
	// restart. This edit is the operator's, so it is not undone.
	content := relay.read(t, "/etc/auu/relay.json")
	if strings.Count(content, `"mode": "off"`) != 1 {
		t.Fatalf("relay.json:\n%s", content)
	}
	relay.putContent(t, "/etc/auu/relay.json", strings.Replace(content, `"mode": "off"`, `"mode": "required"`, 1))
	m := relayRestart(t)
	waitRelayLog(t, m, "client certificates required", 10*time.Second)
	r := alice.auu("inbox")
	expectSays(t, r, 2, certMissing)
	expectSays(t, operator.admin("status"), 0, "client certs:   required", "  live:         0")
	verdict(t, "ok", "An administrator needs no certificate; a user is told in one sentence what to do.")
}

func e16Certs(t *testing.T) {
	// An identity with a mailbox and no live certificate is enrolling
	// again, with an ordinary token.
	tok := issueToken(t, "--note", "alice's laptop")
	r := alice.auu("register", "--token", tok, "--label", "laptop")
	expectSays(t, r, 0, "client certificate for this machine (laptop): expires")
	tok = issueToken(t, "--note", "bob's laptop")
	expectSays(t, bob.auu("register", "--token", tok, "--label", "laptop"), 0,
		"client certificate for this machine (laptop): expires")
	var st struct {
		Serial  string `json:"serial"`
		Present bool   `json:"present"`
	}
	jsonOf(t, alice.auu("cert", "status", "--json"), &st)
	if !st.Present || st.Serial == "" {
		t.Fatalf("cert status: %+v", st)
	}
	state.aliceSerial = st.Serial
	expectSays(t, alice.auu("cert", "status"), 0, "machine: laptop", "serial:  "+st.Serial, "renews:  from")
	expectSays(t, operator.admin("certs", "ls"), 0, "laptop")
	expectSays(t, operator.admin("status"), 0, "  live:         2")
	expectSays(t, alice.auu("inbox"), 0)
	verdict(t, "ok", "")
}

func e17SecondMachine(t *testing.T) {
	// The enrolling guide: copy the home, leaving every relays/*/cert.json
	// behind, then register with a certificate token for this identity.
	expectCode(t, bob.exec("", "sh", "-c", "cp -a "+bob.home+" "+bobDesktop+" && rm "+bobDesktop+"/relays/*/cert.json"), 0)
	desk := bob.at(bobDesktop)
	expectSays(t, desk.auu("inbox", "--no-fetch"), 0)
	expectSays(t, desk.auu("inbox"), 2, certMissing)
	tok := issueToken(t, "--use", "cert", "--for", state.bobFP, "--note", "Bob's desktop")
	expectSays(t, desk.auu("register", "--token", tok, "--label", "desktop"), 0,
		"client certificate for this machine (desktop): expires")
	ls := desk.auu("cert", "ls")
	expectSays(t, ls, 0, "laptop", "desktop", "* is this machine")
	marked := 0
	for _, l := range strings.Split(ls.stdout, "\n") {
		if strings.HasPrefix(l, "* ") && !strings.HasPrefix(l, "* is this machine") {
			marked++
		}
	}
	if marked != 1 {
		t.Errorf("cert ls marks %d rows as this machine:\n%s", marked, ls.stdout)
	}
	expectSays(t, desk.auu("send", "--to", "alice", "--subject", "from the desktop", "still bob"), 0, "sent to alice")
	var in inboxJSON
	jsonOf(t, alice.auu("inbox", "--json"), &in)
	if in.Fetch.Delivered != 1 || in.Messages[len(in.Messages)-1].FromName != "bob" {
		t.Errorf("alice's inbox after the desktop wrote: %+v", in)
	}
	verdict(t, "ok", "")
}

func e18Rotate(t *testing.T) {
	r := operator.ca("relay", "--host", relayName, "--out", bundleOut, "--passphrase-file", operatorPass)
	expectSays(t, r, 0, "rotation      2, keeping 1 earlier client intermediate(s)")
	keepBundle(t)
	deliverBundle(t)
	m := relayRestart(t)
	if !strings.Contains(relayLogSince(m), "bundle_source=credential") {
		t.Error("the restarted relay did not read the credential")
	}
	r = alice.auu("inbox")
	expectSays(t, r, 0, "the server certificate authority of "+relayName+" was rotated: issued",
		"Only the relay operator's offline authority can issue one, so this is a rotation, not an attack; recorded.")
	r = alice.auu("inbox")
	expectCode(t, r, 0)
	expectNot(t, r, "was rotated")
	// Bob's certificate, from the retired client intermediate, still works.
	expectSays(t, bob.auu("send", "--to", "alice", "after the rotation"), 0, "sent to alice")
	verdict(t, "ok", "The rotation is announced once and recorded; certificates from the retired intermediate keep working.")
}

func e19Revoke(t *testing.T) {
	r := operator.admin("certs", "revoke", state.aliceSerial, "--reason", "laptop stolen", "--yes")
	expectSays(t, r, 0, "revoked "+state.aliceSerial[:16])
	expectSays(t, alice.auu("inbox"), 2, certRevoked)
	expectSays(t, operator.admin("certs", "ls", "--all"), 0, "laptop stolen")
	tok := issueToken(t, "--note", "alice again")
	expectSays(t, alice.auu("register", "--token", tok, "--label", "laptop"), 0,
		"client certificate for this machine (laptop): expires")
	expectSays(t, alice.auu("inbox"), 0)
	verdict(t, "ok", "Revocation bites on the very next request; a new token restores the machine.")
}

const locked = "auu: your identity is locked: run 'auu unlock' in your own terminal"

// receiveOnly is the other sentence exit 4 carries: the agent is unlocked
// to receive and the command originates.
const receiveOnly = "auu: the agent is unlocked to receive; run 'auu unlock --send' at a terminal to send for the next 10 minutes"

func e20Passphrase(t *testing.T) {
	expectCode(t, alice.exec("", "sh", "-c", "umask 077 && printf 'alice passphrase\\n' > "+alicePass), 0)
	r := alice.auu("passphrase", "set", "--passphrase-file", alicePass)
	expectSays(t, r, 0, "encrypted the keys in /home/alice/.auu")
	expectSays(t, alice.auu("agent", "status"), 0, "agent:  running", "keys:   unlocked to receive until")
	// Unlocked to receive, which is what set leaves: reading works and
	// sending is the other sentence.
	expectCode(t, alice.auu("inbox"), 0)
	r = alice.auu("send", "--to", "bob", "while unlocked to receive")
	expectCode(t, r, 4)
	stderrIs(t, r, receiveOnly)
	expectSays(t, alice.auu("lock"), 0, "locked")
	r = alice.auu("send", "--to", "bob", "while locked")
	expectCode(t, r, 4)
	stderrIs(t, r, locked)
	r = alice.auu("unlock", "--send", "--ttl", "2s", "--passphrase-file", alicePass)
	expectSays(t, r, 0, "unlocked to send until")
	expectSays(t, alice.auu("send", "--to", "bob", "while unlocked to send"), 0, "sent to bob")
	time.Sleep(3 * time.Second)
	// Send scope ended; the agent is back to receive, not locked.
	r = alice.auu("send", "--to", "bob", "after the send ttl")
	expectCode(t, r, 4)
	stderrIs(t, r, receiveOnly)
	var st struct {
		Running bool   `json:"running"`
		Locked  bool   `json:"locked"`
		Scope   string `json:"scope"`
	}
	jsonOf(t, alice.auu("agent", "status", "--json"), &st)
	if !st.Running || st.Locked || st.Scope != "receive" {
		t.Errorf("agent status: %+v, want running, unlocked to receive", st)
	}
	expectCode(t, alice.auu("inbox"), 0)
	// Bob's side sees nothing of any of it: one message, from the window.
	var in inboxJSON
	jsonOf(t, bob.auu("inbox", "--json"), &in)
	if in.Fetch.Delivered != 1 {
		t.Errorf("bob got %d messages, want the one sent while unlocked", in.Fetch.Delivered)
	}
	// Back to the clear for the matrix, which encrypts where it needs to.
	expectSays(t, alice.auu("passphrase", "remove", "--passphrase-file", alicePass), 0,
		"decrypted the keys in /home/alice/.auu; they are on disk in the clear again")
	expectSays(t, alice.auu("agent", "status"), 0, "agent:  not running")
	verdict(t, "ok", "Exit code 4 and one of two sentences, on the wire nothing; the send window closes on its own and the agent goes on reading.")
}

func e21DayTwo(t *testing.T) {
	r := operator.ca("show")
	expectSays(t, r, 0, "relays issued:", relayName)
	expectSays(t, operator.admin("token", "ls", "--all"), 0, "Bob's desktop")
	expectSays(t, operator.admin("certs", "ls", "--all"), 0, "laptop", "desktop")
	expectSays(t, operator.admin("mailboxes", "ls"), 0, state.aliceFP[:16], state.bobFP[:16])
	// The guide's backup line, as auu, and the copy opens.
	r = relayAuu.exec("", "sh", "-c", `sqlite3 /var/lib/auu/relay.db ".backup /var/lib/auu/backup.db" && `+
		`sqlite3 /var/lib/auu/backup.db "select count(*) from mailboxes" && rm /var/lib/auu/backup.db`)
	expectSays(t, r, 0, "2")
	verdict(t, "ok", "")
}
