//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// matrixRow is one thing that goes wrong in the wild.
type matrixRow struct {
	id, slug, what string
	run            func(t *testing.T)
}

// The matrix. Each family starts from the snapshot the cycle left, and
// each row undoes its own fault, so a row runs alone with
// -run 'TestMatrix/K/K13' once TestCycle has run.
func TestMatrix(t *testing.T) {
	if !haveSnapshot() {
		t.Fatal("no snapshot to start from: run TestCycle first")
	}
	families := []struct {
		name, what string
		rows       []matrixRow
	}{
		{"M", "stored messages vandalised", messageRows},
		{"K", "the user's keys and settings", keyRows},
		{"R", "the relay: settings, files, disk", relayRows},
		{"X", "expiry and rotation", expiryRows},
		{"N", "the network and the agent", networkRows},
		{"C", "channels", channelRows},
		{"W", "watching", watchRows},
		{"L", "mail left on the relay", keepRows},
		{"S", "a channel answered by a program", serveRows},
		{"A", "the signed allow list", allowRows},
		{"P", "the card, the listing and the knock", cardRows},
		{"F", "mail across peered relays", forwardRows},
		{"G", "a database an older release wrote", upgradeRows},
	}
	for _, f := range families {
		f := f
		t.Run(f.name, func(t *testing.T) {
			restore(t)
			loadState(t)
			if setup := familySetup[f.name]; setup != nil {
				setup(t)
			}
			for _, row := range f.rows {
				row := row
				t.Run(row.id+"_"+row.slug, func(t *testing.T) {
					begin(t, row.id, f.name, row.what)
					row.run(t)
				})
			}
		})
	}
}

// familySetup is what a family needs doing once, after the restore and before
// its rows, when the cycle does not leave that state behind.
//
// A lookup rather than a field on the table above, so the eleven families that
// need nothing keep their three-value literals and this file's diff is one
// entry. Family F needs three relays peered, which is two bundles and a dozen
// commands; per row it would be that many times over for no gain.
//
// A row still runs alone. With -run 'TestMatrix/F/F03' the family's own body
// executes — restore, loadState, this — and only the row subtests are filtered,
// so the state a row needs is there whether the whole family runs or one row
// does.
var familySetup = map[string]func(*testing.T){
	"F": peerTheRelays,
}

// loadState reads from the machines what the cycle recorded in memory, so
// the matrix can run in a process of its own.
func loadState(t *testing.T) {
	t.Helper()
	var id struct {
		Fingerprint string `json:"fingerprint"`
	}
	jsonOf(t, alice.auu("id", "--json"), &id)
	state.aliceFP = id.Fingerprint
	jsonOf(t, bob.auu("id", "--json"), &id)
	state.bobFP = id.Fingerprint
	state.aliceLine = strings.TrimSpace(alice.auu("id", "export").stdout)
	state.bobLine = strings.TrimSpace(bob.auu("id", "export").stdout)
	var st struct {
		Serial string `json:"serial"`
	}
	jsonOf(t, alice.auu("cert", "status", "--json"), &st)
	state.aliceSerial = st.Serial
	r := operator.ca("show", "--json")
	expectCode(t, r, 0)
	state.anchor = find(t, reHex64, r.stdout)
	if state.aliceFP == "" || state.bobFP == "" || state.aliceSerial == "" {
		t.Fatalf("state: %+v", state)
	}
}

// --- shared helpers for the rows -------------------------------------------

const (
	aliceRelayDir = "/home/alice/.auu/relays/relay.example.com"
	bobRelayDir   = "/home/bob/.auu/relays/relay.example.com"
	relayDB       = "/var/lib/auu/relay.db"
	credential    = "/run/credentials/auu-relay/relay-bundle"
	relaySettings = "/etc/auu/relay.json"
	adminsFile    = "/etc/auu/admins"
	messagesDir   = "/var/lib/auu/messages"
)

// sendJSON sends a message and returns what send --json said.
func sendJSON(t *testing.T, from *machine, to string, args ...string) sent {
	t.Helper()
	var s sent
	full := append([]string{"send", "--to", to, "--json"}, args...)
	r := from.auu(full...)
	if r.code != 0 {
		t.Fatalf("send: exit %d\n%s%s", r.code, r.stdout, r.stderr)
	}
	jsonOf(t, r, &s)
	return s
}

// queued is the relay's row ids queued for a recipient, ascending.
func queued(t *testing.T, fp string) []int64 {
	t.Helper()
	out := relay.sql(t, fmt.Sprintf("SELECT id FROM messages WHERE to_fp='%s' ORDER BY id", fp))
	var ids []int64
	for _, l := range strings.Fields(out) {
		n, err := strconv.ParseInt(l, 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, n)
	}
	return ids
}

// holds reports whether a relay's queue holds an id. A row about one
// message says what became of that message: with a channel set to keep,
// which is the default, the mail an earlier row read is queued beside it,
// and a count of the whole mailbox would be a count of the family's
// history.
func holds(ids []int64, id int64) bool {
	for _, have := range ids {
		if have == id {
			return true
		}
	}
	return false
}

func relayFile(fp string, id int64) string {
	return fmt.Sprintf("%s/%s/%s/%d", messagesDir, fp[:2], fp, id)
}

// queueOne sends one message from alice to bob and returns its relay id
// and file.
func queueOne(t *testing.T, args ...string) (int64, string) {
	t.Helper()
	before := queued(t, state.bobFP)
	sendJSON(t, alice, "bob", args...)
	after := queued(t, state.bobFP)
	if len(after) != len(before)+1 {
		t.Fatalf("queued %v before, %v after", before, after)
	}
	id := after[len(after)-1]
	return id, relayFile(state.bobFP, id)
}

// queueForAlice is queueOne the other way about: bob sends, and the id is
// alice's relay row, for a row that is about what alice's machine does
// with it.
func queueForAlice(t *testing.T, args ...string) int64 {
	t.Helper()
	before := queued(t, state.aliceFP)
	sendJSON(t, bob, "alice", args...)
	after := queued(t, state.aliceFP)
	if len(after) != len(before)+1 {
		t.Fatalf("queued %v before, %v after", before, after)
	}
	return after[len(after)-1]
}

// fetchJSON is inbox --json for a machine, with any further arguments.
func fetchJSON(t *testing.T, m *machine, args ...string) inboxJSON {
	t.Helper()
	var in inboxJSON
	r := m.auu(append([]string{"inbox", "--json"}, args...)...)
	if r.code != 0 {
		t.Fatalf("inbox --json: exit %d\n%s%s", r.code, r.stdout, r.stderr)
	}
	jsonOf(t, r, &in)
	return in
}

// drain collects everything queued for a machine and removes it, so a row
// leaves nothing behind on the relay or in the spool. A fetch alone no
// longer empties a mailbox: a channel keeps its mail until it is removed,
// which is what auu rm is for.
func drain(m *machine) {
	var in inboxJSON
	r := m.auu("inbox", "--json")
	if r.code != 0 {
		return
	}
	if err := json.Unmarshal([]byte(r.stdout), &in); err != nil {
		return
	}
	ids := make([]string, 0, len(in.Messages))
	for _, msg := range in.Messages {
		ids = append(ids, msg.ID)
	}
	if len(ids) > 0 {
		m.auu(append([]string{"rm"}, ids...)...)
	}
}

// dbBackup takes an online copy of the relay's database and returns what
// restores it, which stops the relay to do so.
func dbBackup(t *testing.T) func() {
	t.Helper()
	if nofault {
		return func() {}
	}
	undoSeq++
	keep := fmt.Sprintf("/snap/undo/db-%d", undoSeq)
	relay.mustRoot(t, "mkdir -p /snap/undo && sqlite3 "+relayDB+" '.backup "+keep+"'")
	// Once: a row that restores part way and again in its cleanup would
	// put the database back a second time after mail had moved on, and
	// with it the message sequence, so that every message after it sat
	// behind bob's cursor. R20 did exactly that after A9 gave it a
	// restore mid-row, and B5's sentence in R25 is what found it.
	restored := false
	return func() {
		if restored {
			return
		}
		restored = true
		compose("stop", "relay")
		relay.root("cp " + keep + " " + relayDB + " && chown auu:auu " + relayDB + " && rm -f " + relayDB + "-wal " + relayDB + "-shm")
		relayStart(t)
	}
}

// editJSON rewrites a JSON file through a function, keeping owner and mode.
func editJSON(t *testing.T, m *machine, path string, f func(map[string]any)) func() {
	t.Helper()
	if nofault {
		return func() {}
	}
	var v map[string]any
	if err := json.Unmarshal([]byte(m.read(t, path)), &v); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	f(v)
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	undo := m.backup(t, path)
	m.putContent(t, path, string(out)+"\n")
	return undo
}

// carol is a fresh person on bob's machine, in a home of her own; a row
// that needs somebody who has never enrolled uses one.
var carolSeq int

func newCarol(t *testing.T) *machine {
	t.Helper()
	carolSeq++
	home := fmt.Sprintf("/home/bob/.auu-carol%d", carolSeq)
	c := bob.at(home)
	t.Cleanup(func() { bob.root("rm -rf " + home) })
	return c
}

// enrolCarol enrols a fresh person and returns her machine.
func enrolCarol(t *testing.T) *machine {
	t.Helper()
	c := newCarol(t)
	tok := issueToken(t, "--note", "carol")
	r := c.auu("enrol", "--name", "carol", "--label", "carol-box", "--yes", tok)
	if r.code != 0 {
		t.Fatalf("carol could not enrol: %s%s", r.stdout, r.stderr)
	}
	return c
}

// encryptAlice puts alice's home under a passphrase and returns what takes
// it off again.
func encryptAlice(t *testing.T) func() {
	t.Helper()
	alice.exec("", "sh", "-c", "umask 077 && printf 'alice passphrase\\n' > "+alicePass)
	r := alice.auu("passphrase", "set", "--passphrase-file", alicePass)
	if r.code != 0 {
		t.Fatalf("passphrase set: %s%s", r.stdout, r.stderr)
	}
	return func() {
		alice.auu("passphrase", "remove", "--passphrase-file", alicePass)
		alice.auu("agent", "stop")
	}
}

// hostBundle is a host copy of a bundle put where the relay picks it up,
// and the relay restarted onto it.
func deliverHostBundle(t *testing.T, local string) mark {
	t.Helper()
	hostFile(t, local, relay, "/etc/auu/delivered/relay-bundle.json")
	record(relay, "scp "+filepath.Base(local)+" /etc/auu/delivered/relay-bundle.json", "", result{})
	return relayRestart(t)
}

// forgeBundle issues a bundle from the operator's authority dated at a
// moment, to a host file, and returns the host path.
func forgeBundle(t *testing.T, caDir string, at time.Time, host string) string {
	t.Helper()
	r := operator.exec("", "forge", "relay", "--dir", caDir, "--host", host, "--passphrase-file", operatorPass,
		"--at", at.UTC().Format(time.RFC3339), "--out", bundleOut)
	if r.code != 0 {
		t.Fatalf("forge relay: %s%s", r.stdout, r.stderr)
	}
	local := filepath.Join(workDir, fmt.Sprintf("forged-%d.json", undoSeq))
	tmp := fetch(t, operator, bundleOut)
	if err := os.Rename(tmp, local); err != nil {
		t.Fatal(err)
	}
	operator.exec("", "rm", bundleOut)
	return local
}

// credBackup keeps the relay's credential on the host, and returns a plain
// copy of it, for delivering again, and what restores it and restarts the
// relay.
func credBackup(t *testing.T) (string, func()) {
	t.Helper()
	undoSeq++
	keep := filepath.Join(workDir, fmt.Sprintf("cred-%d.tar", undoSeq))
	plain := filepath.Join(workDir, fmt.Sprintf("cred-%d.json", undoSeq))
	r := runHost(nil, "docker", "cp", relay.id+":"+credential, "-")
	if r.code != 0 {
		t.Fatalf("backing up the credential: %s", r.stderr)
	}
	if err := os.WriteFile(keep, []byte(r.stdout), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := runHost(nil, "docker", "cp", relay.id+":"+credential, plain); r.code != 0 {
		t.Fatalf("copying the credential: %s", r.stderr)
	}
	return plain, func() {
		f, err := os.Open(keep)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if r := runHost(f, "docker", "cp", "-", relay.id+":"+filepath.Dir(credential)); r.code != 0 {
			fmt.Fprintln(os.Stderr, "restoring the credential:", r.stderr)
		}
		relayRestart(t)
	}
}
