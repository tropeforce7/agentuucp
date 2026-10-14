//go:build e2e

package e2e

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
)

// The user's keys and settings, on alice's machine unless said.
var keyRows = []matrixRow{
	{"K01", "identity_deleted", "identity.json deleted", k01},
	{"K02", "identity_emptied", "identity.json emptied, as an editor crash leaves it", k02},
	{"K03", "identity_name_edited", "the name inside identity.json edited to mallory", k03},
	{"K04", "home_key_deleted", "an encrypted home with home.key deleted", k04},
	{"K05", "identity_key_deleted", "an encrypted home with identity.key deleted", k05},
	{"K06", "wrong_passphrase", "the wrong passphrase given to unlock", k06},
	{"K07", "cert_deleted", "this machine's cert.json deleted, with certificates required", k07},
	{"K08", "cert_truncated", "cert.json truncated", k08},
	{"K09", "cert_from_another_machine", "bob's cert.json copied over alice's", k09},
	{"K10", "cert_relay_field_edited", "the relay field inside cert.json edited", k10},
	{"K11", "anchor_deleted", "trust_anchor.pem deleted", k11},
	{"K12", "anchor_replaced", "trust_anchor.pem replaced by another authority's anchor", k12},
	{"K13", "anchor_hash_removed", "the trust_anchor_spki line removed from relay.json", k13},
	{"K14", "relay_json_trailing_comma", "relay.json hand-edited with a trailing comma", k14},
	{"K15", "cursor_garbage", "the cursor file holds 'abc'", k15},
	{"K16", "cursor_deleted", "the cursor file deleted", k16},
	{"K17", "cursor_too_high", "the cursor set far ahead", k17},
	{"K18", "peers_line_wrapped", "a line of authorized_peers wrapped by a mail client", k18},
	{"K19", "permissions_opened", "chmod 644 identity.json and chmod -R 777 on the home, to fix a permission error", k19},
	{"K20", "config_invalid", "config.json not valid JSON", k20},
	{"K21", "home_copied_with_cert", "bob's whole home copied to a second machine, cert.json included, against the guide", k21},
	{"K22", "token_used_twice", "an enrolment token used a second time", k22},
	{"K23", "token_pasted_badly", "a token pasted with a trailing space, then with quotes around it", k23},
	{"K24", "token_for_somebody_else", "alice uses a token issued to bob", k24},
	{"K25", "export_line_broken", "an export line pasted with a line break inside it", k25},
	{"K26", "own_line_added", "alice adds her own export line as a peer", k26},
	{"K27", "unknown_recipient", "send --to a name that is not a peer", k27},
	{"K28", "init_force_encrypted", "auu init --force on an encrypted home", k28},
	{"K29", "home_read_only", "the home directory made read-only", k29},
	{"K30", "cursor_skipped_mail", "the cursor set to mail it never fetched, inside the relay's span", k30},
}

const (
	noIdentity  = "auu: no identity: run 'auu init --name YOUR-NAME' first"
	aliceIDFile = "/home/alice/.auu/identity.json"
)

func k01(t *testing.T) {
	defer alice.remove(t, aliceIDFile)()
	r := alice.auu("inbox")
	expectCode(t, r, 1)
	stderrIs(t, r, noIdentity)
	verdict(t, "ok", "")
}

func k02(t *testing.T) {
	defer alice.write(t, aliceIDFile, "")()
	r := alice.auu("inbox")
	expectCode(t, r, 5)
	stderrIs(t, r, "auu: "+aliceIDFile+" is not valid JSON (unexpected end of JSON input): if you have a backup "+
		"of this home, restore it; if not, this identity is lost and 'auu init --force' makes a new one")
	verdict(t, "ok", "The file, the fact, Go's reason in brackets, what to do, and exit 5: a person's.")
}

func k03(t *testing.T) {
	defer alice.edit(t, aliceIDFile, `"name": "alice"`, `"name": "mallory"`)()
	r := alice.auu("id", "export")
	expectCode(t, r, 0)
	line := strings.TrimSpace(r.stdout)
	if !strings.HasSuffix(line, ".mallory") {
		t.Errorf("export line ends %q", line[len(line)-12:])
	}
	expectSays(t, alice.auu("send", "--to", "bob", "--subject", "renamed", "still me"), 0, "sent to bob")
	in := fetchJSON(t, bob)
	if in.Fetch.Delivered != 1 || in.Messages[len(in.Messages)-1].FromName != "alice" {
		t.Errorf("bob's view: %+v", in)
	}
	verdict(t, "observed", "Names are local labels by design: the export line now ends .mallory, but bob's peer list still says alice, "+
		"and the fingerprint is what everything checks.")
}

func k04(t *testing.T) {
	defer encryptAlice(t)()
	defer alice.remove(t, "/home/alice/.auu/home.key")()
	r := alice.auu("send", "--to", "bob", "while home.key is gone")
	expectSays(t, r, 5, "identity.json holds no keys and there is no home.key to unlock them with: a passphrase change was interrupted",
		"run 'auu passphrase set' or 'auu passphrase remove' again, whichever was interrupted, to finish it")
	verdict(t, "ok", "The sentence names what is missing and what to run, and exit 5 says it is a person's.")
}

func k05(t *testing.T) {
	defer encryptAlice(t)()
	defer alice.remove(t, "/home/alice/.auu/identity.key")()
	r := alice.auu("send", "--to", "bob", "while identity.key is gone")
	expectSays(t, r, 5, "identity.json holds no keys and there is no identity.key", "a passphrase change was interrupted")
	verdict(t, "ok", "Right sentence, and exit 5.")
}

func k06(t *testing.T) {
	defer encryptAlice(t)()
	expectSays(t, alice.auu("lock"), 0, "locked")
	alice.exec("", "sh", "-c", "umask 077 && printf 'not the passphrase\\n' > /home/alice/wrong")
	r := alice.auu("unlock", "--passphrase-file", "/home/alice/wrong")
	expectSays(t, r, 1, "wrong passphrase, or the file has been altered")
	r = alice.auu("send", "--to", "bob", "still locked")
	expectCode(t, r, 4)
	verdict(t, "ok", "A failed unlock leaves the keys locked.")
}

func k07(t *testing.T) {
	defer alice.remove(t, aliceRelayDir+"/cert.json")()
	r := alice.auu("inbox")
	expectSays(t, r, 2, certMissing)
	verdict(t, "ok", "")
}

func k08(t *testing.T) {
	defer alice.truncate(t, aliceRelayDir+"/cert.json", 200)()
	r := alice.auu("inbox")
	expectCode(t, r, 5)
	stderrIs(t, r, "auu: "+aliceRelayDir+"/cert.json will not read (unexpected EOF): "+
		"run 'auu register --relay relay.example.com --token TOKEN' to replace it")
	verdict(t, "ok", "The file, the fact, Go's reason in brackets, the command that replaces it — on every path that "+
		"meets the file, not only the dial — and exit 5.")
}

func k09(t *testing.T) {
	undo := alice.backup(t, aliceRelayDir+"/cert.json")
	defer undo()
	if !nofault {
		copyFile(t, bob, bobRelayDir+"/cert.json", alice, aliceRelayDir+"/cert.json")
		alice.mustRoot(t, "chown alice:alice "+aliceRelayDir+"/cert.json")
	}
	r := alice.auu("inbox")
	expectSays(t, r, 2, "this relay requires a client certificate and this machine's is for another identity")
	verdict(t, "ok", "The relay refuses a certificate that does not belong to the signing identity, and the client says so; "+
		"nothing on the machine noticed first.")
}

func k10(t *testing.T) {
	defer alice.edit(t, aliceRelayDir+"/cert.json", `"relay": "https://relay.example.com:9443"`, `"relay": "https://other.example.com:9443"`)()
	r := alice.auu("inbox")
	expectCode(t, r, 5)
	stderrIs(t, r, "auu: this machine's "+aliceRelayDir+"/cert.json for relay.example.com was issued by "+
		"https://other.example.com:9443: run 'auu register --relay relay.example.com --token TOKEN' to get one for this relay")
	verdict(t, "ok", "A file that is there and wrong is not a file that is missing: named, with the relay it was issued "+
		"by and the command that gets one for this relay, before anything is dialled, and exit 5.")
}

func k11(t *testing.T) {
	defer alice.remove(t, aliceRelayDir+"/trust_anchor.pem")()
	r := alice.auu("inbox")
	expectSays(t, r, 5, "relay.json records a trust anchor for relay.example.com but "+aliceRelayDir+"/trust_anchor.pem is missing; "+
		"enrol again with a token")
	verdict(t, "ok", "The sentence as before, and exit 5.")
}

func k12(t *testing.T) {
	operator.exec("", "rm", "-rf", "/home/you/other-ca")
	r := operator.ca("init", "--name", "Somebody Else", "--dir", "/home/you/other-ca", "--passphrase-file", operatorPass)
	expectCode(t, r, 0)
	undo := alice.backup(t, aliceRelayDir+"/trust_anchor.pem")
	defer undo()
	if !nofault {
		copyFile(t, operator, "/home/you/other-ca/ta.pem", alice, aliceRelayDir+"/trust_anchor.pem")
		alice.mustRoot(t, "chown alice:alice "+aliceRelayDir+"/trust_anchor.pem")
	}
	r = alice.auu("inbox")
	expectSays(t, r, 5, "holds a different trust anchor than relay.json records",
		"it has been replaced, so nothing here should be trusted until you enrol again")
	verdict(t, "ok", "The file is checked against the hash relay.json records, and exit 5 says a person looks.")
}

func k13(t *testing.T) {
	defer editJSON(t, alice, aliceRelayDir+"/relay.json", func(v map[string]any) { delete(v, "trust_anchor_spki") })()
	r := alice.auu("inbox")
	expectCode(t, r, 5)
	stderrIs(t, r, "auu: "+aliceRelayDir+"/relay.json records no trust anchor but "+aliceRelayDir+"/trust_anchor.pem is here; "+
		"relay.json has been edited. Enrol again with a token, or run 'auu anchor pin HASH' with the hash from the relay's operator")
	verdict(t, "ok", "The pinned file beside a record that names none is caught as an edit, with two ways back, and exit 5; "+
		"pinning is not silently off.")
}

func k14(t *testing.T) {
	defer alice.edit(t, aliceRelayDir+"/relay.json", `"url": "https://relay.example.com:9443",`, `"url": "https://relay.example.com:9443",,`)()
	r := alice.auu("inbox")
	expectCode(t, r, 5)
	stderrIs(t, r, "auu: "+aliceRelayDir+"/relay.json will not read (invalid character ',' looking for beginning of "+
		"object key string): enrol again with a token, or remove the relay with 'auu relay rm relay.example.com' and add it again")
	verdict(t, "ok", "The file, the fact, Go's reason in brackets, two ways out, and exit 5.")
}

func k15(t *testing.T) {
	defer alice.write(t, aliceRelayDir+"/cursor", "abc")()
	r := alice.auu("inbox")
	expectCode(t, r, 5)
	// "is not a message id" since d7b8ff8, where the cursor became a
	// message id held to its shape at the read rather than a number.
	stderrIs(t, r, "auu: "+aliceRelayDir+`/cursor is not a message id ("abc"): run 'auu cursor reset --relay relay.example.com', `+
		"which writes it again; the next fetch starts from the beginning and delivers nothing twice")
	// The advice, followed: the cursor written, and the fetch from the
	// beginning meets the mail alice kept there and delivers none of it.
	expectSays(t, alice.auu("cursor", "reset", "--relay", "relay.example.com", "--yes"), 0,
		"relay.example.com's cursor is 0")
	in := fetchJSON(t, alice)
	if in.Fetch.Delivered != 0 {
		t.Errorf("the fetch after the advice delivered %+v", in.Fetch)
	}
	verdict(t, "ok", "The file, what it holds, what to do and what that costs, and exit 5; the command it names writes "+
		"the cursor, and the fetch after it delivers nothing twice.")
}

func k16(t *testing.T) {
	undo := alice.remove(t, aliceRelayDir+"/cursor")
	expectSays(t, bob.auu("send", "--to", "alice", "--subject", "no cursor", "is anybody fetching"), 0, "sent to alice")
	r := alice.auu("inbox")
	expectSays(t, r, 0, "fetched 1 new message(s)", "no cursor")
	if strings.TrimSpace(r.stderr) != "" {
		t.Errorf("stderr: %q", r.stderr)
	}
	if !alice.exists(aliceRelayDir + "/cursor") {
		t.Error("the cursor was not written back")
	}
	undo()
	verdict(t, "ok", "A missing cursor means fetch from the start; what was collected before is gone from the relay, "+
		"so nothing is delivered twice, and the file is written again.")
}

func k17(t *testing.T) {
	undo := alice.write(t, aliceRelayDir+"/cursor", "999999")
	id := queueForAlice(t, "--subject", "behind the cursor", "will you see this")
	held := queued(t, state.aliceFP)
	// Above everything the relay holds: the relay says its span, and the
	// fetch matches its rows to what alice has. The new one is not hers,
	// so the cursor is set before the relay's first id and the mailbox is
	// fetched again in the same run, the mail alice kept there met by its
	// own id and not delivered again; the sentence is said once, and the
	// cursor ends at the relay's last id.
	r := alice.auu("inbox")
	expectSays(t, r, 0, "behind the cursor")
	stderrIs(t, r, "relay.example.com: this machine's cursor was 999999 and the relay's mail is numbered "+
		strconv.FormatInt(held[0], 10)+" to "+strconv.FormatInt(held[len(held)-1], 10)+
		", so the cursor was reset and mail is fetched from the beginning; nothing is delivered twice here")
	if got := strings.TrimSpace(alice.read(t, aliceRelayDir+"/cursor")); got != strconv.FormatInt(id, 10) {
		t.Errorf("the cursor is %q after the reset, want the relay's last id, %d", got, id)
	}
	if !holds(queued(t, state.aliceFP), id) {
		t.Errorf("queued %v after the reset, want %d kept there as the default channel keeps it", queued(t, state.aliceFP), id)
	}
	// Once: the next fetch is silence.
	r = alice.auu("inbox")
	expectCode(t, r, 0)
	stderrIs(t, r, "")
	undo()
	verdict(t, "ok", "A cursor above everything the relay holds is reset: the new mail is fetched from the relay's "+
		"first id, what alice already had is met and not delivered twice, and one sentence says so.")
}

func k30(t *testing.T) {
	id := queueForAlice(t, "--subject", "skipped", "inside the span")
	undo := alice.write(t, aliceRelayDir+"/cursor", strconv.FormatInt(id, 10))
	// The cursor at the relay's last id, which alice never fetched: the
	// skipped mail is inside the span, and no fetch from the front could
	// reach it without delivering again what came after it. Refused by
	// the relay's count, the file and the command that starts again, at
	// exit 5; the relay still holds the message and the cursor is the
	// bytes that were written.
	r := alice.auu("inbox")
	expectCode(t, r, 5)
	stderrIs(t, r, "auu: 1 message is waiting on relay.example.com before this machine's cursor; "+
		"run 'auu cursor reset --relay relay.example.com' to fetch from the beginning")
	if !holds(queued(t, state.aliceFP), id) {
		t.Errorf("queued %v after the refusal, want %d untouched", queued(t, state.aliceFP), id)
	}
	if got := strings.TrimSpace(alice.read(t, aliceRelayDir+"/cursor")); got != strconv.FormatInt(id, 10) {
		t.Errorf("the cursor is %q after the refusal, want the %d that was written", got, id)
	}
	// The advice, followed: the cursor set to the beginning, and the fetch
	// delivers the skipped message and nothing alice already had.
	expectSays(t, alice.auu("cursor", "reset", "--relay", "relay.example.com", "--yes"), 0,
		"the next fetch from relay.example.com will fetch everything the relay holds")
	in := fetchJSON(t, alice)
	if in.Fetch.Delivered != 1 {
		t.Errorf("the fetch after the advice delivered %+v, want the skipped one alone", in.Fetch)
	}
	undo()
	verdict(t, "ok", "A cursor inside the relay's span beside an empty page and a count is a cursor past mail: "+
		"said with the count and the command, exit 5, nothing acknowledged; the command puts it right, and the "+
		"fetch after it delivers the skipped message alone.")
}

func k18(t *testing.T) {
	content := alice.read(t, "/home/alice/.auu/authorized_peers")
	line := strings.TrimSpace(strings.Split(strings.TrimSpace(content), "\n")[0])
	if len(line) < 200 {
		t.Fatalf("authorized_peers: %q", content)
	}
	// Once the file is back, bob's message is collected, so the next row
	// starts as this one did.
	t.Cleanup(func() { drain(alice) })
	defer alice.write(t, "/home/alice/.auu/authorized_peers", line[:100]+"\n"+line[100:]+"\n")()
	// The first hundred characters, less the "ccx2." prefix, are what the
	// parser counts.
	broken := "/home/alice/.auu/authorized_peers line 1: identity: key line is not the length of a key: 95 encoded bytes, " +
		"want 1248 encoded (was the line wrapped?)"
	r := alice.auu("peers", "ls")
	expectCode(t, r, 5)
	stderrIs(t, r, "auu: "+broken)
	id := queueForAlice(t, "--subject", "am I still your peer", "hello")
	// The fetch is refused by the same line before anything is fetched:
	// the relay still holds the message and nothing was quarantined.
	r = alice.auu("inbox")
	expectCode(t, r, 5)
	stderrIs(t, r, "auu: "+broken)
	if !holds(queued(t, state.aliceFP), id) {
		t.Errorf("queued %v after the refused fetch, want %d untouched", queued(t, state.aliceFP), id)
	}
	if out := alice.exec("", "sh", "-c", "ls /home/alice/.auu/quarantine | wc -l"); strings.TrimSpace(out.stdout) != "0" {
		t.Errorf("the quarantine holds %s entries after the refused fetch, want 0", strings.TrimSpace(out.stdout))
	}
	verdict(t, "ok", "peers ls and inbox both refuse by the line's number, ask whether it was wrapped, and exit 5; the "+
		"inbox fetches nothing and quarantines nothing until the file is fixed.")
}

func k19(t *testing.T) {
	// The home writable by anyone is met first, at open, and refused;
	// then, with the home put back, the key file alone.
	undoHome := alice.chmod(t, "-R 777", "/home/alice/.auu")
	r := alice.auu("inbox")
	expectCode(t, r, 5)
	stderrIs(t, r, "auu: opening auu home: /home/alice/.auu is mode 0777: anyone on this machine can write into your "+
		"home and replace what is in it. Run: chmod 700 /home/alice/.auu")
	undoHome()
	defer alice.chmod(t, "644", aliceIDFile)()
	r = alice.auu("inbox")
	expectCode(t, r, 5)
	stderrIs(t, r, "auu: "+aliceIDFile+" is mode 0644: anyone on this machine can read your keys. Run: chmod 600 "+aliceIDFile)
	verdict(t, "ok", "A home anyone can write and a key file anyone can read are each refused by name, with the chmod that "+
		"puts it back, and exit 5: auu wrote them 0700 and 0600 itself, so a wider mode means somebody changed it.")
}

func k20(t *testing.T) {
	defer alice.write(t, "/home/alice/.auu/config.json", "{")()
	r := alice.auu("inbox")
	expectCode(t, r, 5)
	stderrIs(t, r, "auu: opening auu home: /home/alice/.auu/config.json is not valid JSON (unexpected end of JSON input): "+
		"delete it and set the default relay again with 'auu relay default NAME'; it holds only that, the stream "+
		"settings, your editor and whether vouch questions are answered")
	verdict(t, "ok", "The file is named, with what deleting it costs, and exit 5.")
}

func k21(t *testing.T) {
	copy := "/home/bob/.auu-copy"
	bob.exec("", "rm", "-rf", copy)
	expectCode(t, bob.exec("", "cp", "-a", bob.home, copy), 0)
	defer bob.exec("", "rm", "-rf", copy)
	other := bob.at(copy)
	// Both work, because a certificate is only a file.
	expectSays(t, other.auu("inbox"), 0)
	expectSays(t, bob.auu("inbox"), 0)
	// Until one renews: the relay revokes the old serial as renewed, and
	// the other machine, still holding it, is refused.
	expectSays(t, other.auu("cert", "renew"), 0, "renewed:")
	r := bob.auu("inbox")
	expectSays(t, r, 2, certRevoked)
	// Bob does what the sentence says and asks for a token; an ordinary
	// one is refused, because from the relay's side he has a live
	// certificate: the copy's. A certificate token is what he needs.
	tok := issueToken(t, "--note", "bob after the copy")
	r = bob.auu("register", "--token", tok, "--label", "laptop")
	expectSays(t, r, 2, "relay returned 403: this identity already holds a live certificate on another machine, so adding "+
		"this one needs a certificate token: ask the administrator for one issued with --use cert --for "+state.bobFP)
	tok = issueToken(t, "--use", "cert", "--for", state.bobFP, "--note", "bob's laptop again")
	expectSays(t, bob.auu("register", "--token", tok, "--label", "laptop"), 0, "client certificate for this machine (laptop)")
	verdict(t, "observed", "The trap the enrolling guide warns of: two machines on one certificate work until either renews, "+
		"then the other is told it was revoked with no hint that a copy did it. The copy is still the trap, but when the "+
		"ordinary token is refused bob is now told what to ask for instead, with his own fingerprint in the command, and "+
		"that token works.")
}

func k22(t *testing.T) {
	tok := issueToken(t, "--note", "used twice")
	first := newCarol(t)
	expectSays(t, first.auu("enrol", "--name", "carol", "--label", "one", "--yes", tok), 0, `as "carol"`)
	second := newCarol(t)
	r := second.auu("enrol", "--name", "carol", "--label", "two", "--yes", tok)
	expectSays(t, r, 2, "relay returned 403: enrolment token has already been used",
		"your identity was created in "+second.home+" but the relay refused the token")
	verdict(t, "ok", "Refused by name; the identity made before the refusal is kept and the next command is given.")
}

func k23(t *testing.T) {
	tok := issueToken(t, "--note", "pasted badly")
	r := alice.auu("token", "show", tok+" ")
	expectSays(t, r, 0, "for:     pasted badly")
	c := newCarol(t)
	r = c.auu("enrol", "--name", "carol", "--yes", `"`+tok+`"`)
	expectCode(t, r, 1)
	stderrIs(t, r, `auu: token: malformed: unknown token type "\"ccxt2", expected "ccxt2"`)
	if c.exists(c.home + "/identity.json") {
		t.Error("an identity was created for a token that was refused before anything")
	}
	verdict(t, "observed", "A trailing space is trimmed. Quotes are refused before anything is written, in a sentence that "+
		"is exact and shows the stray quote only as an escape a person may not notice.")
}

func k24(t *testing.T) {
	tok := issueToken(t, "--use", "cert", "--for", state.bobFP, "--note", "for bob")
	r := alice.auu("register", "--token", tok)
	expectSays(t, r, 2, "enrolment token was issued to a different identity")
	verdict(t, "ok", "")
}

func k25(t *testing.T) {
	broken := state.bobLine[:120] + "\n" + state.bobLine[120:]
	r := alice.auu("peers", "add", broken)
	expectCode(t, r, 1)
	stderrIs(t, r, "auu: the line has a break in it; paste it as one line")
	verdict(t, "ok", "The break is named as the mistake, before any length is counted.")
}

func k26(t *testing.T) {
	r := alice.auu("peers", "add", state.aliceLine)
	expectSays(t, r, 1, "that is your own key: messages to yourself need no peer entry, use --to self")
	verdict(t, "ok", "")
}

func k27(t *testing.T) {
	r := alice.auu("send", "--to", "carol", "hello?")
	expectSays(t, r, 1, `no peer matches "carol"`)
	c := enrolCarol(t)
	r = c.auu("send", "--to", "alice", "hello?")
	expectSays(t, r, 1, "no peers yet: add one with 'auu peers add'")
	verdict(t, "ok", "")
}

func k28(t *testing.T) {
	defer encryptAlice(t)()
	r := alice.auu("init", "--name", "alice2", "--force")
	expectSays(t, r, 1, "the keys in /home/alice/.auu are encrypted; run 'auu passphrase remove' first, then init --force, "+
		"then 'auu passphrase set' again")
	verdict(t, "ok", "")
}

func k29(t *testing.T) {
	undo := alice.chmod(t, "-R a-w", "/home/alice/.auu")
	expectSays(t, bob.auu("send", "--to", "alice", "--subject", "read-only", "can you store this"), 0, "sent to alice")
	// The first thing a fetch writes is its lock, so that is what a home
	// that cannot be written refuses.
	r := alice.auu("inbox")
	expectCode(t, r, 1)
	stderrIs(t, r, "auu: taking the fetch lock for relay.example.com: open "+aliceRelayDir+"/fetch.lock: permission denied")
	undo()
	in := fetchJSON(t, alice)
	record(alice, "(after the mode was put back)", "", result{stdout: fmt.Sprintf("%+v\n", in.Fetch)})
	if in.Fetch.Delivered != 1 {
		t.Errorf("after the home was writable again alice fetched %+v; the message sent while it was not is lost", in.Fetch)
	}
	verdict(t, "ok", "Nothing is fetched before the home can be written to, so a home that cannot be loses nothing; "+
		"the sentence names the failure and the path, with exit code 1.")
}
