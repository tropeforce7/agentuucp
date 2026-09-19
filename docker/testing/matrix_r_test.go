//go:build e2e

package e2e

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// The relay: its settings, its files, its disk. Each row edits the relay
// host as root, the way an operator or an intruder would, restarts where
// the fault is one the relay meets at start, and puts things back.
var relayRows = []matrixRow{
	{"R01", "settings_misspelled_key", "relay.json with a misspelled key, listne", r01},
	{"R02", "settings_removed_key", "relay.json with a key from an earlier release, tls.acme", r02},
	{"R03", "settings_bom", "relay.json saved with a byte order mark, as Notepad does", r03bom},
	{"R03b", "settings_crlf", "relay.json saved with CRLF line endings", r03crlf},
	{"R03c", "settings_trailing_comma", "relay.json with a trailing comma after the last setting", r03comma},
	{"R04", "public_url_wrong_port", "public_url names port 9444 while the relay listens on 9443", r04},
	{"R05", "admins_missing", "/etc/auu/admins deleted before a start", r05},
	{"R06", "admins_world_writable", "/etc/auu/admins chmod 0666", r06},
	{"R07", "admins_empty", "/etc/auu/admins emptied", r07},
	{"R08", "admins_crlf", "/etc/auu/admins with CRLF line endings", r08},
	{"R09", "admins_line_wrapped", "the line in /etc/auu/admins wrapped", r09},
	{"R10", "admins_deleted_running", "/etc/auu/admins deleted while the relay runs", r10},
	{"R11", "bundle_never_delivered", "the relay started before any bundle was delivered", r11},
	{"R12", "bundle_for_another_host", "a bundle issued for other.example.com delivered", r12},
	{"R13", "credential_truncated", "the credential truncated", r13},
	{"R14", "credential_version_edited", "the credential's version field edited to 2", r14},
	{"R15", "credential_wrong_name", "the credential installed under another name", r15},
	{"R16", "messages_dir_world_writable", "the message directory chmod 0777", r16},
	{"R17", "messages_dir_owned_by_root", "the message directory owned by root, unwritable to the relay", r17},
	{"R18", "disk_full", "the message directory on a filesystem of one megabyte, and a two-megabyte message", r18},
	{"R20", "database_deleted_running", "relay.db deleted while the relay runs, then a restart", r20},
	{"R21", "database_not_a_database", "relay.db replaced with a text file", r21},
	{"R22", "database_newer_schema", "relay.db marked as schema version 99", r22},
	{"R23", "second_relay_same_database", "a second relay started on the same database", r23},
	{"R24", "messages_dir_deleted_running", "the message directory deleted while the relay runs", r24},
	{"R25", "registration_closed", "the relay restarted with registration closed", r25},
	{"R26", "mailbox_quota", "the relay restarted with a two-message mailbox quota", r26},
	{"R28", "relay_stopped", "the relay stopped", r28},
	{"R29", "public_url_other_name", "public_url changed to a name the certificate does not carry", r29},
	{"R30", "access_log_full", "the access log at full, then at minimal", r30},
	{"R27", "post_rate_limit", "thirty-one messages inside a minute at the shipped limits", r27},
}

// undoThenRestart puts a fault right once the row is over, however it
// ended, and brings the relay back.
func undoThenRestart(t *testing.T, undo func()) {
	t.Cleanup(func() {
		undo()
		relayRestart(t)
	})
}

// expectNoStart restarts the relay expecting it to refuse, and asserts the
// log names the reason.
func expectNoStart(t *testing.T, want ...string) string {
	t.Helper()
	log := relayRestartFails(t)
	for _, w := range want {
		if !strings.Contains(log, w) {
			t.Errorf("the relay's log lacks %q:\n%s", w, log)
		}
	}
	return log
}

// restartObserve restarts the relay and reports whether it came up.
func restartObserve(t *testing.T) (bool, string) {
	t.Helper()
	m := logMark()
	if r := compose("restart", "relay"); r.code != 0 {
		t.Fatalf("restarting the relay: %s", r.stderr)
	}
	deadline := time.Now().Add(20 * time.Second)
	for {
		log := relayLogSince(m)
		if strings.Contains(log, "serving from an auu-ca bundle") {
			waitRelayReady(t)
			return true, log
		}
		if !relayRunning() {
			return false, log
		}
		if time.Now().After(deadline) {
			t.Fatalf("the relay neither served nor stopped:\n%s", log)
		}
		time.Sleep(300 * time.Millisecond)
	}
}

func r01(t *testing.T) {
	undoThenRestart(t, relay.edit(t, relaySettings, `"listen"`, `"listne"`))
	expectNoStart(t, `listne`)
	verdict(t, "ok", "Unknown keys are refused by name at start.")
}

func r02(t *testing.T) {
	undoThenRestart(t, relay.edit(t, relaySettings, `"bundle_credential": "relay-bundle"`,
		`"bundle_credential": "relay-bundle", "acme": {"email": "you@example.com"}`))
	expectNoStart(t, "tls.acme is no longer a setting: ACME was removed")
	verdict(t, "ok", "A setting from an earlier release is named, with where it went.")
}

func r03bom(t *testing.T) {
	undoThenRestart(t, relay.fault(t, relaySettings, `sed -i '1s/^/\xef\xbb\xbf/' `+relaySettings))
	expectNoStart(t, relaySettings+" begins with a byte order mark, three invisible bytes an editor put there; "+
		"save it as plain UTF-8")
	verdict(t, "ok", "Refused by name: the three bytes a person cannot see, and what to save the file as.")
}

func r03crlf(t *testing.T) {
	undoThenRestart(t, relay.fault(t, relaySettings, `sed -i 's/$/\r/' `+relaySettings))
	up, _ := restartObserve(t)
	record(relay, "(restart)", "", result{stdout: fmt.Sprintf("started: %v\n", up)})
	if !up {
		t.Errorf("CRLF line endings were refused")
	}
	verdict(t, "ok", "Carriage returns are whitespace to the JSON decoder.")
}

func r03comma(t *testing.T) {
	undoThenRestart(t, relay.edit(t, relaySettings, `"bundle_credential": "relay-bundle"`, `"bundle_credential": "relay-bundle",`))
	expectNoStart(t, "malformed JSON at byte", "invalid character '}'", "the comma after the last item is one too many")
	verdict(t, "ok", "The byte offset and Go's reason stay, and the mistake a person made is named after them.")
}

func r04(t *testing.T) {
	undoThenRestart(t, relay.edit(t, relaySettings, `"public_url": "https://relay.example.com:9443"`,
		`"public_url": "https://relay.example.com:9444"`))
	m := relayRestart(t)
	log := relayLogSince(m)
	if !strings.Contains(log, "names port 9444 but this relay listens on port 9443") || !strings.Contains(log, "nobody can enrol") {
		t.Errorf("the relay did not warn:\n%s", log)
	}
	// The administrator's machine knows the relay by the right URL, so the
	// tokens it signs name that, and the relay, which now calls itself
	// something else, refuses to register them.
	r := operator.admin("token", "issue", "--note", "wrong port")
	expectSays(t, r, 2, "relay returned 400: token names a different relay")
	verdict(t, "ok", "The relay warns at start in a sentence that says what it costs, and then proves it: the "+
		"administrator cannot issue a token, because the relay no longer answers to the name the token carries.")
}

func r05(t *testing.T) {
	undoThenRestart(t, relay.remove(t, adminsFile))
	expectNoStart(t, "admin file: stat /etc/auu/admins: no such file or directory")
	verdict(t, "ok", "")
}

func r06(t *testing.T) {
	undoThenRestart(t, relay.chmod(t, "0666", adminsFile))
	expectNoStart(t, "admin file /etc/auu/admins is mode 0666: it must not be writable by group or others, "+
		"since whoever can write it can administer the relay")
	verdict(t, "ok", "")
}

func r07(t *testing.T) {
	undoThenRestart(t, relay.write(t, adminsFile, ""))
	relayRestart(t)
	r := operator.admin("status")
	expectSays(t, r, 2, "you are not an administrator of "+relayURL)
	verdict(t, "observed", "An empty file is a relay with no administrators; the administrator is told they are not one, "+
		"where the relay's own reason, no administrators at all, would have pointed at the file.")
}

func r08(t *testing.T) {
	undoThenRestart(t, relay.fault(t, adminsFile, `sed -i 's/$/\r/' `+adminsFile))
	up, log := restartObserve(t)
	record(relay, "(restart)", "", result{stdout: fmt.Sprintf("started: %v\n", up)})
	if up {
		expectSays(t, operator.admin("status"), 0, "administrators: 1")
		verdict(t, "ok", "The carriage return is stripped with the line's whitespace.")
		return
	}
	if !strings.Contains(log, "/etc/auu/admins line 1") {
		t.Errorf("log:\n%s", log)
	}
	verdict(t, "gap", "Refused at line 1 for a character the operator cannot see.")
}

func r09(t *testing.T) {
	line := strings.TrimSpace(relay.read(t, adminsFile))
	undoThenRestart(t, relay.write(t, adminsFile, line[:100]+"\n"+line[100:]+"\n"))
	expectNoStart(t, "/etc/auu/admins line 1: identity:")
	verdict(t, "ok", "Refused at start with the line number.")
}

func r10(t *testing.T) {
	m := logMark()
	undo := relay.remove(t, adminsFile)
	t.Cleanup(undo)
	// The set was loaded at start, so the administrator whose file went
	// before their first request is still one.
	r := operator.admin("status")
	log := relayLogSince(m)
	record(relay, "(the log)", "", result{stdout: log})
	expectSays(t, r, 0, "administrators: 1")
	if !strings.Contains(log, "keeping the administrators loaded earlier") || !strings.Contains(log, "administrators=1") {
		t.Errorf("log:\n%s", log)
	}
	verdict(t, "ok", "The set is loaded at start and the last good one is kept when the file goes; the log says so, "+
		"with the count it kept, and the administrator notices nothing.")
}

func r11(t *testing.T) {
	plain, _ := credBackup(t)
	if nofault {
		verdict(t, "observed", "")
		return
	}
	relay.mustRoot(t, "rm -f "+credential)
	m := logMark()
	if r := compose("restart", "relay"); r.code != 0 {
		t.Fatal(r.stderr)
	}
	waitRelayLog(t, m, "waiting for the bundle to be delivered to /etc/auu/delivered/relay-bundle.json", 20*time.Second)
	r := relayAuu.exec("", "auu-relay", "--config", relaySettings, "--print-config")
	expectCode(t, r, 1)
	stderrIs(t, r, `auu-relay: tls.bundle_credential is "relay-bundle" but CREDENTIALS_DIRECTORY is not set: `+
		`the relay is not running under a unit with LoadCredentialEncrypted=relay-bundle:... in it`)
	// Delivered late, it starts.
	hostFile(t, plain, relay, "/etc/auu/delivered/relay-bundle.json")
	record(relay, "scp relay-bundle.json /etc/auu/delivered/relay-bundle.json", "", result{})
	waitRelayLog(t, m, "serving from an auu-ca bundle", 30*time.Second)
	waitRelayReady(t)
	expectSays(t, alice.auu("inbox"), 0)
	verdict(t, "ok", "With no credential there is no relay, and the check the guide gives says exactly what is missing; "+
		"delivered late, it starts.")
}

func r12(t *testing.T) {
	_, undo := credBackup(t)
	t.Cleanup(undo)
	r := operator.ca("relay", "--host", "other.example.com", "--out", bundleOut, "--passphrase-file", operatorPass)
	expectCode(t, r, 0)
	if nofault {
		operator.exec("", "rm", bundleOut)
		verdict(t, "observed", "")
		return
	}
	deliverBundle(t)
	expectNoStart(t, "public_url names relay.example.com but the bundle was issued for other.example.com: "+
		"run 'auu-ca relay --host relay.example.com' on the offline machine and deliver that bundle, or fix public_url")
	verdict(t, "ok", "The relay refuses to start, naming the host public_url carries, the host the bundle was issued "+
		"for, and the command that issues the right one. Nobody meets a hostname error, and no newcomer is left "+
		"with a half-made home.")
}

func r13(t *testing.T) {
	undoThenRestart(t, relay.truncate(t, credential, 300))
	expectNoStart(t, `tls.bundle_credential "relay-bundle": /run/credentials/auu-relay/relay-bundle: `+
		`the bundle is cut short (unexpected EOF): deliver it again`)
	verdict(t, "ok", "Refused with the setting, the path, what happened to the bundle, Go's reason in brackets, and "+
		"what to do.")
}

func r14(t *testing.T) {
	undoThenRestart(t, relay.edit(t, credential, `"v": 1`, `"v": 2`))
	expectNoStart(t, "bundle version 2, but this build understands 1; it was written by a different release of auu-ca")
	verdict(t, "ok", "")
}

func r15(t *testing.T) {
	// The three names must agree: the credential's, the unit's, and the
	// settings'. Here the settings have a typo.
	undoThenRestart(t, relay.edit(t, relaySettings, `"bundle_credential": "relay-bundle"`, `"bundle_credential": "relay-bundel"`))
	expectNoStart(t, `tls.bundle_credential "relay-bundel": open /run/credentials/auu-relay/relay-bundel: no such file or directory`)
	verdict(t, "ok", "Refused with the name it looked for and where.")
}

func r16(t *testing.T) {
	undoThenRestart(t, relay.chmod(t, "0777", messagesDir))
	expectNoStart(t, "messages directory /var/lib/auu/messages is mode 0777: it holds stored mail and must not be "+
		"writable by group or others")
	verdict(t, "ok", "")
}

func r17(t *testing.T) {
	undo := relay.chown(t, "-R root:root", messagesDir)
	t.Cleanup(undo)
	m := logMark()
	r := alice.auu("send", "--to", "bob", "--subject", "unwritable", "does this get stored")
	expectCode(t, r, 2)
	stderrIs(t, r, "auu: the relay could not store or read a message (storage error); whoever runs it needs to look at its log")
	log := relayLogSince(m)
	if !strings.Contains(log, `level=WARN msg="storage fault" path=`+messagesDir+`/tmp err="open `+messagesDir+`/tmp/`) ||
		!strings.Contains(log, `: permission denied"`) {
		t.Errorf("the relay did not log the fault with its path and reason:\n%s", log)
	}
	// The same fault again inside the minute is not another line.
	r = alice.auu("send", "--to", "bob", "--subject", "still unwritable", "and now?")
	expectCode(t, r, 2)
	if n := strings.Count(relayLogSince(m), `msg="storage fault"`); n != 1 {
		t.Errorf("two faults on one path inside a minute logged %d lines, want 1:\n%s", n, relayLogSince(m))
	}
	undo()
	expectSays(t, alice.auu("send", "--to", "bob", "--subject", "writable again", "now?"), 0, "sent to bob")
	drain(bob)
	verdict(t, "ok", "Alice is told whose problem it is and where they look; the relay's log has one line with the path "+
		"and the reason, and not a second for the same path inside the minute.")
}

func r18(t *testing.T) {
	if nofault {
		verdict(t, "observed", "")
		return
	}
	relay.mustRoot(t, "mount -t tmpfs -o size=1m tmpfs "+messagesDir+" && "+
		"install -d -o auu -g auu -m 0700 "+messagesDir+"/tmp "+messagesDir+"/uploads && "+
		"chown auu:auu "+messagesDir+" && chmod 0700 "+messagesDir)
	t.Cleanup(func() {
		relay.root("umount " + messagesDir)
		alice.exec("", "sh", "-c", "rm -rf /home/alice/.auu/outbox/*")
	})
	alice.exec("", "sh", "-c", "head -c 2000000 /dev/urandom > /home/alice/two-meg.bin")
	r := alice.auu("send", "--to", "bob", "--subject", "two megabytes inline", "--attach", "/home/alice/two-meg.bin", "--inline", "big")
	expectCode(t, r, 2)
	stderrIs(t, r, "auu: the relay is out of storage; whoever runs it needs to make room")
	r = alice.auu("send", "--to", "bob", "--subject", "two megabytes as a stream", "--attach", "/home/alice/two-meg.bin", "big")
	expectCode(t, r, 2)
	stderrIs(t, r, "auu: the relay is out of storage; whoever runs it needs to make room. "+
		"The sealed copy is kept; finish it with 'auu send --resume' when there is room")
	if out := alice.exec("", "sh", "-c", "ls /home/alice/.auu/outbox | wc -l"); strings.TrimSpace(out.stdout) != "2" {
		t.Errorf("the outbox holds %s entries, want the sealed stream and its record", strings.TrimSpace(out.stdout))
	}
	// Room made, as an operator would make it: the filesystem grows, and
	// the resume finishes from the sealed copy. The disk filled under the
	// relay's threshold (max_bytes, 16 MiB at the default), so the relay
	// kept nothing of the attempt and the resume opens anew.
	relay.mustRoot(t, "mount -o remount,size=8m "+messagesDir)
	expectSays(t, alice.auu("send", "--resume"), 0, "sent to bob via relay.example.com as a stream")
	expectSays(t, bob.auu("inbox"), 0, "two megabytes as a stream")
	verdict(t, "ok", "An envelope on a full disk is a 507 and one sentence that says whose problem it is. A stream on the "+
		"same disk is the same 507 part way through, the client keeps the sealed stream and says so, and once there is "+
		"room 'auu send --resume' sends it from the sealed copy, resuming what the relay kept or opening anew.")
}

func r20(t *testing.T) {
	undo := dbBackup(t)
	t.Cleanup(undo)
	if !nofault {
		relay.mustRoot(t, "rm -f "+relayDB+" "+relayDB+"-wal "+relayDB+"-shm")
	}
	r := alice.auu("send", "--to", "bob", "--subject", "after the delete", "still there?")
	record(alice, "(while the relay holds the deleted file open)", "", r)
	// The mailboxes with a message file on disk, which is what the relay
	// counts when it finds them beside a database that knows none of them.
	held := strings.TrimSpace(relay.mustRoot(t, "find "+messagesDir+" -mindepth 3 -type f | xargs -rn1 dirname | sort -u | wc -l"))
	boxes := "mailboxes"
	if held == "1" {
		boxes = "mailbox"
	}
	expectNoStart(t, relayDB+" is new but "+messagesDir+" holds mail for "+held+" "+boxes+": the database was lost. "+
		"Restore "+relayDB+" from a backup, or move the message directory aside to start the relay empty")
	// Restored from the backup, the relay knows its mailboxes again.
	undo()
	expectSays(t, operator.admin("status"), 0, "mailboxes:      2")
	expectSays(t, alice.auu("send", "--to", "bob", "--subject", "after the restore", "and now?"), 0, "sent to bob")
	drain(bob)
	verdict(t, "ok", "Until the restart nothing is amiss: the relay holds the file open. After it the relay refuses to "+
		"start on a fresh database beside mail it knows nothing about, names the count and both remedies, and the "+
		"mail is untouched; restored from the backup, it serves the mailboxes it had.")
}

func r21(t *testing.T) {
	t.Cleanup(dbBackup(t))
	relayStop(t)
	if !nofault {
		relay.mustRoot(t, "rm -f "+relayDB+"-wal "+relayDB+"-shm && printf 'not a database\\n' > "+relayDB+" && chown auu:auu "+relayDB)
	}
	expectNoStart(t, "opening database: relay: pragmas: file is not a database")
	verdict(t, "ok", "")
}

func r22(t *testing.T) {
	t.Cleanup(dbBackup(t))
	if !nofault {
		relay.sql(t, "PRAGMA user_version = 99")
	}
	expectNoStart(t, "relay: database is schema version 99, but this relay understands 6; it was written by a newer release")
	verdict(t, "ok", "")
}

func r23(t *testing.T) {
	r := relayAuu.exec("", "sh", "-c", "CREDENTIALS_DIRECTORY=/run/credentials/auu-relay timeout 5 auu-relay --config "+
		relaySettings+" --listen :9444 2>&1; echo \"exit $?\"")
	record(relayAuu, "(a second relay on the same database, for five seconds)", "", r)
	if !strings.Contains(r.stdout, "relay starting") {
		t.Errorf("the second relay did not start:\n%s", r.stdout)
	}
	expectSays(t, alice.auu("inbox"), 0)
	verdict(t, "observed", "Both run on one SQLite file, each with its own counters and rate limits; nothing refuses it.")
}

func r24(t *testing.T) {
	// A fresh process: the fault line is once a minute per path, and an
	// earlier row's fault on the same directory must not spend this row's.
	relayRestart(t)
	undo := relay.remove(t, messagesDir)
	undoThenRestart(t, undo)
	m := logMark()
	r := alice.auu("send", "--to", "bob", "--subject", "no directory", "where does this go")
	expectCode(t, r, 2)
	stderrIs(t, r, "auu: the relay could not store or read a message (storage error); whoever runs it needs to look at its log")
	log := relayLogSince(m)
	if !strings.Contains(log, `level=WARN msg="storage fault" path=`+messagesDir+`/tmp err="open `+messagesDir+`/tmp/`) ||
		!strings.Contains(log, `: no such file or directory"`) {
		t.Errorf("the relay did not log the fault with its path and reason:\n%s", log)
	}
	relayRestart(t)
	if !relay.exists(messagesDir + "/tmp") {
		t.Error("the restart did not recreate the message directory")
	}
	verdict(t, "ok", "Alice is told whose problem it is; the relay's log names the directory that is not there. A restart "+
		"recreates the directory and drops every queued row as a row without a file, which is the sweep's rule.")
}

func r25(t *testing.T) {
	undoThenRestart(t, extraArgs(t, "--registration closed"))
	relayRestart(t)
	tok := issueToken(t, "--note", "while closed")
	c := newCarol(t)
	r := c.auu("enrol", "--name", "carol", "--yes", tok)
	expectSays(t, r, 2, "relay returned 403: this relay is not accepting new registrations",
		"your identity was created in "+c.home+" but the relay refused the token")
	expectSays(t, alice.auu("send", "--to", "bob", "--subject", "closed to newcomers", "still fine"), 0, "sent to bob")
	drain(bob)
	verdict(t, "observed", "The administrator can still issue a token for a relay that will refuse it; the newcomer "+
		"learns after their identity is made.")
}

func r26(t *testing.T) {
	undoThenRestart(t, extraArgs(t, "--mailbox-max-messages 2"))
	relayRestart(t)
	for i := 1; i <= 2; i++ {
		expectSays(t, alice.auu("send", "--to", "bob", "--subject", fmt.Sprintf("quota %d", i), "fill"), 0, "sent to bob")
	}
	r := alice.auu("send", "--to", "bob", "--subject", "quota 3", "fill")
	expectCode(t, r, 2)
	stderrIs(t, r, "auu: bob's mailbox on the relay is full; they need to run 'auu rm' to make room")
	drain(bob)
	verdict(t, "ok", "")
}

func r27(t *testing.T) {
	// The bucket holds thirty and refills at thirty a minute, so the burst
	// has to be a burst: forty-five at once.
	const burst = 45
	results := make([]result, burst)
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = alice.auu("send", "--to", "bob", "--subject", fmt.Sprintf("burst %d", i+1), "x")
		}(i)
	}
	wg.Wait()
	accepted, refused := 0, 0
	var one result
	for _, r := range results {
		switch {
		case r.code == 0:
			accepted++
		case strings.Contains(r.stderr, "429"):
			refused++
			one = r
		default:
			t.Errorf("a send failed some other way: %d %s", r.code, r.stderr)
		}
	}
	record(alice, fmt.Sprintf("(%d sent at once: %d accepted, %d refused)", burst, accepted, refused), "", result{})
	if refused == 0 || accepted < 30 {
		t.Errorf("%d accepted, %d refused", accepted, refused)
	}
	if !strings.HasPrefix(one.stderr, "auu: relay returned 429: rate limited: posts; it asked for ") ||
		!strings.Contains(one.stderr, "s before the next attempt") {
		t.Errorf("the refusal does not name the limit and the wait: %q", one.stderr)
	}
	drain(bob)
	// The buckets live in memory: a restart empties them for whatever
	// comes after this row.
	relayRestart(t)
	verdict(t, "ok", "The refusal names the limit, posts, and the seconds the relay asked for.")
}

func r28(t *testing.T) {
	relayStop(t)
	t.Cleanup(func() {
		if !relayRunning() {
			relayStart(t)
		}
	})
	r := alice.auu("inbox")
	expectSays(t, r, 2, "auu: contacting relay: Get \"https://relay.example.com:9443/v1/mailbox/",
		"dial tcp: lookup relay.example.com")
	relayStart(t)
	expectSays(t, alice.auu("inbox"), 0)
	verdict(t, "observed", "Go's dial error with the whole URL in it, exit 2. In this network a stopped relay also loses "+
		"its name; on a real host it would be 'connection refused'.")
}

func r29(t *testing.T) {
	undoThenRestart(t, relay.edit(t, relaySettings, `"public_url": "https://relay.example.com:9443"`, `"public_url": "https://relay:9443"`))
	// The certificate carries relay.example.com alone, so under the new
	// name nobody could reach the relay and no token could be issued for
	// it; the relay says so instead of starting.
	expectNoStart(t, "public_url names relay but the bundle was issued for relay.example.com: "+
		"run 'auu-ca relay --host relay' on the offline machine and deliver that bundle, or fix public_url")
	verdict(t, "ok", "The operator is told at start, before anybody is locked out: public_url must name a host the "+
		"bundle was issued for, and the sentence names both and the command that issues a bundle for the new one.")
}

func r30(t *testing.T) {
	undoThenRestart(t, extraArgs(t, "--access-log full"))
	m := relayRestart(t)
	expectSays(t, alice.auu("send", "--to", "bob", "--subject", "logged in full", "hello"), 0, "sent to bob")
	full := relayLogSince(m)
	if !strings.Contains(full, "/v1/mailbox/"+state.bobFP) || !strings.Contains(full, "fp="+state.aliceFP[:16]) {
		t.Errorf("the full access log does not carry the path and the caller:\n%s", full)
	}
	relay.root("rm -f /etc/auu/extra-args")
	m = relayRestart(t)
	expectSays(t, alice.auu("send", "--to", "bob", "--subject", "logged minimally", "hello"), 0, "sent to bob")
	minimal := relayLogSince(m)
	if strings.Contains(minimal, state.bobFP) || strings.Contains(minimal, state.aliceFP[:16]) || !strings.Contains(minimal, "path=/v1/mailbox/{fp}") {
		t.Errorf("the minimal access log carries a fingerprint, or not the route:\n%s", minimal)
	}
	drain(bob)
	verdict(t, "ok", "Full records who wrote to whom; minimal, the shipped setting, records the route.")
}
