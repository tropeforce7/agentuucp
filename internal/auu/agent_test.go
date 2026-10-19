package auu

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/agent"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/keyfile"
	"github.com/tropeforce7/agentuucp/internal/store"
	"github.com/tropeforce7/agentuucp/internal/token"
)

// The agent is another process. 'auu agent start' runs os.Executable(),
// which under go test is this test binary, so TestMain makes the binary
// answer as auu when it is asked to: the tests set helperEnv in their own
// environment, the detached child inherits it, and its TestMain runs Main
// instead of the tests. Nothing sets the variable outside a test.
//
// A serve handler is this binary too, run by helperLine with
// -test.run=TestServeHelperProcess, and it inherits the variable from a
// test that has an agent running. The arguments say which it is: a
// handler run is one, whatever the environment says, because the
// alternative — unsetting the variable on the exec line — is shell syntax,
// and the line runs under sh on one platform and cmd on the other.
const helperEnv = "AUU_TEST_HELPER"

// parentEnv names the test process a helper belongs to, by its pid. A
// helper the run detached, the agent above all, is in its own session and
// released, so no signal that ends the test reaches it, and a Cleanup that
// stops it does not run when the test binary is interrupted, killed or
// timed out. A helper watches the pid it is given and exits when that
// process is gone: agentEnv sets it for every agent a test starts, and the
// serve tests set it on the environment they build by hand.
const parentEnv = "AUU_TEST_PARENT"

// parentPoll is how often a helper on Unix looks for its test process.
const parentPoll = 500 * time.Millisecond

// helperWatchInterval is how often an agent the tests start checks its
// socket.
const helperWatchInterval = 100 * time.Millisecond

func TestMain(m *testing.M) {
	// Run with arguments that are not a test's flags and without the
	// helper switch, this binary was started as auu by something that
	// forgot the switch: running the suite there would start the same
	// thing again, and each of those again (G35, R50a). It says so and
	// stops.
	if os.Getenv(helperEnv) != "1" && strayRun(os.Args) {
		fmt.Fprintf(os.Stderr, "%s: started as %q without %s=1; a test binary run as auu runs no tests\n",
			os.Args[0], strings.Join(os.Args[1:], " "), helperEnv)
		os.Exit(2)
	}
	if os.Getenv(helperEnv) == "1" && !isHandlerRun(os.Args) {
		watchTestParent()
		// An agent this binary runs checks its socket often, so that a
		// test of the watch waits a tick and not thirty seconds; auu
		// itself never sets it and keeps the agent's default.
		agentWatchInterval = helperWatchInterval
		Main("auu")
		return
	}
	os.Exit(m.Run())
}

// testParent is the pid parentEnv names, when it names one. Zero and
// below are refused: to kill they are a process group and every process.
// It is read as 32 bits because a pid is, so a larger number is refused
// rather than narrowed into one of those.
func testParent() (int, bool) {
	pid, err := strconv.ParseInt(os.Getenv(parentEnv), 10, 32)
	if err != nil || pid <= 0 {
		return 0, false
	}
	return int(pid), true
}

func TestTheTestParentIsAPidOrNothing(t *testing.T) {
	for value, want := range map[string]int{
		"":            0,
		"0":           0,
		"-1":          0,
		"-2147483648": 0,
		"2147483648":  0,
		"4294967295":  0,
		"0x10":        0,
		" 1":          0,
		"x":           0,
		"1":           1,
		"2147483647":  2147483647,
	} {
		t.Setenv(parentEnv, value)
		pid, ok := testParent()
		if ok != (want != 0) || pid != want {
			t.Errorf("%s=%q: got %d, %v; want %d", parentEnv, value, pid, ok, want)
		}
	}
}

// strayRun is a run of this binary with an argument that is not one of the
// testing package's flags, as 'agent run' is.
func strayRun(args []string) bool {
	return len(args) > 1 && !strings.HasPrefix(args[1], "-test.")
}

// isHandlerRun says whether these arguments are helperLine's: the test
// binary asked, first thing, to run TestServeHelperProcess as a handler or
// a hook. First thing, because that is where helperLine puts it and an
// auu command never has a flag of Go's test runner among its arguments.
func isHandlerRun(args []string) bool {
	return len(args) > 1 && args[1] == "-test.run=TestServeHelperProcess"
}

const agentPassphrase = "correct horse battery staple"

// encryptedUser is a user whose home is under a passphrase, with the agent
// running detached and unlocked, exactly as 'auu passphrase set' leaves it.
// The runtime directory is short and this test's own, and the agent is
// stopped at the end.
func encryptedUser(t *testing.T, name, relayURL string) *user {
	t.Helper()
	agentEnv(t)
	u := newUser(t, name, relayURL)
	u.encrypt()
	return u
}

// agentEnv is what every test that starts an agent needs: the helper
// switch, a short runtime directory, and a cheap derivation.
func agentEnv(t *testing.T) {
	t.Helper()
	t.Setenv(helperEnv, "1")
	t.Setenv(parentEnv, strconv.Itoa(os.Getpid()))
	dir, err := os.MkdirTemp("", "auu")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	t.Setenv("XDG_RUNTIME_DIR", dir)
	was := cost
	cost = keyfile.TestPassphrase("")
	t.Cleanup(func() { cost = was })
}

// passphraseFile is the passphrase in a file, for --passphrase-file.
func passphraseFile(t *testing.T, secret string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "passphrase")
	if err := os.WriteFile(path, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// encrypt runs passphrase set with the test passphrase, which starts and
// unlocks the agent to receive, and arranges for the agent to be stopped.
func (u *user) encrypt() {
	u.t.Helper()
	u.run("passphrase", "set", "--passphrase-file", passphraseFile(u.t, agentPassphrase))
	u.t.Cleanup(func() { u.tryRun("agent", "stop") })
}

// unlockSend is 'auu unlock --send' with the test passphrase: what a test
// that originates anything from an encrypted home runs first, as a person
// would.
func (u *user) unlockSend() {
	u.t.Helper()
	u.run("unlock", "--send", "--passphrase-file", passphraseFile(u.t, agentPassphrase))
}

// agentStatus is what 'auu agent status --json' says.
func (u *user) agentStatus() agentStatusJSON {
	u.t.Helper()
	var st agentStatusJSON
	if err := json.Unmarshal([]byte(u.run("agent", "status", "--json")), &st); err != nil {
		u.t.Fatal(err)
	}
	return st
}

// idStatus is what 'auu id --json' says.
func (u *user) idStatus() idJSON {
	u.t.Helper()
	var out idJSON
	if err := json.Unmarshal([]byte(u.run("id", "--json")), &out); err != nil {
		u.t.Fatal(err)
	}
	return out
}

// withStdin runs a command with standard input carrying text: a pipe, not
// a terminal.
func (u *user) withStdin(text string, args ...string) (string, error) {
	u.t.Helper()
	return u.answer(strings.TrimSuffix(text, "\n"), args...)
}

// inAnotherProcess runs auu as a separate process against this user's
// home, with standard input not a terminal, and returns what it printed
// and its exit code.
func (u *user) inAnotherProcess(args ...string) (stdout, stderr string, code int) {
	u.t.Helper()
	exe, err := os.Executable()
	if err != nil {
		u.t.Fatal(err)
	}
	cmd := exec.Command(exe, args...)
	cmd.Env = append(os.Environ(), helperEnv+"=1", "AUU_HOME="+u.home)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	cmd.Stdin = nil
	err = cmd.Run()
	var exit *exec.ExitError
	switch {
	case err == nil:
		code = 0
	case errors.As(err, &exit):
		code = exit.ExitCode()
	default:
		u.t.Fatalf("running %v: %v", args, err)
	}
	return out.String(), errb.String(), code
}

func TestPassphraseSetEncryptsTheHomeAndUnlocksTheAgent(t *testing.T) {
	relayURL := startRelay(t)
	agentEnv(t)
	alice := newUser(t, "alice", relayURL)
	before := alice.idStatus()
	if before.Encrypted || before.Locked {
		t.Fatalf("a plain home says %+v", before)
	}
	out := alice.run("passphrase", "set", "--passphrase-file", passphraseFile(t, agentPassphrase))
	t.Cleanup(func() { alice.tryRun("agent", "stop") })
	if !strings.Contains(out, "encrypted the keys in "+alice.home) {
		t.Errorf("set does not say what it did:\n%s", out)
	}
	for _, f := range []string{"home.key", "identity.key"} {
		if _, err := os.Stat(filepath.Join(alice.home, f)); err != nil {
			t.Errorf("%s was not written", f)
		}
	}
	after := alice.idStatus()
	if !after.Encrypted || after.Locked || after.Fingerprint != before.Fingerprint {
		t.Fatalf("after set, id says %+v", after)
	}
	if after.Until == "" {
		t.Error("id does not say until when the agent is unlocked")
	}
	st := alice.agentStatus()
	if !st.Running || st.Locked || len(st.Keys) != 1 || st.Keys[0] != agent.KeyIdentity {
		t.Errorf("agent status says %+v", st)
	}
	text := alice.run("id")
	if !strings.Contains(text, "secrets:     encrypted, unlocked to receive until ") {
		t.Errorf("id does not report the secrets:\n%s", text)
	}
	// The very next command that reads works, through the agent; sending
	// is unlock --send away, and then goes round.
	alice.run("inbox")
	alice.unlockSend()
	alice.run("send", "--to", "self", "--subject", "s", "hello")
	if !strings.Contains(alice.run("inbox"), "hello") && !strings.Contains(alice.run("inbox"), "s ") {
		t.Error("mail did not go round through the agent")
	}
	// A second set is refused; change and remove work; remove locks.
	if _, err := alice.tryRun("passphrase", "set", "--passphrase-file", passphraseFile(t, agentPassphrase)); err == nil {
		t.Error("a second set was accepted")
	}
	alice.run("passphrase", "change", "--passphrase-file", passphraseFile(t, agentPassphrase),
		"--new-passphrase-file", passphraseFile(t, "another passphrase"))
	if _, err := alice.tryRun("unlock", "--passphrase-file", passphraseFile(t, agentPassphrase)); err == nil {
		t.Error("the old passphrase still unlocks")
	}
	alice.run("unlock", "--passphrase-file", passphraseFile(t, "another passphrase"))
	alice.run("passphrase", "remove", "--passphrase-file", passphraseFile(t, "another passphrase"))
	final := alice.idStatus()
	if final.Encrypted || final.Locked {
		t.Errorf("after remove, id says %+v", final)
	}
	if st := alice.agentStatus(); st.Running {
		t.Error("the agent is still running after remove")
	}
	if _, err := alice.tryRun("unlock", "--passphrase-file", passphraseFile(t, agentPassphrase)); err == nil {
		t.Error("unlock on a plain home was accepted")
	}
}

// TestALockedCommandExits4WithOneSentence: the exact message, from a
// process whose standard input is not a terminal, for every command that
// needs a key; and none of them for a command that does not.
func TestALockedCommandExits4WithOneSentence(t *testing.T) {
	relayURL := startRelay(t)
	alice := encryptedUser(t, "alice", relayURL)
	alice.run("lock")
	if st := alice.agentStatus(); !st.Running || !st.Locked {
		t.Fatalf("after lock the agent says %+v", st)
	}
	const want = "your identity is locked: run 'auu unlock' in your own terminal"
	for _, args := range [][]string{
		{"send", "--to", "self", "hello"},
		{"inbox"},
		{"wait", "--thread", "abcdefabcdefabcd", "--timeout", "1s"},
		{"watch", "--timeout", "1s"},
		{"allow", "push"},
		{"lookup", alice.exportFingerprint()},
		{"cert", "ls"},
		{"register"},
	} {
		_, err := alice.tryRun(args...)
		var e *exitError
		if !asExit(err, &e) || e.code != exitLocked {
			t.Errorf("%v: got %v, want exit %d", args, err, exitLocked)
			continue
		}
		if e.Error() != want {
			t.Errorf("%v: message is %q, want %q", args, e.Error(), want)
		}
	}
	// And in another process, where Main prints it with the program's name
	// and exits with the code.
	stdout, stderr, code := alice.inAnotherProcess("send", "--to", "self", "hello")
	if code != exitLocked {
		t.Errorf("another process exited %d, want %d\n%s%s", code, exitLocked, stdout, stderr)
	}
	if strings.TrimSpace(stderr) != "auu: "+want {
		t.Errorf("another process said %q, want %q", strings.TrimSpace(stderr), "auu: "+want)
	}
	// Unlocked again, to send, the same command works and the message was
	// not touched: nothing was sent, nothing was discarded.
	alice.unlockSend()
	alice.run("send", "--to", "self", "hello")
	if out := alice.run("inbox", "--json"); !strings.Contains(out, `"delivered": 1`) {
		t.Errorf("after unlock, inbox says:\n%s", out)
	}
	// No agent at all is the same condition.
	alice.run("agent", "stop")
	_, err := alice.tryRun("send", "--to", "self", "hello")
	var e *exitError
	if !asExit(err, &e) || e.code != exitLocked || e.Error() != want {
		t.Errorf("with no agent: %v", err)
	}
}

// TestATerminalPromptsAndANonTerminalDoesNot: there is no pty in this
// harness, so the test is that the non-terminal path never reads standard
// input — it is given a pipe with a wrong passphrase in it and exits 4,
// not with a wrong-passphrase error.
func TestATerminalPromptsAndANonTerminalDoesNot(t *testing.T) {
	relayURL := startRelay(t)
	alice := encryptedUser(t, "alice", relayURL)
	alice.run("lock")
	_, err := alice.withStdin("not the passphrase\n", "send", "--to", "self", "hello")
	var e *exitError
	if !asExit(err, &e) || e.code != exitLocked {
		t.Fatalf("a pipe on standard input gave %v, want exit %d", err, exitLocked)
	}
	if strings.Contains(err.Error(), "passphrase") {
		t.Errorf("the pipe was read as a passphrase: %v", err)
	}
	// unlock is the one command that does read a pipe, and a wrong
	// passphrase there is refused as one.
	_, err = alice.withStdin("not the passphrase\n", "unlock")
	if err == nil || !strings.Contains(err.Error(), keyfile.ErrPassphrase.Error()) {
		t.Errorf("unlock from a pipe with the wrong passphrase gave %v", err)
	}
	if _, err := alice.withStdin(agentPassphrase+"\n", "unlock", "--ttl", "1h"); err != nil {
		t.Fatalf("unlock from a pipe: %v", err)
	}
	st := alice.agentStatus()
	if st.Locked {
		t.Fatal("not unlocked")
	}
	until, err := time.Parse(time.RFC3339, st.Until)
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Until(until); d < 55*time.Minute || d > 65*time.Minute {
		t.Errorf("--ttl 1h gave an unlock until %s from now", d)
	}
	if _, err := alice.tryRun("unlock", "--ttl", "-1s", "--passphrase-file", passphraseFile(t, agentPassphrase)); err == nil {
		t.Error("a negative ttl was accepted")
	}
	// A short passphrase is refused by set before anything is written.
	bob := newUser(t, "bob", relayURL)
	before, _ := os.ReadFile(filepath.Join(bob.home, "identity.json"))
	if _, err := bob.tryRun("passphrase", "set", "--passphrase-file", passphraseFile(t, "short")); err == nil ||
		!strings.Contains(err.Error(), "at least 8") {
		t.Errorf("a short passphrase gave %v", err)
	}
	after, _ := os.ReadFile(filepath.Join(bob.home, "identity.json"))
	if !bytes.Equal(before, after) {
		t.Error("a refused set changed identity.json")
	}
}

// TestUnlockThenSendInAnotherProcess: unlock with a passphrase file in one
// process, then send and inbox in another with standard input not a
// terminal, against a real relay — the AI's situation.
func TestUnlockThenSendInAnotherProcess(t *testing.T) {
	relayURL := startRelay(t)
	alice := encryptedUser(t, "alice", relayURL)
	alice.run("lock")
	if _, stderr, code := alice.inAnotherProcess("unlock", "--send", "--passphrase-file", passphraseFile(t, agentPassphrase)); code != 0 {
		t.Fatalf("unlock --send in another process exited %d:\n%s", code, stderr)
	} else if !strings.Contains(stderr, "unlocked to send until ") {
		t.Errorf("unlock --send did not say the scope and until when:\n%s", stderr)
	}
	stdout, stderr, code := alice.inAnotherProcess("send", "--to", "self", "--subject", "from the AI", "--json", "hello")
	if code != 0 {
		t.Fatalf("send in another process exited %d:\n%s%s", code, stdout, stderr)
	}
	stdout, stderr, code = alice.inAnotherProcess("inbox", "--json")
	if code != 0 {
		t.Fatalf("inbox in another process exited %d:\n%s%s", code, stdout, stderr)
	}
	var inbox inboxJSON
	if err := json.Unmarshal([]byte(stdout), &inbox); err != nil {
		t.Fatal(err)
	}
	if inbox.Fetch.Delivered != 1 || len(inbox.Messages) != 1 || inbox.Messages[0].Subject != "from the AI" {
		t.Errorf("the message did not go round: %+v", inbox)
	}
	// The identity file on disk holds no key the other process could have
	// read; the seed is nowhere in the home.
	home := snapshotHome(t, alice.home)
	for name, data := range home {
		if bytes.Contains(data, []byte("sign_seed")) || bytes.Contains(data, []byte("BEGIN PRIVATE KEY")) {
			t.Errorf("%s holds a key in the clear", name)
		}
	}
}

func snapshotHome(t *testing.T, root string) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			data, _ := os.ReadFile(path)
			rel, _ := filepath.Rel(root, path)
			out[rel] = data
		}
		return nil
	})
	return out
}

// TestPublicCommandsNeedNoAgent: with the home encrypted and no agent
// socket at all, every command that needs only the public half succeeds.
func TestPublicCommandsNeedNoAgent(t *testing.T) {
	relayURL := startRelay(t)
	alice := encryptedUser(t, "alice", relayURL)
	attachment := filepath.Join(t.TempDir(), "note.txt")
	if err := os.WriteFile(attachment, []byte("kept\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	alice.unlockSend()
	alice.run("send", "--to", "self", "--subject", "kept", "--attach", attachment, "a note")
	alice.run("inbox")
	bob := newUser(t, "bob", relayURL)
	alice.run("peers", "add", bob.exportLine())
	alice.run("agent", "stop")
	if st := alice.agentStatus(); st.Running {
		t.Fatal("the agent is still running")
	}
	var id string
	for _, m := range strings.Split(alice.run("inbox", "--no-fetch"), "\n") {
		if strings.Contains(m, "kept") {
			id = strings.Fields(m)[1]
		}
	}
	if id == "" {
		t.Fatal("the note is not in the inbox listing")
	}
	for _, args := range [][]string{
		{"id"}, {"id", "--json"}, {"id", "export"},
		{"peers", "ls"}, {"peers", "ls", "--json"}, {"peers", "rm", "bob"},
		{"relay", "ls"}, {"relay", "show"},
		{"anchor", "status"},
		{"cert", "status"},
		{"inbox", "--no-fetch"}, {"inbox", "--no-fetch", "--json"},
		{"read", id}, {"read", id, "--json"},
		{"extract", id, "--out", filepath.Join(t.TempDir(), "out")},
		{"quarantine", "ls"},
		{"agent", "status"}, {"lock"},
	} {
		if out, err := alice.tryRun(args...); err != nil {
			t.Errorf("%v with no agent: %v\n%s", args, err, out)
		}
	}
	if out := alice.run("id"); !strings.Contains(out, "secrets:     encrypted, locked") {
		t.Errorf("id does not say locked:\n%s", out)
	}
	if st := alice.idStatus(); !st.Encrypted || !st.Locked {
		t.Errorf("id --json says %+v", st)
	}
}

// TestRegisterAndRenewThroughTheAgent: the machine key is made by
// generate, the CSR is signed by the agent, the written cert.json carries a
// wrapped block, and a TLS handshake with the remote signer completes
// against the relay.
func TestRegisterAndRenewThroughTheAgent(t *testing.T) {
	_, issue := certRelay(t)
	agentEnv(t)
	alice := &user{t: t, home: t.TempDir()}
	alice.run("enrol", "--name", "alice", "--yes", issue(token.UseRegister, ""))
	alice.encrypt()
	if rec := alice.certRecord(); !rec.Encrypted() {
		t.Fatal("set did not wrap the machine key enrol wrote")
	}
	// After set, the key enrol wrote is wrapped, and the handshake with it
	// completes: cert ls is a certificate route.
	if !strings.Contains(alice.run("cert", "ls"), "* is this machine") {
		t.Error("a handshake with the wrapped key did not complete")
	}
	before := alice.certRecord()

	// register makes a new key through the agent, which is send scope:
	// enrolling a machine is a human act.
	alice.unlockSend()
	alice.run("register", "--token", issue(token.UseCert, alice.exportFingerprint()), "--label", "again")
	after := alice.certRecord()
	if !after.Encrypted() {
		t.Fatal("register wrote a plain key into an encrypted home")
	}
	if after.Serial == before.Serial {
		t.Error("register did not get a new certificate")
	}
	if strings.Contains(after.Key, "BEGIN PRIVATE KEY") {
		t.Error("the private key is in cert.json in the clear")
	}
	if !strings.Contains(alice.run("cert", "ls"), "* is this machine") {
		t.Error("a handshake with the registered key did not complete")
	}
	if !strings.Contains(alice.run("cert", "status"), "key:     ML-DSA-65") {
		t.Errorf("cert status cannot name the key's parameter set:\n%s", alice.run("cert", "status"))
	}
	// And renewal, which makes a key while authenticated with the old one.
	out := alice.run("cert", "renew")
	if !strings.Contains(out, "renewed:") {
		t.Errorf("renew:\n%s", out)
	}
	renewed := alice.certRecord()
	if !renewed.Encrypted() || renewed.Serial == after.Serial {
		t.Error("renew did not write a new wrapped key")
	}
	if !strings.Contains(alice.run("cert", "ls"), "* is this machine") {
		t.Error("a handshake with the renewed key did not complete")
	}
	// Mail works over the certificate too.
	alice.run("send", "--to", "self", "hello")
	if out := alice.run("inbox", "--json"); !strings.Contains(out, `"delivered": 1`) {
		t.Errorf("inbox:\n%s", out)
	}
	// Locked, a certificate route is exit 4 and not certificate advice.
	alice.run("lock")
	_, err := alice.tryRun("cert", "ls")
	var e *exitError
	if !asExit(err, &e) || e.code != exitLocked {
		t.Errorf("cert ls with the agent locked gave %v, want exit %d", err, exitLocked)
	}
}

// TestInitForceRefusesAnEncryptedHome: a new identity written beside
// home.key would be the half-converted state, so init says what to do.
func TestInitForceRefusesAnEncryptedHome(t *testing.T) {
	relayURL := startRelay(t)
	alice := encryptedUser(t, "alice", relayURL)
	_, err := alice.tryRun("init", "--name", "alice2", "--force")
	if err == nil || !strings.Contains(err.Error(), "passphrase remove") {
		t.Errorf("init --force on an encrypted home gave %v", err)
	}
	if st := alice.idStatus(); st.Name != "alice" {
		t.Error("init --force replaced the identity anyway")
	}
	// enrol with an existing identity in an encrypted home goes through
	// the agent; a new one on a plain home prints the hint.
	bob := &user{t: t, home: t.TempDir()}
	out := bob.run("init", "--name", "bob", "--relay", relayURL)
	if !strings.Contains(out, "To encrypt these keys under a passphrase: auu passphrase set") {
		t.Errorf("init does not mention passphrase set:\n%s", out)
	}
}

// TestAgentStartStopAndStatus: start is idempotent, stop stops, status
// says which, and two starts do not make two agents.
func TestAgentStartStopAndStatus(t *testing.T) {
	relayURL := startRelay(t)
	alice := encryptedUser(t, "alice", relayURL)
	paths, err := agent.PathsFor(alice.home)
	if err != nil {
		t.Fatal(err)
	}
	if st := alice.agentStatus(); !st.Running || st.Socket != paths.Socket {
		t.Fatalf("status says %+v", st)
	}
	if out := alice.run("agent", "start"); out != "" {
		t.Errorf("a second start printed %q", out)
	}
	if out := alice.run("agent", "stop"); !strings.Contains(out, "stopped") {
		t.Errorf("stop said %q", out)
	}
	deadline := time.Now().Add(5 * time.Second)
	for alice.agentStatus().Running && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if st := alice.agentStatus(); st.Running {
		t.Fatal("still running after stop")
	}
	if out := alice.run("agent", "stop"); !strings.Contains(out, "no agent is running") {
		t.Errorf("a second stop said %q", out)
	}
	if out := alice.run("lock"); !strings.Contains(out, "no agent is running") {
		t.Errorf("lock with no agent said %q", out)
	}
	alice.run("agent", "start")
	st := alice.agentStatus()
	if !st.Running || !st.Locked {
		t.Errorf("after start the agent says %+v, want running and locked", st)
	}
	if text := alice.run("agent", "status"); !strings.Contains(text, "keys:   locked") {
		t.Errorf("status text:\n%s", text)
	}
	log, err := os.ReadFile(paths.Log)
	if err != nil || !strings.Contains(string(log), "started for "+alice.home) {
		t.Errorf("the agent's log does not say it started: %v\n%s", err, log)
	}
	// A plain home has nothing for an agent to hold.
	bob := newUser(t, "bob", relayURL)
	if _, err := bob.tryRun("agent", "start"); err == nil || !strings.Contains(err.Error(), "not encrypted") {
		t.Errorf("agent start on a plain home gave %v", err)
	}
}

// TestTheSkillsExitCodeIsDocumented: the client document's table and
// SKILL.md both name 4.
func TestTheSkillsExitCodeIsDocumented(t *testing.T) {
	for _, f := range []string{"../../docs/client.md", "../../skill/auu-connect/SKILL.md"} {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(data), "| 4 |") {
			t.Errorf("%s does not name exit code 4", f)
		}
		if !strings.Contains(string(data), "auu unlock") {
			t.Errorf("%s does not name auu unlock", f)
		}
	}
}

// TestAHalfConvertedHomeIsFinishedByRunningSetAgain: the CLI's half of
// section 1.5, over the store's.
func TestAHalfConvertedHomeIsFinishedByRunningSetAgain(t *testing.T) {
	relayURL := startRelay(t)
	alice := encryptedUser(t, "alice", relayURL)
	alice.run("agent", "stop")
	// Undo the last rename by hand: the identity is encrypted, and one
	// machine key is not... this home has no certificate, so take home.key
	// away instead, which is the state remove leaves before its last step.
	// Re-create the first set state: home.key beside a plain identity.
	bob := newUser(t, "bob", relayURL)
	homeKey, err := os.ReadFile(filepath.Join(alice.home, "home.key"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bob.home, "home.key"), homeKey, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = bob.tryRun("send", "--to", "self", "x")
	if err == nil || !errors.Is(err, store.ErrInterrupted) {
		t.Fatalf("a half-converted home was not diagnosed: %v", err)
	}
	if _, err := bob.tryRun("id"); err == nil {
		t.Error("id did not refuse a half-converted home")
	}
	bob.run("passphrase", "set", "--passphrase-file", passphraseFile(t, agentPassphrase))
	t.Cleanup(func() { bob.tryRun("agent", "stop") })
	if st := bob.idStatus(); !st.Encrypted || st.Locked {
		t.Errorf("after finishing, id says %+v", st)
	}
	bob.unlockSend()
	bob.run("send", "--to", "self", "x")
}

// localSigner is the identity's signing half held in this process, for an
// identity whose KEM half is the agent's: the shape of the moment the TTL
// runs out between a signed request and the message it fetched.
type localSigner struct{ id *identity.Identity }

func (l localSigner) Public() []byte                  { return l.id.Public().SignPublic() }
func (l localSigner) Sign(msg []byte) ([]byte, error) { return l.id.Sign(msg) }

// TestALockedAgentMidCommandDiscardsNothing: the pre-flight check passed,
// the request was signed, and then the agent locked before the message was
// opened. A message that fails to open because the key is not here is not
// unreadable: it stays queued, unacknowledged, with the cursor where it
// was, whether the first thing in the mailbox is an envelope or a stream;
// and a handshake the agent would not sign is exit 4, not certificate
// advice.
//
// The request has to be signed for the fetch to reach the message at all,
// so the identity here signs locally and decapsulates through the agent;
// a wholly remote identity fails at the signature and proves nothing about
// what happens after it.
func TestALockedAgentMidCommandDiscardsNothing(t *testing.T) {
	for _, first := range []string{"envelope", "stream"} {
		t.Run(first+" first", func(t *testing.T) {
			_, issue := certRelay(t)
			agentEnv(t)
			alice := &user{t: t, home: t.TempDir()}
			alice.run("enrol", "--name", "alice", "--yes", issue(token.UseRegister, ""))
			s, err := store.Open(alice.home)
			if err != nil {
				t.Fatal(err)
			}
			local, err := s.Identity()
			if err != nil {
				t.Fatal(err)
			}
			alice.encrypt()

			// One small message and one large enough to be a stream, both
			// queued, in the order under test.
			cfg, _ := s.Config()
			cfg.StreamThreshold = 64 << 10
			if err := s.SaveConfig(cfg); err != nil {
				t.Fatal(err)
			}
			big := filepath.Join(t.TempDir(), "big.bin")
			if err := os.WriteFile(big, bytes.Repeat([]byte("x"), 200<<10), 0o600); err != nil {
				t.Fatal(err)
			}
			envelope := func() { alice.run("send", "--to", "self", "--subject", "small", "an envelope") }
			stream := func() { alice.run("send", "--to", "self", "--subject", "large", "--attach", big, "a stream") }
			alice.unlockSend()
			if first == "envelope" {
				envelope()
				stream()
			} else {
				stream()
				envelope()
			}

			// Signs here, opens through the agent.
			ac, err := agent.NewClient(alice.home)
			if err != nil {
				t.Fatal(err)
			}
			kem, err := ac.IdentityKEM(local.Public().KEM.Bytes())
			if err != nil {
				t.Fatal(err)
			}
			hybrid, err := identity.FromRemote(local.Suite(), local.Name, local.Public().Bundle(), localSigner{local}, kem)
			if err != nil {
				t.Fatal(err)
			}
			t.Setenv("AUU_HOME", alice.home)
			r, err := s.DefaultRelay()
			if err != nil {
				t.Fatal(err)
			}
			// The connection is made while unlocked — the handshake needs
			// the agent — and kept; then the agent locks under it.
			c, err := dial(s, hybrid, r)
			if err != nil {
				t.Fatal(err)
			}
			if err := c.Health(ctx()); err != nil {
				t.Fatal(err)
			}
			alice.run("lock")

			res, _, err := fetch(context.Background(), s, hybrid, c, r, 0)
			if !isLocked(err) {
				t.Fatalf("fetch with the agent locked gave %v, want the locked condition", err)
			}
			if res.Unreadable != 0 || res.Delivered != 0 || res.Quarantined != 0 {
				t.Errorf("fetch with the agent locked reported %+v; nothing should have been dropped or delivered", res)
			}
			if cursor, _ := s.CursorFor(r); cursor != 0 {
				t.Errorf("the cursor moved to %d with the agent locked", cursor)
			}
			if msgs, _ := s.List(store.Inbox); len(msgs) != 0 {
				t.Errorf("%d message(s) were stored with the agent locked", len(msgs))
			}

			// A fresh handshake, which the agent must sign, is the locked
			// condition too — through crypto/tls's own error, which is why
			// isLocked reads the text as well as the chain.
			c.CloseIdle()
			if err := c.Health(ctx()); !isLocked(err) {
				t.Errorf("a handshake with the agent locked gave %v, want the locked condition", err)
			}
			var e *exitError
			if err := run([]string{"cert", "ls"}); !asExit(err, &e) || e.code != exitLocked {
				t.Errorf("cert ls with the agent locked gave %v, want exit %d", err, exitLocked)
			}

			// Unlocked, both arrive: nothing was lost.
			alice.run("unlock", "--passphrase-file", passphraseFile(t, agentPassphrase))
			out := alice.run("inbox", "--json")
			var inbox inboxJSON
			if err := json.Unmarshal([]byte(out), &inbox); err != nil {
				t.Fatal(err)
			}
			if inbox.Fetch.Delivered != 2 || inbox.Fetch.Unreadable != 0 {
				t.Errorf("after unlock, fetch says %+v; both messages should arrive", inbox.Fetch)
			}
		})
	}
}

// TestTheDamagedExitCodeIsDocumented: the client document's table and
// SKILL.md both name 5, and the skill says whose it is to deal with.
func TestTheDamagedExitCodeIsDocumented(t *testing.T) {
	for _, f := range []string{"../../docs/client.md", "../../skill/auu-connect/SKILL.md"} {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(data), "| 5 |") {
			t.Errorf("%s does not name exit code 5", f)
		}
		if !strings.Contains(string(data), "damaged") || !strings.Contains(string(data), "message names") {
			t.Errorf("%s does not say what 5 means", f)
		}
		if strings.Contains(string(data), "or a message failed to open") {
			t.Errorf("%s still says exit 2 is a message that failed to open, which never happens", f)
		}
	}
	skill, err := os.ReadFile("../../skill/auu-connect/SKILL.md")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(skill), "tell the person which file the message names") {
		t.Error("the skill does not tell the agent to stop and name the file")
	}
}

// A damaged file exits 5 from the command line, after the locked check and
// before the certificate advice: the sentence names the file and what to
// do, and the code says a person has to.
func TestADamagedFileExitsFive(t *testing.T) {
	relayURL := startRelay(t)
	alice := newUser(t, "alice", relayURL)
	if err := os.WriteFile(filepath.Join(alice.home, "config.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := alice.tryRun("inbox")
	var e *exitError
	if !errors.As(err, &e) || e.code != exitDamaged {
		t.Fatalf("inbox with config.json damaged: %v, want exit %d", err, exitDamaged)
	}
	// Met at Open, by the migration that reads config.json first, and
	// wrapped in the home's opening; the sentence names the file all the
	// same, and the exit is the file's.
	if !strings.Contains(err.Error(), filepath.Join(alice.home, "config.json")+" is not valid JSON (unexpected end of JSON input): delete it") {
		t.Fatalf("error %q does not name the file", err)
	}
	if !errors.Is(err, store.ErrDamaged) {
		t.Fatalf("the exit error does not carry ErrDamaged: %v", err)
	}
}

// orphanHelperEnv is TestAgentOrphanHelperProcess's gate: set only by
// TestAnAgentDoesNotOutliveTheRunThatStartedIt, for the child it runs.
const orphanHelperEnv = "AUU_TEST_ORPHAN_HELPER"

// TestAgentOrphanHelperProcess is the test run that the test below kills:
// it starts an agent as every test with an encrypted user does, says where,
// and waits to be killed.
func TestAgentOrphanHelperProcess(t *testing.T) {
	if os.Getenv(orphanHelperEnv) != "1" {
		t.Skip("the child of TestAnAgentDoesNotOutliveTheRunThatStartedIt, not a test of its own")
	}
	u := encryptedUser(t, "alice", startRelay(t))
	fmt.Printf("%s\n%s\n", u.home, os.Getenv("XDG_RUNTIME_DIR"))
	// Standard input is a pipe the parent never writes to; this returns
	// only if the parent goes, and then the Cleanups stop the agent.
	io.Copy(io.Discard, os.Stdin)
}

// A test run that is killed runs none of its Cleanups, so the agent it
// started is stopped by nobody: it is in a session of its own and was
// released, and three were found running days after the runs that started
// them. The agent watches the test process instead and goes with it.
func TestAnAgentDoesNotOutliveTheRunThatStartedIt(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestAgentOrphanHelperProcess$", "-test.count=1")
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, helperEnv+"=") && !strings.HasPrefix(kv, parentEnv+"=") {
			cmd.Env = append(cmd.Env, kv)
		}
	}
	cmd.Env = append(cmd.Env, orphanHelperEnv+"=1")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdin.Close()
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	killed := false
	t.Cleanup(func() {
		if !killed {
			cmd.Process.Kill()
			cmd.Wait()
		}
	})
	lines := bufio.NewScanner(stdout)
	var where []string
	for len(where) < 2 && lines.Scan() {
		where = append(where, lines.Text())
	}
	if len(where) < 2 {
		cmd.Process.Kill()
		cmd.Wait()
		killed = true
		t.Fatalf("the helper run never said where its agent is:\n%s", stderr.String())
	}
	home, runtimeDir := where[0], where[1]
	t.Setenv("XDG_RUNTIME_DIR", runtimeDir)
	c, err := agent.NewClient(home)
	if err != nil {
		t.Fatal(err)
	}
	// The killed run's Cleanups never remove what it made, so this does;
	// and when the agent outlived it, stopping it here is what keeps this
	// test from leaving the orphan it is about.
	t.Cleanup(func() {
		c.Stop()
		os.RemoveAll(home)
		os.RemoveAll(runtimeDir)
	})
	if _, err := c.Status(); err != nil {
		t.Fatalf("the agent does not answer before the kill: %v", err)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	cmd.Wait()
	killed = true
	// Polled, as startAgent polls for it to come up: the agent is another
	// process, and its answering is the only thing that says it is there.
	deadline := time.Now().Add(10 * time.Second)
	for {
		_, err := c.Status()
		if errors.Is(err, agent.ErrNotRunning) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the agent still answers ten seconds after the test run that started it was killed (status: %v)", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
