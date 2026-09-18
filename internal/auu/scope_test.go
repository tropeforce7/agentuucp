package auu

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/agent"
	"github.com/tropeforce7/agentuucp/internal/relay"
	"github.com/tropeforce7/agentuucp/internal/store"
	"github.com/tropeforce7/agentuucp/internal/token"
)

// TestReceiveScopeReadsAndCannotOriginate is the plan's client list, end
// to end through a real agent: after 'passphrase set' the agent is
// unlocked to receive, and every command that reads, lists, watches or
// acknowledges works — an inbox fetch that reads a stream's blob and an
// 'auu rm' on a real message id among them, which is what proves the ids
// the client puts in a path against the classifier's refusal of anything
// escaped — while every command that originates exits 4 with the agent's
// sentence, exactly. After 'unlock --send' they work; after 'lock --send'
// they are refused again.
func TestReceiveScopeReadsAndCannotOriginate(t *testing.T) {
	relayURL, _ := startRelayConfig(t, relay.Config{Streams: true, Limits: relay.DefaultLimits()})
	agentEnv(t)
	alice, bob := watchers(t, relayURL)
	// bob streams anything over 64 KiB, so alice's fetch reads a blob.
	s, _, _ := bob.opened()
	cfg, err := s.Config()
	if err != nil {
		t.Fatal(err)
	}
	cfg.StreamThreshold = 64 << 10
	if err := s.SaveConfig(cfg); err != nil {
		t.Fatal(err)
	}
	big := filepath.Join(t.TempDir(), "big.bin")
	if err := os.WriteFile(big, bytes.Repeat([]byte("x"), 200<<10), 0o600); err != nil {
		t.Fatal(err)
	}
	bob.run("send", "--to", "alice", "--subject", "small", "an envelope")
	bob.run("send", "--to", "alice", "--subject", "large", "--attach", big, "a stream")

	alice.encrypt()
	if st := alice.agentStatus(); !st.Running || st.Locked || st.Scope != string(agent.ScopeReceive) || st.SendExpires != "" {
		t.Fatalf("after passphrase set the agent says %+v, want unlocked to receive", st)
	}
	if out := alice.run("agent", "status"); !strings.Contains(out, "keys:   unlocked to receive until ") {
		t.Errorf("agent status does not say the scope:\n%s", out)
	}
	if out := alice.run("id"); !strings.Contains(out, "secrets:     encrypted, unlocked to receive until ") {
		t.Errorf("id does not say the scope:\n%s", out)
	}
	if st := alice.idStatus(); st.Locked || st.Scope != string(agent.ScopeReceive) || st.SendExpires != "" {
		t.Errorf("id --json says %+v", st)
	}

	// Reads. The fetch delivers both, the stream's payload through the
	// blob route.
	var inbox inboxJSON
	if err := json.Unmarshal([]byte(alice.run("inbox", "--json")), &inbox); err != nil {
		t.Fatal(err)
	}
	if inbox.Fetch.Delivered != 2 || inbox.Fetch.Unreadable != 0 {
		t.Fatalf("in receive scope the fetch says %+v; both messages, the stream included, should arrive", inbox.Fetch)
	}
	large := recordOf(t, alice, store.Inbox, "large")
	if !large.Streamed {
		t.Fatal("the large message did not arrive as a stream")
	}
	small := recordOf(t, alice, store.Inbox, "small")
	for _, args := range [][]string{
		{"inbox"},
		{"quarantine", "ls"},
		{"allow", "show"},
		{"channel", "ls"},
		{"lookup", bob.exportFingerprint()},
		{"rm", small.Inner.ID[:12]},
	} {
		if _, err := alice.tryRun(args...); err != nil {
			t.Errorf("in receive scope, %v: %v", args, err)
		}
	}
	// wait and watch --fetch sign a held listing and time out with nothing
	// to report: exit 3, not 4, is the listing having been signed.
	for _, args := range [][]string{
		{"wait", "--thread", "abcdefabcdefabcd", "--timeout", "1s"},
		{"watch", "--fetch", "--timeout", "1s"},
	} {
		_, err := alice.tryRun(args...)
		var e *exitError
		if !asExit(err, &e) || e.code != exitTimeout {
			t.Errorf("in receive scope, %v: %v, want exit %d", args, err, exitTimeout)
		}
	}

	// Originating: exit 4, the agent's sentence and nothing else.
	originate := [][]string{
		{"send", "--to", "bob", "hello"},
		{"send", "--to", "bob", "--attach", big, "a stream"},
		{"reply", large.Inner.ID[:12], "thanks"},
		{"allow", "push"},
		{"register"},
	}
	for _, args := range originate {
		_, err := alice.tryRun(args...)
		var e *exitError
		if !asExit(err, &e) || e.code != exitLocked {
			t.Errorf("in receive scope, %v: %v, want exit %d", args, err, exitLocked)
			continue
		}
		if e.Error() != agent.ReceiveOnlyMessage {
			t.Errorf("in receive scope, %v said %q, want %q", args, e.Error(), agent.ReceiveOnlyMessage)
		}
	}
	// And from another process, whose standard input is not a terminal:
	// the sentence on standard error, prefixed as every auu error is.
	stdout, stderr, code := alice.inAnotherProcess("send", "--to", "bob", "hello")
	if code != exitLocked || strings.TrimSpace(stderr) != "auu: "+agent.ReceiveOnlyMessage || stdout != "" {
		t.Errorf("another process exited %d and said %q / %q", code, stdout, stderr)
	}
	// Nothing was sent.
	if out := bob.run("inbox", "--json"); strings.Contains(out, `"delivered": 1`) {
		t.Error("a refused send reached bob")
	}

	// unlock --send: the same commands work, and status says so.
	_, stderr, code = alice.inAnotherProcess("unlock", "--send", "--passphrase-file", passphraseFile(t, agentPassphrase))
	if code != 0 || !strings.Contains(stderr, "unlocked to send until ") || !strings.Contains(stderr, " (receive until ") {
		t.Fatalf("unlock --send exited %d and said %q", code, stderr)
	}
	if st := alice.agentStatus(); st.Scope != string(agent.ScopeSend) || st.SendExpires == "" || st.Until == "" {
		t.Fatalf("after unlock --send the agent says %+v", st)
	}
	if out := alice.run("agent", "status"); !strings.Contains(out, "keys:   unlocked to send until ") || !strings.Contains(out, " (receive until ") {
		t.Errorf("agent status after unlock --send:\n%s", out)
	}
	if st := alice.idStatus(); st.Scope != string(agent.ScopeSend) || st.SendExpires == "" {
		t.Errorf("id --json after unlock --send says %+v", st)
	}
	for _, args := range originate[:4] {
		if _, err := alice.tryRun(args...); err != nil {
			t.Errorf("in send scope, %v: %v", args, err)
		}
	}
	if err := json.Unmarshal([]byte(bob.run("inbox", "--json")), &inbox); err != nil {
		t.Fatal(err)
	}
	if inbox.Fetch.Delivered != 3 {
		t.Errorf("after unlock --send bob's fetch says %+v, want the three sends", inbox.Fetch)
	}

	// lock --send drops to receive without locking: reads work, sends do
	// not, and the agent still holds the keys.
	if out := alice.run("lock", "--send"); !strings.HasPrefix(out, "unlocked to receive until ") {
		t.Errorf("lock --send said %q", out)
	}
	if st := alice.agentStatus(); st.Locked || st.Scope != string(agent.ScopeReceive) || st.SendExpires != "" {
		t.Fatalf("after lock --send the agent says %+v", st)
	}
	alice.run("inbox")
	_, err = alice.tryRun("send", "--to", "bob", "again")
	var e *exitError
	if !asExit(err, &e) || e.code != exitLocked || e.Error() != agent.ReceiveOnlyMessage {
		t.Errorf("after lock --send, send gave %v", err)
	}
	// lock --send on a locked agent is nothing; lock locks.
	alice.run("lock")
	if out := alice.run("lock", "--send"); strings.TrimSpace(out) != "locked" {
		t.Errorf("lock --send on a locked agent said %q", out)
	}
	if st := alice.agentStatus(); !st.Locked || st.Scope != "" {
		t.Errorf("after lock the agent says %+v", st)
	}
}

// TestEnrolAsksForSendScopeAtATerminal: enrol on an encrypted home (a
// second relay, or this one again) registers and makes a machine key,
// which is send scope, and it is the one command that asks a person at a
// terminal for the passphrase into send scope rather than into receive
// and then being refused. There is no terminal in this harness, so what is
// proved is the branch before the terminal: from a pipe, an agent unlocked
// to receive is told the receive sentence and a locked one the locked
// sentence, by ensureUnlocked and not by the agent's later refusal; and a
// send-scope unlock is what enrol then finds enough.
func TestEnrolAsksForSendScopeAtATerminal(t *testing.T) {
	_, issue := certRelay(t)
	agentEnv(t)
	alice := &user{t: t, home: t.TempDir()}
	alice.run("enrol", "--name", "alice", "--yes", issue(token.UseRegister, ""))
	alice.encrypt()
	// The same relay again, so a certificate token: this identity already
	// holds a live certificate there.
	enrol := func() error {
		_, err := alice.withStdin("", "enrol", "--name", "alice", "--yes", issue(token.UseCert, alice.exportFingerprint()))
		return err
	}
	// Receive scope, not a terminal: the receive sentence.
	err := enrol()
	var e *exitError
	if !asExit(err, &e) || e.code != exitLocked || e.Error() != agent.ReceiveOnlyMessage {
		t.Fatalf("enrol from a pipe in receive scope gave %v, want exit %d and the receive sentence", err, exitLocked)
	}
	// Locked, not a terminal: the locked sentence.
	alice.run("lock")
	err = enrol()
	if !asExit(err, &e) || e.code != exitLocked || !strings.Contains(e.Error(), "your identity is locked") {
		t.Fatalf("enrol from a pipe with the agent locked gave %v, want the locked sentence", err)
	}
	// A terminal, stood in: the person is asked once, and what they are
	// asked into is send scope for its ten minutes, so enrol goes through
	// and the agent says so.
	asked := 0
	var prompts []string
	wasTerminal, wasAsk := stdinIsTerminal, askPassphrase
	stdinIsTerminal = func() bool { return true }
	askPassphrase = func(prompt string) ([]byte, error) {
		asked++
		prompts = append(prompts, prompt)
		return []byte(agentPassphrase), nil
	}
	t.Cleanup(func() { stdinIsTerminal, askPassphrase = wasTerminal, wasAsk })
	if err := enrol(); err != nil {
		t.Fatalf("enrol at a terminal with the agent locked: %v", err)
	}
	if asked != 1 {
		t.Fatalf("the person was asked %d times, want once", asked)
	}
	// Enrol asks into send, so its prompt does not warn of a second asking.
	if want := "Passphrase for " + alice.home + ": "; prompts[0] != want {
		t.Fatalf("enrol's prompt is %q, want %q", prompts[0], want)
	}
	if st := alice.agentStatus(); st.Scope != string(agent.ScopeSend) || st.SendExpires == "" {
		t.Fatalf("after enrol at a terminal the agent says %+v, want send scope with an expiry", st)
	}
	// And from receive scope, the same: asked again, into send.
	alice.run("lock", "--send")
	if err := enrol(); err != nil {
		t.Fatalf("enrol at a terminal in receive scope: %v", err)
	}
	if asked != 2 {
		t.Fatalf("the person was asked %d times in all, want twice", asked)
	}
	if st := alice.agentStatus(); st.Scope != string(agent.ScopeSend) {
		t.Fatalf("after the second enrol the agent says %+v", st)
	}
	// Every other command asks a person into receive: a send at a terminal
	// with the agent locked is asked once, unlocked to receive, and then
	// refused by the agent with the receive sentence.
	alice.run("lock")
	_, err = alice.tryRun("send", "--to", "self", "hello")
	if !asExit(err, &e) || e.code != exitLocked || e.Error() != agent.ReceiveOnlyMessage {
		t.Fatalf("send at a terminal with the agent locked gave %v, want the receive sentence after the prompt", err)
	}
	if asked != 3 {
		t.Fatalf("the person was asked %d times in all, want three", asked)
	}
	if st := alice.agentStatus(); st.Locked || st.Scope != string(agent.ScopeReceive) {
		t.Fatalf("after send at a terminal the agent says %+v, want receive scope", st)
	}
	// The double asking is by design, and the receive prompt says so, so
	// the second asking — the sentence naming unlock --send — is no
	// surprise.
	if want := "Passphrase for " + alice.home + " (to receive; a command that sends will ask again): "; prompts[2] != want {
		t.Fatalf("the receive prompt is %q, want %q", prompts[2], want)
	}
	stdinIsTerminal = wasTerminal
	// register --token, for a second machine key, is not enrol: it loads
	// the identity as every command does and meets the agent's refusal,
	// with the same sentence.
	alice.run("lock", "--send")
	_, err = alice.withStdin("", "register", "--token", issue(token.UseCert, alice.exportFingerprint()), "--label", "again")
	if !asExit(err, &e) || e.code != exitLocked || e.Error() != agent.ReceiveOnlyMessage {
		t.Fatalf("register from a pipe in receive scope gave %v, want exit %d and the receive sentence", err, exitLocked)
	}
}

// TestServeNeedsSendScope: serve on a home under a passphrase refuses to
// start with the agent unlocked to receive, in its own words naming the
// unlock that lasts until lock; starts under send scope, warning when that
// scope will end; and when it ends under a running service, stops the same
// way rather than failing reply after reply, leaving the message for the
// next serve.
func TestServeNeedsSendScope(t *testing.T) {
	alice, bob := newExpertCold(t, modeReadOnly)
	// agentEnv makes this test binary answer as auu wherever it runs with
	// helperEnv set, and the handler is this test binary too; TestMain
	// tells a handler run by its arguments, so the exec line is the one
	// every serve test uses.
	agentEnv(t)
	bob.encrypt()
	const needsSend = "the agent is unlocked to receive, and serve originates every reply: run 'auu unlock --send --ttl 0' at a terminal, which lasts until 'auu lock'"

	// Receive scope: refused before anything, exit 4, serve's sentence.
	_, err := bob.tryRun("serve", "--once")
	var e *exitError
	if !asExit(err, &e) || e.code != exitLocked || e.Error() != needsSend {
		t.Fatalf("serve in receive scope gave %v, want exit %d and %q", err, exitLocked, needsSend)
	}
	// Locked: the locked sentence, as before. And never a prompt, even at
	// a terminal: a person there is told the unlock to make.
	asked := 0
	wasTerminal, wasAsk := stdinIsTerminal, askPassphrase
	stdinIsTerminal = func() bool { return true }
	askPassphrase = func(prompt string) ([]byte, error) { asked++; return []byte(agentPassphrase), nil }
	t.Cleanup(func() { stdinIsTerminal, askPassphrase = wasTerminal, wasAsk })
	_, err = bob.tryRun("serve", "--once")
	if !asExit(err, &e) || e.code != exitLocked || e.Error() != needsSend {
		t.Fatalf("serve in receive scope at a terminal gave %v, want %q", err, needsSend)
	}
	bob.run("lock")
	_, err = bob.tryRun("serve", "--once")
	if !asExit(err, &e) || e.code != exitLocked || !strings.Contains(e.Error(), "your identity is locked") {
		t.Fatalf("serve with the agent locked gave %v, want the locked sentence", err)
	}
	if asked != 0 {
		t.Fatalf("serve prompted %d times; it never prompts", asked)
	}
	stdinIsTerminal = wasTerminal

	// Send scope with an expiry: starts, and warns naming the time.
	bob.unlockSend()
	stderr := captureStderr(t, func() { bob.serve(t) })
	if !strings.Contains(stderr, "the agent's send scope ends at ") || !strings.Contains(stderr, "serve will stop then; 'auu unlock --send --ttl 0' lasts until 'auu lock'") {
		t.Fatalf("serve under a send scope that ends did not warn:\n%s", stderr)
	}
	// Send scope until lock: starts, and no warning.
	bob.run("unlock", "--send", "--ttl", "0", "--passphrase-file", passphraseFile(t, agentPassphrase))
	stderr = captureStderr(t, func() { bob.serve(t) })
	if strings.Contains(stderr, "send scope ends") {
		t.Fatalf("serve under a send scope until lock warned:\n%s", stderr)
	}
	// Narrowed again: refused again.
	bob.run("lock", "--send")
	_, err = bob.tryRun("serve", "--once")
	if !asExit(err, &e) || e.code != exitLocked || e.Error() != needsSend {
		t.Fatalf("serve after lock --send gave %v, want %q", err, needsSend)
	}

	// Send scope that ends under a running service: serve starts inside
	// it, the handler takes longer than it lasts, the reply is refused,
	// and serve stops with its sentence. Nothing is recorded against the
	// message, the reply is on disk, and the next serve, under a proper
	// unlock, sends it without running the handler again.
	marker := filepath.Join(t.TempDir(), "runs")
	t.Setenv(handlerScript, "append:"+marker+";sleep:2s;echo:the expert has spoken")
	sent := alice.ask(t, "jostle", "a question", "asked while sendable")
	bob.run("unlock", "--send", "--ttl", "1s", "--passphrase-file", passphraseFile(t, agentPassphrase))
	stderr = captureStderr(t, func() { _, err = bob.tryRun("serve", "--once") })
	if !asExit(err, &e) || e.code != exitLocked || e.Error() != needsSend {
		t.Fatalf("serve whose send scope ended under it gave %v, want exit %d and %q; stderr:\n%s", err, exitLocked, needsSend, stderr)
	}
	if runs := strings.Count(readFile(t, marker), "\n"); runs != 1 {
		t.Fatalf("the handler ran %d times, want once", runs)
	}
	if entry := bob.ledgerOf(t).Messages[sent.ID]; entry != nil && (!entry.Handled.IsZero() || entry.Failures != 0) {
		t.Fatalf("the message was recorded against: %+v", entry)
	}
	if st := bob.agentStatus(); st.Locked || st.Scope != string(agent.ScopeReceive) {
		t.Fatalf("after the send scope ended the agent says %+v, want unlocked to receive", st)
	}
	bob.run("unlock", "--send", "--ttl", "0", "--passphrase-file", passphraseFile(t, agentPassphrase))
	report := bob.round(t)
	if len(report.Answered) != 1 || report.Answered[0].ID != sent.ID {
		t.Fatalf("the round after the unlock: %+v", report)
	}
	if runs := strings.Count(readFile(t, marker), "\n"); runs != 1 {
		t.Fatalf("the handler ran %d times in all, want once: the reply was on disk", runs)
	}
	if reply := alice.replyOn(t, sent.Thread); reply.Text != "the expert has spoken" {
		t.Fatalf("the reply is %q", reply.Text)
	}
}

// TestTheTestBinaryKnowsAHandlerRunFromAnAuuRun: with helperEnv set, the
// binary is auu for the arguments 'auu agent start' hands it and a test
// runner for the arguments helperLine hands it, on any platform, since the
// decision reads the arguments and not the shell.
func TestTheTestBinaryKnowsAHandlerRunFromAnAuuRun(t *testing.T) {
	exe := "auu.test"
	for name, tc := range map[string]struct {
		args []string
		want bool
	}{
		"the agent, detached":             {[]string{exe, "agent", "run", "--home", "/h"}, false},
		"a command in another process":    {[]string{exe, "send", "--to", "self", "hello"}, false},
		"a handler":                       {[]string{exe, "-test.run=TestServeHelperProcess", "handler"}, true},
		"a before hook":                   {[]string{exe, "-test.run=TestServeHelperProcess", "before"}, true},
		"the whole line, as sh splits it": {strings.Fields(helperLine(t, "handler")), true},
		"nothing":                         {[]string{exe}, false},
		"the flag anywhere but first":     {[]string{exe, "send", "--to", "self", "-test.run=TestServeHelperProcess"}, false},
	} {
		if got := isHandlerRun(tc.args); got != tc.want {
			t.Errorf("%s: isHandlerRun(%q) = %v, want %v", name, tc.args, got, tc.want)
		}
	}
}

// TestRenewalIsReceiveScope: a home in receive scope — the default after
// 'passphrase set' — renews its machine certificate, by hand with
// 'auu cert renew' and on its own at sixty days before expiry, because
// renewal is maintenance of this machine's transport credential and lets
// nothing act as the person. Enrolment still asks for send.
func TestRenewalIsReceiveScope(t *testing.T) {
	_, issue := certRelay(t)
	agentEnv(t)
	alice := &user{t: t, home: t.TempDir()}
	alice.run("enrol", "--name", "alice", "--yes", issue(token.UseRegister, ""))
	alice.encrypt()
	if st := alice.agentStatus(); st.Scope != string(agent.ScopeReceive) {
		t.Fatalf("after passphrase set the agent says %+v, want receive", st)
	}
	before := alice.certRecord()

	// By hand, in receive scope: a new serial, the key wrapped, the
	// handshake with it completing.
	if out := alice.run("cert", "renew"); !strings.HasPrefix(out, "renewed: ") {
		t.Fatalf("cert renew said %q", out)
	}
	renewed := alice.certRecord()
	if renewed.Serial == before.Serial || !renewed.Encrypted() {
		t.Fatalf("cert renew in receive scope: serial %s → %s, encrypted %v", before.Serial[:8], renewed.Serial[:8], renewed.Encrypted())
	}
	if !strings.Contains(alice.run("cert", "ls"), "* is this machine") {
		t.Fatal("a handshake with the renewed key did not complete")
	}

	// On its own, at sixty days: a command that reads renews first, still
	// in receive scope, and then reads.
	setExpiry(t, alice, time.Now().Add(store.RenewBefore-time.Second))
	alice.run("inbox")
	auto := alice.certRecord()
	if auto.Serial == renewed.Serial {
		t.Fatal("the automatic renewal inside the window did not happen in receive scope")
	}
	if st := alice.agentStatus(); st.Scope != string(agent.ScopeReceive) {
		t.Fatalf("after two renewals the agent says %+v; renewal must not have needed send scope", st)
	}

	// Enrolment is not renewal: from a pipe in receive scope it is the
	// receive sentence, at the request that makes it enrolment.
	_, err := alice.withStdin("", "register", "--token", issue(token.UseCert, alice.exportFingerprint()), "--label", "again")
	var e *exitError
	if !asExit(err, &e) || e.code != exitLocked || e.Error() != agent.ReceiveOnlyMessage {
		t.Fatalf("register from a pipe in receive scope gave %v, want exit %d and the receive sentence", err, exitLocked)
	}
	if alice.certRecord().Serial != auto.Serial {
		t.Fatal("a refused register changed the certificate")
	}
}
