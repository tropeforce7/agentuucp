//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

// A channel answered by a program: 'auu serve' on bob's machine, with a
// shell script for the handler that a Claude Code wrapper would otherwise
// be. Every row sets its own expert up and takes it down again, so the
// relay and both spools are as they were found.
var serveRows = []matrixRow{
	{"S01", "answered", "an ask on a served channel is answered by the program", s01},
	{"S02", "follow_up", "a follow-up is the thread's second turn, in the same worktree", s02},
	{"S03", "side_copy", "a side copy's reply carries a patch the asker can apply", s03},
	{"S04", "two_threads", "two threads, two worktrees in a side copy and one in read-only", s04},
	{"S05", "stranger", "a stranger's ask sits in quarantine and is never answered", s05},
	{"S06", "handler_fails", "a handler that fails leaves the message unread and counted", s06},
	{"S07", "caught_up", "mail that arrived while serve was down is answered by the next round", s07},
	{"S08", "long_running", "the service answers while it waits and stops on a signal", s08},
	{"S09", "hooks", "before and after run around the handler, and a red after sends nothing", s09},
	{"S10", "key_proxy", "the key-holding proxy: the handler is given a token and never the key", s10},
}

const (
	bobProject  = "/home/bob/project"
	bobBin      = "/home/bob/bin"
	bobHandler  = "/home/bob/bin/handler.sh"
	bobServe    = "/home/bob/.auu/serve.json"
	bobServeDir = "/home/bob/.auu/serve"
	serveLog    = "/tmp/serve.log"
)

// servedChannel gives bob a project, a handler and a serve.json for one
// channel, runs one empty round so that the ledger exists — a first start
// leaves the mail it finds, which is not what these rows are about — and
// returns what takes the whole of it away again.
//
// rows is the rest of the channel's row in serve.json, as JSON text.
func servedChannel(t *testing.T, mode, script string, rows ...string) func() {
	t.Helper()
	return servedChannelWith(t, mode, script, "", rows...)
}

// servedChannelWith is servedChannel with more of the file: top is JSON
// text for the top level beside channels, such as a proxy section.
func servedChannelWith(t *testing.T, mode, script, top string, rows ...string) func() {
	t.Helper()
	bob.mustRoot(t, "install -d -o bob -g bob "+bobBin)
	writeAsBob(t, bobHandler, script)
	bob.mustRoot(t, "chmod 0755 "+bobHandler+" && chown bob:bob "+bobHandler)

	// The project the expert speaks for: a repository with one commit, as
	// small as a repository can be.
	bob.mustRoot(t, "install -d -o bob -g bob "+bobProject)
	r := bob.exec("", "sh", "-c", "cd "+bobProject+
		" && git init -q -b main && printf 'the project\\n' > README"+
		" && git add README && git -c user.email=bob@example.invalid -c user.name=bob commit -q -m 'the first commit'")
	if r.code != 0 {
		t.Fatalf("making the project: %s%s", r.stdout, r.stderr)
	}

	undoChannel := bobChannel(t, "jostle", "--description", "Jostle: answered by a program")
	expectSays(t, bob.auu("channel", "keep", "jostle", "off"), 0,
		"jostle: mail is removed from the relay once it is fetched")

	extra := ""
	if len(rows) > 0 {
		extra = "," + strings.Join(rows, ",")
	}
	if top != "" {
		top = "," + top
	}
	writeAsBob(t, bobServe, `{"v":1,"channels":{"jostle":{"dir":"`+bobProject+
		`","exec":"`+bobHandler+`","mode":"`+mode+`"`+extra+`}}`+top+`}`+"\n")
	expectSays(t, bob.auu("serve", "check"), 0, "jostle: "+mode+" in "+bobProject)
	// The ledger, so that what a row sends next is new mail rather than a
	// backlog a first start leaves alone. Whatever the cycle left in bob's
	// inbox is that backlog, and it is left where it is.
	expectCode(t, bob.auu("serve", "--once"), 0)

	return func() { drainServe(t, undoChannel) }
}

// writeAsBob puts a file in bob's home as bob, which is how a person on
// that machine would write it.
func writeAsBob(t *testing.T, path, content string) {
	t.Helper()
	r := bob.exec(content, "sh", "-c", "cat > "+shq(path))
	if r.code != 0 {
		t.Fatalf("writing %s: %s%s", path, r.stdout, r.stderr)
	}
}

// drainServe is drain for a row that served. As well as the mail on both
// machines it takes away what serving leaves behind: any service still
// running, the worktrees registered in bob's checkout, serve's state and
// its file, and the project itself.
func drainServe(t *testing.T, undoChannel func()) {
	t.Helper()
	bob.root("pkill -u bob -TERM auu; true")
	drain(bob)
	drain(alice)
	// Quarantine is not drained by inbox; a row that put something there
	// removes it itself.
	bob.root("rm -rf " + bobServeDir + " " + bobServe)
	bob.root("cd " + bobProject + " && git worktree prune; true")
	bob.root("rm -rf " + bobProject + " " + bobBin + " " + serveLog)
	undoChannel()
}

// readMessage is one message read in full, which is where its text and its
// attachments are.
type readMessage struct {
	ID          string `json:"id"`
	Thread      string `json:"thread"`
	InReplyTo   string `json:"in_reply_to"`
	Type        string `json:"type"`
	Subject     string `json:"subject"`
	Text        string `json:"text"`
	Attachments []struct {
		Name string `json:"name"`
		Size int64  `json:"size"`
	} `json:"attachments"`
}

// servedJSON is what 'auu serve ls --json' gives.
type servedJSON struct {
	Channels []struct {
		Name     string `json:"name"`
		Dir      string `json:"dir"`
		Mode     string `json:"mode"`
		Worktree string `json:"worktree"`
		Threads  []struct {
			Thread   string `json:"thread"`
			Turns    int    `json:"turns"`
			Worktree string `json:"worktree"`
		} `json:"threads"`
	} `json:"channels"`
}

// ask sends one message from alice to bob's served channel.
func ask(t *testing.T, subject, text string, args ...string) sent {
	t.Helper()
	return sendJSON(t, alice, "bob", append([]string{"--channel", "jostle", "--subject", subject}, append(args, text)...)...)
}

// replyOnThread is the reply alice has received on a thread, read in full,
// waiting for it to arrive if it is not there yet.
func replyOnThread(t *testing.T, thread string, not string, within time.Duration) readMessage {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		in := fetchJSON(t, alice)
		for _, m := range in.Messages {
			if m.Thread == thread && m.Type == "reply" && m.ID != not {
				var full readMessage
				jsonOf(t, alice.auu("read", m.ID, "--json"), &full)
				return full
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no reply on thread %s in %s", thread[:12], within)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// answering is a handler that prints one line and says what it was given.
const answering = `#!/bin/sh
printf 'the expert has read it\n'
printf 'turn=%s mode=%s worktree=%s\n' "$AUU_TURN" "$AUU_MODE" "$AUU_WORKTREE"
`

func s01(t *testing.T) {
	defer servedChannel(t, "read-only", answering)()
	sent := ask(t, "where is the parser?", "I cannot find it.")

	expectSays(t, bob.auu("serve", "--once"), 0, "jostle: answered "+sent.ID[:12])
	reply := replyOnThread(t, sent.Thread, "", 5*time.Second)
	if reply.InReplyTo != sent.ID || reply.Subject != "where is the parser?" {
		t.Errorf("the reply: %+v", reply)
	}
	if !strings.HasPrefix(reply.Text, "the expert has read it") {
		t.Errorf("the reply says:\n%s", reply.Text)
	}
	if !strings.Contains(reply.Text, "turn=1 mode=read-only") {
		t.Errorf("the handler was told:\n%s", reply.Text)
	}
	// The ask is read here, since the reply is the acknowledgement.
	in := fetchJSON(t, bob, "--no-fetch")
	for _, m := range in.Messages {
		if m.ID == sent.ID && !m.Read {
			t.Error("the ask is still unread after it was answered")
		}
	}
	verdict(t, "ok", "")
}

func s02(t *testing.T) {
	defer servedChannel(t, "read-only", answering)()
	sent := ask(t, "a question", "the first")
	expectCode(t, bob.auu("serve", "--once"), 0)
	first := replyOnThread(t, sent.Thread, "", 5*time.Second)

	// A reply carries no channel of its own — it goes to bob's default —
	// and the thread is what says which channel answers it.
	expectCode(t, alice.auu("reply", first.ID[:12], "and one more thing"), 0)
	expectCode(t, bob.auu("serve", "--once"), 0)
	second := replyOnThread(t, sent.Thread, first.ID, 5*time.Second)

	if !strings.Contains(second.Text, "turn=2 ") {
		t.Errorf("the follow-up is not the second turn:\n%s", second.Text)
	}
	firstTree := field(t, first.Text, "worktree=")
	if tree := field(t, second.Text, "worktree="); tree != firstTree {
		t.Errorf("the follow-up ran in %s, the ask in %s", tree, firstTree)
	}
	verdict(t, "ok", "")
}

// changing is a handler that makes a change and answers.
const changing = `#!/bin/sh
printf 'a line the expert added\n' >> README
printf 'new.txt: added by the expert\n' > new.txt
printf 'I have made the change.\n'
`

func s03(t *testing.T) {
	defer servedChannel(t, "side-copy", changing)()
	sent := ask(t, "please add a line", "Add a line to the README.")
	expectCode(t, bob.auu("serve", "--once"), 0)
	reply := replyOnThread(t, sent.Thread, "", 5*time.Second)

	if len(reply.Attachments) != 1 || !strings.HasSuffix(reply.Attachments[0].Name, ".patch") {
		t.Fatalf("the reply carries %+v", reply.Attachments)
	}
	if !strings.Contains(reply.Text, "apply with git apply") {
		t.Errorf("the reply does not say what the attachment is:\n%s", reply.Text)
	}
	// Alice applies it to a copy of the project as she has it.
	expectCode(t, alice.auu("extract", reply.ID, "--out", "/home/alice/patch"), 0)
	r := alice.exec("", "sh", "-c", "rm -rf /home/alice/work && mkdir -p /home/alice/work && cd /home/alice/work"+
		" && git init -q -b main && printf 'the project\\n' > README"+
		" && git apply --check /home/alice/patch/"+reply.Attachments[0].Name+
		" && git apply /home/alice/patch/"+reply.Attachments[0].Name+
		" && cat README new.txt")
	if r.code != 0 {
		t.Fatalf("the patch does not apply: exit %d\n%s%s", r.code, r.stdout, r.stderr)
	}
	if !strings.Contains(r.stdout, "a line the expert added") || !strings.Contains(r.stdout, "added by the expert") {
		t.Errorf("what applied:\n%s", r.stdout)
	}
	alice.root("rm -rf /home/alice/work /home/alice/patch")
	verdict(t, "ok", "")
}

func s04(t *testing.T) {
	undo := servedChannel(t, "side-copy", answering)
	one := ask(t, "one", "the first thread")
	two := ask(t, "two", "the second thread")
	expectCode(t, bob.auu("serve", "--once"), 0)
	firstTree := field(t, replyOnThread(t, one.Thread, "", 5*time.Second).Text, "worktree=")
	secondTree := field(t, replyOnThread(t, two.Thread, "", 5*time.Second).Text, "worktree=")
	if firstTree == secondTree || firstTree == "" {
		t.Errorf("two threads of a side copy shared the worktree %q", firstTree)
	}
	var ls servedJSON
	jsonOf(t, bob.auu("serve", "ls", "--json"), &ls)
	if len(ls.Channels) != 1 || len(ls.Channels[0].Threads) != 2 {
		t.Errorf("serve ls: %+v", ls.Channels)
	}
	undo()

	// The same two asks on a read-only channel share one worktree, and a
	// commit made between them is in it.
	defer servedChannel(t, "read-only", answering)()
	three := ask(t, "three", "the first thread")
	expectCode(t, bob.auu("serve", "--once"), 0)
	thirdTree := field(t, replyOnThread(t, three.Thread, "", 5*time.Second).Text, "worktree=")

	r := bob.exec("", "sh", "-c", "cd "+bobProject+" && printf 'the news\\n' > NEWS && git add NEWS"+
		" && git -c user.email=bob@example.invalid -c user.name=bob commit -q -m 'a second commit'")
	if r.code != 0 {
		t.Fatalf("committing: %s%s", r.stdout, r.stderr)
	}
	four := ask(t, "four", "the second thread")
	expectCode(t, bob.auu("serve", "--once"), 0)
	fourthTree := field(t, replyOnThread(t, four.Thread, "", 5*time.Second).Text, "worktree=")
	if fourthTree != thirdTree {
		t.Errorf("a read-only channel made a second worktree: %q then %q", thirdTree, fourthTree)
	}
	if !bob.exists(fourthTree + "/NEWS") {
		t.Errorf("the worktree did not follow the checkout: no NEWS in %s", fourthTree)
	}
	verdict(t, "ok", "")
}

func s05(t *testing.T) {
	defer servedChannel(t, "read-only", answering)()
	// Bob's allow list is what keeps a stranger off the relay altogether,
	// so it comes off for the row that is about quarantine.
	expectSays(t, bob.auu("allow", "clear"), 0, "allow list cleared")
	defer bob.auu("allow", "push")

	carol := enrolCarol(t)
	expectCode(t, carol.auu("peers", "add", state.bobLine), 0)
	var s sent
	jsonOf(t, carol.auu("send", "--to", "bob", "--channel", "jostle",
		"--subject", "a stranger asks", "--json", "will it answer me?"), &s)

	expectSays(t, bob.auu("serve", "--once"), 0, "nothing to answer")
	q := bob.auu("quarantine", "ls")
	expectSays(t, q, 0, "a stranger asks")
	in := fetchJSON(t, bob, "--no-fetch")
	for _, m := range in.Messages {
		if m.ID == s.ID {
			t.Error("a stranger's ask reached the inbox")
		}
	}
	if r := carol.auu("inbox", "--json"); strings.Contains(r.stdout, `"type":"reply"`) {
		t.Errorf("the stranger was answered:\n%s", r.stdout)
	}
	expectCode(t, bob.auu("rm", s.ID), 0)
	verdict(t, "ok", "")
}

// failing is a handler that cannot do its job.
const failing = `#!/bin/sh
echo "the tests will not run here" >&2
exit 3
`

func s06(t *testing.T) {
	defer servedChannel(t, "read-only", failing)()
	sent := ask(t, "a question", "the first")

	r := bob.auu("serve", "--once")
	expectSays(t, r, 1, "was not answered: exited 3: the tests will not run here", "attempt 1 of 3")
	in := fetchJSON(t, bob, "--no-fetch")
	found := false
	for _, m := range in.Messages {
		if m.ID == sent.ID {
			found = true
			if m.Read {
				t.Error("a message nobody answered was marked read")
			}
		}
	}
	if !found {
		t.Error("the ask is not in the inbox")
	}
	var led struct {
		Messages map[string]struct {
			Failures int  `json:"failures"`
			GaveUp   bool `json:"gave_up"`
		} `json:"messages"`
	}
	if err := json.Unmarshal([]byte(bob.read(t, bobServeDir+"/ledger.json")), &led); err != nil {
		t.Fatalf("the ledger: %v", err)
	}
	if e := led.Messages[sent.ID]; e.Failures != 1 || e.GaveUp {
		t.Errorf("the ledger says %+v", e)
	}
	// Three attempts in all, then it is given up on and left for its owner.
	expectCode(t, bob.auu("serve", "--once"), 1)
	expectSays(t, bob.auu("serve", "--once"), 1, "given up after 3 attempts")
	expectSays(t, bob.auu("serve", "--once"), 0, "nothing to answer")
	verdict(t, "ok", "")
}

func s07(t *testing.T) {
	defer servedChannel(t, "read-only", answering)()
	// Nothing is running: the ask waits on the relay and in the inbox.
	sent := ask(t, "while it was down", "answer this when you wake up")
	expectSays(t, bob.auu("serve", "--once"), 0, "jostle: answered "+sent.ID[:12])
	reply := replyOnThread(t, sent.Thread, "", 5*time.Second)
	if reply.InReplyTo != sent.ID {
		t.Errorf("the reply: %+v", reply)
	}
	verdict(t, "ok", "")
}

func s08(t *testing.T) {
	defer servedChannel(t, "read-only", answering)()
	// The service, as a unit file would start it: detached, its output on
	// a file, running as bob.
	bob.mustRoot(t, "runuser -u bob -- env HOME=/home/bob AUU_HOME=/home/bob/.auu "+
		"XDG_RUNTIME_DIR=/run/user/1002 sh -c 'nohup auu serve >"+serveLog+" 2>&1 &'")

	sent := ask(t, "while it waits", "you are holding the line; answer this")
	reply := replyOnThread(t, sent.Thread, "", 60*time.Second)
	if reply.InReplyTo != sent.ID {
		t.Errorf("the reply: %+v", reply)
	}

	// Stopped the way a service manager stops it.
	bob.mustRoot(t, "pkill -u bob -TERM -f 'auu serve'")
	deadline := time.Now().Add(20 * time.Second)
	for bob.root("pgrep -u bob -f 'auu serve' >/dev/null").code == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the service did not stop when it was told")
		}
		time.Sleep(200 * time.Millisecond)
	}
	if log := bob.read(t, serveLog); strings.Contains(log, "panic") {
		t.Errorf("the service's log:\n%s", log)
	}
	// The lock went with the process, so another serve can take it.
	expectSays(t, bob.auu("serve", "--once"), 0, "nothing to answer")
	verdict(t, "ok", "")
}

func s09(t *testing.T) {
	const before = `#!/bin/sh
printf 'the before hook was here\n' > /home/bob/hook-marker
echo "before ran" >&2
`
	const after = `#!/bin/sh
echo "after saw AUU_STATUS=$AUU_STATUS" >&2
`
	const readsMarker = `#!/bin/sh
printf 'the handler read: %s' "$(cat /home/bob/hook-marker)"
`
	defer servedChannel(t, "read-only", readsMarker,
		`"before":"/home/bob/bin/before.sh"`, `"after":"/home/bob/bin/after.sh"`)()
	writeAsBob(t, "/home/bob/bin/before.sh", before)
	writeAsBob(t, "/home/bob/bin/after.sh", after)
	bob.mustRoot(t, "chmod 0755 /home/bob/bin/before.sh /home/bob/bin/after.sh")
	defer bob.root("rm -f /home/bob/hook-marker")

	sent := ask(t, "the hooks", "do they run?")
	r := bob.auu("serve", "--once")
	expectSays(t, r, 0, "before ran", "after saw AUU_STATUS=0")
	reply := replyOnThread(t, sent.Thread, "", 5*time.Second)
	if !strings.Contains(reply.Text, "the handler read: the before hook was here") {
		t.Errorf("the handler did not see what before wrote:\n%s", reply.Text)
	}

	// An after hook that refuses is a gate: the answer does not go out and
	// the message is tried again.
	writeAsBob(t, "/home/bob/bin/after.sh", "#!/bin/sh\necho \"the check failed\" >&2\nexit 1\n")
	bob.mustRoot(t, "chmod 0755 /home/bob/bin/after.sh")
	second := ask(t, "the gate", "does a red after stop it?")
	expectSays(t, bob.auu("serve", "--once"), 1,
		"was not answered: after exited 1: the check failed")
	in := fetchJSON(t, bob, "--no-fetch")
	for _, m := range in.Messages {
		if m.ID == second.ID && m.Read {
			t.Error("a message whose answer was refused was marked read")
		}
	}
	for _, m := range fetchJSON(t, alice).Messages {
		if m.Thread == second.Thread && m.Type == "reply" {
			t.Error("an answer went out past a red after hook")
		}
	}
	verdict(t, "ok", "")
}

// field reads "name=value" out of a line of a handler's output.
func field(t *testing.T, text, name string) string {
	t.Helper()
	for _, line := range strings.Fields(text) {
		if v, ok := strings.CutPrefix(line, name); ok {
			return v
		}
	}
	t.Errorf("no %s in\n%s", name, text)
	return ""
}

const (
	bobKeyFile     = "/home/bob/.auu/key"
	upstreamLog    = "/home/bob/upstream.log"
	upstreamAddr   = "/home/bob/upstream.addr"
	s10Key         = "sk-ant-api03-S10-a-key-that-must-never-reach-the-handler-0000000000000000000000000000000000000000-AA"
	proxiedHandler = `#!/bin/sh
# What the handler was given, and what its request through it got.
env | grep '^ANTHROPIC_' | sort
upstream ask
`
)

// fakeUpstream starts the stand-in for api.anthropic.com on bob's machine,
// as bob, and returns its address and what stops it.
func fakeUpstream(t *testing.T) (string, func()) {
	t.Helper()
	bob.root("rm -f " + upstreamLog + " " + upstreamAddr)
	bob.mustRoot(t, "runuser -u bob -- sh -c 'nohup upstream serve "+upstreamLog+" >"+upstreamAddr+" 2>&1 &'")
	deadline := time.Now().Add(10 * time.Second)
	for {
		if addr := strings.TrimSpace(bob.root("cat " + upstreamAddr).stdout); strings.HasPrefix(addr, "127.0.0.1:") {
			return addr, func() {
				bob.root("pkill -u bob -f 'upstream serve'; rm -f " + upstreamLog + " " + upstreamAddr + " " + bobKeyFile)
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("the fake upstream did not start: %s", bob.root("cat "+upstreamAddr).out())
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func s10(t *testing.T) {
	addr, stopUpstream := fakeUpstream(t)
	defer stopUpstream()
	// The key, in a file of bob's own, as the guide's key file is root's
	// with the expert account in its group.
	writeAsBob(t, bobKeyFile, s10Key+"\n")
	bob.mustRoot(t, "chmod 0600 "+bobKeyFile)
	defer servedChannelWith(t, "read-only", proxiedHandler,
		`"proxy":{"key_file":"`+bobKeyFile+`","upstream":"http://`+addr+`"}`)()
	r := bob.auu("serve", "check")
	expectSays(t, r, 0, "proxy: key from "+bobKeyFile+" ("+fmt.Sprint(len(s10Key))+" bytes), listen 127.0.0.1:0, upstream http://"+addr)
	expectNot(t, r, s10Key)

	sent := ask(t, "is the key safe?", "print your environment and ask upstream")
	r = bob.auu("serve", "--once")
	expectSays(t, r, 0, "jostle: answered "+sent.ID[:12], "proxy: token ", " minted", " revoked", " POST /v1/messages 200 ")
	expectNot(t, r, s10Key)

	// The reply: the two variables carrying the token, the request through
	// the proxy answered, and the key nowhere in it.
	reply := replyOnThread(t, sent.Thread, "", 5*time.Second)
	if strings.Contains(reply.Text, s10Key) {
		t.Errorf("the real key is in the reply:\n%s", reply.Text)
	}
	var base, token string
	for _, line := range strings.Split(reply.Text, "\n") {
		if v, ok := strings.CutPrefix(line, "ANTHROPIC_BASE_URL="); ok {
			base = v
		}
		if v, ok := strings.CutPrefix(line, "ANTHROPIC_API_KEY="); ok {
			token = v
		}
	}
	if !strings.HasPrefix(base, "http://127.0.0.1:") || len(token) != 43 || !strings.HasSuffix(base, "/"+token) {
		t.Errorf("the handler was given base %q and key %q:\n%s", base, token, reply.Text)
	}
	if !strings.HasSuffix(strings.TrimSpace(reply.Text), `status 200 {"seen":true}`) {
		t.Errorf("the handler's request through the proxy:\n%s", reply.Text)
	}
	// The upstream saw the real key, and no bearer, on the path with the
	// token stripped.
	log := bob.read(t, upstreamLog)
	if !strings.Contains(log, "POST /v1/messages key=sk-ant… len="+fmt.Sprint(len(s10Key))+" authorization=absent\n") {
		t.Errorf("the upstream's log:\n%s", log)
	}
	verdict(t, "ok", "The handler holds a URL that is worthless off the host and dead after the invocation; "+
		"the key it never saw reached the upstream from serve alone.")
}
