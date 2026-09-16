//go:build e2e

package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// The stack is brought up by run.sh; the tests find it by its compose
// project name and speak to each machine with docker exec, which is the
// container form of ssh. Nothing is published to the host.
const (
	composeFile = "compose.yaml"
	project     = "auu-e2e"
	relayURL    = "https://relay.example.com:9443"
	relayName   = "relay.example.com"
	outDir      = "out"
)

var (
	// nofault makes every fault helper a no-op, to see which rows still
	// pass without the thing they are about. See TESTING.md.
	nofault = os.Getenv("AUU_E2E_NOFAULT") == "1"
	// slow adds the rows that need real time to pass.
	slow = os.Getenv("AUU_E2E_SLOW") == "1"
)

// machine is one of the four containers, spoken to as one user of it.
type machine struct {
	service string
	user    string
	uid     int
	home    string // AUU_HOME
	caHome  string // AUU_CA_HOME, the operator only
	dir     string // HOME, when it is not /home/<user>
	id      string // container id, resolved once
}

var (
	relay    = &machine{service: "relay", user: "root"}
	relayAuu = &machine{service: "relay", user: "auu", dir: "/var/lib/auu"}
	operator = &machine{service: "operator", user: "you", uid: 1000, home: "/home/you/.auu", caHome: "/home/you/.auu-ca"}
	alice    = &machine{service: "alice", user: "alice", uid: 1001, home: "/home/alice/.auu"}
	bob      = &machine{service: "bob", user: "bob", uid: 1002, home: "/home/bob/.auu"}
	machines = []*machine{relay, operator, alice, bob}

	// workDir holds what the tests keep across steps: bundles as issued,
	// so a rotation can be rolled back.
	workDir string
)

// at is the same machine and user with another auu home: the second
// machine a person copies their identity to, played by another directory.
func (m *machine) at(home string) *machine {
	c := *m
	c.home = home
	return &c
}

func (m *machine) String() string { return m.user + "@" + m.service }

// result is what a command produced.
type result struct {
	stdout, stderr string
	code           int
}

func (r result) out() string { return r.stdout + r.stderr }

func TestMain(m *testing.M) {
	for _, mc := range machines {
		out, err := exec.Command("docker", "compose", "-f", composeFile, "ps", "-q", mc.service).Output()
		id := strings.TrimSpace(string(out))
		if err != nil || id == "" {
			fmt.Fprintf(os.Stderr, "the %s container is not up: run make e2e, or docker compose up -d in %s\n",
				mc.service, mustCwd())
			os.Exit(2)
		}
		mc.id = id
	}
	relayAuu.id = relay.id
	var err error
	if workDir, err = os.MkdirTemp("", "auu-e2e"); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	code := m.Run()
	os.RemoveAll(workDir)
	if err := writeReport(); err != nil {
		fmt.Fprintln(os.Stderr, "writing the report:", err)
		if code == 0 {
			code = 1
		}
	}
	os.Exit(code)
}

func mustCwd() string {
	d, _ := os.Getwd()
	return d
}

// compose runs a docker compose subcommand for the stack.
func compose(args ...string) result {
	return runHost(nil, "docker", append([]string{"compose", "-f", composeFile}, args...)...)
}

func runHost(stdin io.Reader, name string, args ...string) result {
	cmd := exec.Command(name, args...)
	cmd.Stdin = stdin
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	err := cmd.Run()
	r := result{stdout: so.String(), stderr: se.String()}
	if ee, ok := err.(*exec.ExitError); ok {
		r.code = ee.ExitCode()
	} else if err != nil {
		r.code = -1
		r.stderr += err.Error()
	}
	return r
}

// env is the environment a login session would give this user.
func (m *machine) env() []string {
	if m.user == "root" {
		return nil
	}
	dir := m.dir
	if dir == "" {
		dir = "/home/" + m.user
	}
	e := []string{
		"-e", "HOME=" + dir,
		"-e", "AUU_HOME=" + m.home,
		"-e", "XDG_RUNTIME_DIR=/run/user/" + strconv.Itoa(m.uid),
	}
	if m.caHome != "" {
		e = append(e, "-e", "AUU_CA_HOME="+m.caHome)
	}
	return e
}

// exec runs a command on the machine as its user, with stdin as given; an
// empty stdin is end of file at once, which is what a script sees.
func (m *machine) exec(stdin string, argv ...string) result {
	args := []string{"exec", "--user", m.user}
	var in io.Reader
	if stdin != "" {
		// -i attaches stdin; without it the command sees end of file at
		// once, which is what a script that gives no input looks like.
		args = append(args, "-i")
		in = strings.NewReader(stdin)
	}
	args = append(args, m.env()...)
	args = append(args, m.id)
	args = append(args, argv...)
	r := runHost(in, "docker", args...)
	record(m, strings.Join(argv, " "), stdin, r)
	return r
}

func (m *machine) auu(args ...string) result { return m.exec("", append([]string{"auu"}, args...)...) }
func (m *machine) admin(args ...string) result {
	return m.exec("", append([]string{"auu-admin"}, args...)...)
}
func (m *machine) ca(args ...string) result {
	return m.exec("", append([]string{"auu-ca"}, args...)...)
}
func (m *machine) auuIn(stdin string, args ...string) result {
	return m.exec(stdin, append([]string{"auu"}, args...)...)
}

// root runs a shell script on the machine as root, the way an operator or
// an intruder with the box would. A stopped container is reached with a
// one-off container on the same volumes.
func (m *machine) root(script string) result {
	r := runHost(nil, "docker", "exec", "--user", "root", m.id, "sh", "-c", script)
	if r.code != 0 && strings.Contains(r.stderr, "is not running") {
		r = runHost(nil, "docker", "compose", "-f", composeFile, "run", "--rm", "--no-deps", "-T",
			"--user", "root", "--entrypoint", "sh", m.service, "-c", script)
	}
	record(m.asRoot(), "sh -c "+strconv.Quote(script), "", r)
	return r
}

func (m *machine) asRoot() *machine {
	c := *m
	c.user = "root"
	return &c
}

// mustRoot is root for a step that is setup rather than the subject.
func (m *machine) mustRoot(t *testing.T, script string) string {
	t.Helper()
	r := m.root(script)
	if r.code != 0 {
		t.Fatalf("on %s as root, %q: exit %d\n%s%s", m.service, script, r.code, r.stdout, r.stderr)
	}
	return r.stdout
}

// read returns a file's bytes, as root.
func (m *machine) read(t *testing.T, path string) string {
	t.Helper()
	return m.mustRoot(t, "cat "+shq(path))
}

func (m *machine) exists(path string) bool {
	return m.root("test -e "+shq(path)).code == 0
}

// stat is "owner:mode size" of a path, as root.
func (m *machine) stat(t *testing.T, path string) string {
	t.Helper()
	return strings.TrimSpace(m.mustRoot(t, "stat -c '%U:%a %s' "+shq(path)))
}

func shq(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// copyFile carries a file from one machine to another through the host,
// which is what scp does. Mode bits travel with it.
func copyFile(t *testing.T, from *machine, src string, to *machine, dst string) {
	t.Helper()
	tmp := filepath.Join(t.TempDir(), filepath.Base(src))
	if r := runHost(nil, "docker", "cp", from.id+":"+src, tmp); r.code != 0 {
		t.Fatalf("copying %s from %s: %s", src, from.service, r.stderr)
	}
	if r := runHost(nil, "docker", "cp", tmp, to.id+":"+dst); r.code != 0 {
		t.Fatalf("copying to %s:%s: %s", to.service, dst, r.stderr)
	}
	record(to.asRoot(), fmt.Sprintf("scp %s:%s %s", from, src, dst), "", result{})
}

// hostFile puts a file from the host into a machine.
func hostFile(t *testing.T, local string, to *machine, dst string) {
	t.Helper()
	if r := runHost(nil, "docker", "cp", local, to.id+":"+dst); r.code != 0 {
		t.Fatalf("copying %s to %s:%s: %s", local, to.service, dst, r.stderr)
	}
}

// fetch brings a file from a machine to the host, and returns its path.
func fetch(t *testing.T, from *machine, src string) string {
	t.Helper()
	tmp := filepath.Join(t.TempDir(), filepath.Base(src))
	if r := runHost(nil, "docker", "cp", from.id+":"+src, tmp); r.code != 0 {
		t.Fatalf("copying %s from %s: %s", src, from.service, r.stderr)
	}
	return tmp
}

// --- the relay's lifecycle -------------------------------------------------

// relayLog is everything the relay container has written, its stdout and
// stderr in one stream: the journal. A mark is a line count, and the log
// since a mark is what a restart or a request wrote after it; that is
// exact where a timestamp is a clock's opinion.
type mark int

func relayLog() string {
	cmd := exec.Command("docker", "logs", relay.id)
	var b bytes.Buffer
	cmd.Stdout, cmd.Stderr = &b, &b
	cmd.Run()
	return b.String()
}

func logMark() mark { return mark(strings.Count(relayLog(), "\n")) }

func relayLogSince(m mark) string {
	lines := strings.Split(relayLog(), "\n")
	if int(m) > len(lines) {
		return strings.Join(lines, "\n")
	}
	return strings.Join(lines[m:], "\n")
}

// waitRelayLog polls the log after a mark for a line containing text.
func waitRelayLog(t *testing.T, m mark, text string, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		log := relayLogSince(m)
		if strings.Contains(log, text) {
			return log
		}
		if time.Now().After(deadline) {
			t.Fatalf("the relay log never said %q in %s; it says:\n%s", text, timeout, log)
		}
		time.Sleep(300 * time.Millisecond)
	}
}

// relayRestart restarts the relay and waits until it answers. It is the
// operator's systemctl restart. The mark it returns is where the restart
// begins in the log.
func relayRestart(t *testing.T) mark {
	t.Helper()
	m := logMark()
	if r := compose("restart", "relay"); r.code != 0 {
		t.Fatalf("restarting the relay: %s", r.stderr)
	}
	waitRelayLog(t, m, "serving from an auu-ca bundle", 30*time.Second)
	waitRelayReady(t)
	return m
}

// waitRelayReady waits for the listener: the log line comes a moment
// before the socket does.
func waitRelayReady(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		// bash opens a TCP connection for a redirection; nothing is sent.
		r := runHost(nil, "docker", "exec", alice.id, "bash", "-c", "exec 3<>/dev/tcp/relay.example.com/9443")
		if r.code == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the relay never listened: %s", r.stderr)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// relayRestartFails restarts the relay expecting it to exit, and returns
// the log of the attempt.
func relayRestartFails(t *testing.T) string {
	t.Helper()
	m := logMark()
	if r := compose("restart", "relay"); r.code != 0 {
		t.Fatalf("restarting the relay: %s", r.stderr)
	}
	deadline := time.Now().Add(30 * time.Second)
	for relayRunning() {
		if time.Now().After(deadline) {
			t.Fatalf("the relay kept running; the log says:\n%s", relayLogSince(m))
		}
		time.Sleep(300 * time.Millisecond)
	}
	return relayLogSince(m)
}

// relayStart starts a stopped relay and waits for it.
func relayStart(t *testing.T) mark {
	t.Helper()
	m := logMark()
	if r := compose("start", "relay"); r.code != 0 {
		t.Fatalf("starting the relay: %s", r.stderr)
	}
	waitRelayLog(t, m, "serving from an auu-ca bundle", 30*time.Second)
	waitRelayReady(t)
	return m
}

func relayRunning() bool {
	r := runHost(nil, "docker", "inspect", "-f", "{{.State.Running}}", relay.id)
	return strings.TrimSpace(r.stdout) == "true"
}

func relayStop(t *testing.T) {
	t.Helper()
	if r := compose("stop", "relay"); r.code != 0 {
		t.Fatalf("stopping the relay: %s", r.stderr)
	}
}

// extraArgs sets the flags appended to the relay's command line, and
// returns the undo.
func extraArgs(t *testing.T, args string) func() {
	t.Helper()
	relay.mustRoot(t, "printf '%s' "+shq(args)+" > /etc/auu/extra-args")
	return func() { relay.root("rm -f /etc/auu/extra-args") }
}

// --- faults ----------------------------------------------------------------
//
// Every fault is done on the machine that owns the file, as root, and every
// one returns its undo; a case defers the undo so cases are independent.
// With AUU_E2E_NOFAULT=1 nothing is done, and the undo does nothing.

var undoSeq int

// backup copies a path to the host as a tar stream and returns what puts
// it back, or removes it if it did not exist. docker cp works on a stopped
// container too, so a fault that stops the relay can still be undone, and
// the tar keeps the owner and the mode, which a plain host file cannot.
func (m *machine) backup(t *testing.T, path string) func() {
	t.Helper()
	undoSeq++
	keep := filepath.Join(workDir, fmt.Sprintf("undo-%s-%d.tar", m.service, undoSeq))
	existed := m.exists(path)
	isDir := false
	if existed {
		isDir = m.root("test -d "+shq(path)).code == 0
		r := runHost(nil, "docker", "cp", m.id+":"+path, "-")
		if r.code != 0 {
			t.Fatalf("backing up %s:%s: %s", m.service, path, r.stderr)
		}
		if err := os.WriteFile(keep, []byte(r.stdout), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return func() {
		if !existed || isDir {
			m.root("rm -rf " + shq(path))
		}
		if existed {
			f, err := os.Open(keep)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return
			}
			defer f.Close()
			if r := runHost(f, "docker", "cp", "-", m.id+":"+filepath.Dir(path)); r.code != 0 {
				fmt.Fprintf(os.Stderr, "restoring %s:%s: %s\n", m.service, path, r.stderr)
			}
		}
	}
}

func (m *machine) fault(t *testing.T, path, script string) func() {
	t.Helper()
	if nofault {
		return func() {}
	}
	undo := m.backup(t, path)
	m.mustRoot(t, script)
	return undo
}

// flipByte changes one byte in place; the length is unchanged.
func (m *machine) flipByte(t *testing.T, path string, offset int64) func() {
	t.Helper()
	before := m.stat(t, path)
	undo := m.fault(t, path, fmt.Sprintf(
		`b=$(dd if=%s bs=1 skip=%d count=1 2>/dev/null | od -An -tu1 | tr -d ' '); `+
			`printf "\\$(printf '%%03o' $(( (b ^ 1) & 255 )))" | dd of=%s bs=1 seek=%d conv=notrunc 2>/dev/null`,
		shq(path), offset, shq(path), offset))
	if !nofault {
		if after := m.stat(t, path); after != before {
			t.Fatalf("flipping a byte changed %s from %q to %q", path, before, after)
		}
	}
	return undo
}

func (m *machine) truncate(t *testing.T, path string, size int64) func() {
	t.Helper()
	return m.fault(t, path, fmt.Sprintf("truncate -s %d %s", size, shq(path)))
}

func (m *machine) remove(t *testing.T, path string) func() {
	t.Helper()
	return m.fault(t, path, "rm -rf "+shq(path))
}

func (m *machine) chmod(t *testing.T, mode, path string) func() {
	t.Helper()
	return m.fault(t, path, "chmod "+mode+" "+shq(path))
}

func (m *machine) chown(t *testing.T, owner, path string) func() {
	t.Helper()
	return m.fault(t, path, "chown "+owner+" "+shq(path))
}

// write replaces a file's content (creating it), keeping the owner and mode
// of an existing file.
func (m *machine) write(t *testing.T, path, content string) func() {
	t.Helper()
	return m.fault(t, path, "printf '%s' "+shq(content)+" > "+shq(path))
}

// writeAs creates a file with an owner and mode.
func (m *machine) writeAs(t *testing.T, path, content, owner, mode string) func() {
	t.Helper()
	return m.fault(t, path, "printf '%s' "+shq(content)+" > "+shq(path)+
		" && chown "+owner+" "+shq(path)+" && chmod "+mode+" "+shq(path))
}

// edit replaces exactly one occurrence of old with new in a file, keeping
// its owner and mode. The replacement is done here, not with sed, so that
// what is written is exact.
func (m *machine) edit(t *testing.T, path, old, new string) func() {
	t.Helper()
	if nofault {
		return func() {}
	}
	content := m.read(t, path)
	if n := strings.Count(content, old); n != 1 {
		t.Fatalf("editing %s: %q occurs %d times, want once", path, old, n)
	}
	undo := m.backup(t, path)
	m.putContent(t, path, strings.Replace(content, old, new, 1))
	return undo
}

// putContent writes content into an existing file through a temp file, so
// the owner and mode stay.
func (m *machine) putContent(t *testing.T, path, content string) {
	t.Helper()
	tmp := filepath.Join(t.TempDir(), "content")
	if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	hostFile(t, tmp, m, "/snap/put")
	m.mustRoot(t, "cat /snap/put > "+shq(path)+" && rm -f /snap/put")
}

// swap exchanges two files of equal size.
func (m *machine) swap(t *testing.T, a, b string) func() {
	t.Helper()
	if nofault {
		return func() {}
	}
	sa, sb := m.stat(t, a), m.stat(t, b)
	if strings.Fields(sa)[1] != strings.Fields(sb)[1] {
		t.Fatalf("swapping %s (%s) and %s (%s): sizes differ", a, sa, b, sb)
	}
	ua, ub := m.backup(t, a), m.backup(t, b)
	m.mustRoot(t, "mv "+shq(a)+" /snap/swap && mv "+shq(b)+" "+shq(a)+" && mv /snap/swap "+shq(b))
	return func() { ua(); ub() }
}

// sql runs a statement against the relay's database as auu.
func (m *machine) sql(t *testing.T, stmt string) string {
	t.Helper()
	r := m.root("runuser -u auu -- sqlite3 /var/lib/auu/relay.db " + shq(stmt))
	if r.code != 0 {
		t.Fatalf("sqlite3 %q: %s", stmt, r.stderr)
	}
	return strings.TrimSpace(r.stdout)
}

// sqlFault is sql as a fault, backing the database up first.
func (m *machine) sqlFault(t *testing.T, stmt string) func() {
	t.Helper()
	if nofault {
		return func() {}
	}
	undo := m.backup(t, "/var/lib/auu/relay.db")
	m.sql(t, stmt)
	return undo
}

// --- snapshots -------------------------------------------------------------

// snapshot keeps every machine's state after the cycle, for the matrix to
// start each family from.
func snapshot(t *testing.T) {
	t.Helper()
	for _, m := range []*machine{operator, alice, bob} {
		m.mustRoot(t, fmt.Sprintf("tar -C /home/%s -cf /snap/%s.tar .", m.user, m.service))
	}
	relayStop(t)
	relay.mustRoot(t, "tar -C /var/lib/auu -cf /snap/relay-state.tar . && tar -C /etc/auu -cf /snap/relay-etc.tar .")
	relayStart(t)
}

func haveSnapshot() bool { return relay.exists("/snap/relay-state.tar") }

// restore puts every machine back as the snapshot has it. Agents are
// stopped first: one holding keys for a home that is about to be replaced
// would be a machine no person ever has.
func restore(t *testing.T) {
	t.Helper()
	for _, m := range []*machine{operator, alice, bob} {
		m.root("pkill -u " + m.user + " auu; true")
		m.mustRoot(t, fmt.Sprintf("rm -rf /home/%s/.auu* /home/%s/*; tar -C /home/%s -xf /snap/%s.tar",
			m.user, m.user, m.user, m.service))
	}
	relayStop(t)
	relay.mustRoot(t, "rm -rf /var/lib/auu/* /var/lib/auu/.[!.]* /etc/auu/*; "+
		"tar -C /var/lib/auu -xf /snap/relay-state.tar && tar -C /etc/auu -xf /snap/relay-etc.tar")
	relayStart(t)
}

// --- assertions ------------------------------------------------------------

func expectCode(t *testing.T, r result, code int) {
	t.Helper()
	if r.code != code {
		t.Errorf("exit %d, want %d\nstdout: %s\nstderr: %s", r.code, code, r.stdout, r.stderr)
	}
}

func expectSays(t *testing.T, r result, code int, want ...string) {
	t.Helper()
	expectCode(t, r, code)
	for _, w := range want {
		if !strings.Contains(r.out(), w) {
			t.Errorf("output lacks %q\nstdout: %s\nstderr: %s", w, r.stdout, r.stderr)
		}
	}
}

func expectNot(t *testing.T, r result, unwanted ...string) {
	t.Helper()
	for _, w := range unwanted {
		if strings.Contains(r.out(), w) {
			t.Errorf("output has %q and must not\nstdout: %s\nstderr: %s", w, r.stdout, r.stderr)
		}
	}
}

// stderrIs asserts the whole of stderr, trimmed, is one sentence.
func stderrIs(t *testing.T, r result, want string) {
	t.Helper()
	if got := strings.TrimSpace(r.stderr); got != want {
		t.Errorf("stderr is\n  %q\nwant\n  %q", got, want)
	}
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	return lines[len(lines)-1]
}

// jsonOf decodes a command's stdout.
func jsonOf(t *testing.T, r result, v any) {
	t.Helper()
	if err := json.Unmarshal([]byte(r.stdout), v); err != nil {
		t.Fatalf("not JSON: %v\n%s%s", err, r.stdout, r.stderr)
	}
}

var (
	reHex64 = regexp.MustCompile(`[0-9a-f]{64}`)
	reHex32 = regexp.MustCompile(`\b[0-9a-f]{32}\b`)
)

func find(t *testing.T, re *regexp.Regexp, s string) string {
	t.Helper()
	m := re.FindString(s)
	if m == "" {
		t.Fatalf("no match for %s in:\n%s", re, s)
	}
	return m
}

// --- the report ------------------------------------------------------------

type step struct {
	who, cmd, stdin, stdout, stderr string
	code                            int
}

type row struct {
	id, family, happened string
	steps                []step
	relayLog             string
	verdict, note        string
	failed, skipped      bool
	from                 mark
}

var (
	reportMu sync.Mutex
	report   []*row
	current  *row
)

// begin opens a row; everything run until the subtest ends is recorded in
// it, and the relay's log over the same time is attached.
func begin(t *testing.T, id, family, happened string) {
	t.Helper()
	r := &row{id: id, family: family, happened: happened, from: logMark()}
	reportMu.Lock()
	current = r
	reportMu.Unlock()
	t.Cleanup(func() {
		r.relayLog = strings.TrimSpace(relayLogSince(r.from))
		r.failed = t.Failed()
		r.skipped = t.Skipped()
		reportMu.Lock()
		report = append(report, r)
		current = nil
		reportMu.Unlock()
	})
}

func record(m *machine, cmd, stdin string, r result) {
	reportMu.Lock()
	defer reportMu.Unlock()
	if current == nil {
		return
	}
	current.steps = append(current.steps, step{who: m.String(), cmd: cmd, stdin: stdin,
		stdout: r.stdout, stderr: r.stderr, code: r.code})
}

// verdict is the report's judgement of a row: ok, gap or observed, and why.
func verdict(t *testing.T, v, note string) {
	t.Helper()
	reportMu.Lock()
	defer reportMu.Unlock()
	if current == nil {
		t.Fatal("verdict outside a row")
	}
	current.verdict, current.note = v, note
}

func writeReport() error {
	reportMu.Lock()
	defer reportMu.Unlock()
	if len(report) == 0 {
		return nil
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# AgentUUCP in containers: what each party saw\n\n")
	// A run with the faults off says so in its first line and writes its
	// own file: its FAILED rows are the point of it, and one that took the
	// real report's name was read as the real report going red.
	faults := ""
	if nofault {
		faults = " Faults off (AUU_E2E_NOFAULT=1): a row that FAILED depends on its fault, which is what this run is for."
	}
	fmt.Fprintf(&b, "Run %s. %d rows. Verdicts: `ok` reported well, `gap` a person would have needed more, `observed` recorded as found.%s\n\n",
		time.Now().Format(time.RFC3339), len(report), faults)
	counts := map[string]map[string]int{}
	var families []string
	for _, r := range report {
		if counts[r.family] == nil {
			counts[r.family] = map[string]int{}
			families = append(families, r.family)
		}
		v := r.verdict
		switch {
		case r.skipped:
			v = "skipped"
		case r.failed:
			v = "FAILED"
		case v == "":
			v = "unjudged"
		}
		counts[r.family][v]++
	}
	sort.Strings(families)
	fmt.Fprintf(&b, "| family | ok | gap | observed | skipped | FAILED |\n|---|---|---|---|---|---|\n")
	for _, f := range families {
		c := counts[f]
		fmt.Fprintf(&b, "| %s | %d | %d | %d | %d | %d |\n", f, c["ok"], c["gap"], c["observed"], c["skipped"], c["FAILED"])
	}
	b.WriteString("\n")
	for _, r := range report {
		v := r.verdict
		switch {
		case r.skipped:
			v = "skipped"
		case r.failed:
			v = "FAILED"
		}
		fmt.Fprintf(&b, "## %s: %s\n\n", r.id, r.happened)
		fmt.Fprintf(&b, "Verdict: **%s**", v)
		if r.note != "" {
			fmt.Fprintf(&b, ". %s", r.note)
		}
		b.WriteString("\n\n")
		for _, s := range r.steps {
			fmt.Fprintf(&b, "```\n%s$ %s\n", s.who, s.cmd)
			if s.stdin != "" {
				fmt.Fprintf(&b, "<stdin: %q>\n", s.stdin)
			}
			if s.stdout != "" {
				b.WriteString(strings.TrimRight(s.stdout, "\n") + "\n")
			}
			if s.stderr != "" {
				b.WriteString("[stderr] " + strings.ReplaceAll(strings.TrimRight(s.stderr, "\n"), "\n", "\n[stderr] ") + "\n")
			}
			fmt.Fprintf(&b, "[exit %d]\n```\n\n", s.code)
		}
		if r.relayLog != "" {
			fmt.Fprintf(&b, "Relay log:\n\n```\n%s\n```\n\n", r.relayLog)
		}
	}
	return os.WriteFile(filepath.Join(outDir, reportName()), []byte(b.String()), 0o644)
}

// reportName is report.md, or report-nofault.md for a run with the faults
// off, so that the run meant to fail can never overwrite the run that
// proves the suite green. run.sh names the test log the same way.
func reportName() string {
	if nofault {
		return "report-nofault.md"
	}
	return "report.md"
}

// --- a command left running ------------------------------------------------

// running is a command on a machine that has not finished: a watch, which
// returns when something happens elsewhere.
type running struct {
	m       *machine
	argv    []string
	started time.Time
	done    chan result
}

// start runs a command on the machine without waiting for it; wait
// collects what it produced. What it printed is recorded in the row when
// it finishes.
func (m *machine) start(argv ...string) *running {
	args := []string{"exec", "--user", m.user}
	args = append(args, m.env()...)
	args = append(args, m.id)
	args = append(args, argv...)
	p := &running{m: m, argv: argv, started: time.Now(), done: make(chan result, 1)}
	go func() {
		r := runHost(nil, "docker", args...)
		record(m, strings.Join(argv, " "), "", r)
		p.done <- r
	}()
	return p
}

func (m *machine) startAuu(args ...string) *running {
	return m.start(append([]string{"auu"}, args...)...)
}

// wait is the command's result, and how long it ran; a command still
// running after the patience fails the test.
func (p *running) wait(t *testing.T, patience time.Duration) (result, time.Duration) {
	t.Helper()
	select {
	case r := <-p.done:
		return r, time.Since(p.started)
	case <-time.After(patience):
		t.Fatalf("%s on %s did not finish in %s", strings.Join(p.argv, " "), p.m, patience)
		return result{}, 0
	}
}

// finished reports whether the command has returned, without waiting.
func (p *running) finished() bool {
	select {
	case r := <-p.done:
		p.done <- r
		return true
	default:
		return false
	}
}
