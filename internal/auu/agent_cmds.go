package auu

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/tropeforce7/agentuucp/internal/agent"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/keyfile"
	"github.com/tropeforce7/agentuucp/internal/store"
	"github.com/tropeforce7/agentuucp/internal/term"
)

// Encrypting a home, and the agent that makes it bearable.
//
// The rule that every command here follows: a passphrase is read from a
// terminal, from --passphrase-file, or from a standard input that is not a
// terminal — and only by unlock and passphrase. Every other command that
// finds the agent locked prompts if and only if its standard input is a
// terminal, and otherwise exits 4 with one sentence naming unlock. The
// passphrase is never in an argument, an environment variable, a message,
// or the AI's context.

// cost is what a new home.key is encrypted at. Its zero value is keyfile's
// defaults; a test turns it down. As in auu-ca, nothing else assigns it.
var cost keyfile.Passphrase

func withSecret(secret []byte) keyfile.Passphrase {
	p := cost
	p.Secret = secret
	return p
}

// lockedErr is the whole of what an AI or a script is told: exit code 4 and
// this sentence. It is returned only for this condition.
func lockedErr() error {
	return &exitError{code: exitLocked,
		err: fmt.Errorf("your identity is locked: run '%s unlock' in your own terminal", prog)}
}

// receiveOnlyErr is the other thing exit code 4 says: the agent is unlocked
// to receive and this command originates. The sentence is the agent's own,
// verbatim, so the skill has one string to know.
func receiveOnlyErr() error {
	return &exitError{code: exitLocked, err: errors.New(agent.ReceiveOnlyMessage)}
}

// isLocked tells a locked agent apart from every other failure. The
// sentinel is the rule; the text is for the one path that loses the
// chain — crypto/tls builds a fresh error around a signer's — and the text
// is the agent's own constant, not a guess.
func isLocked(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, identity.ErrLocked) || strings.Contains(err.Error(), agent.LockedMessage)
}

// isReceiveOnly tells an agent that would not originate apart from every
// other failure, by the agent's own sentence. It never comes wrapped in
// identity.ErrLocked, so the text is the whole test.
func isReceiveOnly(err error) bool {
	return err != nil && strings.Contains(err.Error(), agent.ReceiveOnlyMessage)
}

// ensureUnlocked makes sure the agent for an encrypted home is running and
// unlocked in at least the scope asked for, asking a person at a terminal
// for the passphrase if it is not, and refusing anything that is not a
// person.
//
// Every command asks for receive: one that originates finds out at the
// agent, which refuses with the receive sentence, and exit 4 says what to
// run. Enrolment asks for send, because registering a machine is a human
// act and the person is at the terminal already: asked once into send
// scope for its ten minutes, rather than into receive and then refused.
func ensureUnlocked(s *store.Store, scope agent.Scope) error {
	c, err := agent.NewClient(s.Root())
	if err != nil {
		return err
	}
	st, err := c.Status()
	if err == nil && !st.Locked && (scope == agent.ScopeReceive || st.Scope == agent.ScopeSend) {
		return nil
	}
	if err != nil && !errors.Is(err, agent.ErrNotRunning) {
		return err
	}
	if !stdinIsTerminal() {
		if err == nil && !st.Locked {
			return receiveOnlyErr()
		}
		return lockedErr()
	}
	// The prompt says which scope it opens, because a command that sends
	// may ask twice at a terminal: this prompt, into receive, and then the
	// receive sentence naming the unlock that sends. By design — the send
	// unlock is a decision, not something a command makes for you — and
	// said here so the second asking is not a surprise.
	prompt := fmt.Sprintf("Passphrase for %s (to receive; a command that sends will ask again): ", s.Root())
	ttl := agent.DefaultTTL
	if scope == agent.ScopeSend {
		prompt = fmt.Sprintf("Passphrase for %s: ", s.Root())
		ttl = agent.DefaultSendTTL
	}
	secret, err := askPassphrase(prompt)
	if err != nil {
		return err
	}
	return unlockWith(s, c, secret, ttl, scope)
}

// The terminal, as ensureUnlocked sees it. Variables so that a test, which
// has no terminal, can stand one in and see which scope a command asks a
// person for; nothing else reads a passphrase through these.
var (
	stdinIsTerminal = func() bool { return term.IsTerminal(int(os.Stdin.Fd())) }
	askPassphrase   = term.FromTerminal
)

// unlockWith starts the agent if none is running, unlocks it in the scope
// asked for, and says until when.
func unlockWith(s *store.Store, c *agent.Client, secret []byte, ttl time.Duration, scope agent.Scope) error {
	if _, err := c.Status(); errors.Is(err, agent.ErrNotRunning) {
		if err := startAgent(s.Root()); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if err := c.Unlock(secret, ttl, scope); err != nil {
		return err
	}
	st, err := c.Status()
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, untilLine(st))
	return nil
}

// untilLine is the one line every unlock and status prints: the scope,
// and when each ends.
func untilLine(st agent.Status) string {
	receive := "until lock or logout"
	if !st.Until.IsZero() {
		receive = "until " + st.Until.Local().Format("15:04")
	}
	if st.Scope != agent.ScopeSend {
		return "unlocked to receive " + receive
	}
	send := "until lock or logout"
	if !st.SendUntil.IsZero() {
		send = "until " + st.SendUntil.Local().Format("15:04")
	}
	return "unlocked to send " + send + " (receive " + receive + ")"
}

// encryptedHome opens the store and says whether it is encrypted, refusing
// a half-converted one by name.
func encryptedHome() (*store.Store, bool, error) {
	s, err := openStore()
	if err != nil {
		return nil, false, err
	}
	enc, err := s.Encrypted()
	if err != nil {
		return nil, false, err
	}
	return s, enc, nil
}

// cmdPassphrase encrypts a home, changes the passphrase, or decrypts it.
func cmdPassphrase(args []string) error {
	if len(args) == 0 {
		return usageErrf("usage: %s passphrase set|change|remove", prog)
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "set":
		return passphraseSet(rest)
	case "change":
		return passphraseChange(rest)
	case "remove":
		return passphraseRemove(rest)
	default:
		return usageErrf("unknown passphrase subcommand %q; run '%s passphrase set|change|remove'", sub, prog)
	}
}

// passphraseSet encrypts a plain home and unlocks the agent, so the very
// next command works.
func passphraseSet(args []string) error {
	fs := newFlagSet("passphrase set")
	file := fs.String("passphrase-file", "", "read the passphrase from the first line of this file")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) > 0 {
		return usageErrf("unexpected argument %q", positional[0])
	}
	s, err := openStore()
	if err != nil {
		return err
	}
	enc, err := s.Encrypted()
	if err != nil {
		// A half-converted home: finishing needs the passphrase it was
		// started with, once.
		if !errors.Is(err, store.ErrInterrupted) {
			return err
		}
		fmt.Fprintf(os.Stderr, "%s: %v\n", prog, err)
		secret, err := term.ReadPassphrase(fmt.Sprintf("Passphrase for %s: ", s.Root()), *file)
		if err != nil {
			return err
		}
		if err := s.EncryptHome(withSecret(secret)); err != nil {
			return err
		}
		fmt.Printf("finished encrypting the keys in %s\n", s.Root())
		c, err := agent.NewClient(s.Root())
		if err != nil {
			return err
		}
		return unlockWith(s, c, secret, agent.DefaultTTL, agent.ScopeReceive)
	}
	if enc {
		return usageErrf("%v; run '%s passphrase change' to change the passphrase", store.ErrEncrypted, prog)
	}
	if !s.HasIdentity() {
		return store.ErrNoIdentity
	}
	secret, err := term.ReadNewPassphrase("Passphrase: ", *file)
	if err != nil {
		return err
	}
	if err := s.EncryptHome(withSecret(secret)); err != nil {
		return err
	}
	fmt.Printf("encrypted the keys in %s\n", s.Root())
	fmt.Printf("\nThe passphrase is not recoverable and is not stored anywhere: without it\n")
	fmt.Printf("these keys are lost. Back up %s as it is now.\n", s.Root())
	c, err := agent.NewClient(s.Root())
	if err != nil {
		return err
	}
	return unlockWith(s, c, secret, agent.DefaultTTL, agent.ScopeReceive)
}

func passphraseChange(args []string) error {
	fs := newFlagSet("passphrase change")
	oldFile := fs.String("passphrase-file", "", "read the current passphrase from the first line of this file")
	newFile := fs.String("new-passphrase-file", "", "read the new passphrase from the first line of this file")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) > 0 {
		return usageErrf("unexpected argument %q", positional[0])
	}
	s, enc, err := encryptedHome()
	if err != nil {
		return err
	}
	if !enc {
		return usageErrf("%v; run '%s passphrase set' to encrypt it", store.ErrNotEncrypted, prog)
	}
	old, err := term.ReadPassphrase("Current passphrase: ", *oldFile)
	if err != nil {
		return err
	}
	fresh, err := term.ReadNewPassphrase("New passphrase: ", *newFile)
	if err != nil {
		return err
	}
	if err := s.ChangePassphrase(old, withSecret(fresh)); err != nil {
		return err
	}
	fmt.Printf("changed the passphrase on %s\n", s.Root())
	return nil
}

// passphraseRemove decrypts a home and locks the agent: what it held is
// on disk in the clear now, and holding it too would be pointless.
func passphraseRemove(args []string) error {
	fs := newFlagSet("passphrase remove")
	file := fs.String("passphrase-file", "", "read the passphrase from the first line of this file")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) > 0 {
		return usageErrf("unexpected argument %q", positional[0])
	}
	s, err := openStore()
	if err != nil {
		return err
	}
	enc, err := s.Encrypted()
	if err != nil {
		if !errors.Is(err, store.ErrInterrupted) {
			return err
		}
		fmt.Fprintf(os.Stderr, "%s: %v\n", prog, err)
	} else if !enc {
		return usageErrf("%v", store.ErrNotEncrypted)
	}
	secret, err := term.ReadPassphrase(fmt.Sprintf("Passphrase for %s: ", s.Root()), *file)
	if err != nil {
		return err
	}
	if err := s.DecryptHome(secret); err != nil {
		return err
	}
	if c, err := agent.NewClient(s.Root()); err == nil {
		if _, err := stopAgent(c); err != nil {
			fmt.Fprintf(os.Stderr, "%s: stopping the agent: %v\n", prog, err)
		}
	}
	fmt.Printf("decrypted the keys in %s; they are on disk in the clear again\n", s.Root())
	return nil
}

// stopAgent tells the agent to stop and waits until it has: the agent
// answers stop and then exits, and a caller that goes on to say "stopped"
// or to read the home in the clear should not be racing it. It reports
// whether there was one to stop.
func stopAgent(c *agent.Client) (bool, error) {
	if err := c.Stop(); err != nil {
		if errors.Is(err, agent.ErrNotRunning) {
			return false, nil
		}
		return false, err
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := c.Status(); errors.Is(err, agent.ErrNotRunning) {
			return true, nil
		}
		if time.Now().After(deadline) {
			return true, errors.New("the agent acknowledged stop but is still answering")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// cmdUnlock is how a person unlocks: at a terminal, from a file for a
// secret manager, or from a pipe.
func cmdUnlock(args []string) error {
	fs := newFlagSet("unlock")
	// The default is the scope's, DefaultTTL to receive and DefaultSendTTL
	// to send, so it is decided after parsing from whether --ttl was given.
	ttl := fs.Duration("ttl", 0, "stay unlocked this long; 0 means not until 'auu lock'. 8h to receive, 10m to send")
	send := fs.Bool("send", false, "unlock to send as well as receive, for --ttl; the passphrase is asked for again")
	file := fs.String("passphrase-file", "", "read the passphrase from the first line of this file")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) > 0 {
		return usageErrf("unexpected argument %q", positional[0])
	}
	scope := agent.ScopeReceive
	if *send {
		scope = agent.ScopeSend
	}
	ttlGiven := false
	fs.Visit(func(f *flag.Flag) { ttlGiven = ttlGiven || f.Name == "ttl" })
	if !ttlGiven {
		*ttl = agent.DefaultTTL
		if *send {
			*ttl = agent.DefaultSendTTL
		}
	}
	if *ttl < 0 {
		return usageErrf("--ttl must not be negative")
	}
	s, enc, err := encryptedHome()
	if err != nil {
		return err
	}
	if !enc {
		return usageErrf("%v, so there is nothing to unlock; '%s passphrase set' encrypts it",
			store.ErrNotEncrypted, prog)
	}
	secret, err := term.ReadPassphrase(fmt.Sprintf("Passphrase for %s: ", s.Root()), *file)
	if err != nil {
		return err
	}
	c, err := agent.NewClient(s.Root())
	if err != nil {
		return err
	}
	return unlockWith(s, c, secret, *ttl, scope)
}

// cmdLock drops the keys from the agent, or with --send drops send scope
// and keeps receive. The agent keeps running, so the next unlock needs no
// restart.
func cmdLock(args []string) error {
	fs := newFlagSet("lock")
	send := fs.Bool("send", false, "drop send scope only; the agent stays unlocked to receive")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) > 0 {
		return usageErrf("unexpected argument %q", positional[0])
	}
	s, err := openStore()
	if err != nil {
		return err
	}
	c, err := agent.NewClient(s.Root())
	if err != nil {
		return err
	}
	if *send {
		if err := c.LockSend(); err != nil {
			if errors.Is(err, agent.ErrNotRunning) {
				fmt.Println("no agent is running; nothing was unlocked")
				return nil
			}
			return err
		}
		st, err := c.Status()
		if err != nil {
			return err
		}
		if st.Locked {
			fmt.Println("locked")
			return nil
		}
		fmt.Println(untilLine(st))
		return nil
	}
	if err := c.Lock(); err != nil {
		if errors.Is(err, agent.ErrNotRunning) {
			fmt.Println("no agent is running; nothing was unlocked")
			return nil
		}
		return err
	}
	fmt.Println("locked")
	return nil
}

// cmdAgent starts, stops and reports on the agent, and runs one in the
// foreground, which is what start does detached.
func cmdAgent(args []string) error {
	if len(args) == 0 {
		return usageErrf("usage: %s agent start|stop|status|run", prog)
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "start":
		return agentStart(rest)
	case "stop":
		return agentStop(rest)
	case "status":
		return agentStatus(rest)
	case "run":
		return agentRun(rest)
	default:
		return usageErrf("unknown agent subcommand %q; run '%s agent start|stop|status'", sub, prog)
	}
}

func agentStart(args []string) error {
	fs := newFlagSet("agent start")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) > 0 {
		return usageErrf("unexpected argument %q", positional[0])
	}
	s, enc, err := encryptedHome()
	if err != nil {
		return err
	}
	if !enc {
		return usageErrf("%v, so there is nothing for an agent to hold; '%s passphrase set' encrypts it",
			store.ErrNotEncrypted, prog)
	}
	c, err := agent.NewClient(s.Root())
	if err != nil {
		return err
	}
	if _, err := c.Status(); err == nil {
		return nil
	} else if !errors.Is(err, agent.ErrNotRunning) {
		return err
	}
	return startAgent(s.Root())
}

func agentStop(args []string) error {
	fs := newFlagSet("agent stop")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) > 0 {
		return usageErrf("unexpected argument %q", positional[0])
	}
	s, err := openStore()
	if err != nil {
		return err
	}
	c, err := agent.NewClient(s.Root())
	if err != nil {
		return err
	}
	was, err := stopAgent(c)
	if err != nil {
		return err
	}
	if !was {
		fmt.Println("no agent is running")
		return nil
	}
	fmt.Println("stopped")
	return nil
}

type agentStatusJSON struct {
	Running bool   `json:"running"`
	Locked  bool   `json:"locked"`
	Until   string `json:"until,omitempty"`
	// Scope is receive or send while unlocked, and SendExpires is when
	// send scope ends, RFC 3339; absent when send scope lasts until lock,
	// and when the scope is receive. The skill reads Scope before its
	// first send.
	Scope       string   `json:"scope,omitempty"`
	SendExpires string   `json:"send_expires,omitempty"`
	Keys        []string `json:"keys"`
	Socket      string   `json:"socket"`
}

func agentStatus(args []string) error {
	fs := newFlagSet("agent status")
	asJSON := fs.Bool("json", false, "machine readable output")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) > 0 {
		return usageErrf("unexpected argument %q", positional[0])
	}
	s, err := openStore()
	if err != nil {
		return err
	}
	c, err := agent.NewClient(s.Root())
	if err != nil {
		return err
	}
	out := agentStatusJSON{Keys: []string{}, Socket: c.Socket(), Locked: true}
	st, err := c.Status()
	switch {
	case errors.Is(err, agent.ErrNotRunning):
	case err != nil:
		return err
	default:
		out.Running, out.Locked = true, st.Locked
		if !st.Until.IsZero() {
			out.Until = st.Until.Format(time.RFC3339)
		}
		out.Scope = string(st.Scope)
		if !st.SendUntil.IsZero() {
			out.SendExpires = st.SendUntil.Format(time.RFC3339)
		}
		if st.Keys != nil {
			out.Keys = st.Keys
		}
	}
	if *asJSON {
		return printJSON(out)
	}
	if !out.Running {
		fmt.Printf("agent:  not running\n")
		fmt.Printf("socket: %s\n", out.Socket)
		return nil
	}
	fmt.Printf("agent:  running\n")
	if out.Locked {
		fmt.Printf("keys:   locked\n")
	} else {
		fmt.Printf("keys:   %s\n", statusLine(st))
	}
	if len(out.Keys) > 0 {
		fmt.Printf("held:   %s\n", strings.Join(out.Keys, ", "))
	}
	fmt.Printf("socket: %s\n", out.Socket)
	return nil
}

// statusLine is untilLine with dates, for 'agent status', where a window
// that ends tomorrow should say so.
func statusLine(st agent.Status) string {
	const layout = "2006-01-02 15:04"
	receive := "until lock or logout"
	if !st.Until.IsZero() {
		receive = "until " + st.Until.Local().Format(layout)
	}
	if st.Scope != agent.ScopeSend {
		return "unlocked to receive " + receive
	}
	send := "until lock or logout"
	if !st.SendUntil.IsZero() {
		send = "until " + st.SendUntil.Local().Format(layout)
	}
	return "unlocked to send " + send + " (receive " + receive + ")"
}

// agentRun is the agent itself, in the foreground: what start runs
// detached, and what a user service would run.
func agentRun(args []string) error {
	fs := newFlagSet("agent run")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) > 0 {
		return usageErrf("unexpected argument %q", positional[0])
	}
	s, enc, err := encryptedHome()
	if err != nil {
		return err
	}
	if !enc {
		return usageErrf("%v, so there is nothing for an agent to hold", store.ErrNotEncrypted)
	}
	if err := agent.Run(ctx(), s, agent.Options{}); err != nil {
		if errors.Is(err, agent.ErrAnotherAgent) {
			return usageErrf("%v", err)
		}
		return err
	}
	return nil
}

// startAgent runs 'auu agent run' detached for a home, and returns once it
// answers. Its output goes to a log file beside the socket.
func startAgent(home string) error {
	paths, err := agent.PathsFor(home)
	if err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	logFile, err := os.OpenFile(paths.Log, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer logFile.Close()
	if err := spawnDetached(exe, []string{"agent", "run"}, home, logFile); err != nil {
		return fmt.Errorf("starting the agent: %w", err)
	}
	c, err := agent.NewClient(home)
	if err != nil {
		return err
	}
	// Not a sleep for the sake of it: the agent is another process, and
	// "it answers" is the only thing that says it is up. Ten seconds is
	// far longer than it takes and short enough to notice a failure.
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := c.Status(); err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if tail, err := os.ReadFile(paths.Log); err == nil && len(tail) > 0 {
		return fmt.Errorf("the agent did not start; its log says:\n%s", strings.TrimSpace(string(tail)))
	}
	return fmt.Errorf("the agent did not start; see %s", paths.Log)
}
