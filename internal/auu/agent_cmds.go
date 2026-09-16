package auu

import (
	"errors"
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

// ensureUnlocked makes sure the agent for an encrypted home is running and
// unlocked, asking a person at a terminal for the passphrase if it is not,
// and refusing anything that is not a person.
func ensureUnlocked(s *store.Store) error {
	c, err := agent.NewClient(s.Root())
	if err != nil {
		return err
	}
	st, err := c.Status()
	if err == nil && !st.Locked {
		return nil
	}
	if err != nil && !errors.Is(err, agent.ErrNotRunning) {
		return err
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return lockedErr()
	}
	secret, err := term.FromTerminal(fmt.Sprintf("Passphrase for %s: ", s.Root()))
	if err != nil {
		return err
	}
	return unlockWith(s, c, secret, agent.DefaultTTL)
}

// unlockWith starts the agent if none is running, unlocks it, and says
// until when.
func unlockWith(s *store.Store, c *agent.Client, secret []byte, ttl time.Duration) error {
	if _, err := c.Status(); errors.Is(err, agent.ErrNotRunning) {
		if err := startAgent(s.Root()); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if err := c.Unlock(secret, ttl); err != nil {
		return err
	}
	st, err := c.Status()
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, untilLine(st))
	return nil
}

func untilLine(st agent.Status) string {
	if st.Until.IsZero() {
		return "unlocked until lock or logout"
	}
	return "unlocked until " + st.Until.Local().Format("15:04")
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
		return unlockWith(s, c, secret, agent.DefaultTTL)
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
	return unlockWith(s, c, secret, agent.DefaultTTL)
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
	ttl := fs.Duration("ttl", agent.DefaultTTL, "lock again this long after unlocking; 0 means not until 'auu lock'")
	file := fs.String("passphrase-file", "", "read the passphrase from the first line of this file")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) > 0 {
		return usageErrf("unexpected argument %q", positional[0])
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
	return unlockWith(s, c, secret, *ttl)
}

// cmdLock drops the keys from the agent. The agent keeps running, so the
// next unlock needs no restart.
func cmdLock(args []string) error {
	fs := newFlagSet("lock")
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
	Running bool     `json:"running"`
	Locked  bool     `json:"locked"`
	Until   string   `json:"until,omitempty"`
	Keys    []string `json:"keys"`
	Socket  string   `json:"socket"`
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
	switch {
	case out.Locked:
		fmt.Printf("keys:   locked\n")
	case st.Until.IsZero():
		fmt.Printf("keys:   unlocked until lock or logout\n")
	default:
		fmt.Printf("keys:   unlocked until %s\n", st.Until.Local().Format("2006-01-02 15:04"))
	}
	if len(out.Keys) > 0 {
		fmt.Printf("held:   %s\n", strings.Join(out.Keys, ", "))
	}
	fmt.Printf("socket: %s\n", out.Socket)
	return nil
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
