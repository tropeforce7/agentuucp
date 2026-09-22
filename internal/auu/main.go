// Package auu is the client: it sends and receives end-to-end encrypted
// messages between agents run by different people, through an untrusted relay.
//
// It is one program under two names. cmd/auu builds it as auu, the short form
// used throughout the documentation, and the module root builds it as
// agentuucp so that "go install github.com/tropeforce7/agentuucp@latest" has
// something to install. Both call Main with the name they were built under.
package auu

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/tropeforce7/agentuucp/internal/agent"
	"github.com/tropeforce7/agentuucp/internal/client"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// Exit codes. The skill relies on these to tell apart "you asked for something
// impossible" from "the network is down" from "nothing arrived in time" from
// "a human has to unlock the keys" from "a file on this machine needs a
// person".
const (
	exitOK        = 0
	exitUsage     = 1
	exitTransport = 2
	exitTimeout   = 3
	exitLocked    = 4
	exitDamaged   = 5
)

const usage = `auu - encrypted agent-to-agent messaging over an untrusted relay

Usage:
  auu init --name NAME [--relay URL] [--anchor HASH] [--force]
  auu id [export]
  auu lookup FINGERPRINT|SHORT-ID|PEER [--json]   # what the relay knows about an id
  auu enrol --name NAME [--label MACHINE] <enrolment-token>
  auu register [--token TOKEN] [--label MACHINE]
  auu token show <enrolment-token>

  auu relay add URL [--name NAME] [--anchor HASH] [--default]
  auu relay ls [--json]               # every relay this home knows
  auu relay show [NAME] [--json]
  auu relay default NAME              # which relay commands use when none is named
  auu relay rename OLD NEW
  auu relay rm NAME [--yes]

  auu cert status [--json]            # this machine's client certificate
  auu cert ls [--json]                # every machine on your identity
  auu cert renew

  auu anchor [status] [--json]        # the relay's trust anchor this machine pinned
  auu anchor pin HASH                 # pin one and keep the identity; HASH from auu-ca
  auu anchor forget

  auu peers add <export-line | @file | ->
  auu peers ls [--json]
  auu peers rm <name|fingerprint>
  auu peers fetch NAME|SHORT-ID|FINGERPRINT [--yes]   # add a peer found on the relay, at a terminal
  auu listed [--json]                 # who on the relay chose to be listed, verified here
  auu knock NAME|SHORT-ID|FINGERPRINT [--text "..."] [--yes]   # one message to somebody who has not admitted you

  auu allow push                     # sign your peer list and push it to every relay
  auu allow clear
  auu allow show [--json]            # what each relay holds for you, verified with your key

  auu card push [--listed] [--knocks]   # sign your card and push it to every relay
  auu card clear                     # a card that says neither; not listed, no knocks
  auu card show [--json]             # what each relay holds for you, verified with your key

  auu channel ls [PEER] [--json]      # your channels and what each relay holds, or a peer's
  auu channel create NAME [--description TEXT] [--not-before T] [--not-after T]
  auu channel update NAME [--description TEXT] [--not-before T|none] [--not-after T|none]
  auu channel close NAME [--at T]
  auu channel delete NAME
  auu channel keep NAME on|off        # whether a fetch leaves that channel's mail on the relay
  auu channel push                    # give every relay the directory as it is here
  auu channel pull                    # take the directory a relay holds, from another machine

  auu send --to NAME|self [--subject S] [--channel NAME] [--attach FILE]... [TEXT | --body-file F | - | --edit]
  auu reply MESSAGE-ID|THREAD-ID [--channel NAME] [--attach FILE]... [TEXT | --body-file F | - | --edit]
  auu send --resume

  auu inbox [--json] [--no-fetch] [--channel NAME]
  auu read MESSAGE-ID [--json]
  auu extract MESSAGE-ID [--out DIR]
  auu rm MESSAGE-ID... [--local-only | --remote-only] [--json]
  auu wait --thread THREAD-ID [--timeout 10m] [--interval 20s] [--json]
  auu watch [--event message|directory]... [--channel NAME]... [--peer NAME]...
            [--timeout 10m] [--interval 20s] [--fetch] [--json]   # return when something arrives

  auu serve [--once] [--backlog] [--config FILE] [--json]   # answer a channel for a project
  auu serve check [--config FILE]     # read serve.json and say what it would serve
  auu serve ls [--config FILE] [--json]   # what is served, and the threads it is holding
  auu serve proxy [--config FILE]     # the key-holding proxy as its own process, for another account

  auu quarantine ls [--json]
  auu quarantine show MESSAGE-ID [--json]
  auu quarantine trust MESSAGE-ID

  auu passphrase set|change|remove   # encrypt this home's keys, or stop
  auu unlock [--ttl 8h] [--passphrase-file PATH]
  auu lock
  auu agent start|stop|status [--json]

  auu version [--json]               # the version this binary was built from; --version is the same

  auu skill install [--dir DIR] [--force] [--json]   # write the Claude Code skills the binary carries
  auu skill ls [--dir DIR] [--json]  # which of them the directory holds, and whether they match
  auu skill show NAME|reference      # print one, without installing it

  auu completion zsh|bash            # print a completion script for your shell

Every command that talks to a relay takes --relay NAME. Without it the relay
is AUU_RELAY, and then the default from 'auu relay default'. Commands that
read your mail or set your policy — inbox, wait, watch, allow, channel — cover
every relay you are on unless --relay narrows them.

Run 'auu COMMAND -h' for the flags of one command.
`

// exitError carries a specific exit code out of a command.
type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string { return e.err.Error() }
func (e *exitError) Unwrap() error { return e.err }

// usageText is the usage block under whichever name the program was
// installed as. The constant is written with the short name; the long one is
// substituted, which is safe because every "auu " in it is the program.
func usageText() string { return strings.ReplaceAll(usage, "auu ", prog+" ") }

func usageErrf(format string, a ...any) error {
	return &exitError{code: exitUsage, err: fmt.Errorf(format, a...)}
}

func transportErr(err error) error {
	return &exitError{code: exitTransport, err: storageFaultHint(err)}
}

// storageFaultHint turns the relay's storage 500 into a sentence that says
// whose problem it is. Only that one 500: a 507 has its own sentences, and
// the relay's other 500 names what it could not do. The relay has logged
// the cause, once a minute per path, which is where the operator looks.
//
// The sentence wraps the error rather than replacing it, so that whatever
// decides on the failure later — a wait asking whether to try again — can
// still find the status beneath the words.
func storageFaultHint(err error) error {
	var httpErr *client.HTTPError
	if !errors.As(err, &httpErr) || httpErr.Status != http.StatusInternalServerError ||
		httpErr.Message != relayapi.MsgStorageError {
		return err
	}
	return &storageFault{err}
}

// storageFault is the relay's storage 500 with the sentence a person reads,
// and the error it came as beneath it.
type storageFault struct{ err error }

func (e *storageFault) Error() string {
	return "the relay could not store or read a message (storage error); whoever runs it needs to look at its log"
}

func (e *storageFault) Unwrap() error { return e.err }

// prog is the name this program was installed under: auu from cmd/auu,
// agentuucp from the module root. Every piece of advice the program prints
// names itself with it, so "run 'auu inbox'" is never shown to somebody who
// only has agentuucp on their PATH.
var prog = "auu"

// Main runs the command line under the given program name and exits with the
// command's code.
func Main(name string) {
	prog = name
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, prog+": "+err.Error())
		var e *exitError
		if errors.As(err, &e) {
			os.Exit(e.code)
		}
		os.Exit(exitUsage)
	}
}

func run(args []string) error {
	err := dispatch(args)
	if isLocked(err) {
		// Before the certificate advice: a handshake that failed because
		// the agent would not sign is not a certificate problem.
		return lockedErr()
	}
	if isReceiveOnly(err) {
		// The same code, the agent's other sentence: unlocked, but not to
		// originate what this command originates.
		return receiveOnlyErr()
	}
	if errors.Is(err, store.ErrDamaged) {
		// A file in this home is damaged or has been altered. The message
		// names it and what to do; the code says it is a person's to do,
		// not the skill's to retry. Before the certificate advice, which
		// would only see that a file could not be read.
		return &exitError{code: exitDamaged, err: err}
	}
	return adviseCert(err)
}

// adviseCert turns a relay's certificate refusal into the one thing the user
// can do about it.
//
// It is applied at the single exit rather than in each command because every
// command that reaches the relay can meet it, and a bare "401: this relay
// requires a client certificate" tells somebody what happened without telling
// them what to do.
func adviseCert(err error) error {
	if err == nil {
		return nil
	}
	have := false
	if s, openErr := store.OpenDefault(); openErr == nil {
		have = s.HasAnyCert()
	}
	// errors.As, not a type switch on what ClassifyCertError returns. The
	// client works one of these out for itself when a refusal arrives with
	// no alert, and by the time it reaches here a command that spans several
	// relays has wrapped it in the name of the one that failed. A type
	// switch sees the wrapper and prints the errno instead of the advice.
	classified := client.ClassifyCertError(err, have)
	var problem *client.CertProblem
	if errors.As(classified, &problem) {
		return &exitError{code: exitTransport, err: errors.New(problem.Advice(prog))}
	}
	var refused *client.CertRefused
	if errors.As(classified, &refused) {
		return &exitError{code: exitTransport, err: errors.New(refused.Advice(prog))}
	}
	// And the other end of the connection: a relay whose own certificate this
	// machine cannot verify. The message underneath is never useful, because
	// a platform verifier that has not heard of ML-DSA says something about
	// key sizes.
	pinned := false
	if s, openErr := store.OpenDefault(); openErr == nil {
		pinned = s.HasAnyAnchor()
	}
	var anchorProblem *client.AnchorProblem
	if errors.As(client.ClassifyAnchorError(err, pinned), &anchorProblem) {
		return &exitError{code: exitTransport, err: errors.New(anchorProblem.Advice(prog))}
	}
	return err
}

func dispatch(args []string) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Print(usageText())
		return nil
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "init":
		return cmdInit(rest)
	case "id":
		return cmdID(rest)
	case "lookup":
		return cmdLookup(rest)
	case "listed":
		return cmdListed(rest)
	case "knock":
		return cmdKnock(rest)
	case "enrol", "enroll":
		return cmdEnrol(rest)
	case "register":
		return cmdRegister(rest)
	case "cert":
		return cmdCert(rest)
	case "anchor":
		return cmdAnchor(rest)
	case "relay":
		return cmdRelay(rest)
	case "token":
		return cmdToken(rest)
	case "peers":
		return cmdPeers(rest)
	case "allow":
		return cmdAllow(rest)
	case "card":
		return cmdCard(rest)
	case "channel", "channels":
		return cmdChannel(rest)
	case "send":
		return cmdSend(rest)
	case "reply":
		return cmdReply(rest)
	case "inbox":
		return cmdInbox(rest)
	case "read":
		return cmdRead(rest)
	case "extract":
		return cmdExtract(rest)
	case "rm":
		return cmdRm(rest)
	case "wait":
		return cmdWait(rest)
	case "watch":
		return cmdWatch(rest)
	case "serve":
		return cmdServe(rest)
	case "quarantine":
		return cmdQuarantine(rest)
	case "passphrase":
		return cmdPassphrase(rest)
	case "unlock":
		return cmdUnlock(rest)
	case "lock":
		return cmdLock(rest)
	case "agent":
		return cmdAgent(rest)
	case "version", "--version":
		return cmdVersion(rest)
	case "skill", "skills":
		return cmdSkill(rest)
	case "completion":
		return cmdCompletion(rest)
	case "__complete":
		return cmdComplete(rest)
	default:
		return usageErrf("unknown command %q; run '%s help'", cmd, prog)
	}
}

// openStore opens the local auu home.
func openStore() (*store.Store, error) {
	s, err := store.OpenDefault()
	if err != nil {
		return nil, fmt.Errorf("opening auu home: %w", err)
	}
	return s, nil
}

// loadIdentity opens the store and the user's identity together, for a
// command that is about to use the private keys.
//
// In an encrypted home the identity is remote, and this is where a locked
// agent is dealt with before the command begins: a person at a terminal is
// asked for the passphrase, and anything else — an AI, a script — is told
// to have the person run unlock, with exit code 4. A command that needs
// only the public half calls requireIdentity instead and never gets here.
func loadIdentity() (*store.Store, *identity.Identity, error) {
	s, err := openStore()
	if err != nil {
		return nil, nil, err
	}
	id, err := s.Identity()
	if err != nil {
		return nil, nil, err
	}
	if id.Remote() {
		if err := ensureUnlocked(s, agent.ScopeReceive); err != nil {
			return nil, nil, err
		}
	}
	return s, id, nil
}

// requireIdentity opens the store and the owner's public half, for a
// command that reads mail already on disk or prints what the identity is.
// It touches no key and no agent, so it works with the identity locked.
func requireIdentity() (*store.Store, *identity.Public, error) {
	s, err := openStore()
	if err != nil {
		return nil, nil, err
	}
	self, err := s.Self()
	if err != nil {
		return nil, nil, err
	}
	return s, self, nil
}

// dial builds a client for one relay, presenting this machine's client
// certificate when it has one there.
//
// A certificate close to its expiry is renewed first, so a machine in regular
// use never reaches the day it stops working. The renewal is best-effort: see
// renewIfExpiring.
func dial(s *store.Store, id *identity.Identity, r *store.Relay) (*client.Client, error) {
	c, err := dialNoRenew(s, id, r)
	if err != nil {
		return nil, err
	}
	// A renewal retires the certificate it was authenticated with, so the
	// client that performed it is holding a revoked one. Rebuilt here, with
	// the certificate that came back, or the very next request would be
	// refused for the renewal having succeeded.
	if renewIfExpiring(s, id, c, r, time.Now()) {
		return dialNoRenew(s, id, r)
	}
	return c, nil
}

// dialNoRenew is dial without the renewal check, for the paths that are the
// renewal, or that run before this machine has a certificate at all.
func dialNoRenew(s *store.Store, id *identity.Identity, r *store.Relay) (*client.Client, error) {
	var cert *tls.Certificate
	rec, err := s.CertFor(r)
	switch {
	case err == nil:
		if cert, err = rec.TLS(); err != nil {
			// A certificate file we cannot read is worth saying out loud:
			// the alternative is a puzzling 401 from the relay.
			return nil, fmt.Errorf("%w; run '%s register --relay %s --token TOKEN' to replace it",
				err, prog, r.Name)
		}
	case errors.Is(err, store.ErrNoCert):
		// None is a state, not a failure: a relay may not use them at all,
		// and a machine not yet enrolled has none to offer.
	default:
		// A file that is there and wrong is not a file that is missing.
		// Dialling without it, as before, left the relay's refusal of a
		// certificate it never saw as the only word said; the store's
		// sentence names the file and what to run.
		return nil, err
	}
	anchor, err := pinnedAnchor(s, r)
	if err != nil {
		return nil, err
	}
	c, err := client.NewWithAnchor(r.URL, id, cert, anchor)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// dialNoCert is dialNoRenew without this machine's certificate.
//
// Registering is how a machine whose certificate the relay refuses replaces
// it, and a refusal happens in the handshake, before any route is chosen: a
// client that offered the old one would fail the very command sent to fix it,
// and the advice it printed would name that command. Neither /v1/register nor
// /v1/health reads a client certificate, so there is nothing to leave behind.
func dialNoCert(s *store.Store, id *identity.Identity, r *store.Relay) (*client.Client, error) {
	anchor, err := pinnedAnchor(s, r)
	if err != nil {
		return nil, err
	}
	return client.NewWithAnchor(r.URL, id, nil, anchor)
}

// pinnedAnchor builds the trust anchor half of a client, if this machine
// pinned one for that relay, wired to say once when the relay's authority is
// rotated and to remember it afterwards.
//
// The ratchet is the relay's own: a rotation on one relay says nothing about
// another, and comparing one relay's intermediate against another's record
// would refuse an honest relay as a replay.
func pinnedAnchor(s *store.Store, r *store.Relay) (*client.Anchor, error) {
	rec, err := s.AnchorFor(r)
	if errors.Is(err, store.ErrNoAnchor) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &client.Anchor{
		Cert:          rec.Cert,
		SeenSPKI:      r.ServerIntSPKI,
		SeenNotBefore: r.ServerIntNotBefore,
		OnRotation: func(now, before time.Time) {
			fmt.Fprintf(os.Stderr,
				"%s: the server certificate authority of %s was rotated: issued %s, "+
					"replacing one issued %s. Only the relay operator's offline authority "+
					"can issue one, so this is a rotation, not an attack; recorded.\n",
				prog, r.Name,
				now.Local().Format(client.StampFormat), before.Local().Format(client.StampFormat))
		},
		OnSeen: func(spki string, notBefore time.Time) error {
			return s.SeenIntermediateFor(r, spki, notBefore)
		},
	}, nil
}

// relayFlag registers --relay on a command that talks to one. It is here
// rather than in each command so that the flag is spelled once, and so that a
// command which talks to no relay is the one that has to do something
// different: not registering it makes --relay the usual unknown-flag error.
func relayFlag(fs *flag.FlagSet) *string {
	return fs.String("relay", "",
		"which relay to use: a name from 'auu relay ls', or its URL")
}

// selectRelay is the relay a command acts on: --relay, then AUU_RELAY, then
// the home's default. It refuses with the list of relays when there is none,
// because "which relay" is not a question somebody can answer without it.
func selectRelay(s *store.Store, flag string) (*store.Relay, error) {
	query := strings.TrimSpace(flag)
	source := "--relay"
	if query == "" {
		query, source = strings.TrimSpace(os.Getenv("AUU_RELAY")), "AUU_RELAY"
	}
	if query != "" {
		r, err := s.Relay(query)
		if err != nil {
			return nil, usageErrf("%s: %v", source, err)
		}
		return r, nil
	}
	r, err := s.DefaultRelay()
	if errors.Is(err, store.ErrNoDefaultRelay) {
		relays, listErr := s.Relays()
		if listErr != nil {
			return nil, listErr
		}
		if len(relays) == 0 {
			return nil, usageErrf("this home is not on any relay yet; join one with "+
				"'%s enrol --name NAME TOKEN', or add one with '%s relay add URL'", prog, prog)
		}
		return nil, usageErrf("no relay selected: pass --relay NAME, set AUU_RELAY, "+
			"or run '%s relay default NAME'; this home has %s", prog, s.RelayNames())
	}
	if err != nil {
		return nil, err
	}
	return r, nil
}

// relayOf is the relay a stored message came through, which is where a reply
// to it goes and where its payload still is.
//
// An explicit --relay overrides it: somebody who says which relay they mean
// means it. Every record names its relay; Load refused one that does not.
func relayOf(s *store.Store, m *store.Stored, flag string) (*store.Relay, error) {
	if strings.TrimSpace(flag) != "" {
		return selectRelay(s, flag)
	}
	r, err := s.Relay(m.Relay)
	if errors.Is(err, store.ErrNoSuchRelay) {
		return nil, usageErrf("that message came through %s, which has been removed; pass --relay", m.Relay)
	}
	if err != nil {
		return nil, err
	}
	return r, nil
}

// selectedRelays is what a command that covers your whole mail acts on:
// every relay you are registered on, or just the one named. inbox, wait and
// allow use it, because "what mail do I have" is not a question about one
// relay.
func selectedRelays(s *store.Store, flag string) ([]*store.Relay, error) {
	if strings.TrimSpace(flag) != "" || strings.TrimSpace(os.Getenv("AUU_RELAY")) != "" {
		r, err := selectRelay(s, flag)
		if err != nil {
			return nil, err
		}
		return []*store.Relay{r}, nil
	}
	relays, err := s.Relays()
	if err != nil {
		return nil, err
	}
	var out []*store.Relay
	for _, r := range relays {
		if s.Registered(r) {
			out = append(out, r)
		}
	}
	if len(out) == 0 {
		// Not registered anywhere the home knows of. Fall back to the single
		// relay rule so the failure names a relay rather than nothing.
		r, err := selectRelay(s, flag)
		if err != nil {
			return nil, err
		}
		return []*store.Relay{r}, nil
	}
	return out, nil
}

func ctx() context.Context { return context.Background() }

// readText resolves message text from a positional argument, a file, or stdin.
func readText(positional []string, bodyFile string) (string, error) {
	text, err := rawText(positional, bodyFile)
	if err != nil {
		return "", err
	}
	return foldCRLF(text), nil
}

// rawText is the text as it was given, from the arguments, a file or
// standard input.
func rawText(positional []string, bodyFile string) (string, error) {
	switch {
	case bodyFile != "" && len(positional) > 0:
		return "", usageErrf("give message text or --body-file, not both")
	case bodyFile != "":
		data, err := os.ReadFile(bodyFile)
		if err != nil {
			return "", usageErrf("reading --body-file: %v", err)
		}
		return string(data), nil
	case len(positional) == 1 && positional[0] == "-":
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return "", fmt.Errorf("reading stdin: %w", err)
		}
		return string(data), nil
	case len(positional) > 0:
		return strings.Join(positional, " "), nil
	default:
		// No text given at all: read stdin if it is a pipe, otherwise complain.
		info, err := os.Stdin.Stat()
		if err == nil && (info.Mode()&os.ModeCharDevice) == 0 {
			data, err := io.ReadAll(os.Stdin)
			if err != nil {
				return "", fmt.Errorf("reading stdin: %w", err)
			}
			return string(data), nil
		}
		return "", usageErrf("no message text: pass it as an argument, with --body-file, or on stdin")
	}
}

// foldCRLF is the one place a message's text is made ready for the rule:
// a Windows line ending becomes a line break, since a file or an editor
// there writes CRLF and a refusal naming U+000D at every send would be the
// wrong sentence for an honest file. A carriage return on its own is left
// for the rule to refuse; the wire rule is unchanged, and a receiver from
// this build refuses a text with one however it was sent.
func foldCRLF(s string) string { return strings.ReplaceAll(s, "\r\n", "\n") }

// stringList collects a repeatable flag.
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

// newFlagSet builds a flag set that reports usage errors as exit code 1.
func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	return fs
}

// Flag introspection, for completion. When flagSink is set and a command is
// run with the sentinel as its only argument, parseArgs records the command's
// flag set into the sink and returns errFlagsListed instead of parsing. This
// is how completion asks a command for its real flags, rather than keeping a
// copy of them that would drift; every command builds its flags and calls
// parseArgs before it does anything else, so nothing else happens.
var (
	flagSink       *[]flagInfo
	errFlagsListed = errors.New("flags listed")
)

const flagsSentinel = "--__flags"

type flagInfo struct {
	name   string
	usage  string
	isBool bool
}

// parseArgs parses flags that may appear before, after, or between positional
// arguments. Go's flag package stops at the first positional, which would make
// "auu read ID --json" silently ignore the flag.
func parseArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	if flagSink != nil && len(args) == 1 && args[0] == flagsSentinel {
		fs.VisitAll(func(f *flag.Flag) {
			b, ok := f.Value.(interface{ IsBoolFlag() bool })
			*flagSink = append(*flagSink, flagInfo{name: f.Name, usage: f.Usage, isBool: ok && b.IsBoolFlag()})
		})
		return nil, errFlagsListed
	}
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, &exitError{code: exitUsage, err: err}
		}
		if fs.NArg() == 0 {
			return positional, nil
		}
		positional = append(positional, fs.Arg(0))
		args = fs.Args()[1:]
	}
}
