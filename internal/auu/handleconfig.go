package auu

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/tropeforce7/agentuucp/internal/channels"
	"github.com/tropeforce7/agentuucp/internal/store"
	"github.com/tropeforce7/agentuucp/internal/wire"
)

// handle.json: the table of scripts this machine runs on asks.
//
// A route takes the asks on one channel of this home's mailbox and runs a
// program the host named for each, with the message as files and
// environment variables and never on its command line. The file is the
// host's, read at start and never written, as serve.json is.

// handleFile is the file's name in the home. --config names another.
const handleFile = "handle.json"

// How a route runs its jobs: one at a time in the order they were taken,
// or several at once.
const (
	executionSequential = "sequential"
	executionParallel   = "parallel"
)

// Defaults, which are what the file leaves out, and the bounds it is held
// to. A route's timeout and retries default as a served channel's do.
const (
	defaultWorkersTotal   = 2
	defaultParallel       = 2
	defaultMaxQueued      = 1000
	defaultMaxQueuedBytes = 1 << 30
	defaultMaxLogBytes    = 1 << 20
	defaultKeepFailed     = 168 * time.Hour
	maxHandleWorkers      = 64
	minMaxLogBytes        = 4096
)

// handleConfig is the file.
type handleConfig struct {
	V              int                     `json:"v"`
	WorkersTotal   int                     `json:"workers_total,omitempty"`
	SupervisorReap bool                    `json:"supervisor_reaps,omitempty"`
	Routes         map[string]*handleRoute `json:"routes"`
	// path is where it was read from, for the sentences.
	path string
}

// handleRoute is one route's row. The durations are text in the file and
// parsed once, so that a bad one is refused by name at check rather than
// met at a launch.
type handleRoute struct {
	Channel        string   `json:"channel"`
	Command        []string `json:"command"`
	Execution      string   `json:"execution,omitempty"`
	MaxParallel    int      `json:"max_parallel,omitempty"`
	Idempotent     bool     `json:"idempotent,omitempty"`
	Timeout        string   `json:"timeout,omitempty"`
	Retries        int      `json:"retries,omitempty"`
	MaxQueued      int      `json:"max_queued,omitempty"`
	MaxQueuedBytes int64    `json:"max_queued_bytes,omitempty"`
	MaxLogBytes    int64    `json:"max_log_bytes,omitempty"`
	MaxReplyBytes  int64    `json:"max_reply_bytes,omitempty"`
	KeepFailed     string   `json:"keep_failed,omitempty"`

	name       string
	timeout    time.Duration
	keepFailed time.Duration
	// program is the command's first element as it will be run: a path
	// with a separator resolved against the file's directory at load, a
	// bare name looked up on the PATH at check.
	program string
}

// handlePath is the file this run reads: --config, or handle.json in the
// home.
func handlePath(s *store.Store, flag string) string {
	if strings.TrimSpace(flag) != "" {
		return flag
	}
	return filepath.Join(s.Root(), handleFile)
}

// loadHandleConfig reads the file and fills in what it left out. It is read
// strictly: an unknown key, a key twice, a key that matches only by case
// and trailing data are each refused by name, since a misspelled setting
// that did nothing would be a route run otherwise than its host wrote.
func loadHandleConfig(path string) (*handleConfig, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, usageErrf("no %s; a handle service is one file, and there is none here. "+
			"Write it and check it with '%s handle check'", path, prog)
	}
	if err != nil {
		return nil, err
	}
	cfg := &handleConfig{path: path}
	if err := wire.Decode(data, cfg); errors.Is(err, wire.ErrTrailing) {
		return nil, usageErrf("%s: trailing data after the JSON object", path)
	} else if err != nil {
		return nil, usageErrf("%s: %v", path, err)
	}
	if cfg.V != 1 {
		return nil, usageErrf("%s: v is %d; this %s understands version 1", path, cfg.V, prog)
	}
	if len(cfg.Routes) == 0 {
		return nil, usageErrf("%s: no routes; a handle file that handles nothing is a mistake, not a setting", path)
	}
	if cfg.WorkersTotal == 0 {
		cfg.WorkersTotal = defaultWorkersTotal
	}
	base := filepath.Dir(path)
	for _, name := range cfg.names() {
		r := cfg.Routes[name]
		// The strict decode takes null for a pointer as nil, so a route
		// written as null is refused here by name, before anything reads it.
		if r == nil {
			return nil, cfg.errf(name, "it is null; a route is an object, with channel and command at least")
		}
		r.name = name
		if r.Execution == "" {
			r.Execution = executionSequential
		}
		if r.MaxParallel == 0 {
			r.MaxParallel = 1
			if r.Execution == executionParallel {
				r.MaxParallel = defaultParallel
			}
		}
		if r.Retries == 0 {
			r.Retries = defaultRetries
		}
		if r.MaxQueued == 0 {
			r.MaxQueued = defaultMaxQueued
		}
		if r.MaxQueuedBytes == 0 {
			r.MaxQueuedBytes = defaultMaxQueuedBytes
		}
		if r.MaxLogBytes == 0 {
			r.MaxLogBytes = defaultMaxLogBytes
		}
		// A program named with a separator is a path, and a relative one is
		// relative to the file, not to the directory a unit started handle
		// in; a bare name is the PATH's, looked up at check.
		if len(r.Command) > 0 && hasSeparator(r.Command[0]) {
			r.program = resolveAgainst(base, r.Command[0])
		}
		errf := func(format string, a ...any) error { return cfg.errf(name, format, a...) }
		r.timeout, err = duration(errf, "timeout", r.Timeout, defaultTimeout)
		if err != nil {
			return nil, err
		}
		r.keepFailed, err = duration(errf, "keep_failed", r.KeepFailed, defaultKeepFailed)
		if err != nil {
			return nil, err
		}
	}
	return cfg, nil
}

// hasSeparator says whether a program is named as a path rather than as a
// name for the PATH: a separator anywhere, or, on Windows, a volume.
func hasSeparator(program string) bool {
	return strings.ContainsRune(program, '/') || strings.ContainsRune(program, filepath.Separator) ||
		filepath.VolumeName(program) != ""
}

// names is every route in the file, in order, so that two runs say the
// same things in the same order.
func (cfg *handleConfig) names() []string {
	out := make([]string, 0, len(cfg.Routes))
	for name := range cfg.Routes {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// channels is every route's channel, in the routes' order.
func (cfg *handleConfig) channels() []string {
	var out []string
	for _, name := range cfg.names() {
		out = append(out, cfg.Routes[name].Channel)
	}
	return out
}

// errf is a refusal that names the file, the route and what is wrong with
// it, since a person reading it is looking at the file.
func (cfg *handleConfig) errf(route, format string, a ...any) error {
	return usageErrf("%s: route %q: %s", cfg.path, route, fmt.Sprintf(format, a...))
}

// check is every rule the file must satisfy, over every route, without
// connecting anywhere: the names, the channels, the programs and the
// numbers. It is what 'auu handle check' runs, so that a file with a typo
// in it is refused whole rather than one route at a time.
func (cfg *handleConfig) check() error {
	if cfg.WorkersTotal < 0 {
		return usageErrf("%s: workers_total is %d; it cannot be fewer than none", cfg.path, cfg.WorkersTotal)
	}
	if cfg.WorkersTotal > maxHandleWorkers {
		return usageErrf("%s: workers_total is %d, more workers than this %s runs (%d at most)",
			cfg.path, cfg.WorkersTotal, prog, maxHandleWorkers)
	}
	names := cfg.names()
	byChannel := map[string]string{}
	for i, name := range names {
		r := cfg.Routes[name]
		if err := channels.ValidName(name); err != nil {
			return cfg.errf(name, "%v", err)
		}
		// A route id is a directory under handle/jobs/ and handle/kept/;
		// none of those is a message id's shape today, but the rule costs
		// nothing and keeps a route from ever meeting one.
		if threadShaped(name) {
			return cfg.errf(name, "a name of 32 hex characters is the shape of a message id; rename it")
		}
		// Two ids that fold to one are one directory on macOS and Windows,
		// and would share their jobs.
		for _, earlier := range names[:i] {
			if strings.EqualFold(earlier, name) {
				return cfg.errf(name, "routes %q and %q are one directory where case does not count; rename one", earlier, name)
			}
		}
		if r.Channel == "" {
			return cfg.errf(name, "channel is required: it is the channel whose asks the route handles")
		}
		if err := channels.ValidName(r.Channel); err != nil {
			return cfg.errf(name, "channel %q: %v", r.Channel, err)
		}
		// Fan-out is not in this version: an ask is one job, under one
		// route, and two routes on a channel would be two.
		if other, ok := byChannel[r.Channel]; ok {
			return cfg.errf(name, "routes %q and %q are both on channel %q; a channel belongs to one route", other, name, r.Channel)
		}
		byChannel[r.Channel] = name
		if err := r.checkCommand(cfg); err != nil {
			return err
		}
		switch r.Execution {
		case executionSequential, executionParallel:
		default:
			return cfg.errf(name, "execution %q is neither %s nor %s", r.Execution, executionSequential, executionParallel)
		}
		if r.MaxParallel < 0 {
			return cfg.errf(name, "max_parallel is %d; it cannot be fewer than none", r.MaxParallel)
		}
		if r.Execution == executionSequential && r.MaxParallel > 1 {
			return cfg.errf(name, "a sequential route runs one at a time; drop max_parallel or make it parallel")
		}
		if r.MaxParallel > maxHandleWorkers {
			return cfg.errf(name, "max_parallel is %d, more than this %s runs at once (%d at most)", r.MaxParallel, prog, maxHandleWorkers)
		}
		if r.MaxParallel > cfg.WorkersTotal {
			return usageErrf("%s: workers_total is %d, fewer than route %q's max_parallel of %d, which could never all run",
				cfg.path, cfg.WorkersTotal, name, r.MaxParallel)
		}
		if r.Retries < 0 {
			return cfg.errf(name, "retries is %d; it cannot be fewer than none", r.Retries)
		}
		if r.MaxQueued < 0 {
			return cfg.errf(name, "max_queued is %d; it cannot be fewer than none", r.MaxQueued)
		}
		if r.MaxQueuedBytes < 0 {
			return cfg.errf(name, "max_queued_bytes is %d; it cannot be fewer than none", r.MaxQueuedBytes)
		}
		if r.MaxLogBytes < 0 {
			return cfg.errf(name, "max_log_bytes is %d; it cannot be fewer than none", r.MaxLogBytes)
		}
		if r.MaxLogBytes < minMaxLogBytes {
			return cfg.errf(name, "max_log_bytes is %d, too small to hold a sentence (%d at least)", r.MaxLogBytes, minMaxLogBytes)
		}
		if r.MaxReplyBytes < 0 {
			return cfg.errf(name, "max_reply_bytes is %d; it cannot be fewer than none", r.MaxReplyBytes)
		}
	}
	return nil
}

// checkCommand holds a route's command to what can be run: a list whose
// first element names a program that is there as a regular file, and no
// element a program could not be given. Nothing is run. There is no check
// of the executable bit, since Windows has none; a program that cannot be
// run says so in its own words at its first attempt.
func (r *handleRoute) checkCommand(cfg *handleConfig) error {
	if len(r.Command) == 0 {
		return cfg.errf(r.name, "command is required: it is the program to run and its arguments, as a list")
	}
	if strings.TrimSpace(r.Command[0]) == "" {
		return cfg.errf(r.name, "command's first element is empty; it is the program to run")
	}
	for i, arg := range r.Command {
		if strings.ContainsRune(arg, 0) {
			return cfg.errf(r.name, "command's element %d holds a NUL, which no program's argument can carry", i)
		}
	}
	if r.program == "" {
		found, err := exec.LookPath(r.Command[0])
		if err != nil {
			return cfg.errf(r.name, "command's program %q is not on the PATH: %v", r.Command[0], err)
		}
		r.program = found
	}
	info, err := os.Stat(r.program)
	if errors.Is(err, os.ErrNotExist) {
		return cfg.errf(r.name, "command's program %s does not exist", r.program)
	}
	if err != nil {
		return cfg.errf(r.name, "command's program %s: %v", r.program, err)
	}
	if !info.Mode().IsRegular() {
		return cfg.errf(r.name, "command's program %s is not a regular file", r.program)
	}
	return nil
}

// checkFolds asks the disk under handleDir whether it takes two route ids
// as one directory, which check, comparing case alone, cannot see (serve's
// probe, shared). It runs after check.
func (cfg *handleConfig) checkFolds(handleDir string) error {
	earlier, name, err := checkFolds(handleDir, "route", cfg.names())
	if earlier != "" {
		return cfg.errf(name, "routes %q and %q are one directory on this filesystem, which takes them as one name; rename one", earlier, name)
	}
	return err
}

// checkAgainstServe refuses a route on a channel serve answers, naming
// both files. serve.json is read from its place in the home whatever
// --config named for handle, since that is the one serve.json either side
// can see; a serve run with --config elsewhere is beyond it, which the
// guide says. A serve.json that will not read is refused here too, since
// nothing can then say which channels it serves.
func (cfg *handleConfig) checkAgainstServe(s *store.Store) error {
	path := filepath.Join(s.Root(), serveFile)
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	served, err := loadServeConfig(path)
	if err != nil {
		return usageErrf("%s: its routes are checked against %s, which will not read: %v", cfg.path, path, err)
	}
	for _, name := range cfg.names() {
		channel := cfg.Routes[name].Channel
		if _, ok := served.Channels[channel]; ok {
			return cfg.errf(name, "channel %q is served by %s; a channel belongs to one service, serve's or handle's", channel, path)
		}
	}
	return nil
}

// warnDefault says that a route on the default channel takes the asks
// there and nothing else: a reply to one of its acknowledgements arrives on
// default too, and is left unhandled, as every reply is.
func (cfg *handleConfig) warnDefault() {
	for _, name := range cfg.names() {
		if cfg.Routes[name].Channel == channels.Default {
			fmt.Fprintf(os.Stderr, "%s: route %q handles the default channel: a reply to one of its acknowledgements arrives there and is left unhandled, as every reply is\n",
				prog, name)
		}
	}
}

// loadHandle reads and checks the file a run names, every rule of it:
// what 'auu handle check' runs before it says anything.
func loadHandle(s *store.Store, config string) (*handleConfig, error) {
	cfg, err := loadHandleConfig(handlePath(s, config))
	if err != nil {
		return nil, err
	}
	if err := cfg.check(); err != nil {
		return nil, err
	}
	if err := cfg.checkFolds(s.HandleDir()); err != nil {
		return nil, err
	}
	if err := cfg.checkAgainstServe(s); err != nil {
		return nil, err
	}
	return cfg, nil
}

func cmdHandle(args []string) error {
	fs := newFlagSet("handle")
	config := fs.String("config", "", "the file to read instead of handle.json in the home")
	once := fs.Bool("once", false, "one round: fetch, take the asks, run what is runnable, and stop")
	backlog := fs.Bool("backlog", false, "at a route's first round, run the asks already in the inbox instead of leaving them")
	asJSON := fs.Bool("json", false, "machine readable output")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	switch {
	case len(positional) == 1 && positional[0] == "check":
		return handleCheck(*config)
	case len(positional) == 1 && positional[0] == "run":
		return handleRunCmd(*config, *once, *backlog, *asJSON)
	default:
		return usageErrf("usage: %s handle check [--config FILE], or %s handle run [--once] [--backlog] [--config FILE] [--json]", prog, prog)
	}
}

// handleCheck reads the file and says what it would run, without touching
// a key, a relay or the network: it is what a host runs after editing it.
func handleCheck(config string) error {
	s, err := openStore()
	if err != nil {
		return err
	}
	cfg, err := loadHandle(s, config)
	if err != nil {
		return err
	}
	for _, name := range cfg.names() {
		r := cfg.Routes[name]
		if r.Execution == executionParallel {
			fmt.Printf("%s: channel %q, parallel, up to %d at once\n", name, r.Channel, r.MaxParallel)
		} else {
			fmt.Printf("%s: channel %q, sequential\n", name, r.Channel)
		}
		quoted := make([]string, len(r.Command))
		for i, arg := range r.Command {
			quoted[i] = fmt.Sprintf("%q", arg)
		}
		fmt.Printf("  command:  %s\n", strings.Join(quoted, " "))
		fmt.Printf("  program:  %s\n", r.program)
		fmt.Printf("  jobs:     %s\n", filepath.Join(s.HandleDir(), "jobs", name))
		if r.Idempotent {
			fmt.Printf("  retries:  %d, idempotent: a failed attempt is run again\n", r.Retries)
		} else {
			fmt.Printf("  retries:  %d, not idempotent: a started attempt that fails is not run again\n", r.Retries)
		}
		reply := "no cap"
		if r.MaxReplyBytes > 0 {
			reply = fmt.Sprintf("%d bytes", r.MaxReplyBytes)
		}
		fmt.Printf("  limits:   timeout %s, max_queued %d, max_queued_bytes %d, max_log_bytes %d, max_reply_bytes %s, keep_failed %s\n",
			r.timeout, r.MaxQueued, r.MaxQueuedBytes, r.MaxLogBytes, reply, r.keepFailed)
	}
	reaps := "no"
	if cfg.SupervisorReap {
		reaps = "yes"
	}
	fmt.Printf("\nworkers_total %d, supervisor_reaps %s\n", cfg.WorkersTotal, reaps)
	fmt.Printf("\n%s is good for %s\n", cfg.path, plural(len(cfg.Routes), "route"))
	cfg.warnDefault()
	warnKept(s, cfg.channels())
	return nil
}
