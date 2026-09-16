package auu

import (
	"encoding/json"
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
)

// serve.json: the table of what this machine answers for.
//
// An expert host speaks for several projects, one channel each, and that
// table belongs in a file its owner edits rather than on a command line
// repeated in a unit file. It is read at start and never written: nothing
// in auu edits it, so a person's comments about their own machine are
// theirs to keep.

// serveFile is the file's name in the home. --config names another.
const serveFile = "serve.json"

// The modes a channel is served in: the reply is the handler's text alone,
// or the handler's text and the worktree's change so far.
const (
	modeReadOnly = "read-only"
	modeSideCopy = "side-copy"
)

// Defaults, which are what the file leaves out.
const (
	defaultTimeout   = 30 * time.Minute
	defaultMaxTurns  = 50
	defaultRetries   = 3
	defaultThreadTTL = 168 * time.Hour
)

// serveConfig is the file.
type serveConfig struct {
	V        int                      `json:"v"`
	Channels map[string]*serveChannel `json:"channels"`
	// path is where it was read from, for the sentences.
	path string
}

// serveChannel is one channel's row. The durations are text in the file and
// parsed once, so that a bad one is refused by name rather than met at the
// moment a handler was about to run.
type serveChannel struct {
	Dir       string `json:"dir"`
	Exec      string `json:"exec"`
	Mode      string `json:"mode,omitempty"`
	Before    string `json:"before,omitempty"`
	After     string `json:"after,omitempty"`
	Timeout   string `json:"timeout,omitempty"`
	MaxTurns  int    `json:"max_turns,omitempty"`
	Retries   int    `json:"retries,omitempty"`
	ThreadTTL string `json:"thread_ttl,omitempty"`

	name      string
	timeout   time.Duration
	threadTTL time.Duration
}

// servePath is the file this run reads: --config, or serve.json in the home.
func servePath(s *store.Store, flag string) string {
	if strings.TrimSpace(flag) != "" {
		return flag
	}
	return filepath.Join(s.Root(), serveFile)
}

// loadServeConfig reads the file and fills in what it left out. Unknown keys
// are an error, as they are everywhere in this project: a misspelled one
// that silently did nothing would be a channel nobody was serving.
func loadServeConfig(path string) (*serveConfig, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, usageErrf("no %s; an expert host is one file, and there is none here. "+
			"Write it and check it with '%s serve check'", path, prog)
	}
	if err != nil {
		return nil, err
	}
	cfg := &serveConfig{path: path}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(cfg); err != nil {
		return nil, usageErrf("%s: %v", path, err)
	}
	if cfg.V != 1 {
		return nil, usageErrf("%s: v is %d; this %s understands version 1", path, cfg.V, prog)
	}
	if len(cfg.Channels) == 0 {
		return nil, usageErrf("%s: no channels; a serve file that serves nothing is a mistake, not a setting", path)
	}
	for _, name := range cfg.names() {
		ch := cfg.Channels[name]
		ch.name = name
		if ch.Mode == "" {
			ch.Mode = modeReadOnly
		}
		if ch.MaxTurns == 0 {
			ch.MaxTurns = defaultMaxTurns
		}
		if ch.Retries == 0 {
			ch.Retries = defaultRetries
		}
		ch.timeout, err = duration(cfg, name, "timeout", ch.Timeout, defaultTimeout)
		if err != nil {
			return nil, err
		}
		ch.threadTTL, err = duration(cfg, name, "thread_ttl", ch.ThreadTTL, defaultThreadTTL)
		if err != nil {
			return nil, err
		}
	}
	return cfg, nil
}

// duration parses one of the file's durations, or gives the default.
func duration(cfg *serveConfig, channel, field, text string, fallback time.Duration) (time.Duration, error) {
	if strings.TrimSpace(text) == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(text)
	if err != nil {
		return 0, cfg.errf(channel, "%s %q is not a length of time (30m, 2h, 168h)", field, text)
	}
	if d <= 0 {
		return 0, cfg.errf(channel, "%s is %s; it must be more than nothing", field, text)
	}
	return d, nil
}

// names is every channel in the file, in order, so that two runs say the
// same things in the same order.
func (cfg *serveConfig) names() []string {
	out := make([]string, 0, len(cfg.Channels))
	for name := range cfg.Channels {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// errf is a refusal that names the file, the channel and what is wrong with
// it, since a person reading it is looking at the file.
func (cfg *serveConfig) errf(channel, format string, a ...any) error {
	return usageErrf("%s: channel %q: %s", cfg.path, channel, fmt.Sprintf(format, a...))
}

// check is every rule the file must satisfy, over every channel, without
// connecting anywhere: the names, the directories, the programs and the
// numbers. It is what 'auu serve check' runs and what 'auu serve' runs
// before it takes its lock, so that a file with a typo in it stops the
// service rather than one channel of it.
func (cfg *serveConfig) check() error {
	for _, name := range cfg.names() {
		ch := cfg.Channels[name]
		if err := channels.ValidName(name); err != nil {
			return cfg.errf(name, "%v", err)
		}
		switch ch.Mode {
		case modeReadOnly, modeSideCopy:
		default:
			return cfg.errf(name, "mode %q is neither %s nor %s", ch.Mode, modeReadOnly, modeSideCopy)
		}
		if strings.TrimSpace(ch.Dir) == "" {
			return cfg.errf(name, "dir is required: it is the checkout the worktrees are made from")
		}
		if err := gitRepository(ch.Dir); err != nil {
			return cfg.errf(name, "%v", err)
		}
		if strings.TrimSpace(ch.Exec) == "" {
			return cfg.errf(name, "exec is required: it is the program that answers")
		}
		if ch.MaxTurns < 1 {
			return cfg.errf(name, "max_turns is %d; a channel that answers nothing is not served", ch.MaxTurns)
		}
		if ch.Retries < 0 {
			return cfg.errf(name, "retries is %d; it cannot be fewer than none", ch.Retries)
		}
	}
	if _, err := exec.LookPath("git"); err != nil {
		return usageErrf("git is not on the PATH, and every channel is served from a git worktree: %v", err)
	}
	return nil
}

// gitRepository says whether a directory is one, in the terms a person can
// act on. A worktree's own .git is a file rather than a directory, which is
// why only its presence is asked about.
func gitRepository(dir string) error {
	info, err := os.Stat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("dir %s does not exist", dir)
	}
	if err != nil {
		return fmt.Errorf("dir %s: %v", dir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("dir %s is not a directory", dir)
	}
	if _, err := os.Stat(filepath.Join(dir, ".git")); err != nil {
		return fmt.Errorf("dir %s is not a git repository (no .git); "+
			"the worktree a handler runs in is what keeps it off the checkout", dir)
	}
	return nil
}

// warnKept says which served channels keep their mail on the relay. Keep is
// on for every channel unless its owner turned it off, so a message serve
// answers stays queued until the owner removes it, and an expert answering
// all year would fill its own mailbox and refuse its askers. Said by name,
// at the start of every run, and by 'serve check'.
func warnKept(s *store.Store, cfg *serveConfig) {
	settings, err := s.ChannelSettings()
	if err != nil {
		// A file that will not read is said by the fetch, which is about to
		// read it too; nothing here is worth failing a service for.
		return
	}
	var kept []string
	for _, name := range cfg.names() {
		// Absent is kept, which is the default for every channel.
		if one, ok := settings.Channels[name]; !ok || one.Keep {
			kept = append(kept, name)
		}
	}
	if len(kept) == 0 {
		return
	}
	fmt.Fprintf(os.Stderr,
		"%s: mail answered on %s stays on the relay until you remove it, and a mailbox that fills refuses your askers; "+
			"run '%s channel keep NAME off' for each, or '%s rm' for what is there\n",
		prog, quotedList(kept), prog, prog)
}

// quotedList is a list of names as a sentence reads them.
func quotedList(names []string) string {
	quoted := make([]string, len(names))
	for i, n := range names {
		quoted[i] = fmt.Sprintf("%q", n)
	}
	switch len(quoted) {
	case 1:
		return quoted[0]
	case 2:
		return quoted[0] + " and " + quoted[1]
	default:
		return strings.Join(quoted[:len(quoted)-1], ", ") + " and " + quoted[len(quoted)-1]
	}
}
