package auu

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/tropeforce7/agentuucp/internal/channels"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/store"
	"github.com/tropeforce7/agentuucp/internal/wire"
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
	// Proxy is the key-holding proxy, absent for a host whose handler is
	// given no key by serve at all; see serveproxy.go.
	Proxy *proxyConfig `json:"proxy,omitempty"`
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
	if err := wire.Decode(data, cfg); errors.Is(err, wire.ErrTrailing) {
		return nil, usageErrf("%s: trailing data after the JSON object", path)
	} else if err != nil {
		return nil, usageErrf("%s: %v", path, err)
	}
	if cfg.V != 1 {
		return nil, usageErrf("%s: v is %d; this %s understands version 1", path, cfg.V, prog)
	}
	if len(cfg.Channels) == 0 {
		return nil, usageErrf("%s: no channels; a serve file that serves nothing is a mistake, not a setting", path)
	}
	// A relative path in the file is relative to the file, not to the
	// working directory a wrapper or a supervisor started serve in.
	base := filepath.Dir(path)
	for _, name := range cfg.names() {
		ch := cfg.Channels[name]
		// The strict decode takes null for a pointer as nil, so a channel
		// written as null is refused here by name, before anything reads it.
		if ch == nil {
			return nil, cfg.errf(name, "it is null; a channel is an object, with dir and exec at least")
		}
		ch.name = name
		if ch.Mode == "" {
			ch.Mode = modeReadOnly
		}
		ch.Dir = resolveAgainst(base, ch.Dir)
		if ch.MaxTurns == 0 {
			ch.MaxTurns = defaultMaxTurns
		}
		if ch.Retries == 0 {
			ch.Retries = defaultRetries
		}
		errf := func(format string, a ...any) error { return cfg.errf(name, format, a...) }
		ch.timeout, err = duration(errf, "timeout", ch.Timeout, defaultTimeout)
		if err != nil {
			return nil, err
		}
		ch.threadTTL, err = duration(errf, "thread_ttl", ch.ThreadTTL, defaultThreadTTL)
		if err != nil {
			return nil, err
		}
	}
	if cfg.Proxy != nil {
		cfg.Proxy.fill()
		cfg.Proxy.KeyFile = resolveAgainst(base, cfg.Proxy.KeyFile)
		cfg.Proxy.Control = resolveAgainst(base, cfg.Proxy.Control)
	}
	return cfg, nil
}

// resolveAgainst is a path setting from a file made absolute against the
// file's own directory; an absolute one, an empty one, and one that is
// only whitespace (which check refuses) are left as they are.
func resolveAgainst(base, value string) string {
	if strings.TrimSpace(value) == "" || filepath.IsAbs(value) {
		return value
	}
	return filepath.Join(base, value)
}

// duration parses one of a file's durations, or gives the default. errf
// is the file's refusal for the row the duration is in, serve.json's for
// a channel and handle.json's for a route.
func duration(errf func(format string, a ...any) error, field, text string, fallback time.Duration) (time.Duration, error) {
	if strings.TrimSpace(text) == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(text)
	if err != nil {
		return 0, errf("%s %q is not a length of time (30m, 2h, 168h)", field, text)
	}
	if d <= 0 {
		return 0, errf("%s is %s; it must be more than nothing", field, text)
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

// checkAgainstHandle refuses a channel a route of handle.json takes,
// naming both files, the converse of handle's checkAgainstServe. handle.json
// is read from its place in the home whatever --config named for serve,
// since that is the one handle.json either side can see. A handle.json that
// will not read is refused here too, since nothing can then say which
// channels its routes take.
func (cfg *serveConfig) checkAgainstHandle(s *store.Store) error {
	path := filepath.Join(s.Root(), handleFile)
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	handled, err := loadHandleConfig(path)
	if err != nil {
		return usageErrf("%s: its channels are checked against %s, which will not read: %v", cfg.path, path, err)
	}
	for _, name := range cfg.names() {
		for _, route := range handled.names() {
			if handled.Routes[route].Channel == name {
				return cfg.errf(name, "route %q of %s takes it; a channel belongs to one service, serve's or handle's", route, path)
			}
		}
	}
	return nil
}

// checkFolds asks the disk under serveDir whether it takes two channel
// names as one directory, which check, comparing case alone, cannot see: a
// filesystem that folds Unicode normalisation, as APFS does, takes é
// composed and é decomposed as one name, and the standard library has no
// table to say so (S63). It runs after check, whose rule every name has met
// before it is joined onto anything.
func (cfg *serveConfig) checkFolds(serveDir string) error {
	earlier, name, err := checkFolds(serveDir, "channel", cfg.names())
	if earlier != "" {
		return cfg.errf(name, "channels %q and %q are one directory on this filesystem, which takes them as one name; rename one", earlier, name)
	}
	return err
}

// checkFolds is the probe both services' files are held to, serve's
// channels under serve/ and handle's routes under handle/: what names the
// kind of name, for the probe's directory and the sentence. It makes a
// directory of its own under dir, on the filesystem the names' directories
// are on, so a running service's directories are never touched and two
// checks never meet; makes each name in it in order, a name the disk
// answers as already there being one it folds onto an earlier; and removes
// the directory whatever happened. Two names the disk takes as one come
// back as earlier and name, for the caller's sentence; every name has met
// its file's rule before it is given here.
func checkFolds(dir, what string, names []string) (earlier, name string, err error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", err
	}
	probe, err := os.MkdirTemp(dir, "."+what+"-names-")
	if err != nil {
		return "", "", fmt.Errorf("asking the disk under %s whether it folds the %ss' names: %w", dir, what, err)
	}
	defer os.RemoveAll(probe)
	var made []string
	for _, name := range names {
		path := filepath.Join(probe, name)
		err := os.Mkdir(path, 0o700)
		if errors.Is(err, fs.ErrExist) {
			for _, earlier := range made {
				if sameDir(filepath.Join(probe, earlier), path) {
					return earlier, name, nil
				}
			}
		}
		if err != nil {
			return "", "", fmt.Errorf("asking the disk under %s whether it folds the %ss' names: %w", dir, what, err)
		}
		made = append(made, name)
	}
	return "", "", nil
}

// check is every rule the file must satisfy, over every channel, without
// connecting anywhere: the names, the directories, the programs and the
// numbers. It is what 'auu serve check' runs and what 'auu serve' runs
// before it takes its lock, so that a file with a typo in it stops the
// service rather than one channel of it.
func (cfg *serveConfig) check() error {
	names := cfg.names()
	for i, name := range names {
		ch := cfg.Channels[name]
		if err := channels.ValidName(name); err != nil {
			return cfg.errf(name, "%v", err)
		}
		// A read-only channel's worktree is worktrees/<channel>, beside a
		// side copy's worktrees/<thread>, and a thread id is what a
		// sender chooses: a channel named as one, in either case since
		// the filesystem may fold it, would share a thread's directory,
		// and letting the thread go would remove it (F7).
		if threadShaped(name) {
			return cfg.errf(name, "a name of 32 hex characters is the shape of a thread id, whose worktree is in the same directory as a channel's; rename it")
		}
		// Each channel is a directory under serve/channels/, and in
		// read-only mode that directory holds the worktree's base; two
		// names that fold to one are one directory on macOS and Windows,
		// and would share it.
		for _, earlier := range names[:i] {
			if strings.EqualFold(earlier, name) {
				return cfg.errf(name, "channels %q and %q are one directory where case does not count; rename one", earlier, name)
			}
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
	// A side copy's patch is taken with the base after --end-of-options,
	// which git has from 2.24. A version line that cannot be read is left
	// to fail where git is used, in git's words.
	if line, err := gitOutput("", "--version"); err == nil && !gitAtLeast(line, 2, 24) {
		return usageErrf("%s is older than 2.24, which auu serve needs", line)
	}
	if cfg.Proxy != nil {
		if err := cfg.Proxy.check(cfg); err != nil {
			return err
		}
	}
	return nil
}

// threadShaped says whether a name has a thread id's shape, 32 hex
// characters, in either case.
func threadShaped(name string) bool {
	return len(name) == 32 && message.ValidID(strings.ToLower(name)) == nil
}

// gitAtLeast says whether git's version line, "git version 2.54.0" with
// whatever a packager adds after it, is at least major.minor. A line it
// cannot read is taken as new enough.
func gitAtLeast(line string, major, minor int) bool {
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return true
	}
	parts := strings.SplitN(fields[2], ".", 3)
	if len(parts) < 2 {
		return true
	}
	gotMajor, err1 := strconv.Atoi(parts[0])
	gotMinor, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return true
	}
	return gotMajor > major || gotMajor == major && gotMinor >= minor
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

// warnKept says which of the channels a service reads keep their mail on
// the relay: serve's channels, or handle's routes' channels. Keep is on for
// every channel unless its owner turned it off, so a message a service
// answers stays queued until the owner removes it, and a service answering
// all year would fill its own mailbox and refuse its askers. Said by name,
// at the start of every run, and by 'serve check' and 'handle check'.
func warnKept(s *store.Store, names []string) {
	settings, err := s.ChannelSettings()
	if err != nil {
		// A file that will not read is said by the fetch, which is about to
		// read it too; nothing here is worth failing a service for.
		return
	}
	var kept []string
	for _, name := range names {
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
	return plainList(quoted)
}

// plainList is a list of words as a sentence reads them: "a", "a and b",
// "a, b and c".
func plainList(words []string) string {
	switch len(words) {
	case 0:
		return ""
	case 1:
		return words[0]
	case 2:
		return words[0] + " and " + words[1]
	default:
		return strings.Join(words[:len(words)-1], ", ") + " and " + words[len(words)-1]
	}
}
