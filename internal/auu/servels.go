package auu

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	"github.com/tropeforce7/agentuucp/internal/message"
)

// auu serve ls, and the sweep: what an expert host is holding, and the
// letting go of what it no longer needs.

// serveInterval is how often a relay that cannot hold a listing open is
// asked between rounds. It is the watch's own default, and there is no
// setting for it: a relay that can hold answers the moment mail arrives,
// and one that cannot is not made faster by asking harder. A test
// shortens it.
var serveInterval = 20 * time.Second

// serveLsJSON is what --json gives.
type serveLsJSON struct {
	Channels []servedChannelJSON `json:"channels"`
}

type servedChannelJSON struct {
	Name string `json:"name"`
	Dir  string `json:"dir"`
	Mode string `json:"mode"`
	// Worktree is the channel's own, which only a read-only channel has.
	Worktree string             `json:"worktree,omitempty"`
	Threads  []servedThreadJSON `json:"threads"`
}

type servedThreadJSON struct {
	Thread string    `json:"thread"`
	Turns  int       `json:"turns"`
	Last   time.Time `json:"last"`
	// Worktree is the thread's own, which only a side-copy thread has.
	Worktree string `json:"worktree,omitempty"`
}

// serveLs says what is served and what state is being kept for it. It needs
// no key and touches no relay: it is the file and the ledger, read.
func serveLs(config string, asJSON bool) error {
	s, err := openStore()
	if err != nil {
		return err
	}
	cfg, err := loadServeConfig(servePath(s, config))
	if err != nil {
		return err
	}
	root := s.ServeDir()
	led, err := loadLedger(filepath.Join(root, ledgerFile))
	if err != nil {
		return err
	}
	out := serveLsJSON{Channels: []servedChannelJSON{}}
	for _, name := range cfg.names() {
		ch := cfg.Channels[name]
		row := servedChannelJSON{Name: name, Dir: ch.Dir, Mode: ch.Mode, Threads: []servedThreadJSON{}}
		if ch.Mode == modeReadOnly {
			row.Worktree = existingDir(filepath.Join(root, "worktrees", name))
		}
		for _, thread := range threadsOn(led, name) {
			t := servedThreadJSON{Thread: thread, Turns: led.answered(thread), Last: lastOn(led, thread)}
			// A thread the ledger holds under a name that is not a message
			// id was refused by handle and has no worktree; the name is
			// not joined onto a path to find out.
			if ch.Mode == modeSideCopy && message.ValidID(thread) == nil {
				t.Worktree = existingDir(filepath.Join(root, "worktrees", thread))
			}
			row.Threads = append(row.Threads, t)
		}
		out.Channels = append(out.Channels, row)
	}
	if asJSON {
		return printJSON(out)
	}
	for _, row := range out.Channels {
		fmt.Printf("%s: %s in %s\n", row.Name, row.Mode, row.Dir)
		if row.Worktree != "" {
			fmt.Printf("  worktree: %s\n", row.Worktree)
		}
		if len(row.Threads) == 0 {
			fmt.Println("  no threads yet")
			continue
		}
		for _, t := range row.Threads {
			fmt.Printf("  %s  %s  last %s\n", threadName(t.Thread), plural(t.Turns, "turn"), stampLocal(t.Last))
			if t.Worktree != "" {
				fmt.Printf("    %s\n", t.Worktree)
			}
		}
	}
	return nil
}

// threadName is a thread id as 'ls' prints it: the short form of an id, and
// of anything else, which only a record written by hand puts in the ledger,
// the same twelve bytes quoted, so that they cannot reach the terminal as
// anything but text.
func threadName(thread string) string {
	if message.ValidID(thread) == nil {
		return shortID(thread)
	}
	return strconv.Quote(shortID(thread))
}

// threadsOn is every thread the ledger holds for a channel, latest first,
// leaving out the ones that were only ever skipped: they are there so that
// old mail is not answered, not because anything was done with them.
func threadsOn(led *ledger, channel string) []string {
	last := map[string]time.Time{}
	for _, e := range led.Messages {
		if e.Channel != channel || e.Skipped {
			continue
		}
		if t := e.last(); t.After(last[e.Thread]) {
			last[e.Thread] = t
		} else if _, seen := last[e.Thread]; !seen {
			last[e.Thread] = t
		}
	}
	out := make([]string, 0, len(last))
	for thread := range last {
		out = append(out, thread)
	}
	sort.Slice(out, func(i, j int) bool {
		if !last[out[i]].Equal(last[out[j]]) {
			return last[out[i]].After(last[out[j]])
		}
		return out[i] < out[j]
	})
	return out
}

// lastOn is when a thread was last touched, by the ledger.
func lastOn(led *ledger, thread string) time.Time {
	var last time.Time
	for _, e := range led.Messages {
		if e.Thread == thread && e.last().After(last) {
			last = e.last()
		}
	}
	return last
}

// existingDir is the path if it is there, and nothing if it is not: 'ls'
// says what is, not what would be.
func existingDir(path string) string {
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		return path
	}
	return ""
}

// sweep lets go of the threads nothing has touched for thread_ttl: the
// state directory, and in side-copy the worktree. The ledger keeps their
// ids, so a swept message is not answered a second time.
//
// A read-only channel's worktree and channel directory are never swept:
// they are the channel's, they hold the warm session's memory of the
// project, and they last as long as the channel is in the file.
func (r *serveRun) sweep() error {
	dir := filepath.Join(r.root, "threads")
	entries, err := os.ReadDir(dir)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	now := time.Now()
	for _, e := range entries {
		// An entry serve made is a directory named by a thread id; anything
		// else under threads/ is not serve's to let go of, and its name is
		// never joined onto the worktrees directory.
		if !e.IsDir() || message.ValidID(e.Name()) != nil {
			continue
		}
		thread := e.Name()
		last, ttl, sweepable := r.threadIdle(thread, filepath.Join(dir, thread))
		if !sweepable || now.Sub(last) <= ttl {
			continue
		}
		if err := r.letGo(thread, filepath.Join(dir, thread)); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "%s: thread %s has been idle for %s; its working copy is gone\n",
			prog, shortID(thread), ttl)
	}
	return r.sweepKept()
}

// sweepKept lets go of serve's kept directory for a thread whose own
// directory is gone, removed by hand, so that kept/ does not grow for
// ever: it is aged as a thread is, by the ledger, or by the directory's
// own time where the ledger has nothing for it, and one with anything
// unsettled is kept. Only a directory named by a thread id is serve's.
func (r *serveRun) sweepKept() error {
	dir := filepath.Join(r.root, "kept")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	now := time.Now()
	for _, e := range entries {
		if !e.IsDir() || message.ValidID(e.Name()) != nil {
			continue
		}
		thread := e.Name()
		stateDir := filepath.Join(r.root, "threads", thread)
		if _, err := os.Lstat(stateDir); !errors.Is(err, fs.ErrNotExist) {
			continue
		}
		last, ttl, sweepable := r.threadIdle(thread, filepath.Join(dir, thread))
		if !sweepable || now.Sub(last) <= ttl {
			continue
		}
		if err := r.letGo(thread, stateDir); err != nil {
			return err
		}
	}
	return nil
}

// threadIdle is when a thread was last touched and which ttl applies, and
// whether it may be swept at all.
//
// A thread with anything unsettled is work: a message being tried again, or
// one whose reply is written and waiting for a relay to come back, needs
// exactly the state this would delete. A thread the ledger has no time for
// — a directory left by hand, or one from a ledger since moved aside, whose
// entries are only skipped — is aged by the directory's own time, which is
// the best there is.
// The ttl is the channel's that answered it, and the default for a channel
// that has since left the file, since state under the home should not grow
// for ever because somebody stopped serving something.
func (r *serveRun) threadIdle(thread, path string) (last time.Time, ttl time.Duration, sweepable bool) {
	ttl = defaultThreadTTL
	for _, e := range r.led.Messages {
		if e.Thread != thread {
			continue
		}
		if !e.settled() {
			return time.Time{}, ttl, false
		}
		if t := e.last(); t.After(last) {
			last = t
		}
		if ch := r.cfg.Channels[e.Channel]; ch != nil {
			ttl = ch.threadTTL
		}
	}
	if last.IsZero() {
		info, err := os.Stat(path)
		if err != nil {
			return last, ttl, false
		}
		last = info.ModTime()
	}
	return last, ttl, true
}

// letGo removes one thread's worktree, its state directory and serve's kept
// directory for it. The worktree
// goes through git where the channel that made it is still in the file, so
// that the registration in the checkout goes with it; where it is not, the
// directory is removed and the next worktree made from that checkout prunes
// what is left.
func (r *serveRun) letGo(thread, stateDir string) error {
	worktree := filepath.Join(r.root, "worktrees", thread)
	if _, err := os.Stat(worktree); err == nil {
		removed := false
		for _, e := range r.led.Messages {
			if e.Thread != thread {
				continue
			}
			if ch := r.cfg.Channels[e.Channel]; ch != nil {
				if _, err := gitRun(ch.Dir, "worktree", "remove", "--force", worktree); err == nil {
					removed = true
				}
				break
			}
		}
		if !removed {
			if err := os.RemoveAll(worktree); err != nil {
				return err
			}
		}
	}
	if err := os.RemoveAll(filepath.Join(r.root, "kept", thread)); err != nil {
		return err
	}
	return os.RemoveAll(stateDir)
}

// printJSONLine is one object on one line, for the long run's report: a
// round to a line makes a log something a reader can follow. A line that
// cannot be written is the error, as printJSON's is (G47, R62), and the
// run ends with it as --once does; the round's work is done and kept by
// then, so nothing of it is done again.
func printJSONLine(v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = fmt.Println(string(data))
	return err
}
