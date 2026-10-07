package relay

import (
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
)

// Admins is an administrator file as it was loaded: the keys it held, by
// fingerprint, and the size and modification time it had, so that a relay
// handed the set can tell when the file has changed since.
type Admins struct {
	Keys    map[string]*identity.Public
	Size    int64
	ModTime time.Time
}

// LoadAdmins reads a relay's authorized administrator file: export lines in
// exactly the format a user keeps in authorized_peers, parsed by exactly the
// same code.
//
// This is the ssh authorized_keys model. It means the relay holds an
// administrator's public key directly, so an administrator need not be a
// registered user of the relay to administer it, and there is no bootstrap
// problem: the operator puts the first line in the file.
//
// The size and time recorded are from before the read, so a write that
// lands during it is seen as a change on the next look rather than missed.
func LoadAdmins(path string) (*Admins, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("admin file: %w", err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("admin file %s is a directory", path)
	}
	// This file decides who may administer the relay. Anyone who can write it
	// can appoint themselves. The check is Unix's: on Windows, Go makes a
	// FileMode up from the read-only attribute — 0666 or 0444, whoever the
	// file belongs to — and it says nothing about who can write, so the
	// check would refuse every file there and protect nothing.
	if perm := info.Mode().Perm(); runtime.GOOS != "windows" && perm&0o022 != 0 {
		return nil, fmt.Errorf("admin file %s is mode %04o: it must not be writable "+
			"by group or others, since whoever can write it can administer the relay", path, perm)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("admin file: %w", err)
	}
	keys, err := identity.ParseExportLines(path, data)
	if err != nil {
		return nil, err
	}
	admins := &Admins{Keys: map[string]*identity.Public{}, Size: info.Size(), ModTime: info.ModTime()}
	for _, pub := range keys {
		admins.Keys[pub.Fingerprint()] = pub
	}
	return admins, nil
}

// adminSet is the live view of that file.
//
// It holds the set loaded at start, so the first request is served from what
// start had, and re-reads the file when its size or modification time
// changes, checked on the requests that need it, so appointing or removing
// an administrator is an edit rather than a restart. A read that fails after
// startup keeps the last good set: a truncated or half-written file must not
// lock every administrator out of a relay that is under attack.
type adminSet struct {
	path string
	log  *slog.Logger

	mu       sync.Mutex
	admins   map[string]*identity.Public
	size     int64
	modTime  time.Time
	complain bool // whether the next failure is worth a line
}

// newAdminSet starts from the set loaded at start, when the caller has one,
// and loads the file itself when it was given the path alone, so that a relay
// never serves its first request from an empty set on a file it was told
// about. A file that cannot be loaded here leaves the relay with no
// administrators until it can be, and says so once.
func newAdminSet(path string, loaded *Admins, log *slog.Logger) *adminSet {
	a := &adminSet{path: path, log: log, admins: map[string]*identity.Public{}, complain: true}
	if path == "" {
		return a
	}
	if loaded == nil {
		var err error
		if loaded, err = LoadAdmins(path); err != nil {
			log.Warn("admin file could not be read at start; this relay has no administrators until it can be",
				"path", path, "err", err)
			// This is the run of failures' one line; the next is when the
			// file loads.
			a.complain = false
			return a
		}
	}
	a.admins, a.size, a.modTime = loaded.Keys, loaded.Size, loaded.ModTime
	return a
}

// enabled reports whether this relay has an administrator file at all. Without
// one there is no admin API.
func (a *adminSet) enabled() bool { return a != nil && a.path != "" }

// lookup returns an administrator's key, refreshing from disk first if the
// file has changed.
func (a *adminSet) lookup(fp string) (*identity.Public, bool) {
	if !a.enabled() {
		return nil, false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.refreshLocked()
	pub, ok := a.admins[fp]
	return pub, ok
}

// count reports how many administrators the relay currently recognises.
func (a *adminSet) count() int {
	if !a.enabled() {
		return 0
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.refreshLocked()
	return len(a.admins)
}

func (a *adminSet) refreshLocked() {
	info, err := os.Stat(a.path)
	if err != nil {
		a.warn("admin file could not be read; keeping the administrators loaded earlier", err)
		return
	}
	if info.Size() == a.size && info.ModTime().Equal(a.modTime) {
		return
	}
	admins, err := LoadAdmins(a.path)
	if err != nil {
		a.warn("admin file could not be reloaded; keeping the administrators loaded earlier", err)
		return
	}
	a.admins, a.size, a.modTime = admins.Keys, admins.Size, admins.ModTime
	a.complain = true
	// An operator who edits the file wants to see that the relay took it,
	// and one who did not wants to know that somebody did.
	a.log.Info("administrators reloaded", "count", len(a.admins), "path", a.path)
}

// warn logs once per run of failures, so a file that has been deleted does not
// produce a line on every request.
func (a *adminSet) warn(msg string, err error) {
	if !a.complain {
		return
	}
	a.complain = false
	a.log.Warn(msg, "path", a.path, "err", err, "administrators", len(a.admins))
}

// AdminFileMode is the loosest mode an admin file may have.
const AdminFileMode fs.FileMode = 0o755
