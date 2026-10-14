package auu

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tropeforce7/agentuucp/internal/lockfile"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// A streamed message's files are replaced only once the replacement is
// whole (G29, R44). The same sealed stream can come through two of a
// recipient's relays, and the second delivery saves over the first's
// record; it used to remove the first's files before its download began,
// so a download that failed left the record naming files that were gone.
// Now the download is staged under a name of its own, and only a whole,
// verified copy is swapped in: the old files moved aside, the new ones
// renamed into place, the record saved, and the old ones removed; a
// failure before the save puts the old ones back. Between the swap and the
// save the old record names the new files, which are the same bytes, by
// the manifest's hashes, so a crash there loses nothing.

// spoolLockWait is how long a swap waits for another to finish: a swap is
// two renames and a record's save.
var spoolLockWait = 30 * time.Second

// replaceSpool fills a staged copy of dir with fill, then swaps it in and
// saves the record with save, under the home's spool lock. fill is given a
// path that does not exist and must create it whole or not at all.
func replaceSpool(ctx context.Context, s *store.Store, dir string, fill func(target string) error, save func() error) error {
	var tag [8]byte
	if _, err := rand.Read(tag[:]); err != nil {
		return err
	}
	staged := dir + ".new-" + hex.EncodeToString(tag[:])
	// The staged copy is held by a lock of its own for as long as this
	// delivery runs, so a later swap tells one being written from one a
	// process left behind when it died (sweepStaged).
	own, err := lockfile.Try(staged + stagedLockSuffix)
	if err != nil {
		return err
	}
	defer func() {
		own.Release()
		os.Remove(staged + stagedLockSuffix)
	}()
	if err := fill(staged); err != nil {
		return err
	}
	lock, _, err := lockfile.Take(ctx, s.SpoolLockPath(), spoolLockWait, nil)
	if err != nil {
		os.RemoveAll(staged)
		return err
	}
	defer lock.Release()
	sweepStaged(filepath.Dir(dir))

	aside := dir + ".old"
	// A swap a crash cut short: the old files aside and none in place
	// are put back; the old files aside beside a placed copy are the
	// same bytes, and go.
	if _, err := os.Lstat(aside); err == nil {
		if _, err := os.Lstat(dir); errors.Is(err, fs.ErrNotExist) {
			if err := os.Rename(aside, dir); err != nil {
				os.RemoveAll(staged)
				return err
			}
		} else if err := os.RemoveAll(aside); err != nil {
			os.RemoveAll(staged)
			return err
		}
	}
	_, statErr := os.Lstat(dir)
	hadOld := statErr == nil
	if hadOld {
		if err := os.Rename(dir, aside); err != nil {
			os.RemoveAll(staged)
			return err
		}
	}
	putBack := func() {
		if hadOld {
			os.RemoveAll(dir)
			os.Rename(aside, dir)
		}
	}
	if err := os.Rename(staged, dir); err != nil {
		os.RemoveAll(staged)
		putBack()
		return err
	}
	if err := save(); err != nil {
		if hadOld {
			putBack()
		} else {
			// A first delivery whose record would not save leaves no
			// files that no record names.
			os.RemoveAll(dir)
		}
		return err
	}
	if hadOld {
		os.RemoveAll(aside)
	}
	return nil
}

// stagedLockSuffix names the lock beside a staged copy.
const stagedLockSuffix = ".lock"

// sweepStaged removes, from a box's directory, the staged copies of
// deliveries whose process died before their swap: the download cut short
// by an interrupt or a crash, which ToDirectory's .part and the staged name
// are, and which nothing else would ever remove. A staged copy whose lock
// is still held is a delivery under way and is left alone; one whose lock
// can be taken has no process behind it. Run under the spool lock.
func sweepStaged(boxDir string) {
	locks, err := filepath.Glob(filepath.Join(boxDir, "*.d.new-*"+stagedLockSuffix))
	if err != nil {
		return
	}
	for _, path := range locks {
		l, err := lockfile.Try(path)
		if err != nil {
			continue
		}
		base := strings.TrimSuffix(path, stagedLockSuffix)
		os.RemoveAll(base + ".part")
		os.RemoveAll(base)
		l.Release()
		os.Remove(path)
	}
}
