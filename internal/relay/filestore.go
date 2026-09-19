package relay

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"

	"github.com/tropeforce7/agentuucp/internal/regular"
)

// Message bodies live one to a file, under a directory beside the database.
// SQLite keeps the index, the counters, and the transaction that makes them
// agree; it is bad at holding a gigabyte in a single value and good at
// everything else here.
//
// The path is derived and never stored: messages/<fp[:2]>/<fp>/<id>. Both
// components are validated long before they reach this file — a fingerprint is
// 64 lowercase hex characters, an id is an integer SQLite issued — so there is
// nothing in a path that a caller chose. Sharding on the first two characters
// keeps the top directory at 256 entries however many mailboxes there are.

const (
	// dirMode and fileMode are what the relay creates. Nobody but the relay's
	// own user has any business reading stored mail, ciphertext or not.
	dirMode  fs.FileMode = 0o700
	fileMode fs.FileMode = 0o600

	// tmpName holds writes in progress. A file here is never visible to a
	// read, and everything in it is removed at startup.
	tmpName = "tmp"
)

func (s *Store) mailboxDir(fp string) string { return filepath.Join(s.dir, fp[:2], fp) }

func (s *Store) messagePath(fp string, id int64) string {
	return filepath.Join(s.mailboxDir(fp), strconv.FormatInt(id, 10))
}

func (s *Store) tmpDir() string { return filepath.Join(s.dir, tmpName) }

// storageErr turns a full disk into the answer the sender should get. An
// operator running out of room is a 507 and a message that says so, not a 500
// that says nothing.
func storageErr(err error) error {
	if errors.Is(err, syscall.ENOSPC) || errors.Is(err, syscall.EDQUOT) {
		return fmt.Errorf("%w: %v", ErrRelayFull, err)
	}
	return err
}

// writeTemp writes raw to a uniquely named file under tmp/ and returns its
// path. The caller renames it into place, or removes it.
func (s *Store) writeTemp(raw []byte) (string, error) {
	var name [16]byte
	if _, err := rand.Read(name[:]); err != nil {
		return "", err
	}
	path := filepath.Join(s.tmpDir(), hex.EncodeToString(name[:]))
	// A fault here is reported against the directory: the file's name is
	// random and the file is gone, and it is the directory the operator
	// looks at — and the once-a-minute limit needs one path to count.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, fileMode)
	if err != nil {
		return "", s.fault(s.tmpDir(), err)
	}
	if _, err := f.Write(raw); err != nil {
		f.Close()
		os.Remove(path)
		return "", s.fault(s.tmpDir(), err)
	}
	// Durable before it is visible: a message the relay has answered 200 for
	// is on disk, whatever happens next.
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(path)
		return "", s.fault(s.tmpDir(), err)
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return "", s.fault(s.tmpDir(), err)
	}
	return path, nil
}

// place moves a temp file to its final path and makes the directory entry
// durable too, so a crash cannot leave the file findable only by inode.
func (s *Store) place(tmp, fp string, id int64) error {
	dir := s.mailboxDir(fp)
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return s.fault(dir, err)
	}
	if err := os.Rename(tmp, s.messagePath(fp, id)); err != nil {
		return s.fault(s.messagePath(fp, id), err)
	}
	return s.fault(dir, fsyncDir(dir))
}

// fsyncDir makes a directory's entries durable. Windows has no such call:
// a directory handle cannot be flushed, and NTFS journals the metadata
// itself, so there the rename is left to the filesystem and the file's own
// fsync above is the whole of the guarantee. The relay is deployed on
// Linux; this is what lets its tests run on Windows.
func fsyncDir(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	// Opened by the handle: what is synced is the directory, and a link
	// planted under its name is refused rather than followed.
	d, err := regular.Dir(path)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// readMessage returns a stored envelope. A missing file is reported as such so
// callers can tell it from a read that failed for another reason.
func (s *Store) readMessage(fp string, id int64) ([]byte, error) {
	raw, err := regular.ReadFile(s.messagePath(fp, id))
	return raw, s.fault(s.messagePath(fp, id), err)
}

// removeMessage unlinks one stored envelope, tolerating its absence.
func (s *Store) removeMessage(fp string, id int64) error {
	if err := os.Remove(s.messagePath(fp, id)); err != nil && !os.IsNotExist(err) {
		return s.fault(s.messagePath(fp, id), err)
	}
	return nil
}

// removeMailboxFiles takes a mailbox's whole directory. Used when the mailbox
// itself is being deregistered.
func (s *Store) removeMailboxFiles(fp string) error {
	if err := os.RemoveAll(s.mailboxDir(fp)); err != nil {
		return s.fault(s.mailboxDir(fp), err)
	}
	// The shard directory is shared, so it is only removed when it empties.
	os.Remove(filepath.Join(s.dir, fp[:2]))
	return nil
}

// prepareDirs creates the message tree. It is called on every open, so a
// directory removed by hand comes back rather than failing the next post.
func (s *Store) prepareDirs() error {
	for _, d := range []string{s.dir, s.tmpDir(), s.uploadDir()} {
		if err := os.MkdirAll(d, dirMode); err != nil {
			return fmt.Errorf("relay: message directory: %w", err)
		}
	}
	return nil
}

// mailboxesHoldingFiles counts the mailbox directories with at least one file
// in them. It reads directory entries and nothing else.
func (s *Store) mailboxesHoldingFiles() (int, error) {
	shards, err := os.ReadDir(s.dir)
	if err != nil {
		return 0, err
	}
	held := 0
	for _, shard := range shards {
		if !shard.IsDir() || shard.Name() == tmpName || shard.Name() == uploadsName {
			continue
		}
		boxes, err := os.ReadDir(filepath.Join(s.dir, shard.Name()))
		if err != nil {
			return 0, err
		}
		for _, box := range boxes {
			if !box.IsDir() {
				continue
			}
			files, err := os.ReadDir(filepath.Join(s.dir, shard.Name(), box.Name()))
			if err != nil {
				return 0, err
			}
			for _, f := range files {
				if !f.IsDir() {
					held++
					break
				}
			}
		}
	}
	return held, nil
}

// SweepResult is what the startup sweep found and put right.
type SweepResult struct {
	// Temp files left by a write that never completed.
	Temp int
	// Files with no row: a crash between the rename and the commit.
	Orphans int
	// Rows with no file, or a file of the wrong size: corruption, or somebody
	// editing the directory by hand. The rows are removed.
	Missing int
}

// Empty reports whether the sweep found nothing to put right.
func (r SweepResult) Empty() bool { return r.Temp == 0 && r.Orphans == 0 && r.Missing == 0 }

// sweep reconciles the directory against the table.
//
// It reads directory entries and stats, never file contents, so it costs one
// stat per message and opens nothing.
func (s *Store) sweep() (SweepResult, error) {
	var res SweepResult

	entries, err := os.ReadDir(s.tmpDir())
	if err != nil {
		return res, err
	}
	for _, e := range entries {
		// The relay writes files here and nothing else; a directory is
		// somebody's and is left where it is rather than failing the start.
		if e.IsDir() {
			continue
		}
		if err := os.Remove(filepath.Join(s.tmpDir(), e.Name())); err != nil {
			return res, err
		}
		res.Temp++
	}

	// Every row, so that both directions can be checked in one pass.
	rows, err := s.db.Query(`SELECT to_fp, id, size FROM messages`)
	if err != nil {
		return res, err
	}
	type key struct {
		fp string
		id int64
	}
	want := map[key]int64{}
	for rows.Next() {
		var k key
		var size int64
		if err := rows.Scan(&k.fp, &k.id, &size); err != nil {
			rows.Close()
			return res, err
		}
		want[k] = size
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return res, err
	}

	// Files that no row claims.
	shards, err := os.ReadDir(s.dir)
	if err != nil {
		return res, err
	}
	for _, shard := range shards {
		if !shard.IsDir() || shard.Name() == tmpName || shard.Name() == uploadsName {
			continue
		}
		boxes, err := os.ReadDir(filepath.Join(s.dir, shard.Name()))
		if err != nil {
			return res, err
		}
		for _, box := range boxes {
			if !box.IsDir() {
				continue
			}
			dir := filepath.Join(s.dir, shard.Name(), box.Name())
			files, err := os.ReadDir(dir)
			if err != nil {
				return res, err
			}
			for _, f := range files {
				// A mailbox holds body files and nothing else; a directory
				// in one is somebody's, and is neither a message nor an
				// orphan to remove.
				if f.IsDir() {
					continue
				}
				// A body file is named by its id's digits and nothing else:
				// a name that parses to the same number another way, "+7"
				// or "007", is not that message's file and is an orphan.
				id, convErr := strconv.ParseInt(f.Name(), 10, 64)
				if convErr == nil && strconv.FormatInt(id, 10) != f.Name() {
					convErr = errors.New("not a canonical id")
				}
				k := key{fp: box.Name(), id: id}
				size, claimed := want[k]
				info, statErr := f.Info()
				switch {
				case convErr != nil || !claimed:
					if err := os.Remove(filepath.Join(dir, f.Name())); err != nil {
						return res, err
					}
					res.Orphans++
				case statErr == nil && info.Size() != size:
					// A file that disagrees with its row is no better than a
					// missing one: the row is what quotas were computed from.
					delete(want, k)
					if err := s.dropMessageRow(k.fp, k.id); err != nil {
						return res, err
					}
					if err := os.Remove(filepath.Join(dir, f.Name())); err != nil {
						return res, err
					}
					res.Missing++
				default:
					delete(want, k)
				}
			}
		}
	}

	// Whatever is left in want has a row and no file.
	for k := range want {
		if err := s.dropMessageRow(k.fp, k.id); err != nil {
			return res, err
		}
		res.Missing++
	}
	return res, nil
}

// dropMessageRow removes one row and its counters, for the sweep. Ordinary
// deletion goes through Delete.
func (s *Store) dropMessageRow(fp string, id int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var size int64
	err = tx.QueryRow(`SELECT size FROM messages WHERE to_fp = ? AND id = ?`, fp, id).Scan(&size)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM messages WHERE to_fp = ? AND id = ?`, fp, id); err != nil {
		return err
	}
	if err := adjustCounters(tx, fp, -1, -size); err != nil {
		return err
	}
	return tx.Commit()
}
