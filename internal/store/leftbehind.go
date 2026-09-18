package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// leftBehindFile records the messages this machine removed from its own
// spool alone, with 'auu rm --local-only', and deliberately left queued on
// the relay. It is the only thing that remembers them: the record is gone,
// so without it the next fetch would find the relay counting mail this
// machine's cursor is past and report a damaged home, telling its owner to
// delete the cursor and fetch again — exactly what they chose not to do.
// It is one relay id per line, and the refresh at the end of a fetch drops
// an id the relay no longer lists.
const leftBehindFile = "left-behind"

const leftBehindAdvice = "fix it, or delete it; it records only the messages you removed here and left " +
	"on the relay, and without it a fetch may say this machine's cursor is past mail"

// LeftBehind is the relay ids this machine removed locally and left on that
// relay, ascending. A relay with no file has none.
func (s *Store) LeftBehind(relayName string) ([]int64, error) {
	if err := ValidRelayName(relayName); err != nil {
		return nil, err
	}
	path := filepath.Join(s.relayDir(relayName), leftBehindFile)
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var ids []int64
	for n, line := range strings.Split(string(data), "\n") {
		text := strings.TrimSpace(line)
		if text == "" {
			continue
		}
		id, err := strconv.ParseInt(text, 10, 64)
		if err != nil || id <= 0 {
			return nil, damaged(path, fmt.Sprintf("has %q on line %d, which is not a message id", text, n+1),
				nil, leftBehindAdvice)
		}
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids, nil
}

// AddLeftBehind records one more, and is a no-op for an id already there.
func (s *Store) AddLeftBehind(relayName string, id int64) error {
	ids, err := s.LeftBehind(relayName)
	if err != nil {
		return err
	}
	for _, have := range ids {
		if have == id {
			return nil
		}
	}
	return s.SetLeftBehind(relayName, append(ids, id))
}

// SetLeftBehind writes the list, whole, and removes the file when there is
// nothing left to remember. The relay's directory is made if it is not
// there, as the cursor's writer makes it.
func (s *Store) SetLeftBehind(relayName string, ids []int64) error {
	// The rule at the call, as SaveRelay runs it: the store's exported
	// edge is a boundary of its own.
	if err := ValidRelayName(relayName); err != nil {
		return err
	}
	path := filepath.Join(s.relayDir(relayName), leftBehindFile)
	if len(ids) == 0 {
		err := os.Remove(path)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	var b strings.Builder
	var last int64
	for _, id := range ids {
		if id == last {
			continue
		}
		fmt.Fprintf(&b, "%d\n", id)
		last = id
	}
	if err := os.MkdirAll(s.relayDir(relayName), dirMode); err != nil {
		return err
	}
	return writeFileAtomic(path, []byte(b.String()), fileMode)
}
