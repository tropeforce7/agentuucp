package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/regular"
)

// leftBehindFile records the messages this machine removed from its own
// spool alone, with 'auu rm --local-only', and deliberately left queued on
// the relay. It is the only thing that remembers them: the record is gone,
// so without it the next fetch would find the relay counting mail this
// machine's cursor is past and report a damaged home, telling its owner to
// delete the cursor and fetch again — exactly what they chose not to do.
//
// It is one message per line: the relay's id for it, its own id from inside
// the seal, the time the relay received it and the size the relay listed it
// at, separated by single spaces. The relay id is what the count and the
// refresh at the end of a fetch go by, and the refresh drops an entry the
// relay no longer lists. The other three name the message whatever the relay
// calls it: a relay whose numbering began again lists other mail under the
// old ids, and a cursor reset finds a message removed here by its own id and
// does not deliver it again. A received time of zero and a size of zero are
// a message whose record could not be read when it was removed, which the
// cheap check before a re-fetch cannot match and the re-fetch still can.
const leftBehindFile = "left-behind"

const leftBehindAdvice = "fix it, or delete it; it records only the messages you removed here and left " +
	"on the relay, and without it a fetch may say this machine's cursor is past mail"

// leftBehindOldShape is the advice for a file written before a line said
// which message it was: it is refused rather than read, since nothing on
// this machine is from before, and deleting it costs what it says.
const leftBehindOldShape = "delete it; it was written before this file named each message by its own id, " +
	"and without it a message you removed here alone may come back once"

// LeftEntry is one message removed here alone and left on a relay.
type LeftEntry struct {
	// RelayID is the relay's id for it when it was left.
	RelayID int64
	// ID is the message's own id, from inside the seal.
	ID string
	// Received is when the relay received it, as the relay listed it;
	// zero when the record it was removed from could not be read.
	Received time.Time
	// Size is the size the relay listed it at; zero likewise.
	Size int64
}

// LeftBehind is the messages this machine removed locally and left on that
// relay, ascending by relay id. A relay with no file has none.
func (s *Store) LeftBehind(relayName string) ([]LeftEntry, error) {
	if err := ValidRelayName(relayName); err != nil {
		return nil, err
	}
	path := filepath.Join(s.relayDir(relayName), leftBehindFile)
	data, err := regular.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []LeftEntry
	for n, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Split(line, " ")
		if len(fields) == 1 {
			if id, err := strconv.ParseInt(fields[0], 10, 64); err == nil && id > 0 {
				return nil, damaged(path, fmt.Sprintf("has a relay id alone on line %d", n+1), nil, leftBehindOldShape)
			}
		}
		e, ok := parseLeftEntry(fields)
		if !ok {
			return nil, damaged(path, fmt.Sprintf("has %q on line %d, which is not a message left on the relay", line, n+1),
				nil, leftBehindAdvice)
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RelayID < out[j].RelayID })
	return out, nil
}

// parseLeftEntry reads one line's four fields, each under its rule: a relay
// id above zero, a message id, a time, and a size of zero or more.
func parseLeftEntry(fields []string) (LeftEntry, bool) {
	if len(fields) != 4 {
		return LeftEntry{}, false
	}
	relayID, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil || relayID <= 0 {
		return LeftEntry{}, false
	}
	if message.ValidID(fields[1]) != nil {
		return LeftEntry{}, false
	}
	received, err := time.Parse(time.RFC3339, fields[2])
	if err != nil {
		return LeftEntry{}, false
	}
	size, err := strconv.ParseInt(fields[3], 10, 64)
	if err != nil || size < 0 {
		return LeftEntry{}, false
	}
	return LeftEntry{RelayID: relayID, ID: fields[1], Received: received.UTC(), Size: size}, true
}

// AddLeftBehind records one more, and is a no-op for a relay id already
// there.
func (s *Store) AddLeftBehind(relayName string, e LeftEntry) error {
	entries, err := s.LeftBehind(relayName)
	if err != nil {
		return err
	}
	for _, have := range entries {
		if have.RelayID == e.RelayID {
			return nil
		}
	}
	return s.SetLeftBehind(relayName, append(entries, e))
}

// SetLeftBehind writes the list, whole, and removes the file when there is
// nothing left to remember. The relay's directory is made if it is not
// there, as the cursor's writer makes it. Two entries under one relay id
// are one: the first is kept.
func (s *Store) SetLeftBehind(relayName string, entries []LeftEntry) error {
	// The rule at the call, as SaveRelay runs it: the store's exported
	// edge is a boundary of its own.
	if err := ValidRelayName(relayName); err != nil {
		return err
	}
	path := filepath.Join(s.relayDir(relayName), leftBehindFile)
	if len(entries) == 0 {
		err := os.Remove(path)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	sorted := append([]LeftEntry(nil), entries...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].RelayID < sorted[j].RelayID })
	var b strings.Builder
	var last int64
	for _, e := range sorted {
		if e.RelayID <= 0 || message.ValidID(e.ID) != nil || e.Size < 0 {
			return fmt.Errorf("store: not a message left on the relay: %d %q %d", e.RelayID, e.ID, e.Size)
		}
		if e.RelayID == last {
			continue
		}
		fmt.Fprintf(&b, "%d %s %s %d\n", e.RelayID, e.ID, e.Received.UTC().Format(time.RFC3339), e.Size)
		last = e.RelayID
	}
	if err := os.MkdirAll(s.relayDir(relayName), dirMode); err != nil {
		return err
	}
	return writeFileAtomic(path, []byte(b.String()), fileMode)
}
