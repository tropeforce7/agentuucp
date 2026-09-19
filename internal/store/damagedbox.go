package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"
)

// damaged/ holds what could not be opened.
//
// A message the relay delivered and this key could not open — did not
// decrypt, addressed to somebody else, a sender who does not hold up, or not
// an envelope at all — used to be acknowledged away with one warning. It is
// kept here instead, the bytes as they came off the wire and a record
// beside them saying which relay's message it was, when, and why in a word,
// so that a person can ask the sender to send it again or hand the bytes to
// somebody who can say more. Nothing here is ever opened again by this
// program; a person removes it with rm.
//
// It is bounded, because a sender the relay accepts could otherwise fill
// this disk with envelopes nothing can open and nothing removes: a budget
// for the whole directory, the oldest kept evicted first to make room, and
// a message that alone exceeds it not kept at all, which the warning says.
const damagedDir = "damaged"

// DamagedBudget is the most damaged/ holds in all: four envelopes at the
// relay's default largest. A variable so a test can fill it without writing
// sixty-four mebibytes; nothing else sets it.
var DamagedBudget int64 = 64 << 20

// DamagedRecord is what is kept beside the bytes: which relay's message it
// was, when that relay received it, and the cause in a word.
type DamagedRecord struct {
	RelayID  int64     `json:"relay_id"`
	Relay    string    `json:"relay"`
	Received time.Time `json:"received"`
	Cause    string    `json:"cause"`
}

// DamagedDir is where damaged messages are kept.
func (s *Store) DamagedDir() string { return s.path(damagedDir) }

// DamagedPath is where one relay's message is kept: the bytes as
// damaged/<relay>/<id>.bin and the record as damaged/<relay>/<id>.json,
// under the relay's name because ids are each relay's own counter and two
// relays' seventh messages are different messages.
//
// The relay name is held to ValidRelayName here, at the call, as every
// exported edge of the store holds what it joins onto a path; the id is
// an int64 the relay numbered, written as digits, and a negative one is
// refused before it is written as anything.
func (s *Store) DamagedPath(relay string, id int64) (string, error) {
	if err := ValidRelayName(relay); err != nil {
		return "", err
	}
	if id < 0 {
		return "", fmt.Errorf("relay message id %d is negative", id)
	}
	return filepath.Join(s.path(damagedDir, relay), strconv.FormatInt(id, 10)+".bin"), nil
}

func recordPath(binPath string) string { return binPath[:len(binPath)-len(".bin")] + ".json" }

// kept is one message under damaged/, for counting and eviction.
type kept struct {
	bin  string
	size int64
	when time.Time
}

// keptMessages lists what is under damaged/, oldest first: by the record's
// received time, and by the file's own time for a .bin whose record is
// missing or unreadable, so that an interrupted keep still counts against
// the budget and can still be evicted.
func (s *Store) keptMessages() ([]kept, error) {
	relays, err := os.ReadDir(s.path(damagedDir))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []kept
	for _, relay := range relays {
		if !relay.IsDir() {
			continue
		}
		entries, err := os.ReadDir(s.path(damagedDir, relay.Name()))
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if e.IsDir() || filepath.Ext(e.Name()) != ".bin" {
				continue
			}
			info, err := e.Info()
			if err != nil {
				return nil, err
			}
			k := kept{bin: s.path(damagedDir, relay.Name(), e.Name()), size: info.Size(), when: info.ModTime()}
			var rec DamagedRecord
			if data, err := os.ReadFile(recordPath(k.bin)); err == nil && json.Unmarshal(data, &rec) == nil && !rec.Received.IsZero() {
				k.when = rec.Received
			}
			out = append(out, k)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].when.Equal(out[j].when) {
			return out[i].bin < out[j].bin
		}
		return out[i].when.Before(out[j].when)
	})
	return out, nil
}

// KeepDamaged keeps the bytes of a message that could not be opened, with
// its record beside them, within the budget: the oldest kept are evicted
// first to make room, and a message that alone exceeds the budget is not
// kept at all, reported as false. It returns how many were evicted. The
// bytes are written before the record, so an interrupted keep leaves bytes
// that count and can be evicted rather than a record naming bytes that are
// not there.
func (s *Store) KeepDamaged(rec DamagedRecord, data []byte) (kept bool, evicted int, err error) {
	if int64(len(data)) > DamagedBudget {
		return false, 0, nil
	}
	have, err := s.keptMessages()
	if err != nil {
		return false, 0, err
	}
	var total int64
	for _, k := range have {
		total += k.size
	}
	for _, k := range have {
		if total+int64(len(data)) <= DamagedBudget {
			break
		}
		if err := os.Remove(k.bin); err != nil && !errors.Is(err, os.ErrNotExist) {
			return false, evicted, err
		}
		if err := os.Remove(recordPath(k.bin)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return false, evicted, err
		}
		total -= k.size
		evicted++
	}
	bin, err := s.DamagedPath(rec.Relay, rec.RelayID)
	if err != nil {
		return false, evicted, err
	}
	if err := os.MkdirAll(filepath.Dir(bin), dirMode); err != nil {
		return false, evicted, err
	}
	if err := writeFileAtomic(bin, data, fileMode); err != nil {
		return false, evicted, err
	}
	record, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return false, evicted, err
	}
	if err := writeFileAtomic(recordPath(bin), append(record, '\n'), fileMode); err != nil {
		return false, evicted, err
	}
	return true, evicted, nil
}

// DamagedKept is how many messages are kept under damaged/ and how many
// bytes they come to.
func (s *Store) DamagedKept() (messages int, bytes int64, err error) {
	have, err := s.keptMessages()
	if err != nil {
		return 0, 0, err
	}
	for _, k := range have {
		bytes += k.size
	}
	return len(have), bytes, nil
}

// MiB says a byte count for a sentence: in mebibytes, whole when it is and
// to one place when it is not, and in kibibytes below one.
func MiB(n int64) string {
	switch {
	case n < 1<<20:
		return fmt.Sprintf("%d KiB", (n+(1<<10)-1)>>10)
	case n%(1<<20) == 0:
		return fmt.Sprintf("%d MiB", n>>20)
	}
	// Rounded up, so a message a byte over the budget is said to be over it.
	tenths := (n*10 + (1 << 20) - 1) >> 20
	return fmt.Sprintf("%d.%d MiB", tenths/10, tenths%10)
}
