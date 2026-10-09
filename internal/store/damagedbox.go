package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/tropeforce7/agentuucp/internal/channels"
	"github.com/tropeforce7/agentuucp/internal/regular"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/wire"
)

// damaged/ holds what could not be opened.
//
// A message the relay delivered and this key could not open — did not
// decrypt, addressed to somebody else, a sender who does not hold up, or not
// an envelope at all — used to be acknowledged away with one warning. It is
// kept here instead, the bytes as they came off the wire and a record
// beside them saying which relay's message it was, when, and why in a word,
// so that a person can ask the sender to send it again or hand the bytes to
// somebody who can say more. Nothing here is opened again by this program
// but for one cause: a message kept as newer, which needs a later auu, is
// opened again by auu damaged reopen once that auu is here. A person
// removes the rest with rm.
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
// CauseNewer begins the cause of a message kept because it carries a
// critical section this build does not know (D29): not damaged, and not the
// sender's to send again, but one a newer auu will read. The fetch writes
// it and the count of such messages reads it, so it is one constant.
const CauseNewer = "newer"

// DamagedRecord's last four fields are what the relay's listing said of
// the row, which the fetch's checks read and the bytes do not carry: the
// kind it was listed under, the channel it was filed under, the relays it
// came through and its size on the relay. A message kept as newer records
// them from this release, so that reopening it runs those checks as the
// fetch would have. A record an earlier release wrote has none: reopen
// then skips the kind check, which the envelope has no half of, checks the
// channel against the envelope's own alone, and says which could not run.
type DamagedRecord struct {
	RelayID  int64     `json:"relay_id"`
	Relay    string    `json:"relay"`
	Received time.Time `json:"received"`
	Cause    string    `json:"cause"`
	Kind     string    `json:"kind,omitempty"`
	Channel  string    `json:"channel,omitempty"`
	Via      string    `json:"via,omitempty"`
	Size     int64     `json:"size,omitempty"`
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
	bin   string
	size  int64
	when  time.Time
	cause string
}

// DamagedEntry is one message kept under damaged/, as auu damaged ls says
// it: the record beside the bytes, and the size of the bytes on disk.
type DamagedEntry struct {
	DamagedRecord
	// Bytes is the size of the kept bytes on this disk.
	Bytes int64
	// NoRecord is bytes whose keep was cut off before the record beside
	// them was written: the relay and id are the path's, the received
	// time is the file's own, and there is no cause.
	NoRecord bool
	// BadRecord is bytes beside a record that does not read by the rule,
	// or names another relay or id; the relay and id are the path's, the
	// received time the file's own, and the reason is in Cause. Like
	// NoRecord, it counts, is evicted and is never reopened.
	BadRecord bool
	bin       string
}

// damagedEntries lists what is under damaged/ by one rule, which the
// budget, the counts and auu damaged ls all read: a directory whose name
// is a relay's name, a .bin in it whose name is an id of 0 or more written
// as the store writes one, and a .json beside it that reads strictly and
// names that relay and that id. A .bin whose keep was cut off before its
// record was written is listed too, with NoRecord and its file's own time,
// and so is one beside a record that does not read or names another
// relay or id, with BadRecord: both still count against the budget and
// are still evicted, as they always were, so that no record can put bytes
// beyond the budget. Anything else is a stray: a name that is not an id, a
// directory that is not a relay's, a record with no bytes. A stray is not
// counted, not evicted and not listed, and is returned by its path so that
// ls can say it is there.
func (s *Store) damagedEntries() (entries []DamagedEntry, strays []string, err error) {
	relays, err := os.ReadDir(s.path(damagedDir))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	for _, relay := range relays {
		dir := s.path(damagedDir, relay.Name())
		if !relay.IsDir() || ValidRelayName(relay.Name()) != nil {
			strays = append(strays, dir)
			continue
		}
		files, err := os.ReadDir(dir)
		if err != nil {
			return nil, nil, err
		}
		for _, f := range files {
			name := f.Name()
			if filepath.Ext(name) == ".json" {
				// A record is said with its bytes, or as a stray when
				// the bytes beside it are not a kept message's.
				if _, err := os.Lstat(filepath.Join(dir, strings.TrimSuffix(name, ".json")+".bin")); err != nil {
					strays = append(strays, filepath.Join(dir, name))
				}
				continue
			}
			bin := filepath.Join(dir, name)
			id, ok := damagedID(name)
			if f.IsDir() || !ok {
				strays = append(strays, bin)
				continue
			}
			info, err := f.Info()
			if err != nil {
				return nil, nil, err
			}
			rec, err := readDamagedRecord(recordPath(bin))
			if errors.Is(err, os.ErrNotExist) {
				entries = append(entries, DamagedEntry{
					DamagedRecord: DamagedRecord{RelayID: id, Relay: relay.Name(), Received: info.ModTime()},
					Bytes:         info.Size(), NoRecord: true, bin: bin,
				})
				continue
			}
			if err == nil && (rec.Relay != relay.Name() || rec.RelayID != id) {
				err = fmt.Errorf("the record names relay %q and id %d", rec.Relay, rec.RelayID)
			}
			if err != nil {
				entries = append(entries, DamagedEntry{
					DamagedRecord: DamagedRecord{RelayID: id, Relay: relay.Name(), Received: info.ModTime(), Cause: err.Error()},
					Bytes:         info.Size(), BadRecord: true, bin: bin,
				})
				continue
			}
			entries = append(entries, DamagedEntry{DamagedRecord: rec, Bytes: info.Size(), bin: bin})
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Received.Equal(entries[j].Received) {
			return entries[i].bin < entries[j].bin
		}
		return entries[i].Received.Before(entries[j].Received)
	})
	sort.Strings(strays)
	return entries, strays, nil
}

// damagedID is the id a kept message's file name gives: a .bin whose stem
// is an id of 0 or more written as strconv writes it, so that one id has
// one name and 07.bin is not 7.bin.
func damagedID(name string) (int64, bool) {
	stem, ok := strings.CutSuffix(name, ".bin")
	if !ok {
		return 0, false
	}
	id, err := strconv.ParseInt(stem, 10, 64)
	if err != nil || id < 0 || strconv.FormatInt(id, 10) != stem {
		return 0, false
	}
	return id, true
}

// readDamagedRecord reads a record strictly: the file this program wrote,
// and nothing that only resembles it.
func readDamagedRecord(path string) (DamagedRecord, error) {
	var rec DamagedRecord
	data, err := regular.ReadFile(path)
	if err != nil {
		return rec, err
	}
	if err := wire.Decode(data, &rec); err != nil {
		return rec, err
	}
	if rec.Received.IsZero() {
		return rec, errors.New("the record has no received time")
	}
	// What the listing said is held to the listing's own rules again, as
	// the client held it when it came: a kind that is a row's, a channel's
	// name, a size of 0 or more, and relays' names that become a reply's
	// path.
	if rec.Kind != "" && rec.Kind != relayapi.KindEnvelope && rec.Kind != relayapi.KindKnock {
		return rec, fmt.Errorf("the record's kind %q is not one a kept row is listed under", rec.Kind)
	}
	if rec.Channel != "" {
		if err := channels.ValidName(rec.Channel); err != nil {
			return rec, fmt.Errorf("the record's channel: %w", err)
		}
	}
	if rec.Size < 0 {
		return rec, fmt.Errorf("the record's size %d is below zero", rec.Size)
	}
	if rec.Via != "" {
		if err := CheckAddress(nil, strings.Split(rec.Via, "!"), relayapi.MaxHops); err != nil {
			return rec, fmt.Errorf("the record's via: %w", err)
		}
	}
	return rec, nil
}

// keptMessages lists what is under damaged/ by damagedEntries' rule,
// oldest first, for the budget and the counts.
func (s *Store) keptMessages() ([]kept, error) {
	entries, _, err := s.damagedEntries()
	if err != nil {
		return nil, err
	}
	out := make([]kept, 0, len(entries))
	for _, e := range entries {
		out = append(out, kept{bin: e.bin, size: e.Bytes, when: e.Received, cause: e.Cause})
	}
	return out, nil
}

// DamagedEntries is every message kept under damaged/, oldest first, and
// the path of every stray beside them.
func (s *Store) DamagedEntries() ([]DamagedEntry, []string, error) {
	return s.damagedEntries()
}

// ErrNotDamaged is a relay and id with no kept message.
var ErrNotDamaged = errors.New("nothing is kept under damaged/ for that relay and id")

// ErrNoRecord is a relay and id whose bytes are kept with no record beside
// them: a keep cut off before the record was written.
var ErrNoRecord = errors.New("its bytes are kept with no record beside them")

// ReadDamaged reads one kept message: its record, held to the entry rule,
// and its bytes, read through regular and refused over DamagedBudget, the
// most a keep ever writes.
func (s *Store) ReadDamaged(relay string, id int64) (DamagedEntry, []byte, error) {
	bin, err := s.DamagedPath(relay, id)
	if err != nil {
		return DamagedEntry{}, nil, err
	}
	rec, err := readDamagedRecord(recordPath(bin))
	if errors.Is(err, os.ErrNotExist) {
		if _, berr := os.Lstat(bin); berr == nil {
			return DamagedEntry{}, nil, ErrNoRecord
		}
		return DamagedEntry{}, nil, ErrNotDamaged
	}
	if err != nil {
		return DamagedEntry{}, nil, fmt.Errorf("%s: %w", recordPath(bin), err)
	}
	if rec.Relay != relay || rec.RelayID != id {
		return DamagedEntry{}, nil, fmt.Errorf("%s names relay %q and id %d, not the file it is beside", recordPath(bin), rec.Relay, rec.RelayID)
	}
	f, err := regular.Open(bin)
	if errors.Is(err, os.ErrNotExist) {
		return DamagedEntry{}, nil, ErrNotDamaged
	}
	if err != nil {
		return DamagedEntry{}, nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, DamagedBudget+1))
	if err != nil {
		return DamagedEntry{}, nil, err
	}
	if int64(len(data)) > DamagedBudget {
		return DamagedEntry{}, nil, fmt.Errorf("%s is over %s, more than a keep ever writes", bin, MiB(DamagedBudget))
	}
	return DamagedEntry{DamagedRecord: rec, Bytes: int64(len(data)), bin: bin}, data, nil
}

// RemoveDamaged removes one kept message, bytes and record: once it has
// been opened and filed, or found already held.
func (s *Store) RemoveDamaged(relay string, id int64) error {
	bin, err := s.DamagedPath(relay, id)
	if err != nil {
		return err
	}
	if err := os.Remove(bin); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Remove(recordPath(bin)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
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
	// A relay that said no received time gets this machine's: the record
	// is read strictly and wants one, and the budget orders by it.
	if rec.Received.IsZero() {
		rec.Received = time.Now().UTC()
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

// DamagedNeedingNewer is how many of the messages kept under damaged/ were
// kept because they need a newer auu, by their records' cause, so that the
// sentence about the rest can stop telling a person to ask for these again.
func (s *Store) DamagedNeedingNewer() (int, error) {
	have, err := s.keptMessages()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, k := range have {
		if k.cause == CauseNewer || strings.HasPrefix(k.cause, CauseNewer+":") {
			n++
		}
	}
	return n, nil
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
