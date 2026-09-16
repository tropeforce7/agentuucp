package store

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// A record in a box that will not read is said to be, once per file per
// command, and the rest of the box is still listed; a record that reads
// and holds no message is the same. The container suite's M09 found a
// flipped record simply absent from the listing.
func TestAnUnreadableSpoolFileIsSaidToBe(t *testing.T) {
	s := newStore(t)
	now := time.Now().UTC().Truncate(time.Second)
	good := stored("00000000000000000000000000000001", now.Add(-time.Hour))
	flipped := stored("00000000000000000000000000000002", now)
	empty := stored("00000000000000000000000000000003", now)
	for _, m := range []*Stored{good, flipped, empty} {
		if err := s.Save(Inbox, m); err != nil {
			t.Fatal(err)
		}
	}
	flippedPath := s.msgPath(Inbox, flipped.Inner.ID)
	data, err := os.ReadFile(flippedPath)
	if err != nil {
		t.Fatal(err)
	}
	data[0] ^= 1 // '{' is now 'z'
	if err := os.WriteFile(flippedPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	emptyPath := s.msgPath(Inbox, empty.Inner.ID)
	if err := os.WriteFile(emptyPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var msgs []*Stored
	stderr := captureStderr(t, func() {
		msgs, err = s.List(Inbox)
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 || msgs[0].Inner.ID != good.Inner.ID {
		t.Fatalf("listed %d, want the one good record", len(msgs))
	}
	want := "warning: " + flippedPath + " could not be read (invalid character 'z' looking for beginning of value) and is not listed\n" +
		"warning: " + emptyPath + " could not be read (the record holds no message) and is not listed\n"
	if stderr != want {
		t.Fatalf("stderr:\n%s\nwant:\n%s", stderr, want)
	}

	// Once per file: a second listing in the same command says nothing.
	stderr = captureStderr(t, func() { _, err = s.List(Inbox) })
	if err != nil || stderr != "" {
		t.Fatalf("second listing: %v, stderr %q, want silence", err, stderr)
	}
	// And the other boxes are their own: the same file name in another box
	// is another file.
	if err := s.Save(Quarantine, flipped); err != nil {
		t.Fatal(err)
	}
	q := s.msgPath(Quarantine, flipped.Inner.ID)
	if err := os.WriteFile(q, data, 0o600); err != nil {
		t.Fatal(err)
	}
	stderr = captureStderr(t, func() { _, err = s.List(Quarantine) })
	if err != nil || !strings.HasPrefix(stderr, "warning: "+q+" could not be read (") {
		t.Fatalf("quarantine listing: %v, stderr %q", err, stderr)
	}
}

// What could not be opened is kept as bytes and a record under
// damaged/<relay>/, within a budget for the whole directory: the oldest
// kept go first to make room, and a message that alone exceeds the budget
// is not kept at all. An interrupted keep leaves bytes with no record, which
// count and can be evicted.
func TestDamagedMessagesAreKeptWithinTheBudget(t *testing.T) {
	s := newStore(t)
	restore := DamagedBudget
	DamagedBudget = 1000
	t.Cleanup(func() { DamagedBudget = restore })
	now := time.Now().UTC().Truncate(time.Second)
	rec := func(relay string, id int64, ago time.Duration) DamagedRecord {
		return DamagedRecord{RelayID: id, Relay: relay, Received: now.Add(-ago), Cause: "did not decrypt"}
	}

	// Kept: the bytes byte for byte, the record beside them, both private.
	bin := bytes.Repeat([]byte{7}, 400)
	kept, evicted, err := s.KeepDamaged(rec("work", 7, 3*time.Hour), bin)
	if err != nil || !kept || evicted != 0 {
		t.Fatalf("keep: kept %v, evicted %d, %v", kept, evicted, err)
	}
	path := s.DamagedPath("work", 7)
	if path != filepath.Join(s.root, "damaged", "work", "7.bin") {
		t.Fatalf("kept at %s", path)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, bin) {
		t.Fatalf("the bytes: %v", err)
	}
	var back DamagedRecord
	raw, err := os.ReadFile(recordPath(path))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if back != rec("work", 7, 3*time.Hour) {
		t.Fatalf("the record: %+v", back)
	}
	if !strings.Contains(string(raw), `"relay_id": 7`) || !strings.Contains(string(raw), `"cause": "did not decrypt"`) {
		t.Fatalf("the record on disk: %s", raw)
	}
	// Go's FileMode on Windows says nothing about who can read a file; the
	// modes are Unix's, and the Windows job reported 666 and 777 for all four.
	if runtime.GOOS != "windows" {
		for _, p := range []string{path, recordPath(path), filepath.Dir(path), s.DamagedDir()} {
			info, err := os.Stat(p)
			if err != nil {
				t.Fatal(err)
			}
			want := os.FileMode(0o600)
			if info.IsDir() {
				want = 0o700
			}
			if info.Mode().Perm() != want {
				t.Errorf("%s is %o, want %o", p, info.Mode().Perm(), want)
			}
		}
	}
	if n, size, err := s.DamagedKept(); err != nil || n != 1 || size != 400 {
		t.Fatalf("kept: %d, %d bytes (%v)", n, size, err)
	}

	// Another relay's seventh message is another message.
	if kept, _, err := s.KeepDamaged(rec("personal", 7, 2*time.Hour), bytes.Repeat([]byte{8}, 400)); err != nil || !kept {
		t.Fatalf("keep on personal: %v %v", kept, err)
	}
	if n, size, err := s.DamagedKept(); err != nil || n != 2 || size != 800 {
		t.Fatalf("kept: %d, %d bytes (%v)", n, size, err)
	}

	// Room is made from the oldest: 800 held, 400 more wanted of a 1000
	// budget, so work's, received first, goes and personal's stays.
	kept, evicted, err = s.KeepDamaged(rec("work", 8, time.Hour), bytes.Repeat([]byte{9}, 400))
	if err != nil || !kept || evicted != 1 {
		t.Fatalf("keep past the budget: kept %v, evicted %d, %v", kept, evicted, err)
	}
	if _, err := os.Stat(s.DamagedPath("work", 7)); !os.IsNotExist(err) {
		t.Fatal("the oldest was not evicted")
	}
	if _, err := os.Stat(recordPath(s.DamagedPath("work", 7))); !os.IsNotExist(err) {
		t.Fatal("the oldest's record was not evicted with it")
	}
	for _, p := range []string{s.DamagedPath("personal", 7), s.DamagedPath("work", 8)} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
	}

	// Exactly the budget fits; one byte over evicts.
	if kept, evicted, err := s.KeepDamaged(rec("work", 9, 30*time.Minute), bytes.Repeat([]byte{1}, 200)); err != nil || !kept || evicted != 0 {
		t.Fatalf("keep to exactly the budget: kept %v, evicted %d, %v", kept, evicted, err)
	}
	if kept, evicted, err := s.KeepDamaged(rec("work", 10, 20*time.Minute), []byte{1}); err != nil || !kept || evicted != 1 {
		t.Fatalf("keep one byte over: kept %v, evicted %d, %v", kept, evicted, err)
	}
	if _, err := os.Stat(s.DamagedPath("personal", 7)); !os.IsNotExist(err) {
		t.Fatal("one byte over did not evict the oldest")
	}

	// A message that alone exceeds the budget is not kept, and evicts
	// nothing to fail to make room for it.
	before, _, _ := s.DamagedKept()
	kept, evicted, err = s.KeepDamaged(rec("work", 11, time.Minute), make([]byte, 1001))
	if err != nil || kept || evicted != 0 {
		t.Fatalf("keep over the budget alone: kept %v, evicted %d, %v", kept, evicted, err)
	}
	if after, _, _ := s.DamagedKept(); after != before {
		t.Fatalf("kept went from %d to %d for a message that was not kept", before, after)
	}
	if _, err := os.Stat(s.DamagedPath("work", 11)); !os.IsNotExist(err) {
		t.Fatal("a message over the budget was written")
	}
	// Exactly the budget alone is kept.
	if kept, _, err := s.KeepDamaged(rec("work", 12, time.Minute), make([]byte, 1000)); err != nil || !kept {
		t.Fatalf("keep exactly the budget alone: kept %v, %v", kept, err)
	}
	if n, size, err := s.DamagedKept(); err != nil || n != 1 || size != 1000 {
		t.Fatalf("after the largest keep: %d, %d bytes (%v)", n, size, err)
	}

	// Bytes without a record, from an interrupted keep, count and are
	// evicted by their own time.
	orphan := s.DamagedPath("work", 13)
	if err := os.WriteFile(orphan, make([]byte, 500), 0o600); err != nil {
		t.Fatal(err)
	}
	if n, size, err := s.DamagedKept(); err != nil || n != 2 || size != 1500 {
		t.Fatalf("with an orphan: %d, %d bytes (%v)", n, size, err)
	}
	if kept, evicted, err := s.KeepDamaged(rec("work", 14, time.Second), make([]byte, 600)); err != nil || !kept || evicted != 2 {
		t.Fatalf("keep beside an orphan: kept %v, evicted %d, %v", kept, evicted, err)
	}
	if _, err := os.Stat(orphan); !os.IsNotExist(err) {
		t.Fatal("the orphan was not evicted")
	}
}

// The sizes in the sentence about a message that was not kept.
func TestSizesAreSaidInWords(t *testing.T) {
	for n, want := range map[int64]string{
		0:                 "0 KiB",
		1:                 "1 KiB",
		1024:              "1 KiB",
		12343:             "13 KiB",
		1<<20 - 1:         "1024 KiB",
		1 << 20:           "1 MiB",
		64 << 20:          "64 MiB",
		70<<20 + 512<<10:  "70.5 MiB",
		64<<20 + 1:        "64.1 MiB",
		1000 << 20:        "1000 MiB",
		DamagedBudget + 1: "64.1 MiB",
		64<<20 + 100<<10:  "64.1 MiB",
	} {
		if got := MiB(n); got != want {
			t.Errorf("MiB(%d) = %q, want %q", n, got, want)
		}
	}
}
