package relay

import (
	"bytes"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestLimitAnUploadRowIsHeldToItsRulesWhereItIsRead: an upload's id names
// its file and its recipient names the mailbox's directory, and both were
// used as read back from relay.db, which only this relay writes but which
// a restored backup, a hand edit or a fault can leave holding anything
// (F4, tracer D's D-C2). The purge now skips a row whose id is not an
// upload id, counts it and says its row number, and removes nothing by its
// path; a placement refuses a row whose recipient is not a fingerprint
// before anything is written.
func TestLimitAnUploadRowIsHeldToItsRulesWhereItIsRead(t *testing.T) {
	s, alice, _ := directoryStore(t)
	dbPath := filepath.Join(filepath.Dir(s.dir), "relay.db")
	var said bytes.Buffer
	s.SetFaultLog(slog.New(slog.NewTextHandler(&said, nil)), time.Now)
	// What the bad id names, from the uploads directory.
	if got := filepath.Clean(s.uploadPath("../../relay.db")); got != dbPath {
		t.Fatalf("the planted id names %s, not the database, so the test proves nothing", got)
	}
	past := time.Now().Add(-time.Hour).Unix()
	fp := alice.Fingerprint()
	if _, err := s.db.Exec(
		`INSERT INTO uploads (id, to_fp, from_fp, size, received, created, expires, channel) VALUES (?, ?, ?, 1, 0, ?, ?, '')`,
		"../../relay.db", fp, fp, time.Now().UTC().Format(time.RFC3339), past); err != nil {
		t.Fatal(err)
	}
	purged, skipped, err := s.PurgeUploads(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(purged) != 0 || skipped != 1 {
		t.Fatalf("the purge removed %d and skipped %d; want 0 and 1", len(purged), skipped)
	}
	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("the database is gone: %v", err)
	}
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM uploads`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("the uploads table holds %d rows, %v", n, err)
	}
	if !strings.Contains(said.String(), "uploads row skipped") || !strings.Contains(said.String(), "row=") || strings.Contains(said.String(), "relay.db") {
		t.Fatalf("the purge said:\n%s", said.String())
	}

	for _, u := range []Upload{
		{ID: strings.Repeat("b", 32), To: "../" + fp[3:], Size: 1},
		{ID: strings.Repeat("b", 32), To: strings.ToUpper(fp), Size: 1},
		{ID: "../../relay.db", To: fp, Size: 1},
	} {
		if _, err := s.placeUpload(&u); !errors.Is(err, ErrForm) {
			t.Errorf("placeUpload of %+v: %v", u, err)
		}
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM messages`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("the messages table holds %d rows, %v", n, err)
	}
}
