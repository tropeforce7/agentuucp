//go:build e2e

package e2e

import (
	"archive/tar"
	"bytes"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	relaypkg "github.com/tropeforce7/agentuucp/internal/relay"
	"github.com/tropeforce7/agentuucp/internal/relay/schemahistory"
)

// A relay upgraded over a database an older release wrote: the deployed
// binary, under the unit's user and paths, carrying a real file forward.
// The unit tests prove what the steps do; this is the proof that the
// program as installed does them to a file it did not make, owned as the
// unit's files are, and says so where an operator reads.
var upgradeRows = []matrixRow{
	{"G01", "carried_forward", "relay A starts on a database schema 11 wrote, and carries it forward", g01},
}

// plantedMailbox is a fingerprint no machine in the stack has, so that the
// administrator's listing can only show it if the row that names it came
// through the steps.
const plantedMailbox = "5c11a5d9e7f1c3b5a79d8e6f4c2b0a1d3e5f7091b3d5f7e9a1c3e5b7d9f1a3c5"

func g01(t *testing.T) {
	// Put the snapshot back afterwards: the fixture replaces the relay's
	// database with one that knows none of the cycle's mailboxes, and the
	// copy stays beside it.
	t.Cleanup(func() { restore(t) })

	// The owner and mode the relay's own database has, read while the
	// container is up, so the file put in its place is owned as the unit's
	// files are. A file carried from the host without them is one the relay
	// cannot open (TESTING.md, "A file that crosses the host loses its owner").
	st := strings.Fields(relay.mustRoot(t, "stat -c '%u %g %a' "+relayDB))
	if len(st) != 3 {
		t.Fatalf("stat of %s: %q", relayDB, st)
	}
	uid, _ := strconv.Atoi(st[0])
	gid, _ := strconv.Atoi(st[1])
	mode, _ := strconv.ParseInt(st[2], 8, 64)

	// The database, built on the host from the text schema 11 was, pasted
	// from git, at user_version 11, with one mailbox row.
	local := filepath.Join(t.TempDir(), "relay.db")
	db, err := sql.Open("sqlite", local)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{schemahistory.SchemaAt11, `PRAGMA user_version = 11`} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`INSERT INTO mailboxes (fp, bundle, name, created) VALUES (?, X'00', 'planted', ?)`,
		plantedMailbox, time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	db.Close()
	body, err := os.ReadFile(local)
	if err != nil {
		t.Fatal(err)
	}
	var archive bytes.Buffer
	tw := tar.NewWriter(&archive)
	if err := tw.WriteHeader(&tar.Header{Name: "relay.db", Mode: mode, Uid: uid, Gid: gid,
		Size: int64(len(body)), ModTime: time.Now()}); err != nil {
		t.Fatal(err)
	}
	tw.Write(body)
	tw.Close()

	// The message files in A's mailboxes, counted before the stop, as R20
	// counts them. The cycle drains every mailbox before the snapshot is
	// taken, so there are none, and the sweep that follows the carry has
	// nothing of the cycle's to remove. That is pinned, not allowed for: a
	// cycle that one day leaves mail behind fails this row, to be
	// repinned on purpose (ruling 49).
	held := strings.TrimSpace(relay.mustRoot(t,
		"find "+messagesDir+" -mindepth 3 -maxdepth 3 -type f -path '"+messagesDir+"/[0-9a-f][0-9a-f]/*/*' | wc -l"))
	if held != "0" {
		t.Fatalf("the snapshot holds %s message files in relay A's mailboxes; this row was pinned on none", held)
	}

	relayStop(t)
	// The relay's WAL and shared memory belong to the file being replaced.
	relay.mustRoot(t, "rm -f "+relayDB+"-wal "+relayDB+"-shm")
	if r := runHost(&archive, "docker", "cp", "-", relay.id+":"+filepath.Dir(relayDB)); r.code != 0 {
		t.Fatalf("copying the schema 11 database into %s: %s", relay.service, r.stderr)
	}
	record(relay.asRoot(), "docker cp - (a tar of relay.db at schema 11, owned "+st[0]+":"+st[1]+" mode "+st[2]+")", "", result{})

	m := relayStart(t)
	log := relayLogSince(m)

	cp := relayDB + ".before-schema-11"
	carried := fmt.Sprintf(`from=11 to=%d copy=%s`, relaypkg.SchemaVersion, cp)
	if !strings.Contains(log, "the database was carried forward") || !strings.Contains(log, carried) {
		t.Errorf("the relay did not say it carried the database forward with %q:\n%s", carried, log)
	}
	if !strings.Contains(log, fmt.Sprintf("schema=%d", relaypkg.SchemaVersion)) {
		t.Errorf("the starting line does not say schema %d:\n%s", relaypkg.SchemaVersion, log)
	}
	// With no message files, the sweep after the carry finds nothing and
	// says nothing.
	if strings.Contains(log, "the message directory did not match the database") {
		t.Errorf("the sweep reported something on a snapshot that holds no mail:\n%s", log)
	}

	// The copy, beside the database, the unit's user's alone, at 11.
	expectSays(t, relay.root("stat -c '%U %a' "+cp), 0, "auu 600")
	expectSays(t, relay.root("sqlite3 "+cp+" 'PRAGMA user_version'"), 0, "11")
	expectSays(t, relay.root("sqlite3 "+relayDB+" 'PRAGMA user_version'"), 0, strconv.Itoa(relaypkg.SchemaVersion))

	// The planted mailbox, through the relay the administrator talks to.
	expectSays(t, operator.admin("mailboxes", "ls"), 0, plantedMailbox[:16], "planted")

	verdict(t, "ok", "Started on a database schema 11 wrote, the relay keeps a copy beside it owned by the unit's "+
		"user and readable by nobody else, carries the database to this schema, says so in the journal naming both "+
		"versions and the copy, and serves the mailbox that database held. The snapshot holds no mail, since the "+
		"cycle drains every mailbox before it is taken, so the sweep that follows the carry has nothing to remove "+
		"and says nothing.")
}
