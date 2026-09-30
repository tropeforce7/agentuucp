package relay

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/channels"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relay/schemahistory"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/token"
)

// The indexes that reached outbound while the schema was still 12, written
// as those commits wrote them: purgeIndex at e8ca901, shareIndex at
// 766a345. A version 12 file has neither, the first, or both, by the build
// that made it.
const (
	purgeIndex = `
CREATE INDEX IF NOT EXISTS outbound_purge ON outbound(state, last_try);`
	shareIndex = `
CREATE INDEX IF NOT EXISTS outbound_share ON outbound(poster_fp, state, size);`
)

// planted is what an old database holds, as the store wrote it, for the
// assertions after it is carried forward.
type planted struct {
	path, messages  string
	alice, bob      *identity.Identity
	envelope        []byte
	tokenID, serial string
	directory       []byte
	allow           []byte
	hash            string // the outbound row's, at 12 and later
}

// oldDatabase builds a database at version v the way a relay of that
// version left it. The rows are written by today's store into a scratch
// database, with today's writers and so today's shapes, and copied into a
// file made from schemahistory's text for v by INSERT … SELECT over the
// old file's own columns; the message file goes with them. At 12 there is
// a waiting outbound row and its carried row, and the queue's counters in
// relay_stats are left at zero, wrong, for the reconcile to put right.
// later is DDL run after the version's own text: the indexes a version 12
// file from a later build has.
func oldDatabase(t *testing.T, v int, later string) planted {
	t.Helper()
	people := ids(t, "alice", "bob")
	p := planted{alice: people[0], bob: people[1]}
	p.envelope = sealed(t, p.bob, p.alice.Public(), "from before")
	now := time.Now()

	scratch := t.TempDir()
	src, err := OpenStore(filepath.Join(scratch, "relay.db"), filepath.Join(scratch, "messages"))
	if err != nil {
		t.Fatal(err)
	}
	p.serial = strings.Repeat("5e", 16)
	if err := src.Register(p.alice.Fingerprint(), p.alice.Public().Bundle(), p.alice.Name, RegisterOptions{
		Cert: &CertRow{Serial: p.serial, FP: p.alice.Fingerprint(), SPKI: strings.Repeat("ab", 32), Label: "laptop",
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(90 * 24 * time.Hour), Created: now},
	}); err != nil {
		t.Fatal(err)
	}
	if err := src.Register(p.bob.Fingerprint(), p.bob.Public().Bundle(), p.bob.Name, RegisterOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := src.Put(p.alice.Fingerprint(), "default", relayapi.KindEnvelope, "", p.envelope, Quotas{}, Forwarded{}); err != nil {
		t.Fatal(err)
	}
	p.tokenID = strings.Repeat("7c", 16)
	if err := src.AddToken(token.Claims{ID: p.tokenID, Issuer: p.bob.Fingerprint(), Relay: "relay.example",
		Use: token.UseRegister, Note: "from before", NotBefore: now.Unix(), NotAfter: now.Add(24 * time.Hour).Unix(),
		Uses: 1}, now); err != nil {
		t.Fatal(err)
	}
	if err := src.SetBlock(strings.Repeat("0b", 32), "gone", p.bob.Fingerprint(), now); err != nil {
		t.Fatal(err)
	}
	d, doc, sig := signedList(t, p.alice, now, p.bob.Fingerprint())
	if _, err := src.SetAllowlist(p.alice.Fingerprint(), d, doc, sig); err != nil {
		t.Fatal(err)
	}
	p.allow = doc
	dir, ddoc, dsig := signedDirectory(t, p.alice, now, channels.Channel{Name: "default"}, channels.Channel{Name: "bugs"})
	if _, err := src.SetDirectory(p.alice.Fingerprint(), dir, ddoc, dsig); err != nil {
		t.Fatal(err)
	}
	p.directory = ddoc
	if v >= 12 {
		p.hash = strings.Repeat("4a", 32)
		if _, err := src.Enqueue(&Outbound{PosterFP: p.bob.Fingerprint(), Neighbour: "bee", Path: "dave",
			ToFP: strings.Repeat("da", 32), Hash: p.hash, Kind: relayapi.KindEnvelope,
			Received: now, GivesUp: now.Add(72 * time.Hour)}, []byte("an envelope going on"), CourierQuotas{}, now.Add(24*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	src.Close()

	target := t.TempDir()
	p.path = filepath.Join(target, "relay.db")
	p.messages = filepath.Join(target, "messages")
	db, err := sql.Open("sqlite", p.path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	var text string
	switch v {
	case 11:
		text = schemahistory.SchemaAt11
	case 12:
		text = schemahistory.SchemaAt12
	default:
		t.Fatalf("no schema text for version %d", v)
	}
	text += later
	if _, err := db.Exec(text); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, v)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`ATTACH DATABASE ? AS src`, filepath.Join(scratch, "relay.db")); err != nil {
		t.Fatal(err)
	}
	for _, table := range tableNames(t, db) {
		cols := strings.Join(columnNames(t, db, table), ", ")
		if _, err := db.Exec(fmt.Sprintf(`INSERT OR REPLACE INTO main.%s (%s) SELECT %s FROM src.%s`,
			table, cols, cols, table)); err != nil {
			t.Fatalf("copying %s: %v", table, err)
		}
	}
	if v >= 12 {
		if _, err := db.Exec(`UPDATE relay_stats SET outbound_messages = 0, outbound_bytes = 0`); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`DETACH DATABASE src`); err != nil {
		t.Fatal(err)
	}
	if err := os.CopyFS(p.messages, os.DirFS(filepath.Join(scratch, "messages"))); err != nil {
		t.Fatal(err)
	}
	return p
}

// tableNames lists a database's own tables, SQLite's left out.
func tableNames(t *testing.T, db *sql.DB) []string {
	t.Helper()
	return strings1(t, db, `SELECT name FROM main.sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
}

// columnNames lists a table's columns in order.
func columnNames(t *testing.T, db *sql.DB, table string) []string {
	t.Helper()
	return strings1(t, db, `SELECT name FROM pragma_table_info(?) ORDER BY cid`, table)
}

func strings1(t *testing.T, db *sql.DB, query string, args ...any) []string {
	t.Helper()
	rows, err := db.Query(query, args...)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// shape is everything PRAGMA says about a database's tables and indexes:
// per table its columns in order, name, type, not null, default and key;
// per index its table, uniqueness, origin, partiality and columns. Two
// databases with one shape answer every query this relay makes the same.
func shape(t *testing.T, path string) map[string]string {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	out := map[string]string{}
	for _, table := range tableNames(t, db) {
		rows, err := db.Query(`SELECT cid, name, type, "notnull", COALESCE(dflt_value, 'NULL'), pk FROM pragma_table_info(?) ORDER BY cid`, table)
		if err != nil {
			t.Fatal(err)
		}
		var cols []string
		for rows.Next() {
			var cid, notnull, pk int
			var name, typ, dflt string
			if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
				t.Fatal(err)
			}
			cols = append(cols, fmt.Sprintf("%d %s %s notnull=%d default=%s pk=%d", cid, name, typ, notnull, dflt, pk))
		}
		rows.Close()
		out["table "+table] = strings.Join(cols, "; ")

		rows, err = db.Query(`SELECT name, "unique", origin, partial FROM pragma_index_list(?)`, table)
		if err != nil {
			t.Fatal(err)
		}
		type index struct {
			name, origin    string
			unique, partial int
		}
		var indexes []index
		for rows.Next() {
			var ix index
			if err := rows.Scan(&ix.name, &ix.unique, &ix.origin, &ix.partial); err != nil {
				t.Fatal(err)
			}
			indexes = append(indexes, ix)
		}
		rows.Close()
		for _, ix := range indexes {
			cols := strings1(t, db, `SELECT COALESCE(name, '') FROM pragma_index_info(?) ORDER BY seqno`, ix.name)
			out["index "+ix.name] = fmt.Sprintf("on %s unique=%d origin=%s partial=%d (%s)",
				table, ix.unique, ix.origin, ix.partial, strings.Join(cols, ", "))
		}
	}
	return out
}

// assertSameShape fails on any table or index that is in one database and
// not the other, or in both and different.
func assertSameShape(t *testing.T, fresh, carried map[string]string) {
	t.Helper()
	for k, want := range fresh {
		got, ok := carried[k]
		if !ok {
			t.Errorf("the carried database has no %s", k)
		} else if got != want {
			t.Errorf("%s differs:\ncarried %s\nfresh   %s", k, got, want)
		}
	}
	for k := range carried {
		if _, ok := fresh[k]; !ok {
			t.Errorf("the carried database has %s, which a fresh one does not", k)
		}
	}
}

func freshShape(t *testing.T) map[string]string {
	t.Helper()
	dir := t.TempDir()
	s, err := OpenStore(filepath.Join(dir, "relay.db"), filepath.Join(dir, "messages"))
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	return shape(t, filepath.Join(dir, "relay.db"))
}

// A database from a kept version is carried forward to this build's
// schema: a copy is kept beside it first, at the version it was found at
// and holding what it held; every row reads back through the store's own
// readers; the sweep finds nothing to do; the counters agree with the rows,
// the queue's two among them, which the step to 12 adds at zero and the
// reconcile fills; and the database has the shape of a fresh one, table
// for table and index for index, which is what holds the steps to the
// schema constant. Version 12 runs in each of the three shapes it was
// written in, three indexes on outbound, four and five.
func TestADatabaseAtEachKeptVersionIsCarriedForward(t *testing.T) {
	fresh := freshShape(t)
	type kept struct {
		name  string
		v     int
		later string
	}
	var cases []kept
	for v := firstKeptVersion; v < schemaVersion; v++ {
		cases = append(cases, kept{strconv.Itoa(v), v, ""})
	}
	cases = append(cases,
		kept{"12 with the index of e8ca901", 12, purgeIndex},
		kept{"12 with the indexes of e8ca901 and 766a345", 12, purgeIndex + shareIndex})
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := oldDatabase(t, c.v, c.later)
			s, err := OpenStore(p.path, p.messages)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if got := openVersion(t, p.path); got != schemaVersion {
				t.Fatalf("the database is at version %d after the open, want %d", got, schemaVersion)
			}
			cp := p.path + ".before-schema-" + strconv.Itoa(c.v)
			if got := s.CarriedForward(); got != (CarriedForward{From: c.v, To: schemaVersion, Copy: cp}) {
				t.Errorf("CarriedForward is %+v, want from %d to %d with the copy at %s", got, c.v, schemaVersion, cp)
			}

			// The copy: there, the owner's alone, at the version found,
			// holding what the database held.
			fi, err := os.Stat(cp)
			if err != nil {
				t.Fatalf("no copy beside the database: %v", err)
			}
			if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
				t.Errorf("the copy's mode is %v, want 0600", fi.Mode().Perm())
			}
			if got := openVersion(t, cp); got != c.v {
				t.Errorf("the copy is at version %d, want %d", got, c.v)
			}
			raw, err := sql.Open("sqlite", cp)
			if err != nil {
				t.Fatal(err)
			}
			var mailboxes, messages int
			raw.QueryRow(`SELECT COUNT(*) FROM mailboxes`).Scan(&mailboxes)
			raw.QueryRow(`SELECT COUNT(*) FROM messages`).Scan(&messages)
			raw.Close()
			if mailboxes != 2 || messages != 1 {
				t.Errorf("the copy holds %d mailboxes and %d messages, want 2 and 1", mailboxes, messages)
			}

			// Every planted row through the store's own readers.
			if _, err := s.Mailbox(p.alice.Fingerprint()); err != nil {
				t.Errorf("the mailbox from before: %v", err)
			}
			certs, err := s.Certs(p.alice.Fingerprint(), true, time.Now())
			if err != nil || len(certs) != 1 || certs[0].Serial != p.serial {
				t.Errorf("the certificate from before: %+v, %v", certs, err)
			}
			rows, err := s.List(p.alice.Fingerprint(), 0, 10)
			if err != nil || len(rows) != 1 {
				t.Fatalf("the listing from before: %d rows, %v", len(rows), err)
			}
			if rows[0].Via != "" || !bytes.Equal(rows[0].Envelope, p.envelope) {
				t.Errorf("the message from before lists via %q and %q, want no via and the envelope", rows[0].Via, rows[0].Envelope)
			}
			if _, err := s.Token(p.tokenID); err != nil {
				t.Errorf("the token from before: %v", err)
			}
			if blocks, err := s.Blocks(); err != nil || len(blocks) != 1 {
				t.Errorf("the block from before: %d, %v", len(blocks), err)
			}
			doc, _, state, found, err := s.Allowlist(p.alice.Fingerprint())
			if err != nil || !found || state != relayapi.AllowSigned || !bytes.Equal(doc, p.allow) {
				t.Errorf("the allow list from before: found %v, state %q, %v", found, state, err)
			}
			if ok, err := s.MayPost(p.alice.Fingerprint(), p.bob.Fingerprint()); err != nil || !ok {
				t.Errorf("the allow list from before does not admit bob: %v, %v", ok, err)
			}
			doc, _, found, err = s.Directory(p.alice.Fingerprint())
			if err != nil || !found || !bytes.Equal(doc, p.directory) {
				t.Errorf("the directory from before: found %v, %v", found, err)
			}
			if c.v >= 12 {
				answer, err := s.CarriedAnswerFor(p.bob.Fingerprint(), p.hash)
				if err != nil || answer.ID == 0 {
					t.Errorf("the queue's row from before is not answered for: %+v, %v", answer, err)
				}
			}

			if swept := s.Swept(); !swept.Empty() {
				t.Errorf("the sweep moved something in a database carried forward: %+v", swept)
			}
			// Reconciled counts mailboxes, and the planted mailboxes'
			// counters came across as the store wrote them; the queue's are
			// relay_stats, which it rewrites and does not count.
			t.Logf("Reconciled() at %s: %d", c.name, s.Reconciled())
			h := serveStore(t, s, Config{})
			h.assertCountersAgree()

			assertSameShape(t, fresh, shape(t, p.path))
		})
	}
}

// A step that fails leaves the database at the version before it: here a
// version 12 file that somebody gave the delivered column by hand, so the
// step to 13 meets a duplicate column. The refusal names the step, what it
// failed with, the version the database is still at and the copy, which
// was made before any step ran.
func TestAStepThatFailsLeavesTheDatabaseAtItsVersion(t *testing.T) {
	p := oldDatabase(t, 12, "")
	db, err := sql.Open("sqlite", p.path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`ALTER TABLE carried ADD COLUMN delivered INTEGER NOT NULL DEFAULT 0`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	_, err = OpenStore(p.path, p.messages)
	if err == nil {
		t.Fatal("a database whose step fails was opened")
	}
	cp := p.path + ".before-schema-12"
	want := fmt.Sprintf("relay: carrying %s forward, the step to schema version 13 failed: "+
		"SQL logic error: duplicate column name: delivered (1); "+
		"the database is still at version 12, and the copy made before the first step is %s, "+
		"which the next start refuses to write over: move it aside before starting again", p.path, cp)
	if err.Error() != want {
		t.Fatalf("error %q\nwant  %q", err, want)
	}
	if got := openVersion(t, p.path); got != 12 {
		t.Fatalf("the database is at version %d after the failed step, want 12", got)
	}
	db, err = sql.Open("sqlite", p.path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var mailboxes, outbound int
	db.QueryRow(`SELECT COUNT(*) FROM mailboxes`).Scan(&mailboxes)
	db.QueryRow(`SELECT COUNT(*) FROM outbound`).Scan(&outbound)
	if mailboxes != 2 || outbound != 1 {
		t.Errorf("after the failed step the database holds %d mailboxes and %d outbound rows, want 2 and 1", mailboxes, outbound)
	}
	if got := openVersion(t, cp); got != 12 {
		t.Errorf("the copy is at version %d, want 12", got)
	}
}

// The sentence for a failed step asks the operator to move the copy aside
// only when the next start would meet it: when no step had completed, so
// the database is still at the version the copy was made at. After a
// completed step the database is at a newer version, whose copy has a
// path of its own.
func TestAFailedStepAsksForTheCopyToMoveOnlyWhenItWouldBeMet(t *testing.T) {
	cause := errors.New("the cause")
	first := stepFailed("relay.db", 11, 12, 11, "relay.db.before-schema-11", cause).Error()
	if want := "relay: carrying relay.db forward, the step to schema version 12 failed: the cause; " +
		"the database is still at version 11, and the copy made before the first step is relay.db.before-schema-11, " +
		"which the next start refuses to write over: move it aside before starting again"; first != want {
		t.Errorf("the first step failing:\n got %q\nwant %q", first, want)
	}
	later := stepFailed("relay.db", 11, 13, 12, "relay.db.before-schema-11", cause).Error()
	if want := "relay: carrying relay.db forward, the step to schema version 13 failed: the cause; " +
		"the database is still at version 12, and the copy made before the first step is relay.db.before-schema-11"; later != want {
		t.Errorf("a later step failing:\n got %q\nwant %q", later, want)
	}
}

// Without the copy nothing moves. The copy cannot be made here because
// its name is longer than a file name may be, 243 bytes of database name
// and 17 of suffix, which every platform this relay runs on refuses at the
// create; the database's own name fits. The refusal names the database,
// the version, the copy's path and the cause, and the database is as it
// was found.
func TestNoCopyMeansNoMigration(t *testing.T) {
	p := oldDatabase(t, 11, "")
	long := filepath.Join(filepath.Dir(p.path), strings.Repeat("r", 240)+".db")
	if err := os.Rename(p.path, long); err != nil {
		t.Fatal(err)
	}
	cp := long + ".before-schema-11"
	_, err := OpenStore(long, p.messages)
	if err == nil {
		t.Fatal("a database was carried forward with no copy kept")
	}
	prefix := fmt.Sprintf("relay: %s is schema version 11 and is carried forward only after a copy is kept, "+
		"and the copy could not be made at %s: ", long, cp)
	if !strings.HasPrefix(err.Error(), prefix) || !strings.HasSuffix(err.Error(), "; nothing was changed") {
		t.Fatalf("error %q\nwant  %q…; nothing was changed", err, prefix)
	}
	if got := openVersion(t, long); got != 11 {
		t.Fatalf("the database is at version %d, want 11 as found", got)
	}
	if entries, _ := os.ReadDir(filepath.Dir(long)); len(entries) != 2 {
		t.Errorf("the refusal left something beside the database: %d entries, want the database and messages", len(entries))
	}
}

// A copy already at the path is refused, never replaced, whatever it is:
// a copy from an earlier upgrade the operator rolled back from, which is
// theirs, or anything else. The sentence names the path and says what to
// do, and the thing at the path and the database are left as found.
func TestACopyAlreadyThereIsNeverReplaced(t *testing.T) {
	for _, c := range []struct {
		name  string
		plant func(t *testing.T, cp string)
		check func(t *testing.T, cp string)
	}{
		{"a file", func(t *testing.T, cp string) {
			if err := os.WriteFile(cp, []byte("the copy from the last upgrade"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, func(t *testing.T, cp string) {
			if b, err := os.ReadFile(cp); err != nil || string(b) != "the copy from the last upgrade" {
				t.Errorf("the file at the copy's path was changed: %q, %v", b, err)
			}
		}},
		{"a symbolic link to nothing", func(t *testing.T, cp string) {
			// The case a write through the path would come from: a link
			// that points where the copy would then be written.
			if err := os.Symlink(filepath.Join(filepath.Dir(cp), "elsewhere"), cp); err != nil {
				t.Skipf("this platform will not make a symbolic link here: %v", err)
			}
		}, func(t *testing.T, cp string) {
			if _, err := os.Lstat(filepath.Join(filepath.Dir(cp), "elsewhere")); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("something was written through the link: %v", err)
			}
			if fi, err := os.Lstat(cp); err != nil || fi.Mode()&fs.ModeSymlink == 0 {
				t.Errorf("the link at the copy's path was changed: %v", err)
			}
		}},
		{"a directory", func(t *testing.T, cp string) {
			if err := os.MkdirAll(filepath.Join(cp, "kept"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(cp, "kept", "note"), []byte("the operator's"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, func(t *testing.T, cp string) {
			if b, err := os.ReadFile(filepath.Join(cp, "kept", "note")); err != nil || string(b) != "the operator's" {
				t.Errorf("the directory at the copy's path was changed: %q, %v", b, err)
			}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := oldDatabase(t, 11, "")
			cp := p.path + ".before-schema-11"
			c.plant(t, cp)
			_, err := OpenStore(p.path, p.messages)
			if err == nil {
				t.Fatal("a database was carried forward over a copy already there")
			}
			want := fmt.Sprintf("relay: %s is schema version 11 and is carried forward only after a copy is kept at %s, "+
				"and something is already there, which the relay never replaces: move it aside, or remove it once it "+
				"is no longer wanted; nothing was changed", p.path, cp)
			if err.Error() != want {
				t.Fatalf("error %q\nwant  %q", err, want)
			}
			if got := openVersion(t, p.path); got != 11 {
				t.Fatalf("the database is at version %d, want 11 as found", got)
			}
			c.check(t, cp)
		})
	}
}

// A database named as a file: URI is refused before anything moves, since
// the copy would be written where SQLite resolves the URI and the file
// calls around it would act on the name as written.
func TestADatabaseNamedAsAURIIsNotCarriedForward(t *testing.T) {
	p := oldDatabase(t, 11, "")
	uri := "file:" + p.path
	_, err := OpenStore(uri, p.messages)
	if err == nil {
		t.Fatal("a database named as a URI was carried forward")
	}
	want := fmt.Sprintf("relay: %s is schema version 11 and is named as a file: URI, which is not carried forward: "+
		"name the database by its path; nothing was changed", uri)
	if err.Error() != want {
		t.Fatalf("error %q\nwant  %q", err, want)
	}
	if got := openVersion(t, p.path); got != 11 {
		t.Fatalf("the database is at version %d, want 11 as found", got)
	}
	if copies, _ := filepath.Glob(p.path + ".before-schema-*"); len(copies) != 0 {
		t.Errorf("the refusal left a copy: %v", copies)
	}
}

// A relay over a database carried from 11 answers as it does over a new
// one: health, a registration, a post and the owner's listing, which
// holds the message from before beside the new one.
func TestAMigratedDatabaseServes(t *testing.T) {
	p := oldDatabase(t, firstKeptVersion, "")
	s, err := OpenStore(p.path, p.messages)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	h := serveStore(t, s, Config{})
	if status, body := h.do(nil, "GET", "/v1/health", nil, nil); status != http.StatusOK {
		t.Fatalf("health: %d %s", status, body)
	}
	carol := ids(t, "carol")[0]
	h.register(carol)
	if status, _, _ := h.send(p.bob, "POST", "/v1/mailbox/"+p.alice.Fingerprint(),
		sealed(t, p.bob, p.alice.Public(), "after"), nil); status != http.StatusOK {
		t.Fatalf("a post into a mailbox from before: %d", status)
	}
	status, body := h.do(p.alice, "GET", "/v1/mailbox/"+p.alice.Fingerprint(), nil, nil)
	if status != http.StatusOK {
		t.Fatalf("the listing: %d %s", status, body)
	}
	var listing relayapi.ListResponse
	if err := json.Unmarshal(body, &listing); err != nil {
		t.Fatal(err)
	}
	if len(listing.Messages) != 2 || listing.Queued != 2 {
		t.Errorf("the listing holds %d messages of %d queued, want the one from before and the new one:\n%s",
			len(listing.Messages), listing.Queued, body)
	}
	h.assertCountersAgree()
}

// A version with no step is refused before anything moves. The tree
// cannot hold such a version between the floor and schemaVersion by
// construction, so the step is asked for one directly: the version the
// floor is at, which nothing steps to, and the one after this build's.
func TestAVersionWithNoStepIsRefusedBeforeAnythingMoves(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenStore(filepath.Join(dir, "relay.db"), filepath.Join(dir, "messages"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, v := range []int{firstKeptVersion, schemaVersion + 1} {
		if err := s.step(v); !errors.Is(err, errNoStep) {
			t.Errorf("the step to %d answered %v, want errNoStep", v, err)
		}
		if got := openVersion(t, filepath.Join(dir, "relay.db")); got != schemaVersion {
			t.Errorf("after the refused step to %d the version is %d, want %d", v, got, schemaVersion)
		}
	}
}

// A new file gets its schema and its version in one transaction, and
// reads back at this build's version with no copy beside it, since there
// was nothing to carry.
func TestANewDatabaseIsCreatedAtThisVersion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "relay.db")
	s, err := OpenStore(path, filepath.Join(dir, "messages"))
	if err != nil {
		t.Fatal(err)
	}
	if got := s.CarriedForward(); got != (CarriedForward{}) {
		t.Errorf("a new database says it was carried forward: %+v", got)
	}
	s.Close()
	if got := openVersion(t, path); got != schemaVersion {
		t.Fatalf("a new database is at version %d, want %d", got, schemaVersion)
	}
	if copies, _ := filepath.Glob(path + ".before-schema-*"); len(copies) != 0 {
		t.Errorf("a new database left copies: %v", copies)
	}
}
