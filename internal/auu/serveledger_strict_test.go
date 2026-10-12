package auu

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestALedgerWithAMisspeltHandledKeyIsRefused is the outside session's
// TestAdv3_ALedgerWithAMisspeltHandledKeyLoadsAsPending (G20), renamed for
// what it now proves: serve's ledger is the record of what has been
// answered, and loadLedger says a file that will not read is refused rather
// than replaced, "the alternative is answering a year of mail for a second
// time". The read was json.Unmarshal, which drops a key it does not know,
// so an entry whose handled key was misspelt, by a hand edit or a restore,
// read as never handled: settled() was false and the message was pending
// work again, answered a second time. The strict decoder refuses the key by
// name.
func TestALedgerWithAMisspeltHandledKeyIsRefused(t *testing.T) {
	for _, entry := range []string{
		`{"thread":"t","channel":"","handeld":"2026-01-01T00:00:00Z","tried":"2026-01-01T00:00:00Z","reply":"r"}`,
		`{"thread":"t","channel":"","handled":"2026-01-01T00:00:00Z","handled":"0001-01-01T00:00:00Z","tried":"2026-01-01T00:00:00Z","reply":"r"}`,
		`{"thread":"t","channel":"","Handled":"2026-01-01T00:00:00Z","tried":"2026-01-01T00:00:00Z","reply":"r"}`,
	} {
		t.Run(entry[:40], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "ledger.json")
			if err := os.WriteFile(path, []byte(`{"v":1,"messages":{"m":`+entry+`}}`), 0o600); err != nil {
				t.Fatal(err)
			}
			l, err := loadLedger(path)
			if err == nil {
				if e := l.Messages["m"]; e != nil && !e.settled() {
					t.Fatalf("the ledger loaded without error and the entry is pending: a misspelt, repeated or case-variant handled key makes answered mail new; want the file refused as unreadable")
				}
				t.Fatalf("the ledger loaded without error; want the file refused as unreadable")
			}
		})
	}
}

// TestALedgerThatReadsTwoWaysIsRefusedAndKept is the ledger's shape row
// for the strict read (R24), as TestLimitStoredRecordShapes holds the
// home's files: the ledger as written is taken, and an unknown key, a key
// given twice, a key that matches only by case, and anything after the
// value (a closing brace, a closing bracket, a stray letter) are each
// refused in the loader's words, naming the file, with the file left
// byte for byte as it was found, since a refusal that wrote is a migration
// in disguise.
func TestALedgerThatReadsTwoWaysIsRefusedAndKept(t *testing.T) {
	id := strings.Repeat("a", 32)
	whole := `{"v":1,"messages":{"` + id + `":{"thread":"` + id + `","channel":"","tried":"2026-09-20T10:00:00Z"}}}`
	path := filepath.Join(t.TempDir(), ledgerFile)
	if err := os.WriteFile(path, []byte(whole), 0o600); err != nil {
		t.Fatal(err)
	}
	if l, err := loadLedger(path); err != nil || l.Messages[id] == nil {
		t.Fatalf("the ledger as written: %v; want it taken", err)
	}
	for _, tc := range []struct{ name, text, says string }{
		{"an unknown key", strings.Replace(whole, `{"v":1,`, `{"v":1,"extra":1,`, 1), `unknown field "extra"`},
		{"a key twice", strings.Replace(whole, `{"v":1,`, `{"v":1,"v":1,`, 1), `key "v" appears twice`},
		{"a key twice in an entry", strings.Replace(whole, `"channel":""`, `"channel":"","channel":""`, 1), `key "channel" appears twice`},
		{"a key in another case", strings.Replace(whole, `"tried"`, `"Tried"`, 1), `key "Tried" matches the field "tried" only by case`},
		{"a closing brace after", whole + "}", "trailing data after the value"},
		{"a closing bracket after", whole + "]", "trailing data after the value"},
		{"a stray letter after", whole + "x", "trailing data after the value"},
	} {
		if err := os.WriteFile(path, []byte(tc.text), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := loadLedger(path)
		if err == nil || !strings.HasPrefix(err.Error(), path+" will not read (") ||
			!strings.Contains(err.Error(), tc.says) ||
			!strings.Contains(err.Error(), "it is the record of what has been answered") {
			t.Errorf("%s: %v; want the file named, %q, and the ledger's advice", tc.name, err, tc.says)
		}
		after, rerr := os.ReadFile(path)
		if rerr != nil || !bytes.Equal(after, []byte(tc.text)) {
			t.Errorf("%s: the refusal changed the file (%v): %q", tc.name, rerr, after)
		}
	}
}
