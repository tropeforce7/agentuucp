package store

import (
	"errors"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/card"
	"github.com/tropeforce7/agentuucp/internal/identity"
)

// card.json is read through the damaged-file path: a home with none has
// pushed no card; one that is there and will not read, or reads to a card
// no relay would take, is said to be, by name, and exits 5. A card that
// breaks a rule is never written.
func TestTheCardFileIsReadThroughTheDamagedPath(t *testing.T) {
	s := newStore(t)
	id, err := identity.Generate("ada")
	if err != nil {
		t.Fatal(err)
	}
	if d, found, err := s.Card(); err != nil || found || d != nil {
		t.Fatalf("a home with no file: %+v %v %v", d, found, err)
	}

	want := &card.Document{V: 1, Owner: id.Fingerprint(), Issued: time.Date(2026, 9, 22, 1, 19, 29, 123456789, time.UTC),
		Name: "ada", Listed: true}
	if err := s.SetCard(want); err != nil {
		t.Fatal(err)
	}
	got, found, err := s.Card()
	if err != nil || !found {
		t.Fatalf("after writing: %v %v", found, err)
	}
	if got.Owner != want.Owner || !got.Issued.Equal(want.Issued) || got.Name != "ada" || !got.Listed || got.Knocks {
		t.Fatalf("the card did not survive the file: %+v", got)
	}
	// issued is in the file, to the nanosecond, since push signs under it.
	raw, _ := os.ReadFile(s.CardPath())
	if !strings.Contains(string(raw), `"issued": "2026-09-22T01:19:29.123456789Z"`) {
		t.Fatalf("the file does not hold issued as signed:\n%s", raw)
	}
	// Both words are in the file, false included, so the file says what
	// it means.
	if !strings.Contains(string(raw), `"knocks": false`) {
		t.Fatalf("the file leaves a false word out:\n%s", raw)
	}
	// Go's FileMode on Windows says nothing about who can read a file; the
	// mode is Unix's, and the Windows job reported 666.
	if runtime.GOOS != "windows" {
		if info, _ := os.Stat(s.CardPath()); info.Mode().Perm() != fileMode {
			t.Fatalf("the file is %o, want %o", info.Mode().Perm(), fileMode)
		}
	}

	// A card that breaks a rule is not written.
	bad := *want
	bad.Name = ""
	if err := s.SetCard(&bad); err == nil || !strings.Contains(err.Error(), "name is empty") {
		t.Fatalf("an invalid card was written, or refused without the rule: %v", err)
	}
	if got, _, _ := s.Card(); got.Name != "ada" {
		t.Fatal("the refused write changed the file")
	}

	// A file that is not JSON.
	if err := os.WriteFile(s.CardPath(), []byte("{not json"), fileMode); err != nil {
		t.Fatal(err)
	}
	_, _, err = s.Card()
	if !errors.Is(err, ErrDamaged) {
		t.Fatalf("a file that is not JSON: %v, want ErrDamaged", err)
	}
	if !strings.HasPrefix(err.Error(), s.CardPath()+" is not valid JSON (") ||
		!strings.Contains(err.Error(), "fix it, or delete it and push your card again with 'auu card push'") {
		t.Fatalf("the sentence: %v", err)
	}
	// A file that is JSON and breaks a rule: hand-edited.
	if err := os.WriteFile(s.CardPath(), []byte(`{"v":1,"owner":"`+id.Fingerprint()+`","issued":"2026-09-22T01:19:29Z","name":"ada smith","listed":true,"knocks":false}`), fileMode); err != nil {
		t.Fatal(err)
	}
	_, _, err = s.Card()
	if !errors.Is(err, ErrDamaged) {
		t.Fatalf("a file that breaks a rule: %v, want ErrDamaged", err)
	}
	if want := s.CardPath() + ` holds a card no relay would take (name "ada smith": letters, digits, '.', '_' and '-' only, beginning with a letter or digit): fix it`; !strings.HasPrefix(err.Error(), want) {
		t.Fatalf("the sentence:\n%v\nwant a prefix of\n%s", err, want)
	}
}

// The file beside the cursor: absent until a push, one RFC 3339 line after,
// read back to the second, gone after a clear, gone with the identity, and
// one that is not a time refused by name with the fix.
func TestCardPushedIsAFileBesideTheCursor(t *testing.T) {
	s := newStore(t)
	r, err := s.AddRelay("work", "https://work.example:9443")
	if err != nil {
		t.Fatal(err)
	}
	if _, found, err := s.CardPushed(r); err != nil || found {
		t.Fatalf("before a push: found %v, %v", found, err)
	}
	at := time.Date(2026, 9, 22, 10, 4, 5, 999, time.FixedZone("AEST", 10*3600))
	if err := s.SetCardPushed(r, at); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(s.relayPath(r, cardPushedFile))
	if err != nil || string(data) != "2026-09-22T00:04:05Z\n" {
		t.Fatalf("the file holds %q (%v); want one UTC line", data, err)
	}
	pushed, found, err := s.CardPushed(r)
	if err != nil || !found || !pushed.Equal(at.Truncate(time.Second)) {
		t.Fatalf("after a push: %v %v %v", pushed, found, err)
	}
	if err := s.ClearCardPushed(r); err != nil {
		t.Fatal(err)
	}
	if _, found, err := s.CardPushed(r); err != nil || found {
		t.Fatalf("after a clear: found %v, %v", found, err)
	}
	// Clearing what is not there is nothing.
	if err := s.ClearCardPushed(r); err != nil {
		t.Fatal(err)
	}
	// It goes with the identity, as the cursor does.
	if err := s.SetCardPushed(r, at); err != nil {
		t.Fatal(err)
	}
	if err := s.ForgetIdentityAt(r); err != nil {
		t.Fatal(err)
	}
	if _, found, _ := s.CardPushed(r); found {
		t.Fatal("card_pushed survived ForgetIdentityAt")
	}
	// A file that is not a time: damaged, by name, with the fix; the
	// text is cut at forty bytes in the sentence.
	if err := os.WriteFile(s.relayPath(r, cardPushedFile), []byte(strings.Repeat("x", 50)+"\n"), fileMode); err != nil {
		t.Fatal(err)
	}
	_, _, err = s.CardPushed(r)
	if !errors.Is(err, ErrDamaged) {
		t.Fatalf("a marker that is not a time: %v, want ErrDamaged", err)
	}
	if !strings.Contains(err.Error(), `is not a time ("`+strings.Repeat("x", 40)+`…")`) ||
		!strings.Contains(err.Error(), "delete it, or run 'auu card push', which writes it again") {
		t.Fatalf("the sentence: %v", err)
	}
}
