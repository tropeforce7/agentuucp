package store

import (
	"os"
	"testing"
	"time"
)

// The file beside the cursor: absent until a push, one RFC 3339 line after,
// read back to the second, gone after a clear, and gone with the identity.
func TestAllowPushedIsAFileBesideTheCursor(t *testing.T) {
	s := newStore(t)
	r, err := s.AddRelay("work", "https://work.example:9443")
	if err != nil {
		t.Fatal(err)
	}
	if _, found, err := s.AllowPushed(r); err != nil || found {
		t.Fatalf("before a push: found %v, %v", found, err)
	}
	at := time.Date(2026, 9, 17, 10, 4, 5, 999, time.FixedZone("AEST", 10*3600))
	if err := s.SetAllowPushed(r, at); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(s.relayPath(r, allowPushedFile))
	if err != nil || string(data) != "2026-09-17T00:04:05Z\n" {
		t.Fatalf("the file holds %q (%v); want one UTC line", data, err)
	}
	pushed, found, err := s.AllowPushed(r)
	if err != nil || !found || !pushed.Equal(at.Truncate(time.Second)) {
		t.Fatalf("after a push: %v %v %v", pushed, found, err)
	}
	if err := s.ClearAllowPushed(r); err != nil {
		t.Fatal(err)
	}
	if _, found, err := s.AllowPushed(r); err != nil || found {
		t.Fatalf("after a clear: found %v, %v", found, err)
	}
	// Clearing what is not there is nothing.
	if err := s.ClearAllowPushed(r); err != nil {
		t.Fatal(err)
	}
	// It goes with the identity, as the cursor does.
	if err := s.SetAllowPushed(r, at); err != nil {
		t.Fatal(err)
	}
	if err := s.ForgetIdentityAt(r); err != nil {
		t.Fatal(err)
	}
	if _, found, _ := s.AllowPushed(r); found {
		t.Fatal("allow_pushed survived ForgetIdentityAt")
	}
}
