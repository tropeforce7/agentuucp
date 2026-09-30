package store

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

func fp(c byte) string { return strings.Repeat(string(c), 64) }

// TestCouriersAdmitsWithdrawsAndIsPerRelay: the whole of what the file is for,
// and the thing about it that is easiest to get wrong.
//
// A courier is a relay's own identity enrolled at its neighbour, so the
// fingerprint that carries mail to one of this identity's relays means nothing
// at another and neither does the name. Two relays in one home therefore keep
// two of these files with nothing in common, and a change at one must not be
// visible at the other — which is what the last third of this test is about,
// because a single file shared between relays would be the natural mistake and
// would admit at one relay somebody only the other was told about.
func TestCouriersAdmitsWithdrawsAndIsPerRelay(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// A relay with no file admits nobody, which is not an error: it is what
	// every relay looks like until somebody admits one.
	if list, err := s.Couriers("work"); err != nil || len(list) != 0 {
		t.Fatalf("a relay with no file: %v %v", list, err)
	}
	if err := s.AddCourier("work", fp('a'), "zed"); err != nil {
		t.Fatal(err)
	}
	if err := s.AddCourier("work", fp('b'), "abe"); err != nil {
		t.Fatal(err)
	}
	// The same name and fingerprint again changes nothing, so the command is
	// safe to repeat.
	if err := s.AddCourier("work", fp('a'), "zed"); err != nil {
		t.Fatal(err)
	}
	list, err := s.Couriers("work")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].Name != "abe" || list[1].Name != "zed" {
		t.Fatalf("Couriers = %+v; want abe and zed in name order", list)
	}
	if list[0].FP != fp('b') || list[1].FP != fp('a') {
		t.Errorf("the names and fingerprints do not match: %+v", list)
	}

	// A name re-keyed replaces the fingerprint rather than adding a second
	// line, since the name is what the person chose and the fingerprint is
	// what the relay now says it is.
	if err := s.AddCourier("work", fp('c'), "zed"); err != nil {
		t.Fatal(err)
	}
	list, _ = s.Couriers("work")
	if len(list) != 2 {
		t.Fatalf("after re-keying: %+v; want still two", list)
	}
	for _, c := range list {
		if c.Name == "zed" && c.FP != fp('c') {
			t.Errorf("zed is %s; want the new fingerprint", c.FP[:8])
		}
	}

	// And the other way round: the same fingerprint under a different name is
	// the operator having renamed that neighbour, and replaces the line too,
	// because keeping both would write a file Couriers then refuses to read —
	// it rejects one fingerprint under two names. What that costs is that
	// removing by the old name finds nothing, which is why AddCourier's comment
	// says so.
	if err := s.AddCourier("work", fp('c'), "zedd"); err != nil {
		t.Fatal(err)
	}
	list, err = s.Couriers("work")
	if err != nil {
		t.Fatalf("after a rename the file will not read: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("after a rename: %+v; want still two", list)
	}
	var names []string
	for _, c := range list {
		names = append(names, c.Name)
	}
	if strings.Join(names, ",") != "abe,zedd" {
		t.Errorf("names are %v; want the old name gone and the new one there", names)
	}
	if removed, err := s.RemoveCourier("work", "zed"); err != nil || removed {
		t.Errorf("removing by the old name = %v, %v; want nothing found", removed, err)
	}
	// Put the name back for the rest of the test.
	if err := s.AddCourier("work", fp('c'), "zed"); err != nil {
		t.Fatal(err)
	}

	// Withdrawing by name, and saying whether it was there.
	removed, err := s.RemoveCourier("work", "abe")
	if err != nil || !removed {
		t.Fatalf("RemoveCourier = %v, %v; want it removed", removed, err)
	}
	removed, err = s.RemoveCourier("work", "abe")
	if err != nil || removed {
		t.Fatalf("removing it twice = %v, %v; want false and no error", removed, err)
	}

	// Per relay. The other relay was never told about zed, and must not have
	// it: a shared file would admit at one relay somebody only the other was
	// told about, which is the whole reason this is keyed by relay.
	if list, err := s.Couriers("home"); err != nil || len(list) != 0 {
		t.Fatalf("the other relay: %+v %v; want nobody", list, err)
	}
	if err := s.AddCourier("home", fp('d'), "zed"); err != nil {
		t.Fatal(err)
	}
	work, _ := s.Couriers("work")
	if len(work) != 1 || work[0].FP != fp('c') {
		t.Errorf("admitting at 'home' changed 'work': %+v", work)
	}
	home, _ := s.Couriers("home")
	if len(home) != 1 || home[0].FP != fp('d') {
		t.Errorf("'home' holds %+v; want its own courier only", home)
	}

	// Emptying removes the file rather than leaving an empty one: a relay with
	// no couriers and a relay whose file says none are one state, and the
	// absent file is the one that needs no explaining.
	if _, err := s.RemoveCourier("work", "zed"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(s.relayDir("work"), couriersFile)); !os.IsNotExist(err) {
		t.Errorf("the file is still there with nothing in it: %v", err)
	}
}

// TestLimitACouriersFileLineIsHeldToItsShape: every way a line can be wrong,
// refused by name and by line number.
//
// The file is written by this program and read back by it, so a bad line means
// somebody edited it or something truncated it. It is held here rather than
// where it is used because this is the one place it is read, and a fingerprint
// that reached an allow list unchecked would become a document the relay
// refuses with a sentence about a file the person never edited — a failure two
// steps from its cause.
func TestLimitACouriersFileLineIsHeldToItsShape(t *testing.T) {
	for _, tc := range []struct {
		name, body, want string
	}{
		{"no name", fp('a') + "\n", "not a fingerprint and a name"},
		{"not a fingerprint", "zzz bar\n", "not a fingerprint"},
		{"a short fingerprint", strings.Repeat("a", 63) + " bar\n", "not a fingerprint"},
		{"a long fingerprint", strings.Repeat("a", 65) + " bar\n", "not a fingerprint"},
		{"upper-case hex", strings.Repeat("A", 64) + " bar\n", "not a fingerprint"},
		{"a name that is not a relay name", fp('a') + " ../x\n", "not a relay name"},
		{"a name that is a Windows device", fp('a') + " con\n", "not a relay name"},
		{"the reserved name", fp('a') + " self\n", "not a relay name"},
		{"one fingerprint twice", fp('a') + " bar\n" + fp('a') + " baz\n", "twice"},
		{"two fingerprints under one name", fp('a') + " bar\n" + fp('b') + " bar\n", "two couriers under the name"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(s.relayDir("work"), dirMode); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(s.relayDir("work"), couriersFile)
			if err := os.WriteFile(path, []byte(tc.body), fileMode); err != nil {
				t.Fatal(err)
			}
			_, err = s.Couriers("work")
			if err == nil {
				t.Fatalf("the line %q was taken", tc.body)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("%v; want it to say %q", err, tc.want)
			}
			// And the advice, so somebody meeting this knows what to do with
			// a file they did not write by hand.
			if !strings.Contains(err.Error(), "auu allow add --courier") {
				t.Errorf("%v; want the advice naming the command that writes it", err)
			}
		})
	}
	// Blank lines and surrounding space are not errors: a file somebody
	// opened in an editor is still their file.
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(s.relayDir("work"), dirMode); err != nil {
		t.Fatal(err)
	}
	body := "\n" + fp('a') + " bar \n\n  " + fp('b') + " baz\n\n"
	if err := os.WriteFile(filepath.Join(s.relayDir("work"), couriersFile), []byte(body), fileMode); err != nil {
		t.Fatal(err)
	}
	list, err := s.Couriers("work")
	if err != nil || len(list) != 2 {
		t.Fatalf("a file with blank lines and spaces: %+v %v", list, err)
	}
}

// TestACouriersFileRoundTripsAsWritten: what SetCouriers writes is what
// Couriers reads, and the form on disk is the one the plan names.
//
// The form matters beyond this package: a person may read the file, and the
// relay's own couriers file uses the same shape, so one line is one sender and
// the fingerprint comes first.
func TestACouriersFileRoundTripsAsWritten(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	in := []AdmittedCourier{{FP: fp('b'), Name: "zed"}, {FP: fp('a'), Name: "abe"}}
	if err := s.SetCouriers("work", in); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(s.relayDir("work"), couriersFile))
	if err != nil {
		t.Fatal(err)
	}
	want := fp('a') + " abe\n" + fp('b') + " zed\n"
	if string(raw) != want {
		t.Errorf("the file is %q; want the fingerprint, a space, the name, in name order", raw)
	}
	out, err := s.Couriers("work")
	if err != nil || len(out) != 2 || out[0] != in[1] || out[1] != in[0] {
		t.Errorf("round trip gave %+v, %v", out, err)
	}
	// A bad entry is refused at the write and leaves what was there, so a
	// caller that passes something wrong does not lose the file.
	if err := s.SetCouriers("work", []AdmittedCourier{{FP: "nope", Name: "bar"}}); err == nil {
		t.Error("SetCouriers took a bad fingerprint")
	}
	if again, err := s.Couriers("work"); err != nil || len(again) != 2 {
		t.Errorf("after a refused write the file is %+v, %v; want the two still there", again, err)
	}
}

// TestAnAdmittedCourierIsNotAPeer: the invariant that decides where a
// courier's own message lands, which nothing tested and which the documents
// now rest on.
//
// An allow list is one list and the relay asks it one question, so whoever
// holds an admitted courier's key may also seal a message and post it
// directly. What bounds that is this: the inbox-or-quarantine decision is
// IsAuthorized, which is this identity's peer list, and admitting a courier
// adds nothing to it — so such a message arrives as a stranger's does. If
// admitting ever touched the peer list, a courier's own mail would land in the
// inbox and the sentence in docs/security.md would be false.
func TestAnAdmittedCourierIsNotAPeer(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	courier := fp('a')
	if err := s.AddCourier("work", courier, "bar"); err != nil {
		t.Fatal(err)
	}
	if s.IsAuthorized(courier) {
		t.Error("an admitted courier is authorized, so its own mail would land in the inbox " +
			"rather than in quarantine")
	}
	peers, err := s.Peers()
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 0 {
		t.Errorf("admitting a courier added %d peer(s)", len(peers))
	}
}

// TestSetCouriersRefusesWhatCouriersCannotRead: the store's exported edge holds
// every rule its own reader holds.
//
// A writer that can produce a file its reader refuses is worse than an
// unchecked read: the file stops 'allow push', a knock and the push offered
// after trusting a sender all at once, and the person has to repair by hand a
// file they never wrote. SetLeftBehind, the writer this was modelled on,
// dedupes for the same reason.
func TestSetCouriersRefusesWhatCouriersCannotRead(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		list []AdmittedCourier
		want string
	}{
		{"one fingerprint twice", []AdmittedCourier{
			{FP: fp('a'), Name: "bar"}, {FP: fp('a'), Name: "baz"},
		}, "listed twice"},
		{"two fingerprints under one name", []AdmittedCourier{
			{FP: fp('a'), Name: "bar"}, {FP: fp('b'), Name: "bar"},
		}, "two couriers under the name"},
		{"two names differing only in case", []AdmittedCourier{
			{FP: fp('a'), Name: "bar"}, {FP: fp('b'), Name: "Bar"},
		}, "two couriers under the name"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := s.SetCouriers("work", tc.list)
			if err == nil {
				t.Fatalf("SetCouriers wrote a file Couriers cannot read: %+v", tc.list)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("%v; want it to say %q", err, tc.want)
			}
			// And nothing was written, so a refused write does not leave a
			// file worse than the one it replaced.
			if list, err := s.Couriers("work"); err != nil || len(list) != 0 {
				t.Errorf("after a refused write: %+v, %v", list, err)
			}
		})
	}
}

// TestCourierNamesAreComparedAsTheRelayComparesThem: folded, because the relay
// folds, and the same rule in all four places this package compares one.
//
// The relay's couriers file refuses two neighbours whose names differ only in
// case, it keys the home it dials from folded, and this home refuses two relays
// whose names differ only in case. Comparing exactly here would let this file
// hold two names the relay's own loader would refuse, and would leave
// 'rm --courier bar' removing one and silently leaving the other admitted —
// which is the ambiguity the check exists to prevent, reached by the route the
// code claimed to guard.
func TestCourierNamesAreComparedAsTheRelayComparesThem(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AddCourier("work", fp('a'), "bar"); err != nil {
		t.Fatal(err)
	}
	// A different neighbour under a name differing only in case replaces it,
	// rather than sitting beside it.
	if err := s.AddCourier("work", fp('b'), "Bar"); err != nil {
		t.Fatal(err)
	}
	list, err := s.Couriers("work")
	if err != nil {
		t.Fatalf("the file will not read: %v", err)
	}
	if len(list) != 1 || list[0].FP != fp('b') {
		t.Fatalf("Couriers = %+v; want the one, under the newer fingerprint", list)
	}
	// And removing by either spelling finds it.
	if removed, err := s.RemoveCourier("work", "bAr"); err != nil || !removed {
		t.Errorf("RemoveCourier by another spelling = %v, %v; want it found", removed, err)
	}
	if list, _ := s.Couriers("work"); len(list) != 0 {
		t.Errorf("after rm: %+v", list)
	}
}

// TestACouriersFileIsHeldToMaxCouriersAtRead: the cap the other two ends have.
func TestACouriersFileIsHeldToMaxCouriersAtRead(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(s.relayDir("work"), dirMode); err != nil {
		t.Fatal(err)
	}
	// Distinct fingerprints and distinct names, or a duplicate check fires
	// before the cap does and the test would pass for the wrong reason.
	var b strings.Builder
	for i := range relayapi.MaxCouriers + 1 {
		fmt.Fprintf(&b, "%064x r%d\n", i, i)
	}
	if err := os.WriteFile(filepath.Join(s.relayDir("work"), couriersFile), []byte(b.String()), fileMode); err != nil {
		t.Fatal(err)
	}
	_, err = s.Couriers("work")
	if err == nil {
		t.Fatalf("a file of %d couriers was read", relayapi.MaxCouriers+1)
	}
	if !strings.Contains(err.Error(), "more than") {
		t.Errorf("%v; want the cap named", err)
	}
}
