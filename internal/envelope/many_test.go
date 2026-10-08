package envelope

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/recipients"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/testutil"
	"github.com/tropeforce7/agentuucp/internal/wire"
)

// readers makes n identities to write to.
func readers(t *testing.T, n int) []*identity.Identity {
	t.Helper()
	out := make([]*identity.Identity, n)
	for i := range out {
		id, err := identity.Generate(fmt.Sprintf("reader%d", i))
		if err != nil {
			t.Fatal(err)
		}
		out[i] = id
	}
	return out
}

func publics(ids []*identity.Identity) []*identity.Public {
	out := make([]*identity.Public, len(ids))
	for i, id := range ids {
		out[i] = id.Public()
	}
	return out
}

// listOf is the recipients section's list in a record, or nil.
func listOf(t *testing.T, sections []wire.Section) []string {
	t.Helper()
	for _, s := range sections {
		if s.Name == recipients.Name {
			var l recipients.List
			if err := json.Unmarshal(s.Data, &l); err != nil {
				t.Fatal(err)
			}
			return l.To
		}
	}
	return nil
}

// A message to several, with N drawn from the seed and a made-up section
// riding beside the list (D35): one id, one thread, one time and one body in
// every copy, every copy's section bytes equal, every copy opening for its
// own recipient and for nobody else, and each reader finding the whole list
// in the sender's order with itself in it.
func TestAMessageToSeveralIsOneRecordSealedForEach(t *testing.T) {
	r, seed := testutil.Seed(t)
	alice, _ := pair(t)
	n := 2 + r.IntN(relayapi.MaxRecipients-1)
	to := readers(t, n)
	b := body(t)
	b.Text = testutil.Text(r, r.IntN(4<<10))
	madeUp := testutil.MadeUpSection(r)

	envs, inners, err := SealMany(alice, publics(to), "", b, []wire.Section{madeUp})
	if err != nil {
		t.Fatalf("seed %d: sealing for %d: %v", seed, n, err)
	}
	if len(envs) != n || len(inners) != n {
		t.Fatalf("seed %d: %d envelopes and %d records for %d recipients", seed, len(envs), len(inners), n)
	}
	want := make([]string, n)
	for i, id := range to {
		want[i] = id.Fingerprint()
	}
	var sectionBytes []byte
	for i, env := range envs {
		in := inners[i]
		if in.ID != inners[0].ID || in.Body.Thread != inners[0].Body.Thread || !in.Time.Equal(inners[0].Time) {
			t.Fatalf("seed %d: copy %d has id %s, thread %s, time %s; copy 1 has %s, %s, %s", seed, i+1,
				in.ID, in.Body.Thread, in.Time, inners[0].ID, inners[0].Body.Thread, inners[0].Time)
		}
		if env.To != want[i] || in.To != want[i] {
			t.Fatalf("seed %d: copy %d is addressed to %s; want %s", seed, i+1, env.To, want[i])
		}
		for j, other := range to {
			out, sender, err := Open(other, env)
			if j != i {
				if err == nil {
					t.Fatalf("seed %d: copy %d opened for recipient %d", seed, i+1, j+1)
				}
				continue
			}
			if err != nil {
				t.Fatalf("seed %d: copy %d does not open for its own recipient: %v", seed, i+1, err)
			}
			if sender.Fingerprint() != alice.Fingerprint() || out.Body.Text != b.Text {
				t.Fatalf("seed %d: copy %d did not survive", seed, i+1)
			}
			if got := listOf(t, out.Sections); strings.Join(got, ",") != strings.Join(want, ",") {
				t.Fatalf("seed %d: copy %d's list is %v; want %v", seed, i+1, got, want)
			}
			var gotMadeUp bool
			for _, s := range out.Sections {
				if s.Name == madeUp.Name && bytes.Equal(s.Data, madeUp.Data) {
					gotMadeUp = true
				}
				if s.Name == recipients.Name {
					if sectionBytes == nil {
						sectionBytes = s.Data
					} else if !bytes.Equal(s.Data, sectionBytes) {
						t.Fatalf("seed %d: copy %d's section bytes differ from copy 1's", seed, i+1)
					}
				}
			}
			if !gotMadeUp {
				t.Fatalf("seed %d: the made-up section %q did not survive in copy %d", seed, madeUp.Name, i+1)
			}
		}
	}
}

// One recipient is a message to one: no list, and the same record
// SealSections writes.
func TestAMessageToOneCarriesNoList(t *testing.T) {
	alice, bob := pair(t)
	envs, inners, err := SealMany(alice, []*identity.Public{bob.Public()}, "", body(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(envs) != 1 || inners[0].Sections != nil {
		t.Fatalf("%d envelopes, sections %v; want one and none", len(envs), inners[0].Sections)
	}
	if _, _, err := Open(bob, envs[0]); err != nil {
		t.Fatal(err)
	}
}

// What SealMany refuses, before anything is signed: nobody, more than the
// ceiling, one recipient twice, a list of its own beside the one it writes,
// and a list on a message that is one person's by its own rules.
func TestSealManyRefusesBeforeItSigns(t *testing.T) {
	alice, bob := pair(t)
	many := publics(readers(t, relayapi.MaxRecipients+1))
	signed := countingSigner(t, alice, -1)
	own, err := recipients.Section([]string{bob.Fingerprint()})
	if err != nil {
		t.Fatal(err)
	}
	knock := message.Body{Type: message.TypeKnock, Thread: body(t).Thread, Name: "alice", Text: "alice would like to exchange keys"}
	rows := []struct {
		name     string
		to       []*identity.Public
		b        message.Body
		sections []wire.Section
		want     string
	}{
		{"nobody", nil, body(t), nil, "a message to nobody"},
		{"one over the ceiling", many, body(t), nil, "33 recipients, at most 32"},
		{"a recipient twice", []*identity.Public{bob.Public(), many[0], bob.Public()}, body(t), nil, "is named twice"},
		{"a list of the caller's own", []*identity.Public{bob.Public(), many[0]}, body(t), []wire.Section{own}, "is written by SealMany"},
		{"a knock to several", []*identity.Public{bob.Public(), many[0]}, knock, nil, "one envelope to one person"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			envs, _, err := SealMany(signed.id, row.to, "", row.b, row.sections)
			if err == nil || !strings.Contains(err.Error(), row.want) || envs != nil {
				t.Fatalf("got %d envelopes, %v; want the refusal saying %q", len(envs), err, row.want)
			}
		})
	}
	if n := signed.count.Load(); n != 0 {
		t.Fatalf("%d signatures were made for messages that were refused", n)
	}
	// The ceiling itself is taken.
	if envs, _, err := SealMany(alice, many[:relayapi.MaxRecipients], "", body(t), nil); err != nil || len(envs) != relayapi.MaxRecipients {
		t.Fatalf("thirty-two recipients: %d envelopes, %v", len(envs), err)
	}
}

// A list given by hand to SealSections is held to the rule for that copy: a
// list that does not name the copy's recipient is not sealed.
func TestAHandWrittenListIsHeldToTheRule(t *testing.T) {
	alice, bob := pair(t)
	carol := readers(t, 1)[0]
	elsewhere, err := recipients.Section([]string{alice.Fingerprint(), carol.Fingerprint()})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := SealSections(alice, bob.Public(), "", body(t), []wire.Section{elsewhere}); !errors.Is(err, recipients.ErrForm) {
		t.Fatalf("a copy to bob whose list does not name him: %v; want the rule's refusal", err)
	}
}

// lockingSigner counts its signatures and, past lockAt of them, answers as
// a locked agent does; -1 never locks.
type lockingSigner struct {
	id     *identity.Identity
	count  atomic.Int64
	lockAt int64
	inner  *identity.Identity
}

func (l *lockingSigner) Public() []byte { return l.inner.Public().SignPublic() }
func (l *lockingSigner) Sign(msg []byte) ([]byte, error) {
	n := l.count.Add(1)
	if l.lockAt >= 0 && n > l.lockAt {
		return nil, identity.ErrLocked
	}
	return l.inner.Sign(msg)
}

// countingSigner is from as an identity whose signer counts, and locks after
// lockAt signatures when lockAt is not -1.
func countingSigner(t *testing.T, from *identity.Identity, lockAt int64) *lockingSigner {
	t.Helper()
	l := &lockingSigner{lockAt: lockAt, inner: from}
	id, err := identity.FromRemote(from.Suite(), from.Name, from.Public().Bundle(), l, from.KEM())
	if err != nil {
		t.Fatal(err)
	}
	l.id = id
	return l
}

// The agent locks after the first copy is signed: SealMany says ErrLocked
// and hands back no envelope, so a caller never holds part of a message to
// several and nothing is written for one.
func TestALockAfterTheFirstSignatureSealsNothing(t *testing.T) {
	alice, _ := pair(t)
	l := countingSigner(t, alice, 1)
	envs, inners, err := SealMany(l.id, publics(readers(t, 3)), "", body(t), nil)
	if !errors.Is(err, identity.ErrLocked) {
		t.Fatalf("locked after one signature: %v; want ErrLocked", err)
	}
	if envs != nil || inners != nil {
		t.Fatalf("%d envelopes and %d records came back from a seal that failed", len(envs), len(inners))
	}
	if n := l.count.Load(); n != 2 {
		t.Fatalf("%d signatures asked for; want the first, which was made, and the second, which was refused", n)
	}
}

// One flipped bit in every region of every copy, through the regions the
// single envelope's test names: each copy is guarded as any envelope is.
func TestBitFlipInEveryRegionOfEveryCopy(t *testing.T) {
	r, seed := testutil.Seed(t)
	alice, _ := pair(t)
	to := readers(t, 3)
	envs, _, err := SealMany(alice, publics(to), "", body(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	for i, env := range envs {
		encap := encapSize(t, to[i].Public())
		ct := env.CT
		for name, offset := range map[string]int{
			"encapsulation": encap / 2,
			"ciphertext":    encap + (len(ct)-encap)/2,
			"AEAD tag":      len(ct) - aeadTagSize,
		} {
			flipped := *env
			flipped.CT = testutil.FlipByteBit(ct, offset, r.IntN(8))
			if _, _, err := Open(to[i], &flipped); !errors.Is(err, ErrNotDecrypted) {
				t.Fatalf("seed %d: copy %d with a bit flipped in its %s: %v; want ErrNotDecrypted", seed, i+1, name, err)
			}
		}
	}
}

// The reader's half of the rule, past the sealer: a signed copy whose list
// does not name its reader, one with the list on a knock, and one whose data
// is over the cap and is not a list at all, each malformed, and the last for
// its size, since the size is checked before the decode.
func TestAListThatBreaksTheRuleIsMalformedAtOpen(t *testing.T) {
	alice, bob := pair(t)
	carol := readers(t, 1)[0]
	notBob := wire.Section{Name: recipients.Name, Data: json.RawMessage(
		`{"to":["` + alice.Fingerprint() + `","` + carol.Fingerprint() + `"]}`)}
	// Over the cap, and a JSON string where the list is an object, so a
	// decode that ran first would refuse it in its own words.
	oversize := wire.Section{Name: recipients.Name, Data: json.RawMessage(
		`"` + strings.Repeat("a", recipients.MaxBytes) + `"`)}
	withBob := wire.Section{Name: recipients.Name, Data: json.RawMessage(
		`{"to":["` + bob.Fingerprint() + `","` + carol.Fingerprint() + `"]}`)}

	knock := func() []byte {
		raw := record(t, alice, bob, Version, []wire.Section{withBob})
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		m["body"] = map[string]any{"type": message.TypeKnock, "thread": body(t).Thread,
			"name": "alice", "text": "alice would like to exchange keys"}
		out, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}

	rows := []struct {
		name  string
		inner []byte
		want  string
	}{
		{"a list that does not name the reader", record(t, alice, bob, Version, []wire.Section{notBob}), "does not name " + bob.Fingerprint()[:16]},
		{"a list over its cap", record(t, alice, bob, Version, []wire.Section{oversize}), fmt.Sprintf("over the %d it may be", recipients.MaxBytes)},
		{"a list on a knock", knock(), "one envelope to one person"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			env := sealRecord(t, alice, bob.Public(), Version, row.inner)
			_, _, err := Open(bob, env)
			if !errors.Is(err, ErrMalformed) || !strings.Contains(causeOf(err), row.want) {
				t.Fatalf("got %v (%s); want malformed, saying %q", err, causeOf(err), row.want)
			}
		})
	}
	// The same list naming bob is read.
	env := sealRecord(t, alice, bob.Public(), Version, record(t, alice, bob, Version, []wire.Section{withBob}))
	if _, _, err := Open(bob, env); err != nil {
		t.Fatalf("a list naming the reader: %v", err)
	}
}

// The rule is read only under the signature: a list that breaks it, in a
// record whose signature does not verify, is refused for the signature.
func TestAnUnsignedListIsRefusedForItsSignature(t *testing.T) {
	alice, bob := pair(t)
	mallory := readers(t, 1)[0]
	broken := wire.Section{Name: recipients.Name, Data: json.RawMessage(`{"to":[]}`)}
	env := sealRecord(t, mallory, bob.Public(), Version, record(t, alice, bob, Version, []wire.Section{broken}))
	if _, _, err := Open(bob, env); !errors.Is(err, ErrBadSender) {
		t.Fatalf("an unsigned list: %v; want the signature's refusal", err)
	}
}

// The same order on the envelope path: a signed record with a critical
// section this build does not know and a list that does not name its reader
// is malformed, never one that needs a newer auu, so nothing kept as newer
// carries a list nobody checked.
func TestARecordThatNeedsANewerAuuIsHeldToItsListFirst(t *testing.T) {
	alice, bob := pair(t)
	carol := readers(t, 1)[0]
	notBob := wire.Section{Name: recipients.Name, Data: json.RawMessage(
		`{"to":["` + alice.Fingerprint() + `","` + carol.Fingerprint() + `"]}`)}
	env := sealRecord(t, alice, bob.Public(), VersionCritical,
		record(t, alice, bob, VersionCritical, []wire.Section{later(true), notBob}))
	inner, _, err := Open(bob, env)
	if inner != nil || !errors.Is(err, ErrMalformed) || errors.Is(err, wire.ErrNeedsNewer) {
		t.Fatalf("got %v, %v; want no record and malformed, never needs-newer", inner, err)
	}
}
