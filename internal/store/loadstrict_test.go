package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/vouch"
	"github.com/tropeforce7/agentuucp/internal/wire"
)

// The keys each release wrote, read from its tag (git show
// vX:internal/store/store.go, internal/envelope/envelope.go and
// internal/message/message.go). Stored's outer keys are this build's
// without arrived at all three, and v0.15.0's without copies too; the
// message's keys, a section's, an attachment's, a carried document's and a
// copy's are the same at all three.
var (
	outerKeysV0150 = []string{"channel", "dropped_sections", "inner", "newer", "on_relay", "path", "payload_gone",
		"payload_on_relay", "read", "received", "relay", "relay_id", "relay_size", "sender_name", "streamed", "via"}
	outerKeysV0160 = append(slices.Clone(outerKeysV0150), "copies")
	innerKeys      = []string{"body", "channel", "from", "from_bundle", "id", "sections", "time", "to", "v"}
	bodyKeys       = []string{"about", "attachments", "in_reply_to", "name", "subject", "text", "thread", "type", "vouch", "vouches"}
	attachmentKeys = []string{"data", "media", "name", "sha256", "size"}
	carriedKeys    = []string{"document", "signature"}
	sectionKeys    = []string{"critical", "data", "name"}
	copyKeys       = []string{"dropped", "fingerprint", "name", "path", "refused", "refused_code", "relay_id"}
)

// TestARecordEachReleaseWroteStillLoads: Store.Load reads strictly now
// (R24a), so a record from v0.15.0, v0.16.0 or v0.17.0 loads only if every
// key that release wrote is still a field. Each release's records are
// planted in its exact keys, every omitempty key given a value so that it
// appears, the keys held to the lists read from the tag before anything is
// loaded: an ask with everything a received message can carry, a knock, a
// vouch and a vouch question for the body's keys that belong to one type
// each, and, from v0.16.0, a sent message to two with a copy each. Each
// loads, its arrival read as its received, and the file is as it was.
func TestARecordEachReleaseWroteStillLoads(t *testing.T) {
	now := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	from, to, third := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)
	voucher, err := identity.Generate("xena")
	if err != nil {
		t.Fatal(err)
	}
	subject, err := identity.Generate("victor")
	if err != nil {
		t.Fatal(err)
	}
	doc, sig, err := vouch.Sign(voucher, &vouch.Document{Subject: subject.Fingerprint(), Bundle: subject.Public().Bundle(),
		Name: "victor", Issued: now}, now)
	if err != nil {
		t.Fatal(err)
	}
	carried := message.Carried{Document: doc, Signature: sig}
	type planted struct {
		name string
		box  Box
		m    *Stored
	}
	records := func(t *testing.T, withCopies bool) []planted {
		ask := stored(strings.Repeat("1", 32), now)
		ask.Read, ask.SenderName, ask.Streamed, ask.PayloadOnRelay, ask.PayloadGone = true, "bob", true, true, true
		ask.RelaySize, ask.OnRelay, ask.Channel, ask.Via, ask.Path = 70000, true, "bugs", "far!near", "x!y"
		ask.Newer, ask.DroppedSections = "a-newer-thing", 1
		ask.Inner.V, ask.Inner.FromBundle, ask.Inner.Time, ask.Inner.Channel = 1, []byte("bundle"), now, "bugs"
		ask.Inner.Sections = []wire.Section{{Name: "made-up", Critical: false, Data: json.RawMessage(`{"a":1}`)}}
		ask.Inner.Body.Subject, ask.Inner.Body.InReplyTo = "a subject", strings.Repeat("2", 32)
		ask.Inner.Body.Attachments = []message.Attachment{{Name: "a.txt", Media: "text/plain", Size: 1,
			SHA256: strings.Repeat("0", 64), Data: []byte("x")}}

		knock := stored(strings.Repeat("3", 32), now)
		knock.Inner.Body = message.Body{Type: message.TypeKnock, Thread: knock.Inner.Body.Thread, Name: "alice",
			Text: "hello", Vouches: []message.Carried{carried}}
		vouch := stored(strings.Repeat("4", 32), now)
		vouch.Inner.Body = message.Body{Type: message.TypeVouch, Thread: vouch.Inner.Body.Thread, Vouch: &carried}
		vouchAsk := stored(strings.Repeat("5", 32), now)
		vouchAsk.Inner.Body = message.Body{Type: message.TypeVouchAsk, Thread: vouchAsk.Inner.Body.Thread,
			About: strings.Repeat("d", 64)}
		out := []planted{{"an ask", Inbox, ask}, {"a knock", Inbox, knock}, {"a vouch", Inbox, vouch}, {"a vouch question", Inbox, vouchAsk}}
		if withCopies {
			sent := stored(strings.Repeat("6", 32), now)
			sent.Inner.From, sent.Inner.To = from, to
			sent.Inner.Sections = []wire.Section{recipientsList(t, to, third)}
			sent.Copies = []SentCopy{
				{Fingerprint: to, Name: "bob", Path: "x!y", RelayID: 7},
				{Fingerprint: third, Name: "carol", RefusedCode: "mailbox-full", Refused: "full", Dropped: true},
			}
			out = append(out, planted{"a sent message to two", Sent, sent})
		}
		return out
	}
	for _, tag := range []struct {
		name       string
		outer      []string
		withCopies bool
	}{
		{"v0.15.0", outerKeysV0150, false},
		{"v0.16.0", outerKeysV0160, true},
		{"v0.17.0", outerKeysV0160, true},
	} {
		t.Run(tag.name, func(t *testing.T) {
			s := newStore(t)
			seen := map[string]map[string]bool{}
			note := func(kind string, obj map[string]any) {
				if seen[kind] == nil {
					seen[kind] = map[string]bool{}
				}
				for k := range obj {
					seen[kind][k] = true
				}
			}
			for _, p := range records(t, tag.withCopies) {
				data, err := json.Marshal(p.m)
				if err != nil {
					t.Fatal(err)
				}
				var doc map[string]any
				if err := json.Unmarshal(data, &doc); err != nil {
					t.Fatal(err)
				}
				// This build's one key the tags did not write.
				delete(doc, "arrived")
				note("outer", doc)
				inner := doc["inner"].(map[string]any)
				note("inner", inner)
				body := inner["body"].(map[string]any)
				note("body", body)
				for _, kind := range []struct{ key, as string }{{"attachments", "attachment"}, {"vouches", "carried"}} {
					list, _ := body[kind.key].([]any)
					for _, one := range list {
						note(kind.as, one.(map[string]any))
					}
				}
				if v, ok := body["vouch"].(map[string]any); ok {
					note("carried", v)
				}
				list, _ := inner["sections"].([]any)
				for _, one := range list {
					note("section", one.(map[string]any))
				}
				copies, _ := doc["copies"].([]any)
				for _, one := range copies {
					note("copy", one.(map[string]any))
				}
				text, err := json.MarshalIndent(doc, "", "  ")
				if err != nil {
					t.Fatal(err)
				}
				path := s.msgPath(p.box, p.m.Inner.ID)
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, text, 0o600); err != nil {
					t.Fatal(err)
				}
				got, err := s.Load(p.box, p.m.Inner.ID)
				if err != nil {
					t.Errorf("%s as %s wrote it: %v; want it loaded", p.name, tag.name, err)
					continue
				}
				if !got.Arrived.Equal(now) || got.Inner.Body.Type != p.m.Inner.Body.Type || len(got.Copies) != len(p.m.Copies) {
					t.Errorf("%s as %s wrote it read as arrived %v, type %q, %d copies", p.name, tag.name,
						got.Arrived, got.Inner.Body.Type, len(got.Copies))
				}
				if after, err := os.ReadFile(path); err != nil || !bytes.Equal(after, text) {
					t.Errorf("%s: the load changed the file (%v)", p.name, err)
				}
			}
			want := map[string][]string{"outer": tag.outer, "inner": innerKeys, "body": bodyKeys,
				"attachment": attachmentKeys, "carried": carriedKeys, "section": sectionKeys}
			if tag.withCopies {
				want["copy"] = copyKeys
			}
			for kind, keys := range want {
				var got []string
				for k := range seen[kind] {
					got = append(got, k)
				}
				sort.Strings(got)
				w := slices.Clone(keys)
				sort.Strings(w)
				if !slices.Equal(got, w) {
					t.Errorf("the planted records' %s keys are %v; %s wrote %v", kind, got, tag.name, w)
				}
			}
			if _, ok := seen["copy"]; ok && !tag.withCopies {
				t.Errorf("%s wrote no copies, and a planted record has them", tag.name)
			}
		})
	}
}

// strictRecordShapes is TestLimitStoredRecordShapes's row for the strict
// read of a record itself (R24a): a sent record to two, as this build
// writes it, loads; an unknown key at the top, inside inner, inside
// inner.body and inside a copy, a key given twice at the top and inside the
// body, a key that matches a field only by case at the top and inside
// inner, and a brace after the value are each refused by name, as damage
// naming the record's path, and the file is byte for byte what it was
// before the load.
func strictRecordShapes(t *testing.T) {
	s := newStore(t)
	now := time.Now().UTC().Truncate(time.Second)
	id := strings.Repeat("7", 32)
	from, to, third := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)
	m := stored(id, now)
	m.SenderName = "me"
	m.Inner.From, m.Inner.To = from, to
	m.Inner.Sections = []wire.Section{recipientsList(t, to, third)}
	m.Copies = []SentCopy{{Fingerprint: to, Name: "bob", RelayID: 7}, {Fingerprint: third, Name: "carol"}}
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	whole := string(data)
	path := s.msgPath(Sent, id)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(Sent, id); err != nil {
		t.Fatalf("the record as written: %v; want it loaded", err)
	}
	once := func(old, new string) string {
		t.Helper()
		if strings.Count(whole, old) < 1 {
			t.Fatalf("the record has no %s: %s", old, whole)
		}
		return strings.Replace(whole, old, new, 1)
	}
	for _, tc := range []struct{ name, text, says string }{
		{"an unknown key at the top", once(`{`, `{"zz":1,`), `unknown field "zz"`},
		{"an unknown key inside inner", once(`"inner":{`, `"inner":{"zz":1,`), `unknown field "zz"`},
		{"an unknown key inside the body", once(`"body":{`, `"body":{"zz":1,`), `unknown field "zz"`},
		{"an unknown key inside a copy", once(`"copies":[{`, `"copies":[{"zz":1,`), `unknown field "zz"`},
		{"a key twice at the top", once(`{`, `{"relay":"relay",`), `key "relay" appears twice`},
		{"a key twice inside the body", once(`"body":{`, `"body":{"text":"hi",`), `key "text" appears twice`},
		{"a key by case at the top", once(`"sender_name"`, `"Sender_name"`), `key "Sender_name" matches the field "sender_name" only by case`},
		{"a key by case inside inner", once(`"from":`, `"From":`), `key "From" matches the field "from" only by case`},
		{"a brace after", whole + "}", "trailing data after the value"},
	} {
		if err := os.WriteFile(path, []byte(tc.text), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := s.Load(Sent, id)
		if err == nil || !strings.Contains(err.Error(), tc.says) {
			t.Errorf("%s: %v; want %q", tc.name, err, tc.says)
		}
		// Load calls a record that will not read damaged: the sentence
		// begins with the record's path and ErrDamaged is beneath it, so
		// the listing's warning and every command name the file.
		if err == nil || !strings.HasPrefix(err.Error(), path+" will not read (") ||
			!strings.HasSuffix(err.Error(), "): "+recordAdvice) {
			t.Errorf("%s: %v; want it to name %s and say what to do", tc.name, err, path)
		}
		if !errors.Is(err, ErrDamaged) {
			t.Errorf("%s: not ErrDamaged: %v", tc.name, err)
		}
		if after, rerr := os.ReadFile(path); rerr != nil || string(after) != tc.text {
			t.Errorf("%s: the refusal changed the file (%v)", tc.name, rerr)
		}
	}
}
