package stream

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/recipients"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/testutil"
	"github.com/tropeforce7/agentuucp/internal/wire"
)

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

// countedSource is a source whose every Open is counted, so a test can see
// how many times the payload was read.
func countedSource(name string, data []byte, opens *atomic.Int64) Source {
	return Source{
		Name: name, Media: "application/octet-stream", Size: int64(len(data)),
		Open: func() (io.ReadCloser, error) {
			opens.Add(1)
			return io.NopCloser(bytes.NewReader(data)), nil
		},
	}
}

// A stream to several, with N and the payload drawn from the seed and a
// made-up section beside the list (D35): one id, one time and one body in
// every manifest, the sources hashed once however many copies, each manifest
// version 2 and carrying the same list bytes, and each sealed stream opening
// for its own recipient alone with the payload whole.
func TestAStreamToSeveralIsOneManifestForEach(t *testing.T) {
	r, seed := testutil.Seed(t)
	from, _ := pair(t)
	n := 2 + r.IntN(6)
	to := readers(t, n)
	payload := testutil.Bytes(r, r.IntN(3*MinChunkSize))
	var opens atomic.Int64
	src := countedSource("one.bin", payload, &opens)
	madeUp := testutil.MadeUpSection(r)
	id := strings.Repeat("b", 32)

	ms, err := BuildManifestMany(from, publics(to), id, body(), []Source{src}, MinChunkSize, []wire.Section{madeUp})
	if err != nil {
		t.Fatalf("seed %d: %v", seed, err)
	}
	if got := opens.Load(); got != 1 {
		t.Fatalf("seed %d: the payload was read %d times to build %d manifests; want once", seed, got, n)
	}
	if len(ms) != n {
		t.Fatalf("seed %d: %d manifests for %d recipients", seed, len(ms), n)
	}
	var list []byte
	for i, m := range ms {
		if m.ID != id || !m.Time.Equal(ms[0].Time) || m.V != VersionSections || m.To != to[i].Fingerprint() {
			t.Fatalf("seed %d: manifest %d: id %s, time %s, v %d, to %s", seed, i+1, m.ID, m.Time, m.V, m.To)
		}
		for _, s := range m.Sections {
			if s.Name != recipients.Name {
				continue
			}
			if list == nil {
				list = s.Data
			} else if !bytes.Equal(list, s.Data) {
				t.Fatalf("seed %d: manifest %d's list bytes differ from the first's", seed, i+1)
			}
		}
	}
	for i, m := range ms {
		var buf bytes.Buffer
		if err := Seal(&buf, from, to[i].Public(), m, []Source{src}); err != nil {
			t.Fatalf("seed %d: sealing copy %d: %v", seed, i+1, err)
		}
		for j, reader := range to {
			o, out, err := openAll(t, reader, buf.Bytes())
			if j != i {
				if err == nil {
					t.Fatalf("seed %d: copy %d opened for recipient %d", seed, i+1, j+1)
				}
				continue
			}
			if err != nil {
				t.Fatalf("seed %d: copy %d does not open for its own recipient: %v", seed, i+1, err)
			}
			if !bytes.Equal(out["one.bin"], payload) {
				t.Fatalf("seed %d: copy %d's payload did not survive", seed, i+1)
			}
			if len(o.Manifest.Sections) != 2 {
				t.Fatalf("seed %d: copy %d carries %d sections; want the made-up one and the list", seed, i+1, len(o.Manifest.Sections))
			}
		}
	}
}

// What BuildManifestMany refuses: nobody, one over the ceiling, a recipient
// twice and a list of the caller's own. One recipient writes no list.
func TestBuildManifestManyRefusesWhatSealManyRefuses(t *testing.T) {
	from, to := pair(t)
	many := publics(readers(t, relayapi.MaxRecipients+1))
	src := source("a.txt", []byte("payload"))
	own, err := recipients.Section([]string{to.Fingerprint()})
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("c", 32)
	rows := []struct {
		name     string
		to       []*identity.Public
		sections []wire.Section
		want     string
	}{
		{"nobody", nil, nil, "a stream to nobody"},
		{"one over the ceiling", many, nil, "33 recipients, at most 32"},
		{"a recipient twice", []*identity.Public{to.Public(), many[0], to.Public()}, nil, "is named twice"},
		{"a list of the caller's own", []*identity.Public{to.Public(), many[0]}, []wire.Section{own}, "is written by BuildManifestMany"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			if ms, err := BuildManifestMany(from, row.to, id, body(), []Source{src}, MinChunkSize, row.sections); err == nil || ms != nil || !strings.Contains(err.Error(), row.want) {
				t.Fatalf("got %d manifests, %v; want the refusal saying %q", len(ms), err, row.want)
			}
		})
	}
	ms, err := BuildManifestMany(from, []*identity.Public{to.Public()}, id, body(), []Source{src}, MinChunkSize, nil)
	if err != nil || len(ms) != 1 || ms[0].V != Version || ms[0].Sections != nil {
		t.Fatalf("one recipient: %v; want one version 1 manifest with no sections", err)
	}
	if ms, err := BuildManifestMany(from, many[:relayapi.MaxRecipients], id, body(), []Source{src}, MinChunkSize, nil); err != nil || len(ms) != relayapi.MaxRecipients {
		t.Fatalf("thirty-two recipients: %d manifests, %v", len(ms), err)
	}
}

// The reader's half of the rule on the stream path, past the sender: a
// signed manifest whose list does not name its reader, and one whose list
// is over its cap and not a list at all, each refused as a malformed stream,
// the second for its size; and both pass Validate, since the rule runs only
// once the signature has verified.
func TestAListThatBreaksTheRuleIsRefusedOnTheStreamPath(t *testing.T) {
	from, to := pair(t)
	carol := readers(t, 1)[0]
	rows := []struct {
		name string
		data string
		want string
	}{
		{"a list that does not name the reader", `{"to":["` + from.Fingerprint() + `","` + carol.Fingerprint() + `"]}`,
			"does not name " + to.Fingerprint()[:16]},
		{"a list over its cap", `"` + strings.Repeat("a", recipients.MaxBytes) + `"`,
			fmt.Sprintf("over the %d it may be", recipients.MaxBytes)},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			m, _, _ := sealedWith(t, from, to, []wire.Section{later(false)})
			m.Sections = []wire.Section{{Name: recipients.Name, Data: json.RawMessage(row.data)}}
			if err := m.Validate(); err != nil {
				t.Fatalf("Validate read the list, which waits for the signature: %v", err)
			}
			header, sealed := sealManifestByHand(t, from, to, m)
			_, err := OpenManifest(to, header, sealed)
			if !errors.Is(err, ErrForm) || !strings.Contains(err.Error(), row.want) {
				t.Fatalf("got %v; want ErrForm saying %q", err, row.want)
			}
		})
	}
}

// The rule is read only under the signature: a broken list in a manifest
// whose signature does not verify is refused for the signature.
func TestAnUnsignedListOnAStreamIsRefusedForItsSignature(t *testing.T) {
	from, to := pair(t)
	mallory := readers(t, 1)[0]
	m, _, _ := sealedWith(t, from, to, []wire.Section{later(false)})
	m.Sections = []wire.Section{{Name: recipients.Name, Data: json.RawMessage(`{"to":[]}`)}}
	header, sealed := sealManifestByHand(t, mallory, to, m)
	if _, err := OpenManifest(to, header, sealed); !errors.Is(err, ErrSignature) {
		t.Fatalf("an unsigned list: %v; want ErrSignature", err)
	}
}

// A manifest that needs a newer auu is handed back to be kept as a record
// that waits on the relay, so its list is held to the rule before the sort:
// a signed manifest carrying a critical section this build does not know
// and a list that does not name its reader is refused as malformed, and
// never handed back, since Load would refuse the record it became and every
// fetch would save the stream over again.
func TestAStreamThatNeedsANewerAuuIsHeldToItsListFirst(t *testing.T) {
	from, to := pair(t)
	carol := readers(t, 1)[0]
	m, _, _ := sealedWith(t, from, to, []wire.Section{later(false)})
	m.Sections = []wire.Section{
		later(true),
		{Name: recipients.Name, Data: json.RawMessage(`{"to":["` + from.Fingerprint() + `","` + carol.Fingerprint() + `"]}`)},
	}
	header, sealed := sealManifestByHand(t, from, to, m)
	opened, err := OpenManifest(to, header, sealed)
	if opened != nil || !errors.Is(err, ErrForm) || errors.Is(err, wire.ErrNeedsNewer) {
		t.Fatalf("got %v, %v; want no manifest and ErrForm, never needs-newer", opened, err)
	}
}
