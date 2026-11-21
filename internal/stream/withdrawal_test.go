package stream

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/wire"
	"github.com/tropeforce7/agentuucp/internal/withdraw"
)

// A withdrawal note is always an envelope: the stream sealer refuses a
// manifest carrying the section, whatever it says, so no stream ever goes
// out with one.
func TestAStreamCarriesNoWithdrawal(t *testing.T) {
	from, to := pair(t)
	sec, err := withdraw.Section(strings.Repeat("b", 32), "")
	if err != nil {
		t.Fatal(err)
	}
	src := source("a.txt", []byte("payload"))
	m, err := BuildManifestSections(from, to.Public(), strings.Repeat("a", 32), body(), []Source{src}, MinChunkSize, []wire.Section{sec})
	if !errors.Is(err, ErrForm) || !strings.Contains(err.Error(), "a stream carries no withdrawal section") || m != nil {
		t.Fatalf("got a manifest %v, %v; want none and the stream's refusal of the section", m != nil, err)
	}
}

// On a manifest the section is a name this build does not know: one that a
// hand-built stream carries anyway, and that breaks the rule on every
// count (an ask with an attachment, naming no message it answers), opens,
// read by nothing, as any section this build does not know does.
func TestAWithdrawalOnAManifestIsAnUnknownName(t *testing.T) {
	from, to := pair(t)
	m, _, _ := sealedWith(t, from, to, []wire.Section{later(false)})
	m.Sections = []wire.Section{{Name: withdraw.SectionName, Data: json.RawMessage(`{"id":"not an id"}`)}}
	header, sealed := sealManifestByHand(t, from, to, m)
	opened, err := OpenManifest(to, header, sealed)
	if err != nil {
		t.Fatalf("a manifest carrying the section: %v; want it opened, the section unknown", err)
	}
	if len(opened.Manifest.Sections) != 1 || opened.Manifest.Sections[0].Name != withdraw.SectionName {
		t.Fatalf("the opened manifest carries %+v", opened.Manifest.Sections)
	}
}
