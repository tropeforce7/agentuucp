package identity

import (
	"encoding/base64"
	"strings"
	"testing"
)

// ParseExportLine used to decode the base64 and then let ParseBundle check the
// size, which allocates the whole output from a length the line claims.
//
// Proven by which error comes back: this line is far too long and its last
// character is not valid base64. The base64 message would mean the decode ran
// first.
func TestExportLineLengthIsCheckedBeforeDecoding(t *testing.T) {
	huge := exportPrefix + exportSep + strings.Repeat("A", 1<<20) + "!" + exportSep + "name"
	_, err := ParseExportLine(huge)
	if err == nil {
		t.Fatal("a 1 MiB key line was accepted")
	}
	if strings.Contains(err.Error(), "bad base64") {
		t.Fatalf("the decode ran before the length check: %v", err)
	}
	if !strings.Contains(err.Error(), "encoded bytes") {
		t.Fatalf("error %q does not name the encoded length", err)
	}
}

// The one valid encoded length, and its two neighbours.
func TestExportLineEncodedLengthBoundaries(t *testing.T) {
	id, err := Generate("alice")
	if err != nil {
		t.Fatal(err)
	}
	good := id.Public().ExportLine()
	_, rest, _ := strings.Cut(good, exportSep)
	field, _, _ := strings.Cut(rest, exportSep)
	want := base64.RawURLEncoding.EncodedLen(BundleSize)
	if len(field) != want {
		t.Fatalf("a real export line encodes to %d bytes, want %d", len(field), want)
	}
	if _, err := ParseExportLine(good); err != nil {
		t.Fatalf("a real export line was refused: %v", err)
	}
	for _, n := range []int{want - 1, want + 1} {
		line := exportPrefix + exportSep + strings.Repeat("A", n) + exportSep + "name"
		if _, err := ParseExportLine(line); err == nil {
			t.Fatalf("an encoded length of %d was accepted", n)
		}
	}
	// The older form is refused before its length is read, at any length.
	older := base64.StdEncoding.EncodedLen(BundleSize)
	for _, n := range []int{older - 1, older, older + 1} {
		line := olderExportPrefix + " " + strings.Repeat("A", n) + " name"
		if _, err := ParseExportLine(line); err == nil || !strings.Contains(err.Error(), "an older form") {
			t.Fatalf("an older line of encoded length %d: %v; want it refused by name", n, err)
		}
	}
}

// ParseBundle's own boundary: one byte either side of the only valid size.
func TestParseBundleSizeBoundaries(t *testing.T) {
	if _, err := ParseBundle(make([]byte, BundleSize-1)); err == nil {
		t.Fatal("a bundle one byte short was accepted")
	}
	if _, err := ParseBundle(make([]byte, BundleSize+1)); err == nil {
		t.Fatal("a bundle one byte long was accepted")
	}
	if _, err := ParseBundle(nil); err == nil {
		t.Fatal("an empty bundle was accepted")
	}
	// The valid size is rejected for a different reason: the key material is
	// zeroes, not that the length is wrong.
	if _, err := ParseBundle(make([]byte, BundleSize)); err != nil &&
		strings.Contains(err.Error(), "bytes") && strings.Contains(err.Error(), "want") {
		t.Fatalf("a correctly sized bundle was refused on length: %v", err)
	}
}
