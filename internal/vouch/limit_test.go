package vouch

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// TestLimitVouchV: the one integer a vouch carries is its version, held to
// exactly 1; every other value, the type's extremes included, is refused
// naming the version this build reads.
func TestLimitVouchV(t *testing.T) {
	v, x := gen(t, "v"), gen(t, "x")
	for _, n := range []int{0, 2, -1, math.MinInt, math.MaxInt} {
		d := base(v, x)
		d.V = n
		if err := d.Validate(); err == nil || !strings.Contains(err.Error(), "this build reads 1") {
			t.Errorf("v %d: %v; want the refusal naming the version this build reads", n, err)
		}
	}
	if err := base(v, x).Validate(); err != nil {
		t.Errorf("v 1: %v", err)
	}
}

// TestLimitAVouchAtEveryMaximumFits measures the numbers in
// relayapi.MaxVouchBytes's comment against the encoder: a vouch at every
// maximum — a name of 64 bytes, issued to the nanosecond in a zone with an
// offset — compact and indented by two spaces, each under the cap.
func TestLimitAVouchAtEveryMaximumFits(t *testing.T) {
	v, x := gen(t, "v"), gen(t, "x")
	d := base(v, x)
	d.Name = strings.Repeat("n", identity.MaxNameBytes)
	d.Issued = time.Date(2026, 9, 22, 10, 4, 0, 123456789, time.FixedZone("", -(12*3600+45*60)))
	compact, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	indented, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if len(compact) != 1958 || len(indented) != 1983 {
		t.Errorf("a vouch at every maximum is %d bytes compact and %d indented; MaxVouchBytes's comment says 1,958 and 1,983",
			len(compact), len(indented))
	}
	if len(compact) > relayapi.MaxVouchBytes || len(indented) > relayapi.MaxVouchBytes {
		t.Errorf("a vouch at every maximum does not fit under %d", relayapi.MaxVouchBytes)
	}
}

// TestLimitAVouchsFingerprintsOneShort: the rule that fixes the length of
// the voucher and the subject, which every command that shows a vouch then
// cuts to a short id, is ValidFingerprint at Validate, which Parse and
// Verify both run. Each fed one byte short, and empty, is refused there,
// before anything could slice it.
func TestLimitAVouchsFingerprintsOneShort(t *testing.T) {
	v, x := gen(t, "v"), gen(t, "x")
	for _, c := range []struct {
		label string
		spoil func(d *Document)
		want  string
	}{
		{"voucher one short", func(d *Document) { d.Voucher = d.Voucher[:63] }, "voucher is not a fingerprint"},
		{"voucher empty", func(d *Document) { d.Voucher = "" }, "voucher is not a fingerprint"},
		{"subject one short", func(d *Document) { d.Subject = d.Subject[:63] }, "subject is not a fingerprint"},
		{"subject empty", func(d *Document) { d.Subject = "" }, "subject is not a fingerprint"},
	} {
		d := base(v, x)
		c.spoil(d)
		if err := d.Validate(); err == nil || err.Error() != c.want {
			t.Errorf("%s: %v; want %q", c.label, err, c.want)
		}
		doc, err := json.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Parse(doc); err == nil || err.Error() != c.want {
			t.Errorf("%s through Parse: %v; want %q", c.label, err, c.want)
		}
	}
}
