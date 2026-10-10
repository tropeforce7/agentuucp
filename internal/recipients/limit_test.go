package recipients

import (
	"math"
	"strconv"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/wire"
)

// The two numbers a message to several carries beside its list, the
// request's count and the answer's max, held to [1, relayapi.MaxRecipients]
// at the edges, the type's extremes, the forms a JSON number may not take,
// and a section over its size with a last byte that is not JSON, which is
// refused for its size, so the size is checked before the decode.
func TestLimitRecipientNumbers(t *testing.T) {
	for _, n := range []struct {
		name  string
		key   string
		check func([]byte) (int, error)
	}{
		{CountName, "n", CheckCount},
		{MaxName, "max", CheckMax},
	} {
		t.Run(n.name, func(t *testing.T) {
			doc := func(v string) []byte { return []byte(`{"` + n.key + `":` + v + `}`) }
			for _, v := range []int{1, relayapi.MaxRecipients} {
				got, err := n.check(doc(strconv.Itoa(v)))
				if err != nil || got != v {
					t.Errorf("%d: %d, %v; want it taken", v, got, err)
				}
			}
			for _, v := range []int64{0, -1, relayapi.MaxRecipients + 1, math.MinInt64, math.MaxInt64} {
				_, err := n.check(doc(strconv.FormatInt(v, 10)))
				if err == nil || !strings.Contains(err.Error(), "the "+n.name+" section says "+strconv.FormatInt(v, 10)+", which is not 1 to 32") {
					t.Errorf("%d: %v; want the range refusal naming the section and the value", v, err)
				}
			}
			for _, v := range []string{"9223372036854775808", "1.0", "1e1", `"1"`, "null", "true"} {
				if _, err := n.check(doc(v)); err == nil || !strings.Contains(err.Error(), "the "+n.name+" section") {
					t.Errorf("%s: %v; want the decode's refusal naming the section", v, err)
				}
			}
			// A key the section does not have, and the key absent, which
			// decodes to zero and meets the range.
			if _, err := n.check([]byte(`{"` + n.key + `":1,"more":2}`)); err == nil {
				t.Error("a key the section does not have was taken")
			}
			if _, err := n.check([]byte(`{}`)); err == nil || !strings.Contains(err.Error(), "says 0") {
				t.Errorf("the number absent: %v; want it refused as zero", err)
			}
			// The size edge, by white space, and one over with a last
			// byte that is not JSON: the size is what is refused.
			base := doc("1")
			at := []byte(strings.Repeat(" ", MaxNumberBytes-len(base)) + string(base))
			if _, err := n.check(at); err != nil {
				t.Errorf("a section of %d bytes: %v; want it taken", len(at), err)
			}
			over := append([]byte(" "), at...)
			over[len(over)-1] = 'x'
			if _, err := n.check(over); err == nil || !strings.Contains(err.Error(), "over the 64 it may be") {
				t.Errorf("a section a byte over with a last byte not JSON: %v; want the size refusal", err)
			}
		})
	}
}

// The sections are written as the rule reads them: a count for a message to
// several and nothing for one, so a request to one is the bytes it was; a
// number outside the rule is not written.
func TestTheNumbersAreWrittenAsTheyAreRead(t *testing.T) {
	for _, n := range []int{0, 1} {
		if got, err := CountSection(n); err != nil || got != nil {
			t.Errorf("CountSection(%d) = %v, %v; want nothing", n, got, err)
		}
	}
	for _, n := range []int{2, relayapi.MaxRecipients} {
		got, err := CountSection(n)
		if err != nil || len(got) != 1 || got[0].Name != CountName || got[0].Critical {
			t.Fatalf("CountSection(%d) = %v, %v", n, got, err)
		}
		if back, err := CheckCount(got[0].Data); err != nil || back != n {
			t.Errorf("CountSection(%d) reads back as %d, %v", n, back, err)
		}
		if err := wire.Check(got); err != nil {
			t.Errorf("CountSection(%d) breaks the list's shape: %v", n, err)
		}
	}
	for _, n := range []int{1, relayapi.MaxRecipients} {
		got, err := MaxSection(n)
		if err != nil || len(got) != 1 || got[0].Name != MaxName || got[0].Critical {
			t.Fatalf("MaxSection(%d) = %v, %v", n, got, err)
		}
		if back, err := CheckMax(got[0].Data); err != nil || back != n {
			t.Errorf("MaxSection(%d) reads back as %d, %v", n, back, err)
		}
	}
	for _, n := range []int{relayapi.MaxRecipients + 1, -1} {
		if _, err := CountSection(n); err == nil {
			t.Errorf("CountSection(%d) was written", n)
		}
	}
	for _, n := range []int{0, relayapi.MaxRecipients + 1} {
		if _, err := MaxSection(n); err == nil {
			t.Errorf("MaxSection(%d) was written", n)
		}
	}
	if !wire.Known(CountName, wire.OnRequest) {
		t.Errorf("%s is not registered with the wire on a request", CountName)
	}
	if !wire.Known(MaxName, wire.OnAnswer) {
		t.Errorf("%s is not registered with the wire on an answer", MaxName)
	}
}
