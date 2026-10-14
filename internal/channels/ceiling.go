package channels

import (
	"encoding/json"
	"fmt"

	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/wire"
)

// CeilingName is the health answer's section from wire level 2: the
// largest max_bytes a channel on this relay may name, the most it takes of
// any kind, as the relay computes it for the push (R19). The owner's
// command holds a channel's --max-bytes to it before any push, so the two
// ends never do the arithmetic twice. A relay below level 2 carries none,
// and the level check refuses such a relay before the ceiling is asked.
const CeilingName = "channel-max-bytes"

// CeilingBytes caps the section's data before it is decoded:
// {"max":4611686018427387904} is 27 bytes, and the cap leaves room for a
// writer that indents.
const CeilingBytes = 64

func init() {
	wire.Register(CeilingName, wire.OnAnswer)
}

// Ceiling is the section's data.
type Ceiling struct {
	Max int64 `json:"max"`
}

// CeilingSection is the answer's section for a relay whose ceiling is n,
// which is 1 to relayapi.MaxStreamSize.
func CeilingSection(n int64) ([]wire.Section, error) {
	if n < 1 || n > relayapi.MaxStreamSize {
		return nil, fmt.Errorf("channels: a ceiling of %d is not 1 to %d", n, relayapi.MaxStreamSize)
	}
	data, err := json.Marshal(Ceiling{Max: n})
	if err != nil {
		return nil, err
	}
	return []wire.Section{{Name: CeilingName, Data: data}}, nil
}

// CheckCeiling is the section's rule: the size before the strict decode,
// then 1 to relayapi.MaxStreamSize, the most a channel's max_bytes can be.
func CheckCeiling(data []byte) (int64, error) {
	if len(data) > CeilingBytes {
		return 0, fmt.Errorf("the %s section is %d bytes, over the %d it may be", CeilingName, len(data), CeilingBytes)
	}
	var c Ceiling
	if err := wire.Decode(data, &c); err != nil {
		return 0, fmt.Errorf("the %s section: %v", CeilingName, err)
	}
	if c.Max < 1 || c.Max > relayapi.MaxStreamSize {
		return 0, fmt.Errorf("the %s section says %d, which is not 1 to %d", CeilingName, c.Max, relayapi.MaxStreamSize)
	}
	return c.Max, nil
}
