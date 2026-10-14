package auu

import (
	"errors"
	"fmt"

	"github.com/tropeforce7/agentuucp/internal/channels"
)

// peerDirectoryWords is what a reader of a peer's directory says when
// channels.Verify refuses it, keyed on where Verify refused (D92, R9,
// R15): before or on the signature, the length, the signature itself or
// an owner other than the key, the relay served something the peer did
// not sign as it stands, "do not trust it"; a version this build does not
// read is the peer's newer auu, "update auu"; anything else Validate or
// the decode refuses after a good signature is what the peer signed,
// "tell them". relay names the relay, peer the peer as this home calls
// them, doc the bytes Verify was given.
func peerDirectoryWords(relay, peer string, doc []byte, err error) string {
	switch {
	case channels.CheckLength(doc) != nil, errors.Is(err, channels.ErrSignature), errors.Is(err, channels.ErrOwner):
		return fmt.Sprintf("the directory %s served for %s does not verify against the key you hold; do not trust it", relay, peer)
	case errors.Is(err, channels.ErrVersion):
		return fmt.Sprintf("the directory %s served for %s is one this build cannot read; update auu", relay, peer)
	default:
		return fmt.Sprintf("the directory %s signed is malformed; tell them", peer)
	}
}
