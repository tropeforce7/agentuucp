package identity

import (
	"testing"
)

// mustSign signs with an identity held in this process, which cannot fail;
// the error return exists for the remote identity the agent backs.
func mustSign(t *testing.T, id *Identity, msg []byte) []byte {
	t.Helper()
	sig, err := id.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return sig
}
