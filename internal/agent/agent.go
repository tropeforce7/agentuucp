// Package agent holds a user's unlocked keys in memory and performs every
// private-key operation for the commands that ask, over a local socket, so
// that a human unlocks once and every auu command after that — theirs or
// their AI's — works without a passphrase.
//
// It is ssh-agent's shape. The keys never leave the process: a client sends
// a message and gets a signature, sends a ciphertext and gets a shared
// secret, and composes an identity out of those operations with
// hpke.NewHybridPrivateKey and a crypto.Signer, which is exactly what those
// interfaces exist for. What is on disk is ciphertext under a passphrase
// that is stored nowhere; what is in this process is the home key and the
// identity's halves, for a fixed time after the unlock, and then nothing.
//
// The agent is one per home, found by the home's path (see SocketPath),
// and answers only processes of the same user. A locked agent answers every
// operation that needs a key with one sentence, and the client turns that
// into an exit code the skill knows.
package agent

import (
	"errors"
	"time"
)

const (
	// KeyIdentity names the identity's keys in a request.
	KeyIdentity = "identity"
	// CertPrefix begins the name of a machine key: "cert:" and the relay
	// name whose cert.json holds it.
	CertPrefix = "cert:"
	// PendingPrefix begins the name of a machine key generate has made and
	// nobody has written to disk yet: "pending:" and the relay name. It is
	// a different name from the key on disk on purpose; see Generate.
	PendingPrefix = "pending:"

	// DefaultTTL is how long an unlock lasts when nobody says otherwise: a
	// working day with room either side. It is a time since unlock, not
	// since last use, so a machine that is busy locks on time and a machine
	// that is idle does not lock early.
	DefaultTTL = 8 * time.Hour

	// MaxFrame bounds one request or reply. The largest thing a request
	// carries is a stream's encapsulation or a certificate request, both
	// kilobytes; a megabyte leaves room and refuses anything else before it
	// is read.
	MaxFrame = 1 << 20

	// LockedMessage is the error a locked agent answers every operation that
	// needs a key with, verbatim. The client prints it as it is.
	LockedMessage = "the identity is locked: run 'auu unlock'"
)

// ErrNotRunning is a home with no agent answering. To a command it is the
// same thing as a locked one, and it is wrapped in identity.ErrLocked on
// the way out of every key operation.
var ErrNotRunning = errors.New("no agent is running for this home")

// Home is what the agent reads from the auu home. The store implements it;
// the agent knows nothing about the home's layout, and the store knows
// nothing about the protocol.
type Home interface {
	// Root is the home's directory, which is what names the agent.
	Root() string
	// HomeKey is home.key: a keyfile block whose plaintext is the home key.
	HomeKey() ([]byte, error)
	// IdentityKey is identity.key, sealed under the home key, and the suite
	// the identity is under.
	IdentityKey() (suiteID uint8, wrapped []byte, err error)
	// CertKey is the machine key for one relay, sealed under the home key,
	// as the relay's cert.json holds it.
	CertKey(relay string) (wrapped []byte, err error)
}
