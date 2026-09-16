//go:build !(darwin || linux)

package term

import "errors"

// State is what Restore takes. There is nothing to restore here.
type State struct{}

// IsTerminal is false: this platform's terminal is not known to this
// package, so a passphrase is read with its echo on.
func IsTerminal(int) bool { return false }

// DisableEcho is not available.
func DisableEcho(int) (*State, error) { return nil, errors.ErrUnsupported }

// Restore has nothing to do.
func Restore(int, *State) error { return nil }
