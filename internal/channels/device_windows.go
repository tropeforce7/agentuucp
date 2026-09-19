//go:build windows

package channels

import (
	"path/filepath"
	"strings"
)

// osDevice asks Windows: filepath.Abs is GetFullPathNameW underneath,
// which rewrites a DOS device name in any directory, with or without an
// extension, to a \\.\ device path. What it answers for CONIN$ and
// CONOUT$, which CreateFile understands but the resolver may not, is what
// TestLimitTheDeviceListAgreesWithWindows logs on the Windows job.
func osDevice(stem string) bool {
	if stem == "" {
		return false
	}
	abs, err := filepath.Abs(stem)
	return err == nil && strings.HasPrefix(abs, `\\.\`)
}
