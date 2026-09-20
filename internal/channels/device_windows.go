//go:build windows

package channels

import (
	"path/filepath"
	"strings"
)

// osDevice asks Windows: filepath.Abs is GetFullPathNameW underneath,
// which rewrites a DOS device name to a \\.\ device path — in any
// directory and with or without an extension on older Windows, and on
// Windows Server 2025 for NUL alone, bare, as
// TestLimitTheDeviceListAgreesWithWindows logged on the Windows job's
// first run; CONIN$ and CONOUT$, which CreateFile understands, it left as
// paths there. The list is the wider answer and this the OS's own.
func osDevice(stem string) bool {
	if stem == "" {
		return false
	}
	abs, err := filepath.Abs(stem)
	return err == nil && strings.HasPrefix(abs, `\\.\`)
}
