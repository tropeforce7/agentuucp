//go:build !windows

package channels

// osDevice has no OS to ask off Windows: the list is the rule there.
func osDevice(string) bool { return false }
