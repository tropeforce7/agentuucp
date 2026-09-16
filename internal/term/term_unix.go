//go:build darwin || linux

package term

import (
	"syscall"
	"unsafe"
)

// State is a terminal's settings as DisableEcho found them, for Restore.
type State struct{ t syscall.Termios }

// IsTerminal says whether fd is a terminal: whether it has termios at all.
func IsTerminal(fd int) bool {
	_, err := get(fd)
	return err == nil
}

// DisableEcho turns echo off on fd and returns what to hand Restore.
func DisableEcho(fd int) (*State, error) {
	t, err := get(fd)
	if err != nil {
		return nil, err
	}
	prev := t
	t.Lflag &^= syscall.ECHO
	if err := set(fd, &t); err != nil {
		return nil, err
	}
	return &State{t: prev}, nil
}

// Restore puts fd back as DisableEcho found it.
func Restore(fd int, s *State) error { return set(fd, &s.t) }

func get(fd int) (syscall.Termios, error) {
	var t syscall.Termios
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), ioctlGet, uintptr(unsafe.Pointer(&t))); e != 0 {
		return t, e
	}
	return t, nil
}

func set(fd int, t *syscall.Termios) error {
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), ioctlSet, uintptr(unsafe.Pointer(t))); e != 0 {
		return e
	}
	return nil
}
