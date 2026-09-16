package store

import (
	"fmt"
	"os"
	"runtime"
	"sync"
)

// auu writes every key file 0600 and every directory 0700 itself, so a
// wider mode is not a setting a person chose: it means somebody changed it,
// and the refusal names the file and the chmod that puts it back. The files
// refused are the ones that hold keys — identity.json in its plain form,
// home.key, identity.key, and each relay's cert.json — and the home itself,
// which is what everything under it rests on. authorized_peers and the spool
// hold nothing secret, so a permissive mode on them is a warning, once, and
// not a refusal.
//
// The check is Unix's: on Windows, Go makes a FileMode up from the
// read-only attribute — 0666 or 0444, whoever the file belongs to — and it
// says nothing about who can read, so the check would refuse every file
// there and protect nothing. The relay's admin file makes the same choice.

// privateFile refuses a key file that group or others can read.
func privateFile(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	info, err := os.Stat(path)
	if err != nil {
		// Whatever the read that follows will say about a missing file.
		return nil
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return damaged(path, fmt.Sprintf("is mode %04o", perm), nil,
			fmt.Sprintf("anyone on this machine can read your keys. Run: chmod 600 %s", path))
	}
	return nil
}

// readPrivate is os.ReadFile for a key file: the mode is checked first, so
// a file anyone can read is refused before its contents are used.
func readPrivate(path string) ([]byte, error) {
	if err := privateFile(path); err != nil {
		return nil, err
	}
	return os.ReadFile(path)
}

// privateHome refuses a home that group or others can write. What a
// writable directory allows is replacing what is in it — the peer list,
// a relay's anchor, a cursor — whatever the files' own modes say; a
// directory others can only list exposes no key, since every file in it is
// 0600, and is what a home made by hand under the usual umask looks like.
func privateHome(root string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	info, err := os.Stat(root)
	if err != nil {
		return nil
	}
	if perm := info.Mode().Perm(); perm&0o022 != 0 {
		return damaged(root, fmt.Sprintf("is mode %04o", perm), nil,
			fmt.Sprintf("anyone on this machine can write into your home and replace what is in it. Run: chmod 700 %s", root))
	}
	return nil
}

// warnedModes is the paths already warned about in this process, so a
// command that opens the home more than once says it once.
var warnedModes sync.Map

// warnWritable says, once, that a file or directory holding nothing secret
// can be written by group or others: a peer list anyone can change is a
// trust list anyone can change, and a spool anyone can write is mail
// anyone can plant, but neither is a key, so the command goes on.
func warnWritable(path, what string, dir bool) {
	if runtime.GOOS == "windows" {
		return
	}
	info, err := os.Stat(path)
	if err != nil {
		return
	}
	perm := info.Mode().Perm()
	if perm&0o022 == 0 {
		return
	}
	if _, already := warnedModes.LoadOrStore(path, true); already {
		return
	}
	mode := "600"
	if dir {
		mode = "700"
	}
	fmt.Fprintf(os.Stderr, "warning: %s is mode %04o: anyone on this machine can change %s; run chmod %s %s\n",
		path, perm, what, mode, path)
}
