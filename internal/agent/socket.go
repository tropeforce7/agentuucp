package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
)

// Where the socket lives.
//
// Not in the home: a Unix socket path is at most 104 bytes on macOS and
// AUU_HOME can be anywhere. A per-user runtime directory instead —
// $XDG_RUNTIME_DIR on Linux, which is cleared at logout, the user's
// temporary directory on macOS, %LOCALAPPDATA% on Windows — with one
// subdirectory for auu, mode 0700, and in it one socket per home, named by
// a hash of the home's absolute path so that a test home gets its own
// agent and two homes never share one.

const (
	runtimeSubdir = "auu"
	// idLen is how much of the hash names the socket: 16 hex characters,
	// which is enough to tell homes apart and short enough for the path.
	idLen = 16
)

// Paths is where one home's agent keeps its files.
type Paths struct {
	// Dir is the auu runtime directory.
	Dir string
	// Socket, Lock and Log are this home's files in it.
	Socket string
	Lock   string
	Log    string
}

// SocketPath is the Unix socket the agent for a home listens on.
func SocketPath(home string) (string, error) {
	p, err := PathsFor(home)
	if err != nil {
		return "", err
	}
	return p.Socket, nil
}

// PathsFor is every file the agent for a home uses.
func PathsFor(home string) (*Paths, error) {
	id, err := homeID(home)
	if err != nil {
		return nil, err
	}
	dir, err := runtimeDir()
	if err != nil {
		return nil, err
	}
	return &Paths{
		Dir:    dir,
		Socket: filepath.Join(dir, id+".sock"),
		Lock:   filepath.Join(dir, id+".lock"),
		Log:    filepath.Join(dir, id+".log"),
	}, nil
}

// homeID names a home: the first idLen hex characters of the SHA-256 of
// its absolute path.
func homeID(home string) (string, error) {
	if home == "" {
		return "", errors.New("agent: no home")
	}
	abs, err := filepath.Abs(home)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(abs))
	return hex.EncodeToString(sum[:])[:idLen], nil
}

// runtimeDir is the per-user directory the sockets live in. It is created
// if it does not exist and must be the user's own and nobody else's, and a
// directory, never a link to one: the socket's mode is a second line, and
// this is the first.
func runtimeDir() (string, error) {
	base := os.Getenv("XDG_RUNTIME_DIR")
	if base == "" && runtime.GOOS == "windows" {
		base = os.Getenv("LOCALAPPDATA")
	}
	if base == "" {
		base = os.TempDir()
	}
	dir := filepath.Join(base, runtimeSubdir)
	// What is at the path is looked at before anything is made there, so a
	// link, dangling or not, is named as a link: /tmp is shared, and a link
	// another user planted at /tmp/auu to a directory of this user's own
	// passed the owner check, and the agent wrote its socket, lock and log
	// there and made that directory 0700.
	if err := notALink(dir); err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("agent: creating %s: %w", dir, err)
	}
	// MkdirAll leaves an existing directory alone, and an existing one may
	// be another user's: the first user to run auu on a machine with no
	// XDG_RUNTIME_DIR owns /tmp/auu. That is refused, not shared.
	if err := holdRuntimeDir(dir); err != nil {
		return "", err
	}
	return dir, nil
}

// notALink refuses, by name, anything at the runtime directory's path that
// is not a directory, a symbolic link named as one. Nothing there at all is
// for MkdirAll to make.
func notALink(dir string) error {
	info, err := os.Lstat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("agent: %s is a symbolic link, not a directory; remove it, or set XDG_RUNTIME_DIR to a directory of your own", dir)
	}
	if !info.IsDir() {
		return fmt.Errorf("agent: %s is not a directory; remove it, or set XDG_RUNTIME_DIR to a directory of your own", dir)
	}
	return nil
}

// notOwned is the refusal of a runtime directory another user owns.
func notOwned(dir string) error {
	return fmt.Errorf("agent: %s belongs to another user; set XDG_RUNTIME_DIR to a directory of your own", dir)
}
