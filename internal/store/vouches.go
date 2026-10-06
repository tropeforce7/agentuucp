package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/regular"
	"github.com/tropeforce7/agentuucp/internal/wire"
)

// vouchesDir holds the vouches this identity keeps for its knocks: one file
// per voucher, named by the voucher's fingerprint, the document and the
// signature as they arrived. What decides whether one is kept, and whether
// a newer one replaces it, is the caller's; this keeps and reads.
const vouchesDir = "vouches"

// ErrNoVouch is a voucher with no vouch kept.
var ErrNoVouch = errors.New("no vouch kept from that voucher")

// VouchesDir is the directory the kept vouches are in.
func (s *Store) VouchesDir() string { return s.path(vouchesDir) }

// vouchPath is where a voucher's vouch is kept. The fingerprint came in a
// message, so it is held to its rule here, at the join, whatever the caller
// did first: a name that is not a fingerprint is never a path.
func (s *Store) vouchPath(voucher string) (string, error) {
	if !identity.ValidFingerprint(voucher) {
		return "", fmt.Errorf("store: %q is not a fingerprint, so it names no kept vouch", voucher)
	}
	return filepath.Join(s.path(vouchesDir), voucher+".json"), nil
}

// KeepVouch keeps a vouch under its voucher's fingerprint, replacing the one
// kept before. The old file is removed and the new one made by an exclusive
// create through internal/regular, never renamed onto the name, since the
// name is the network's: whatever stands there that is not this program's
// file — a directory, a link — is refused rather than written through.
func (s *Store) KeepVouch(voucher string, c message.Carried) error {
	path, err := s.vouchPath(voucher)
	if err != nil {
		return err
	}
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.path(vouchesDir), 0o700); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	f, err := regular.Create(path, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// KeptVouch reads the vouch kept from a voucher: the document and the
// signature, strictly, as KeepVouch wrote them. A voucher with none is
// ErrNoVouch; a file that is there and is not a vouch this program wrote is
// damaged and says so, since a file that is there and wrong is not a file
// that is missing.
func (s *Store) KeptVouch(voucher string) (message.Carried, error) {
	path, err := s.vouchPath(voucher)
	if err != nil {
		return message.Carried{}, err
	}
	data, err := regular.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return message.Carried{}, ErrNoVouch
	}
	if err != nil {
		return message.Carried{}, err
	}
	var c message.Carried
	if err := wire.Decode(data, &c); err != nil || len(c.Document) == 0 || len(c.Signature) == 0 {
		return message.Carried{}, &damagedFile{msg: fmt.Sprintf("%s is not a kept vouch; delete it and ask for the vouch again", path)}
	}
	return c, nil
}
