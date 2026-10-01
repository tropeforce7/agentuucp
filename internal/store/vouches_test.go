package store

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/message"
)

const aVoucher = "4c1d000000000000000000000000000000000000000000000000000000000000"

// A kept vouch reads back as it was kept, a newer one replaces it, and a
// voucher with none is ErrNoVouch; a file that is there and is not one is
// damaged, said with the path.
func TestAKeptVouchReadsBackAndIsReplaced(t *testing.T) {
	s := newStore(t)
	if _, err := s.KeptVouch(aVoucher); !errors.Is(err, ErrNoVouch) {
		t.Fatalf("before any: %v, want ErrNoVouch", err)
	}
	first := message.Carried{Document: []byte(`{"first":1}`), Signature: []byte{1, 2}}
	if err := s.KeepVouch(aVoucher, first); err != nil {
		t.Fatal(err)
	}
	got, err := s.KeptVouch(aVoucher)
	if err != nil || string(got.Document) != string(first.Document) || string(got.Signature) != string(first.Signature) {
		t.Fatalf("read back: %+v, %v", got, err)
	}
	second := message.Carried{Document: []byte(`{"second":2}`), Signature: []byte{3}}
	if err := s.KeepVouch(aVoucher, second); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.KeptVouch(aVoucher); string(got.Document) != string(second.Document) {
		t.Fatalf("the newer did not replace the older: %s", got.Document)
	}
	if fi, err := os.Stat(filepath.Join(s.VouchesDir(), aVoucher+".json")); err != nil || (runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600) {
		t.Fatalf("the kept file: %v, %v", fi, err)
	}
	for _, damaged := range []string{
		"not a vouch",
		`{"document":"e30=","signature":"AQ==","note":"a field this program never wrote"}`,
	} {
		if err := os.WriteFile(filepath.Join(s.VouchesDir(), aVoucher+".json"), []byte(damaged), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := s.KeptVouch(aVoucher); err == nil || !strings.Contains(err.Error(), "is not a kept vouch; delete it and ask for the vouch again") {
			t.Fatalf("a damaged file %q: %v", damaged, err)
		}
	}
}

// What stands at a kept vouch's name and is not this program's file is
// refused rather than written through or read: a directory with something
// in it refuses the keep, and a symbolic link is refused at the read by the
// handle's own mode, and replaced at the keep without the file it pointed
// at being touched.
func TestAKeptVouchsNameIsNotWrittenThrough(t *testing.T) {
	s := newStore(t)
	if err := os.MkdirAll(filepath.Join(s.VouchesDir(), aVoucher+".json", "inside"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := s.KeepVouch(aVoucher, message.Carried{Document: []byte("{}"), Signature: []byte{1}}); err == nil {
		t.Fatal("a vouch was kept over a directory")
	}
	if _, err := os.Stat(filepath.Join(s.VouchesDir(), aVoucher+".json", "inside")); err != nil {
		t.Fatalf("the directory was changed: %v", err)
	}
	if runtime.GOOS == "windows" {
		t.Skip("a symbolic link needs a privilege on Windows; the directory case above ran")
	}
	other := "5d2e000000000000000000000000000000000000000000000000000000000000"
	witness := filepath.Join(t.TempDir(), "witness")
	// The file the link points at is a well-formed kept vouch, so a read
	// that followed the link would succeed rather than fail on its content.
	const somebodyElses = `{"document":"e30=","signature":"AQ=="}`
	if err := os.WriteFile(witness, []byte(somebodyElses), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(s.VouchesDir(), other+".json")
	if err := os.Symlink(witness, link); err != nil {
		t.Fatal(err)
	}
	if _, err := s.KeptVouch(other); err == nil || errors.Is(err, ErrNoVouch) {
		t.Fatalf("a link was read as a kept vouch: %v", err)
	}
	if err := s.KeepVouch(other, message.Carried{Document: []byte("{}"), Signature: []byte{1}}); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(witness); string(data) != somebodyElses {
		t.Fatalf("the keep wrote through the link: %q", data)
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("the link is still a link: %v", err)
	}
}
