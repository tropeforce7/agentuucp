package auu

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/envelope"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/store"
	"github.com/tropeforce7/agentuucp/internal/stream"
)

// streamedRecord plants one streamed message of one attachment, its
// payload in the spool by position, saved in the home's inbox, and
// returns the store and the record for extractInto.
func streamedRecord(t *testing.T, name string, data []byte) (*store.Store, *store.Stored) {
	t.Helper()
	alice, err := identity.Generate("alice")
	if err != nil {
		t.Fatal(err)
	}
	bob, err := identity.Generate("bob")
	if err != nil {
		t.Fatal(err)
	}
	sources := []stream.Source{{Name: name, Media: "application/octet-stream", Size: int64(len(data)),
		Open: func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(data)), nil }}}
	id := strings.Repeat("a", 32)
	m, err := stream.BuildManifest(alice, bob.Public(), id, stream.Body{Type: "note", Thread: id, Text: "one file"}, sources, stream.MinChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	var blob bytes.Buffer
	if err := stream.Seal(&blob, alice, bob.Public(), m, sources); err != nil {
		t.Fatal(err)
	}
	full := blob.Bytes()
	n, err := stream.ManifestLength(full[:stream.HeaderSize])
	if err != nil {
		t.Fatal(err)
	}
	opened, err := stream.OpenManifest(bob, full[:stream.HeaderSize], full[stream.HeaderSize:stream.HeaderSize+n])
	if err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := s.AttachmentDir(store.Inbox, id)
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := opened.ToDirectory(bytes.NewReader(full[stream.HeaderSize+n:]), dir); err != nil {
		t.Fatal(err)
	}
	inner := &envelope.Inner{From: alice.Fingerprint(), To: bob.Fingerprint(), ID: id, Time: time.Now().UTC(),
		Body: message.Body{Type: message.TypeNote, Thread: id, Text: "one file"}}
	for _, a := range opened.Manifest.Attachments {
		inner.Body.Attachments = append(inner.Body.Attachments, message.Attachment{Name: a.Name, Media: a.Media, Size: a.Size, SHA256: a.SHA256})
	}
	rec := &store.Stored{Inner: inner, Streamed: true, Received: time.Now().UTC()}
	if err := s.Save(store.Inbox, rec); err != nil {
		t.Fatal(err)
	}
	return s, rec
}

// entriesOf is the names in a directory, for saying what an extract left.
func entriesOf(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// TestAnExtractTakesTheNameOnlyWithVerifiedContent: an attachment's name
// appears in the directory only once its bytes are there whole and
// verified. The bytes go to a temporary of the program's own hidden name
// first, held to the record's size and digest, and the name is taken by
// linking the temporary to it, so a record whose digest does not match
// leaves neither the name nor the temporary; a symbolic link standing at
// the name is not followed but met as a name that stands, and the file
// goes beside it as the next numbered name with what the link points at
// untouched; and the link's temporary is gone once the name is taken. On
// the path a filesystem that refuses hard links takes, the same digest
// leaves nothing under the name either, and the symlink is met the same
// way by the exclusive create.
func TestAnExtractTakesTheNameOnlyWithVerifiedContent(t *testing.T) {
	onEachWritePath(t, func(t *testing.T) {
		payload := []byte(strings.Repeat("the whole file\n", 1000))
		s, rec := streamedRecord(t, "report.txt", payload)
		out := t.TempDir()

		// A digest that does not match: nothing under the name, no
		// temporary, and the sentence naming what was wrong.
		good := rec.Inner.Body.Attachments[0].SHA256
		rec.Inner.Body.Attachments[0].SHA256 = strings.Repeat("0", 64)
		_, err := extractInto(s, store.Inbox, rec, out)
		if err == nil || !strings.Contains(err.Error(), `refusing to write "report.txt": sha256 does not match data`) {
			t.Fatalf("a record whose digest does not match: %v; want the refusal naming it", err)
		}
		if names := entriesOf(t, out); len(names) != 0 {
			t.Fatalf("a refused extract left %v in the directory; want nothing, not the name and not a temporary", names)
		}
		rec.Inner.Body.Attachments[0].SHA256 = good

		// A symbolic link standing at the name, pointing at a witness
		// outside the directory: the name stands, the file goes beside
		// it, the witness is untouched.
		witness := filepath.Join(t.TempDir(), "witness")
		if err := os.WriteFile(witness, []byte("keep me\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		linked := runtime.GOOS != "windows"
		if linked {
			if err := os.Symlink(witness, filepath.Join(out, "report.txt")); err != nil {
				t.Fatal(err)
			}
		}
		written, err := extractInto(s, store.Inbox, rec, out)
		if err != nil {
			t.Fatalf("extractInto: %v", err)
		}
		want := "report.txt"
		if linked {
			want = "report-2.txt"
		}
		if len(written) != 1 || filepath.Base(written[0]) != want {
			t.Fatalf("wrote %v, want %s", written, want)
		}
		if data, err := os.ReadFile(written[0]); err != nil || !bytes.Equal(data, payload) {
			t.Fatalf("the file: %d bytes, %v; want the payload whole", len(data), err)
		}
		if data, _ := os.ReadFile(witness); string(data) != "keep me\n" {
			t.Fatalf("the witness behind the symlink was written: %q", data)
		}
		names := entriesOf(t, out)
		expect := 1
		if linked {
			expect = 2
		}
		if len(names) != expect {
			t.Fatalf("the directory holds %v; want the file and the link alone, no temporary", names)
		}
		for _, name := range names {
			if strings.HasPrefix(name, tempPrefix) {
				t.Fatalf("a temporary was left behind: %v", names)
			}
		}
		// The file is one of its own: not a link to the temporary that
		// was, which is gone, and with the payload's bytes.
		info, err := os.Stat(written[0])
		if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Size() != int64(len(payload)) {
			t.Fatalf("the file: %v %v", info, err)
		}

		// The temporary's name changed under the extract, between the
		// verification and the link: somebody with the directory
		// replaced it with a symbolic link to a file of the person's
		// own. link follows such a link on some platforms and makes the
		// name a link to that file; so the name is compared with the
		// handle the bytes went through, and when it is not that file
		// it is removed and the extract refused, the secret untouched
		// and nothing under the name. The second reader of the findings
		// commit found the window.
		if !linked || !hardLinks {
			return
		}
		secret := filepath.Join(t.TempDir(), "id_key")
		if err := os.WriteFile(secret, []byte("private\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		again := t.TempDir()
		beforeLink = func(tmp string) {
			if err := os.Remove(tmp); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(secret, tmp); err != nil {
				t.Fatal(err)
			}
		}
		t.Cleanup(func() { beforeLink = nil })
		_, err = extractInto(s, store.Inbox, rec, again)
		if err == nil || !strings.Contains(err.Error(), `refusing to write "report.txt": the directory changed under the extract; nothing was written`) {
			t.Fatalf("a temporary swapped for a symlink under the extract: %v; want the refusal", err)
		}
		if names := entriesOf(t, again); len(names) != 0 {
			t.Fatalf("the directory holds %v after the swapped temporary; want nothing under the name", names)
		}
		if data, _ := os.ReadFile(secret); string(data) != "private\n" {
			t.Fatalf("the secret behind the swapped temporary was touched: %q", data)
		}
		if info, err := os.Lstat(secret); err != nil || info.Mode()&os.ModeSymlink != 0 {
			t.Fatalf("the secret: %v %v", info, err)
		}
	})
}

// TestADirectoryAtTheNameIsANameThatStands: a directory standing at an
// attachment's name is a name that stands, as a file or a link there is,
// and the file goes beside it as the next numbered name with the
// directory and what it holds untouched — on both write paths and on
// every platform. Linux and macOS refuse the link and the exclusive
// create over a directory as EEXIST, which the loops always took as a
// name that stands; Windows refuses the create as EISDIR, which they did
// not until the first Windows run, and refused the extract instead. The
// Windows job is where the second word is proved.
func TestADirectoryAtTheNameIsANameThatStands(t *testing.T) {
	onEachWritePath(t, func(t *testing.T) {
		payload := []byte(strings.Repeat("beside the directory\n", 100))
		s, rec := streamedRecord(t, "report.txt", payload)
		out := t.TempDir()
		standing := filepath.Join(out, "report.txt")
		if err := os.Mkdir(standing, 0o700); err != nil {
			t.Fatal(err)
		}
		inside := filepath.Join(standing, "keep")
		if err := os.WriteFile(inside, []byte("keep me\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		written, err := extractInto(s, store.Inbox, rec, out)
		if err != nil {
			t.Fatalf("extractInto with a directory at the name: %v; want the file beside it", err)
		}
		if len(written) != 1 || filepath.Base(written[0]) != "report-2.txt" {
			t.Fatalf("wrote %v, want report-2.txt beside the directory", written)
		}
		if data, err := os.ReadFile(written[0]); err != nil || !bytes.Equal(data, payload) {
			t.Fatalf("the file: %d bytes, %v; want the payload whole", len(data), err)
		}
		if info, err := os.Lstat(standing); err != nil || !info.IsDir() {
			t.Fatalf("the directory at the name: %v, %v; want it standing", info, err)
		}
		if data, _ := os.ReadFile(inside); string(data) != "keep me\n" {
			t.Fatalf("what the directory held was touched: %q", data)
		}
		names := entriesOf(t, out)
		if len(names) != 2 {
			t.Fatalf("the directory holds %v; want the directory and the file alone, no temporary", names)
		}
	})
}
