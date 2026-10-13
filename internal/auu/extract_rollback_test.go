package auu

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/store"
	"github.com/tropeforce7/agentuucp/internal/stream"
)

// TestAFailedExtractionRemovesOnlyTheFilesItWrote: an extract is all or
// nothing. The manifest names a second attachment whose spool file is
// missing, so the first is written and the second fails; the first is
// removed, the file that stood under its name before the extract is left
// as it was, and no paths are returned. Codex's review found the files
// written before a failure left behind.
func TestAFailedExtractionRemovesOnlyTheFilesItWrote(t *testing.T) {
	onEachWritePath(t, func(t *testing.T) {
		s, rec := streamedRecord(t, "report.txt", []byte("verified attachment"))
		// The manifest names a second attachment, but its spool file is
		// missing. The first attachment is valid and is published first.
		second := rec.Inner.Body.Attachments[0]
		second.Name = "second.txt"
		rec.Inner.Body.Attachments = append(rec.Inner.Body.Attachments, second)
		out := t.TempDir()
		witness := filepath.Join(out, "report.txt")
		if err := os.WriteFile(witness, []byte("existing file"), 0600); err != nil {
			t.Fatal(err)
		}
		written, err := extractInto(s, store.Inbox, rec, out)
		if err == nil {
			t.Fatal("missing second spool file should fail extraction")
		}
		t.Logf("extraction returned paths=%v error=%v", written, err)
		if written != nil {
			t.Errorf("a failed extraction returned paths %v; want nil", written)
		}
		if data, err := os.ReadFile(witness); err != nil || string(data) != "existing file" {
			t.Fatalf("existing file changed: %q %v", data, err)
		}
		names := entriesOf(t, out)
		if len(names) != 1 || names[0] != "report.txt" {
			t.Errorf("failed attempt left %v; want only pre-existing report.txt", names)
		}
	})
}

// threeAttachments makes rec name report.txt, second.txt with its spool
// file supplied, and third.txt with none, so the third fails after the
// first two could be written.
func threeAttachments(t *testing.T, s *store.Store, rec *store.Stored) {
	t.Helper()
	first := rec.Inner.Body.Attachments[0]
	second, third := first, first
	second.Name, third.Name = "second.txt", "third.txt"
	rec.Inner.Body.Attachments = append(rec.Inner.Body.Attachments, second, third)
	supplySpool(t, s, rec, 1)
}

// supplySpool copies attachment 0's spool file to attachment i's, which
// the record names with the same size and digest.
func supplySpool(t *testing.T, s *store.Store, rec *store.Stored, i int) {
	t.Helper()
	dir := s.AttachmentDir(store.Inbox, rec.Inner.ID)
	data, err := os.ReadFile(filepath.Join(dir, stream.SpoolName(0)))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, stream.SpoolName(i)), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// onSecondWrite runs do once, when the extract's second attachment is
// verified and before its name is taken: the first attachment's file is
// written by then.
func onSecondWrite(t *testing.T, do func()) {
	t.Helper()
	calls := 0
	beforeLink = func(string) {
		calls++
		if calls == 2 {
			do()
		}
	}
	t.Cleanup(func() { beforeLink = nil })
}

// witnessIn writes a file of somebody's own beside the extract and
// returns a check that it is as it was.
func witnessIn(t *testing.T, dir string) func() {
	t.Helper()
	path := filepath.Join(dir, "keep.txt")
	if err := os.WriteFile(path, []byte("keep me\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return func() {
		t.Helper()
		if data, err := os.ReadFile(path); err != nil || string(data) != "keep me\n" {
			t.Errorf("the file beside the extract changed: %q %v", data, err)
		}
	}
}

// TestAFailedExtractNamesAFileItCouldNotRemove: when the directory stops
// being writable after the first attachment is written, the failure's
// roll back cannot remove that file; it is left, and the error names its
// path and why, with the file beside the extract untouched and no paths
// returned.
func TestAFailedExtractNamesAFileItCouldNotRemove(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a directory's mode bits do not refuse a removal on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root removes from a directory of mode 0500")
	}
	onEachWritePath(t, func(t *testing.T) {
		s, rec := streamedRecord(t, "report.txt", []byte("verified attachment"))
		threeAttachments(t, s, rec)
		out := t.TempDir()
		unchanged := witnessIn(t, out)
		t.Cleanup(func() { os.Chmod(out, 0o700) })
		onSecondWrite(t, func() {
			if err := os.Chmod(out, 0o500); err != nil {
				t.Fatal(err)
			}
		})
		report := filepath.Join(out, "report.txt")
		written, err := extractInto(s, store.Inbox, rec, out)
		if err == nil {
			t.Fatal("an extract into a directory made unwritable part way succeeded")
		}
		if written != nil {
			t.Errorf("a failed extraction returned paths %v; want nil", written)
		}
		msg := err.Error()
		t.Logf("the error: %s", msg)
		if !strings.Contains(msg, "these could not be removed: "+report+" (") || !strings.Contains(msg, "permission denied") {
			t.Errorf("the error %q does not name %s and why it could not be removed", msg, report)
		}
		if data, err := os.ReadFile(report); err != nil || string(data) != "verified attachment" {
			t.Errorf("the file the roll back could not remove: %q %v; want it there as written", data, err)
		}
		unchanged()
	})
}

// TestARetryAfterARolledBackFailureWritesThePlainNames: a failed extract
// leaves nothing of its own, so once the missing spool file is there the
// retry into the same directory writes report.txt and second.txt and not
// report-2.txt beside a file the failure left.
func TestARetryAfterARolledBackFailureWritesThePlainNames(t *testing.T) {
	onEachWritePath(t, func(t *testing.T) {
		s, rec := streamedRecord(t, "report.txt", []byte("verified attachment"))
		second := rec.Inner.Body.Attachments[0]
		second.Name = "second.txt"
		rec.Inner.Body.Attachments = append(rec.Inner.Body.Attachments, second)
		out := t.TempDir()
		unchanged := witnessIn(t, out)
		written, err := extractInto(s, store.Inbox, rec, out)
		if err == nil {
			t.Fatal("missing second spool file should fail extraction")
		}
		if written != nil {
			t.Errorf("a failed extraction returned paths %v; want nil", written)
		}
		if names := entriesOf(t, out); !slices.Equal(names, []string{"keep.txt"}) {
			t.Fatalf("the failed extract left %v; want only keep.txt", names)
		}
		supplySpool(t, s, rec, 1)
		written, err = extractInto(s, store.Inbox, rec, out)
		if err != nil {
			t.Fatalf("the retry: %v", err)
		}
		want := []string{filepath.Join(out, "report.txt"), filepath.Join(out, "second.txt")}
		if !slices.Equal(written, want) {
			t.Errorf("the retry wrote %v; want %v", written, want)
		}
		for _, p := range want {
			if data, err := os.ReadFile(p); err != nil || string(data) != "verified attachment" {
				t.Errorf("%s: %q %v", p, data, err)
			}
		}
		if names := entriesOf(t, out); !slices.Equal(names, []string{"keep.txt", "report.txt", "second.txt"}) {
			t.Errorf("the directory after the retry holds %v; want keep.txt, report.txt, second.txt", names)
		}
		unchanged()
	})
}

// TestAFailedExtractLeavesAFileReplacedMeanwhile: a file somebody put under
// the name the extract wrote, after it was written and before the
// failure, is not the extract's to remove. The roll back leaves it with
// its content, removes the file of its own it can still stand for, and
// says in the error which it left and why. The original is moved aside
// rather than removed, so the replacement cannot be given its inode
// number and pass for it.
func TestAFailedExtractLeavesAFileReplacedMeanwhile(t *testing.T) {
	onEachWritePath(t, func(t *testing.T) {
		s, rec := streamedRecord(t, "report.txt", []byte("verified attachment"))
		threeAttachments(t, s, rec)
		out := t.TempDir()
		unchanged := witnessIn(t, out)
		report := filepath.Join(out, "report.txt")
		aside := filepath.Join(t.TempDir(), "original")
		onSecondWrite(t, func() {
			if err := os.Rename(report, aside); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(report, []byte("somebody else's\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		})
		written, err := extractInto(s, store.Inbox, rec, out)
		if err == nil {
			t.Fatal("missing third spool file should fail extraction")
		}
		if written != nil {
			t.Errorf("a failed extraction returned paths %v; want nil", written)
		}
		if !strings.Contains(err.Error(), report+" (replaced meanwhile, left as it is)") {
			t.Errorf("the error %q does not name %s as replaced and left", err, report)
		}
		if data, err := os.ReadFile(report); err != nil || string(data) != "somebody else's\n" {
			t.Errorf("the replacement: %q %v; want it left as it was", data, err)
		}
		if names := entriesOf(t, out); !slices.Equal(names, []string{"keep.txt", "report.txt"}) {
			t.Errorf("the roll back left %v; want keep.txt and the replacement", names)
		}
		unchanged()
	})
}
