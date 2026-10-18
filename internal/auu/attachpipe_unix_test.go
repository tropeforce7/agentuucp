//go:build unix

package auu

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/message"
)

// TestLimitAnAttachmentThatIsAPipeIsRefused: a pipe, which a process
// substitution such as <(command) hands the program as /dev/fd/N, is read
// once, and an attachment is read to be hashed and again to be sealed; it
// is refused by name with what to do instead, rather than opened.
func TestLimitAnAttachmentThatIsAPipeIsRefused(t *testing.T) {
	pipe := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(pipe, 0o600); err != nil {
		t.Fatal(err)
	}
	reads := map[string]func() error{
		"estimateSize":    func() error { _, err := estimateSize(message.Body{}, []string{pipe}); return err },
		"loadAttachments": func() error { _, err := loadAttachments([]string{pipe}); return err },
		"sourcesFor":      func() error { _, err := sourcesFor([]string{pipe}); return err },
	}
	for name, read := range reads {
		// A read that opens the pipe blocks until a writer comes, so each
		// is given a deadline, and a writer is opened to let it go when
		// the deadline passes: the regression fails, rather than hangs.
		done := make(chan error, 1)
		go func() { done <- read() }()
		select {
		case err := <-done:
			if err == nil || !strings.Contains(err.Error(), "a pipe, which <(command) is, is not attached") {
				t.Errorf("%s: %v; want the pipe refused by name", name, err)
			}
		case <-time.After(10 * time.Second):
			t.Errorf("%s opened the pipe and waited for it", name)
			if w, err := os.OpenFile(pipe, os.O_WRONLY, 0); err == nil {
				w.Close()
			}
			<-done
		}
	}
	if _, err := os.Stat(pipe); err != nil {
		t.Fatalf("the pipe went: %v", err)
	}
}
