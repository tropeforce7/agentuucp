package main

import (
	"bufio"
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/relay"
	"github.com/tropeforce7/agentuucp/internal/relay/schemahistory"
)

// A relay started on a database from the first kept version says, before
// it serves, that it carried the database forward, from which version to
// which, and where the copy is; the copy is there, the owner's alone; and
// the starting line after it names this build's schema. This is the line
// an operator reads in the journal after an upgrade, from the binary, on
// a file made as version 11 made it.
func TestAKeptDatabaseIsCarriedForwardAtTheStart(t *testing.T) {
	bin := buildRelay(t)
	dir := t.TempDir()
	db := filepath.Join(dir, "relay.db")
	raw, err := sql.Open("sqlite", db)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(schemahistory.SchemaAt11); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`PRAGMA user_version = 11`); err != nil {
		t.Fatal(err)
	}
	raw.Close()

	cmd := exec.Command(bin, "--listen", "127.0.0.1:0", "--db", db, "--tls-mode", "off")
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cmd.Process.Kill()
		cmd.Wait()
	}()
	lines := make(chan string, 64)
	go func() {
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()

	cp := db + ".before-schema-11"
	carried := fmt.Sprintf(`from=11 to=%d copy=%s`, relay.SchemaVersion, cp)
	var seen []string
	deadline := time.After(20 * time.Second)
	said, started := false, false
	for !started {
		select {
		case line, ok := <-lines:
			if !ok {
				t.Fatalf("the relay stopped before it started:\n%s", strings.Join(seen, "\n"))
			}
			seen = append(seen, line)
			if strings.Contains(line, "level=INFO") && strings.Contains(line, "the database was carried forward") {
				if !strings.Contains(line, carried) {
					t.Errorf("the carried-forward line does not say %q:\n%s", carried, line)
				}
				said = true
			}
			if strings.Contains(line, `msg="relay starting"`) {
				if !strings.Contains(line, fmt.Sprintf("schema=%d", relay.SchemaVersion)) {
					t.Errorf("the starting line does not name schema %d:\n%s", relay.SchemaVersion, line)
				}
				started = true
			}
		case <-deadline:
			t.Fatalf("the relay did not start within 20s:\n%s", strings.Join(seen, "\n"))
		}
	}
	if !said {
		t.Fatalf("the relay started without saying it carried the database forward:\n%s", strings.Join(seen, "\n"))
	}
	fi, err := os.Stat(cp)
	if err != nil {
		t.Fatalf("no copy beside the database: %v", err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Errorf("the copy's mode is %v, want 0600", fi.Mode().Perm())
	}
}
