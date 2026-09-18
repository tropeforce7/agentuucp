package main

import (
	"bufio"
	"context"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/relay"
)

// buildRelay builds the binary, for the tests that run it as an operator
// would: with arguments and nothing else.
func buildRelay(t *testing.T) string {
	t.Helper()
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go is not on the path")
	}
	bin := filepath.Join(t.TempDir(), "auu-relay")
	if out, err := exec.Command(goTool, "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}

// --version is asked of a binary an operator has been handed, with no
// settings file anywhere near it, and says the schema beside the version:
// what a relay speaks is what decides whether its database can be opened
// by it, and a hash cannot tell an operator that.
func TestVersionNamesTheSchemaAndNeedsNoSettings(t *testing.T) {
	bin := buildRelay(t)
	out, err := exec.Command(bin, "--version").CombinedOutput()
	if err != nil {
		t.Fatalf("auu-relay --version: %v\n%s", err, out)
	}
	line := regexp.MustCompile(`^auu-relay (\S+) \(schema (\d+)\)\n$`).FindStringSubmatch(string(out))
	if line == nil {
		t.Fatalf("auu-relay --version said %q", out)
	}
	if line[1] == "" {
		t.Fatal("the version is empty")
	}
	schema, err := strconv.Atoi(line[2])
	if err != nil || schema != relay.SchemaVersion {
		t.Fatalf("it says schema %q, want %d", line[2], relay.SchemaVersion)
	}
}

// TestABareRelayRefusesAndOffIsSaidOut: the binary started with only a
// listen address and a database exits non-zero with the one sentence, and
// with --tls-mode off it starts and says on its first lines that it is
// serving plain HTTP and what that is for.
func TestABareRelayRefusesAndOffIsSaidOut(t *testing.T) {
	bin := buildRelay(t)
	db := filepath.Join(t.TempDir(), "relay.db")

	// Bounded, because the failure this guards against is a relay that
	// starts and serves: one that is still running after the deadline is
	// that failure, not a slow refusal.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "--listen", "127.0.0.1:0", "--db", db).CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("a bare relay started and served for 20s; it said:\n%s", out)
	}
	if err == nil {
		t.Fatalf("a bare relay exited 0; it said:\n%s", out)
	}
	if got := strings.TrimSpace(string(out)); got != "auu-relay: "+msgNoTLS {
		t.Fatalf("a bare relay said %q, want the one sentence", got)
	}

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
	var seen []string
	deadline := time.After(20 * time.Second)
	started, plain := false, false
	for !(started && plain) {
		select {
		case line, ok := <-lines:
			if !ok {
				t.Fatalf("the relay stopped before it said what it serves:\n%s", strings.Join(seen, "\n"))
			}
			seen = append(seen, line)
			if strings.Contains(line, `msg="relay starting"`) && strings.Contains(line, "tls=off") {
				started = true
			}
			if strings.Contains(line, "serving plain HTTP: for a try on one machine, not for a relay anybody reaches over a network") {
				plain = true
			}
		case <-deadline:
			t.Fatalf("the relay did not say it serves plain HTTP within 20s:\n%s", strings.Join(seen, "\n"))
		}
	}
}
