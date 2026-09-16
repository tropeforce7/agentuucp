package main

import (
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/relay"
)

// --version is asked of a binary an operator has been handed, with no
// settings file anywhere near it, and says the schema beside the version:
// what a relay speaks is what decides whether its database can be opened
// by it, and a hash cannot tell an operator that.
func TestVersionNamesTheSchemaAndNeedsNoSettings(t *testing.T) {
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go is not on the path")
	}
	bin := filepath.Join(t.TempDir(), "auu-relay")
	if out, err := exec.Command(goTool, "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
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
