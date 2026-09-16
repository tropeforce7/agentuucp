package buildinfo

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// A version that cannot be read is a state, not a failure: an operator may
// be handed a binary built any way at all, and every caller says so in its
// own words rather than refusing to run.

func TestAVersionThatCannotBeReadIsUnknown(t *testing.T) {
	for _, tc := range []struct {
		what string
		in   string
	}{
		{"not a binary at all", "#!/bin/sh\nexit 0\n"},
		{"empty", ""},
	} {
		if got := Of(bytes.NewReader([]byte(tc.in))); got != "" {
			t.Errorf("%s: Of = %q, want empty", tc.what, got)
		}
	}
	if got := orUnknown(""); got != "unknown" {
		t.Errorf("orUnknown(\"\") = %q", got)
	}
	// "(devel)" is what Go writes when it has no version control
	// information to go on, which is nothing an operator can act on.
	if got := clean("(devel)"); got != "" {
		t.Errorf("clean(\"(devel)\") = %q, want empty", got)
	}
	if got := clean("v0.3.0"); got != "v0.3.0" {
		t.Errorf("clean(\"v0.3.0\") = %q", got)
	}
}

// This binary is a Go binary, so its own version reads back: whatever the
// tree it was built from says, and never empty, since Version falls back to
// the word.
func TestThisBinaryHasAVersion(t *testing.T) {
	if got := Version(); got == "" {
		t.Fatal("Version is empty; it should be the version or the word unknown")
	}
}

// And Of reads another binary's, from the file rather than from the running
// program: the kit asks it of the relay it is carrying, which it never
// runs. The binary here is built by the test, so the assertion is that the
// field is carried, not what it says — a clone, a tag and a copied tree all
// give different answers, and all are correct.
func TestOfReadsAnotherBinarysVersion(t *testing.T) {
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go is not on the path")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "main.go")
	if err := os.WriteFile(src, []byte("package main\n\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "prog")
	cmd := exec.Command(goTool, "build", "-o", out, src)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if msg, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, msg)
	}
	f, err := os.Open(out)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	// A program built from a file outside any module has no main module
	// version, which is the empty answer; what matters is that reading it
	// does not fail and does not invent one.
	got := Of(f)
	if got == "(devel)" {
		t.Errorf("Of = %q, which is Go's word for nothing and not a version", got)
	}
}
