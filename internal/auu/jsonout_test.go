package auu

import (
	"os"
	"testing"
)

// Both JSON writers return a write that failed (G47, R62): the one a line
// that 'auu serve --json' writes a round to printed and said nothing, so a
// round was reported written when its line was not. Codex's review found
// it. Standard output here is a file already closed, so every write fails.
func TestTheJSONWritersReturnAFailedWrite(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "closed-output")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	old := os.Stdout
	os.Stdout = f
	defer func() { os.Stdout = old }()
	if err := printJSON(map[string]string{"state": "done"}); err == nil {
		t.Error("printJSON reported success on a closed standard output")
	}
	if err := printJSONLine(map[string]string{"state": "done"}); err == nil {
		t.Error("printJSONLine reported success on a closed standard output")
	}
}
