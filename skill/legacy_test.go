package skill

import (
	"crypto/sha256"
	"encoding/hex"
	"os/exec"
	"slices"
	"strings"
	"testing"
)

// The legacy lists are the history's, both ways: every version of the
// connect skill's SKILL.md and of the reference that the tree held before
// the rename is in them, and nothing else is. The walk is of HEAD up to
// the parent of the commit that removed skill/connect/SKILL.md. A
// checkout with no git, or a shallow one, which is every CI job's, has no
// history to walk, and the test says so and skips; the reviewer's gate
// runs it on a full clone.
func TestTheLegacyDigestsAreTheShippedOnes(t *testing.T) {
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skipf("no git to walk the history with (%v); the lists are held to it on a full clone", err)
	}
	run := func(args ...string) (string, error) {
		cmd := exec.Command(git, args...)
		cmd.Dir = ".."
		out, err := cmd.Output()
		return string(out), err
	}
	shallow, err := run("rev-parse", "--is-shallow-repository")
	if err != nil {
		t.Skipf("no repository here to walk (%v); the lists are held to it on a full clone", err)
	}
	if strings.TrimSpace(shallow) == "true" {
		t.Skip("a shallow clone holds no history to walk; the lists are held to it on a full clone")
	}
	rename, err := run("rev-list", "-1", "HEAD", "--", "skill/connect/SKILL.md")
	if err != nil || strings.TrimSpace(rename) == "" {
		t.Fatalf("no commit removed skill/connect/SKILL.md in HEAD's history: %v", err)
	}
	before := strings.TrimSpace(rename) + "^"
	for _, tc := range []struct {
		path string
		list []string
	}{
		{"skill/connect/SKILL.md", LegacyConnect},
		{"skill/reference.md", LegacyReference},
	} {
		commits, err := run("rev-list", before, "--", tc.path)
		if err != nil {
			t.Fatal(err)
		}
		seen := map[string]bool{}
		for _, c := range strings.Fields(commits) {
			blob, err := run("cat-file", "blob", c+":"+tc.path)
			if err != nil {
				// A commit that removed the path has no blob of it.
				continue
			}
			sum := sha256.Sum256([]byte(blob))
			seen[hex.EncodeToString(sum[:])] = true
		}
		if len(seen) == 0 {
			t.Fatalf("%s: no version of it before %s", tc.path, before)
		}
		for d := range seen {
			if !slices.Contains(tc.list, d) {
				t.Errorf("%s: the version %s is in the history and not in the list", tc.path, d)
			}
		}
		for _, d := range tc.list {
			if !seen[d] {
				t.Errorf("%s: the list holds %s, which is no version in the history", tc.path, d)
			}
		}
		if len(tc.list) != len(seen) {
			t.Errorf("%s: the list holds %d digests for %d versions", tc.path, len(tc.list), len(seen))
		}
	}
}

// Legacy knows only the two names: a digest from one list is not taken for
// a file of the other name, nor for a third name.
func TestLegacyKnowsOnlyTheTwoFiles(t *testing.T) {
	if !Legacy("SKILL.md", LegacyConnect[0]) || !Legacy(Reference, LegacyReference[0]) {
		t.Fatal("a listed digest is not legacy under its own name")
	}
	if Legacy(Reference, LegacyConnect[0]) || Legacy("SKILL.md", LegacyReference[0]) {
		t.Fatal("a digest is legacy under the other file's name")
	}
	if Legacy("notes.md", LegacyConnect[0]) {
		t.Fatal("a third name is legacy")
	}
}
