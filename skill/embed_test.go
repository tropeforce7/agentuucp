package skill

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// The embedded files are the tree's, byte for byte, in both directions: every
// skill directory in the tree is in Names and in Files with the same bytes,
// and Names carries nothing the tree does not. The dispatch test in
// internal/auu reads the tree and proves its forms dispatch; this proves
// the binary carries that tree.
func TestEmbeddedSkillsAreTheTreesByteForByte(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	inTree := map[string]bool{}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join(e.Name(), "SKILL.md")); err == nil {
			inTree[e.Name()] = true
		}
	}
	named := map[string]bool{}
	for _, name := range Names() {
		named[name] = true
		if !inTree[name] {
			t.Errorf("Names carries %q, which has no SKILL.md in the tree", name)
		}
	}
	for name := range inTree {
		if !named[name] {
			t.Errorf("the tree has skill %q, which Names does not carry", name)
		}
	}
	if want := []string{"auu-connect", "auu-setup", "auu-relay"}; len(Names()) != 3 || Names()[0] != want[0] || Names()[1] != want[1] || Names()[2] != want[2] {
		t.Errorf("Names is %v, want %v", Names(), want)
	}

	files := []string{Reference}
	for _, name := range Names() {
		files = append(files, filepath.ToSlash(filepath.Join(name, "SKILL.md")))
	}
	for _, f := range files {
		tree, err := os.ReadFile(filepath.FromSlash(f))
		if err != nil {
			t.Errorf("the tree has no %s: %v", f, err)
			continue
		}
		embedded, err := Files.ReadFile(f)
		if err != nil {
			t.Errorf("the binary has no %s: %v", f, err)
			continue
		}
		if !bytes.Equal(tree, embedded) {
			t.Errorf("%s differs between the tree (%d bytes) and the binary (%d bytes); rebuild", f, len(tree), len(embedded))
		}
		if len(embedded) == 0 {
			t.Errorf("%s is empty", f)
		}
	}
	// And nothing else is carried: a file that slipped into the pattern
	// would be written out by install.
	var carried []string
	if err := walk(Files, ".", &carried); err != nil {
		t.Fatal(err)
	}
	if len(carried) != len(files) {
		t.Errorf("the binary carries %v, want %v", carried, files)
	}
}

func walk(fsys interface {
	ReadDir(string) ([]os.DirEntry, error)
}, dir string, out *[]string) error {
	entries, err := fsys.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		p := e.Name()
		if dir != "." {
			p = dir + "/" + p
		}
		if e.IsDir() {
			if err := walk(fsys, p, out); err != nil {
				return err
			}
			continue
		}
		*out = append(*out, p)
	}
	return nil
}
