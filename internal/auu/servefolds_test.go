package auu

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// diskFolds asks the disk under dir itself whether it takes the two names
// as one directory, which is what a test of checkFolds holds it to.
func diskFolds(t *testing.T, dir, a, b string) bool {
	t.Helper()
	if err := os.Mkdir(filepath.Join(dir, a), 0o700); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(filepath.Join(dir, a))
	err := os.Mkdir(filepath.Join(dir, b), 0o700)
	if err == nil {
		os.RemoveAll(filepath.Join(dir, b))
		return false
	}
	if os.IsExist(err) {
		return true
	}
	t.Fatal(err)
	return false
}

// Two channel names a disk takes as one directory, é composed and é
// decomposed on APFS, are refused by name where the disk under serve/ does,
// and taken where it does not (S63): the standard library has no table of
// Unicode normalisation, so check, comparing case, sees two names, and the
// disk's own answer is what says whether they would share a directory
// under serve/channels/ and serve/worktrees/. The assertion follows that
// answer, so the test holds on every disk; the probe is gone either way.
func TestServeCheckRefusesChannelsTheDiskTakesAsOne(t *testing.T) {
	dir := repo(t)
	one := func() *serveChannel {
		return &serveChannel{Dir: dir, Exec: "cat", Mode: modeReadOnly, MaxTurns: 1}
	}
	composed, decomposed := "café", "café"
	cfg := &serveConfig{
		V:        1,
		path:     filepath.Join(t.TempDir(), "serve.json"),
		Channels: map[string]*serveChannel{composed: one(), decomposed: one()},
	}
	if err := cfg.check(); err != nil {
		t.Fatalf("check, which compares case, refused the two spellings: %v", err)
	}
	serveDir := filepath.Join(t.TempDir(), "serve")
	if err := os.MkdirAll(serveDir, 0o700); err != nil {
		t.Fatal(err)
	}
	folds := diskFolds(t, serveDir, composed, decomposed)
	err := cfg.checkFolds(serveDir)
	if folds {
		if err == nil || !strings.Contains(err.Error(), "are one directory on this filesystem, which takes them as one name; rename one") {
			t.Fatalf("this disk takes the two spellings as one, and checkFolds said: %v", err)
		}
	} else if err != nil {
		t.Fatalf("this disk keeps the two spellings apart, and checkFolds refused them: %v", err)
	}
	t.Logf("the disk under %s folds é composed and decomposed: %v", serveDir, folds)
	if entries, _ := os.ReadDir(serveDir); len(entries) != 0 {
		t.Fatalf("the probe left %v under serve/", entries)
	}
}

// TestLimitAChannelNameIsNotAPathAtCheckFolds: checkFolds joins a channel's
// name under its probe directory, and every value of the traversal set is
// refused by channels.ValidName at check before checkFolds is reached, so
// nothing of the set becomes a directory anywhere. A name that check takes
// makes nothing beside the probe, and the probe goes. The same holds for a
// route id in handle.json, whose check and probe are handle's.
func TestLimitAChannelNameIsNotAPathAtCheckFolds(t *testing.T) {
	dir := repo(t)
	for _, v := range pathSet() {
		cfg := &serveConfig{V: 1, path: filepath.Join(t.TempDir(), "serve.json"),
			Channels: map[string]*serveChannel{v: {Dir: dir, Exec: "cat", Mode: modeReadOnly, MaxTurns: 1}}}
		if err := cfg.check(); err == nil {
			// A value check takes is a name, one segment: the probe holds it.
			scratch := t.TempDir()
			serveDir := filepath.Join(scratch, "serve")
			if err := cfg.checkFolds(serveDir); err != nil {
				t.Errorf("checkFolds of %q, which check took: %v", v, err)
			}
			if entries, _ := os.ReadDir(scratch); len(entries) != 1 || entries[0].Name() != "serve" {
				t.Errorf("checkFolds of %q made %v beside serve/", v, entries)
			}
			if entries, _ := os.ReadDir(serveDir); len(entries) != 0 {
				t.Errorf("checkFolds of %q left %v under serve/", v, entries)
			}
		}
	}
	routeIdsAreNotPathsAtCheckFolds(t)
}

// The same at a serve start: auu serve refuses a file whose channels the
// disk under the home's serve/ takes as one, before any key or lock, and
// serves it where the disk keeps them apart.
func TestServeRefusesChannelsTheDiskTakesAsOne(t *testing.T) {
	_, bob := newExpert(t, modeReadOnly)
	composed, decomposed := "caf\u00e9", "cafe\u0301"
	row := *bob.row
	bob.config.Channels = map[string]*serveChannel{composed: bob.row, decomposed: &row}
	bob.write(t)
	serveDir := filepath.Join(bob.home, "serve")
	if err := os.MkdirAll(serveDir, 0o700); err != nil {
		t.Fatal(err)
	}
	folds := diskFolds(t, serveDir, composed, decomposed)
	before, _ := os.ReadFile(filepath.Join(serveDir, ledgerFile))
	var err error
	captureStderr(t, func() { _, err = bob.tryRun("serve", "--once") })
	if folds {
		if err == nil || !strings.Contains(err.Error(), "are one directory on this filesystem") {
			t.Fatalf("auu serve with two channels this disk takes as one: %v", err)
		}
		if after, _ := os.ReadFile(filepath.Join(serveDir, ledgerFile)); string(after) != string(before) {
			t.Error("serve wrote its ledger before refusing the file")
		}
	} else if err != nil && strings.Contains(err.Error(), "one directory") {
		t.Fatalf("this disk keeps the two apart, and serve refused them: %v", err)
	}
}
