package auu

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/skill"
)

// auu skill: the skills the binary carries, written out and looked at.

// runSkill runs an auu command with stdout captured, from no home: the
// skill commands read nothing from a home.
func runSkill(t *testing.T, args ...string) (string, error) {
	t.Helper()
	u := &user{t: t, home: t.TempDir()}
	return u.tryRun(args...)
}

// treeFile is one of the skills as the tree has it.
func treeFile(t *testing.T, rel string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(skillDir, rel))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// install writes the six files with the right modes and the tree's bytes,
// says which, and a second run writes nothing at all.
func TestSkillInstallWritesTheSkillsOnce(t *testing.T) {
	dir := t.TempDir()
	out, err := runSkill(t, "skill", "install", "--dir", dir)
	if err != nil {
		t.Fatal(err)
	}
	skills := filepath.Join(dir, "skills")
	want := "installed auu-connect, auu-setup and auu-relay in " + skills + "\nrestart Claude Code, or start a new session, for it to see them\n"
	if out != want {
		t.Fatalf("install said:\n%s\nwant:\n%s", out, want)
	}
	for _, name := range skill.Names() {
		for _, f := range []struct{ file, rel string }{{"SKILL.md", name + "/SKILL.md"}, {"reference.md", "reference.md"}} {
			path := filepath.Join(skills, name, f.file)
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("%s was not written: %v", path, err)
			}
			if string(got) != string(treeFile(t, f.rel)) {
				t.Errorf("%s is not the tree's %s", path, f.rel)
			}
			if runtime.GOOS != "windows" {
				info, _ := os.Stat(path)
				if info.Mode().Perm() != 0o644 {
					t.Errorf("%s is mode %04o, want 0644", path, info.Mode().Perm())
				}
				dinfo, _ := os.Stat(filepath.Dir(path))
				if dinfo.Mode().Perm() != 0o755 {
					t.Errorf("%s is mode %04o, want 0755", filepath.Dir(path), dinfo.Mode().Perm())
				}
			}
		}
	}
	// Nothing left over from the atomic writes.
	entries, _ := os.ReadDir(filepath.Join(skills, "auu-connect"))
	if len(entries) != 2 {
		t.Errorf("auu-connect holds %d entries, want the two files", len(entries))
	}

	// The second run: identical bytes, nothing written. The mtimes are set
	// back an hour so that a write would show.
	old := time.Now().Add(-time.Hour)
	path := filepath.Join(skills, "auu-connect", "SKILL.md")
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	out, err = runSkill(t, "skill", "install", "--dir", dir)
	if err != nil {
		t.Fatal(err)
	}
	if out != "already installed: auu-connect, auu-setup and auu-relay in "+skills+"\n" {
		t.Fatalf("the second run said:\n%s", out)
	}
	info, _ := os.Stat(path)
	if !info.ModTime().Equal(old) {
		t.Fatal("the second run rewrote a file that was already this binary's")
	}
	var report skillInstallJSON
	out, _ = runSkill(t, "skill", "install", "--dir", dir, "--json")
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatal(err)
	}
	if report.Dir != skills || len(report.Skills) != 6 {
		t.Fatalf("install --json: %+v", report)
	}
	for _, s := range report.Skills {
		if s.State != skillUnchanged {
			t.Errorf("%s is %s after two installs, want unchanged", s.Path, s.State)
		}
	}
}

// The test that matters: a person's edited file is kept and named, exit 1,
// and the rest is still installed; --force replaces it and says so.
func TestSkillInstallKeepsAnEditedFileUnlessForced(t *testing.T) {
	dir := t.TempDir()
	if _, err := runSkill(t, "skill", "install", "--dir", dir); err != nil {
		t.Fatal(err)
	}
	skills := filepath.Join(dir, "skills")
	edited := filepath.Join(skills, "auu-setup", "SKILL.md")
	mine := []byte("# my own auu-setup\n\nI changed this.\n")
	if err := os.WriteFile(edited, mine, 0o644); err != nil {
		t.Fatal(err)
	}
	// And one file removed, so that the run has something to write beside
	// the one it keeps.
	removed := filepath.Join(skills, "auu-connect", "reference.md")
	if err := os.Remove(removed); err != nil {
		t.Fatal(err)
	}

	out, err := runSkill(t, "skill", "install", "--dir", dir)
	var e *exitError
	if !errors.As(err, &e) || e.code != exitUsage {
		t.Fatalf("an edited file: %v\n%s", err, out)
	}
	if err.Error() != edited+" differs from this binary's copy; kept. --force replaces it" {
		t.Fatalf("the refusal: %q", err)
	}
	if got, _ := os.ReadFile(edited); string(got) != string(mine) {
		t.Fatal("the edited file was overwritten without --force")
	}
	if _, err := os.Stat(removed); err != nil {
		t.Fatal("the missing file was not written because another was kept")
	}
	if !strings.Contains(out, "installed auu-connect, auu-setup and auu-relay in "+skills+"\n") {
		t.Fatalf("install with a kept file said:\n%s", out)
	}
	// --json says the same, per file.
	out, err = runSkill(t, "skill", "install", "--dir", dir, "--json")
	if !errors.As(err, &e) || e.code != exitUsage {
		t.Fatalf("--json with a kept file: %v", err)
	}
	var report skillInstallJSON
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	states := map[string]string{}
	for _, s := range report.Skills {
		states[s.Path] = s.State
	}
	if states[edited] != skillKept || states[removed] != skillUnchanged {
		t.Fatalf("the states: %v", states)
	}
	// Two edited files are named together.
	edited2 := filepath.Join(skills, "auu-relay", "reference.md")
	os.WriteFile(edited2, []byte("mine too\n"), 0o644)
	_, err = runSkill(t, "skill", "install", "--dir", dir)
	if err == nil || err.Error() != edited+" and "+edited2+" differ from this binary's copy; kept. --force replaces them" {
		t.Fatalf("two kept files: %v", err)
	}

	// --force replaces them, says which skills were updated, exits 0.
	out, err = runSkill(t, "skill", "install", "--dir", dir, "--force")
	if err != nil {
		t.Fatalf("--force: %v\n%s", err, out)
	}
	if !strings.Contains(out, "installed auu-connect, auu-setup and auu-relay in "+skills+" (updated auu-setup) (updated auu-relay)\n") {
		t.Fatalf("--force said:\n%s", out)
	}
	if got, _ := os.ReadFile(edited); string(got) != string(treeFile(t, "auu-setup/SKILL.md")) {
		t.Fatal("--force did not replace the edited file")
	}
	out, _ = runSkill(t, "skill", "install", "--dir", dir, "--json")
	json.Unmarshal([]byte(out), &report)
	for _, s := range report.Skills {
		if s.State != skillUnchanged {
			t.Errorf("%s is %s after --force, want unchanged", s.Path, s.State)
		}
	}
}

// The directory: --dir, then $CLAUDE_CONFIG_DIR, then the home's .claude,
// in that order.
func TestSkillDirectoryResolvesInOrder(t *testing.T) {
	home := t.TempDir()
	configDir := t.TempDir()
	flagDir := t.TempDir()
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", home)
	} else {
		t.Setenv("HOME", home)
	}
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	dirOf := func(t *testing.T, args ...string) string {
		t.Helper()
		var report skillLsJSON
		out, err := runSkill(t, append([]string{"skill", "ls", "--json"}, args...)...)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal([]byte(out), &report); err != nil {
			t.Fatal(err)
		}
		return report.Dir
	}
	if got := dirOf(t); got != filepath.Join(home, ".claude", "skills") {
		t.Fatalf("with nothing set: %s", got)
	}
	t.Setenv("CLAUDE_CONFIG_DIR", configDir)
	if got := dirOf(t); got != filepath.Join(configDir, "skills") {
		t.Fatalf("with CLAUDE_CONFIG_DIR: %s", got)
	}
	if got := dirOf(t, "--dir", flagDir); got != filepath.Join(flagDir, "skills") {
		t.Fatalf("with --dir: %s", got)
	}
}

// ls reports the three states; show prints the file from the binary; an
// unknown name names the three.
func TestSkillLsAndShow(t *testing.T) {
	dir := t.TempDir()
	skills := filepath.Join(dir, "skills")
	out, err := runSkill(t, "skill", "ls", "--dir", dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range skill.Names() {
		if !strings.Contains(out, name+" ") || !strings.Contains(out, " absent ") {
			t.Fatalf("ls before an install:\n%s", out)
		}
	}
	if _, err := runSkill(t, "skill", "install", "--dir", dir); err != nil {
		t.Fatal(err)
	}
	// One installed, one edited, one gone.
	os.WriteFile(filepath.Join(skills, "auu-setup", "reference.md"), []byte("edited\n"), 0o644)
	os.RemoveAll(filepath.Join(skills, "auu-relay"))
	var report skillLsJSON
	out, _ = runSkill(t, "skill", "ls", "--dir", dir, "--json")
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatal(err)
	}
	states := map[string]string{}
	for _, s := range report.Skills {
		states[s.Name] = s.State
		if s.Path != filepath.Join(skills, s.Name) {
			t.Errorf("%s's path is %s", s.Name, s.Path)
		}
	}
	if states["auu-connect"] != skillInstalled || states["auu-setup"] != skillDiffers || states["auu-relay"] != skillAbsent {
		t.Fatalf("ls --json: %v", states)
	}
	out, _ = runSkill(t, "skill", "ls", "--dir", dir)
	if !strings.Contains(out, "auu-connect  installed  ") || !strings.Contains(out, "auu-setup    differs    ") || !strings.Contains(out, "auu-relay    absent     ") {
		t.Fatalf("ls:\n%s", out)
	}

	for _, c := range []struct{ name, rel string }{{"auu-connect", "auu-connect/SKILL.md"}, {"auu-relay", "auu-relay/SKILL.md"}, {"reference", "reference.md"}} {
		out, err := runSkill(t, "skill", "show", c.name)
		if err != nil {
			t.Fatal(err)
		}
		if out != string(treeFile(t, c.rel)) {
			t.Errorf("show %s is not the tree's %s", c.name, c.rel)
		}
	}
	_, err = runSkill(t, "skill", "show", "nothing")
	if err == nil || err.Error() != `no skill "nothing"; the binary carries auu-connect, auu-setup and auu-relay, and reference` {
		t.Fatalf("show of an unknown name: %v", err)
	}
	if _, err := runSkill(t, "skill", "show"); err == nil || !strings.Contains(err.Error(), "usage: auu skill show auu-connect|auu-setup|auu-relay|reference") {
		t.Fatalf("show with no name: %v", err)
	}
	if _, err := runSkill(t, "skill", "frob"); err == nil || !strings.Contains(err.Error(), `unknown skill subcommand "frob"`) {
		t.Fatalf("an unknown subcommand: %v", err)
	}
}

// The messaging skill's old name is refused, exit 1, in one sentence that
// names the new one, and nothing is printed from the binary.
func TestSkillShowConnectNamesTheNewName(t *testing.T) {
	out, err := runSkill(t, "skill", "show", "connect")
	var e *exitError
	if !errors.As(err, &e) || e.code != exitUsage {
		t.Fatalf("show connect: %v, want exit %d", err, exitUsage)
	}
	if err.Error() != "the connect skill is now auu-connect: auu skill show auu-connect" {
		t.Fatalf("show connect said %q", err.Error())
	}
	if out != "" {
		t.Fatalf("show connect printed %q", out)
	}
}

// version --json carries the skills.
func TestVersionNamesTheSkills(t *testing.T) {
	out, err := runSkill(t, "version", "--json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Version string   `json:"version"`
		Skills  []string `json:"skills"`
	}
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatal(err)
	}
	if v.Version == "" || strings.Join(v.Skills, ",") != "auu-connect,auu-setup,auu-relay" {
		t.Fatalf("version --json: %+v", v)
	}
}
