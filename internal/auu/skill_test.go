package auu

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/buildinfo"
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

// installLines is what install prints for a directory when every file is
// in one state: the first line, a line per file, and the last line when
// one is due.
func installLines(first, skills, forWhom, word, last string) string {
	out := first + " auu-connect, auu-setup and auu-relay in " + skills + forWhom + " " + builtAs() + "\n"
	for _, name := range skill.Names() {
		out += "  " + name + "/SKILL.md: " + word + "\n"
		out += "  " + name + "/reference.md: " + word + "\n"
	}
	if last != "" {
		out += last + "\n"
	}
	return out
}

const seeThemClaude = "restart Claude Code, or start a new session, for it to see them"

// standTerminal stands a terminal in, or takes it away, for one test.
func standTerminal(t *testing.T, is bool) {
	t.Helper()
	was := stdinIsTerminal
	stdinIsTerminal = func() bool { return is }
	t.Cleanup(func() { stdinIsTerminal = was })
}

// answerWith hands the next command a standard input carrying text.
func answerWith(t *testing.T, text string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.WriteString(text); err != nil {
		t.Fatal(err)
	}
	w.Close()
	real := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = real; r.Close() })
}

// aHome gives the test a home of its own and no $CLAUDE_CONFIG_DIR, and
// returns the home.
func aHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", home)
	} else {
		t.Setenv("HOME", home)
	}
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	return home
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
	want := installLines("installed", skills, ", given by --dir", "written", seeThemClaude)
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
	if want := installLines("already installed:", skills, ", given by --dir", "already current", ""); out != want {
		t.Fatalf("the second run said:\n%s\nwant:\n%s", out, want)
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
	for _, line := range []string{
		"installed auu-connect, auu-setup and auu-relay in " + skills + ", given by --dir " + builtAs() + "\n",
		"  auu-setup/SKILL.md: kept, differs from this binary's copy; --force replaces it\n",
		"  auu-connect/reference.md: written\n",
		"  auu-connect/SKILL.md: already current\n",
		seeThemClaude + "\n",
	} {
		if !strings.Contains(out, line) {
			t.Fatalf("install with a kept file said:\n%s\nwant a line %q", out, line)
		}
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
	out, err = runSkill(t, "skill", "install", "--dir", dir)
	if err == nil || err.Error() != edited+" and "+edited2+" differ from this binary's copy; kept. --force replaces them" {
		t.Fatalf("two kept files: %v", err)
	}
	// Nothing was written and two files were kept: not "installed", which
	// would be a false word, and no line about seeing them (D157).
	if !strings.HasPrefix(out, "not all installed: auu-connect, auu-setup and auu-relay in "+skills+", given by --dir "+builtAs()+"\n") ||
		strings.Contains(out, seeThemClaude) {
		t.Fatalf("an install that wrote nothing and kept two said:\n%s", out)
	}

	// --force replaces them, says which skills were updated, exits 0.
	out, err = runSkill(t, "skill", "install", "--dir", dir, "--force")
	if err != nil {
		t.Fatalf("--force: %v\n%s", err, out)
	}
	for _, line := range []string{
		"installed auu-connect, auu-setup and auu-relay in " + skills + ", given by --dir " + builtAs() + "\n",
		"  auu-setup/SKILL.md: replaced\n",
		"  auu-relay/reference.md: replaced\n",
		"  auu-relay/SKILL.md: already current\n",
	} {
		if !strings.Contains(out, line) {
			t.Fatalf("--force said:\n%s\nwant a line %q", out, line)
		}
	}
	if strings.Contains(out, "(updated") {
		t.Fatalf("--force still says (updated NAME):\n%s", out)
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

// The target resolves as documented: --dir alone is DIR/skills; --target
// claude is $CLAUDE_CONFIG_DIR's skills when it is set and the home's
// .claude's when not; --target agents is the home's .agents/skills
// whatever $CLAUDE_CONFIG_DIR says; --dir beside --target, and a word that
// is neither, are refused by their sentences, exit 1. Install and ls
// answer the same directory for each, with the flags in either order.
func TestTheTargetResolvesAsDocumented(t *testing.T) {
	home := aHome(t)
	configDir := t.TempDir()
	flagDir := t.TempDir()
	dirOf := func(t *testing.T, args ...string) (string, string) {
		t.Helper()
		var ls skillLsJSON
		out, err := runSkill(t, append([]string{"skill", "ls", "--json"}, args...)...)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal([]byte(out), &ls); err != nil {
			t.Fatal(err)
		}
		var install skillInstallJSON
		out, err = runSkill(t, append(append([]string{"skill", "install"}, args...), "--json")...)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal([]byte(out), &install); err != nil {
			t.Fatal(err)
		}
		if install.Dir != ls.Dir || install.Target != ls.Target {
			t.Fatalf("%v: install says %s %s and ls %s %s", args, install.Target, install.Dir, ls.Target, ls.Dir)
		}
		return ls.Target, ls.Dir
	}
	for _, tc := range []struct {
		name, config, target, dir string
		args                      []string
	}{
		{"--dir alone", "", targetDir, filepath.Join(flagDir, "skills"), []string{"--dir", flagDir}},
		{"--dir under CLAUDE_CONFIG_DIR", configDir, targetDir, filepath.Join(flagDir, "skills"), []string{"--dir", flagDir}},
		{"claude, nothing set", "", targetClaude, filepath.Join(home, ".claude", "skills"), []string{"--target", "claude"}},
		{"claude under CLAUDE_CONFIG_DIR", configDir, targetClaude, filepath.Join(configDir, "skills"), []string{"--target", "claude"}},
		{"agents under CLAUDE_CONFIG_DIR", configDir, targetAgents, filepath.Join(home, ".agents", "skills"), []string{"--target", "agents"}},
		{"agents, nothing set", "", targetAgents, filepath.Join(home, ".agents", "skills"), []string{"--target", "agents"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("CLAUDE_CONFIG_DIR", tc.config)
			if target, dir := dirOf(t, tc.args...); target != tc.target || dir != tc.dir {
				t.Fatalf("%v resolved to %s %s, want %s %s", tc.args, target, dir, tc.target, tc.dir)
			}
		})
	}
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--dir", flagDir, "--target", "claude"}, "--dir and --target name two places; give one"},
		{[]string{"--target", "agents", "--dir", flagDir}, "--dir and --target name two places; give one"},
		{[]string{"--target", "codex"}, `unknown --target "codex"; claude or agents`},
		{[]string{"--target", "Claude"}, `unknown --target "Claude"; claude or agents`},
	} {
		for _, sub := range []string{"install", "ls"} {
			_, err := runSkill(t, append([]string{"skill", sub}, tc.args...)...)
			var e *exitError
			if !errors.As(err, &e) || e.code != exitUsage || err.Error() != tc.want {
				t.Errorf("skill %s %v: %v, want exit %d %q", sub, tc.args, err, exitUsage, tc.want)
			}
		}
	}
	for _, d := range []string{filepath.Join(home, ".claude", "skills", "auu-connect"), filepath.Join(home, ".agents", "skills", "auu-connect")} {
		if _, err := os.Stat(d); err != nil {
			t.Errorf("%s was not written by the installs above: %v", d, err)
		}
	}
}

// With no target and no terminal to ask at, install and ls refuse, exit 1,
// in the sentence that names the command for each target with the
// directory each would use and the --dir form, and write nothing under
// either; --json refuses the same at a terminal or without one, saying
// that it does not ask, since its reader is a program and the prompt is
// for a person.
func TestNoTargetWithoutATerminalRefusesAndNamesTheCommands(t *testing.T) {
	const noTerminal, noAsking = "there is no terminal to ask at", "--json does not ask"
	for _, tc := range []struct {
		name     string
		terminal bool
		args     []string
		command  string
		why      string
	}{
		{"install through a pipe", false, []string{"skill", "install"}, "skill install", noTerminal},
		{"install --json at a terminal", true, []string{"skill", "install", "--json"}, "skill install", noAsking},
		{"install --json through a pipe", false, []string{"skill", "install", "--json"}, "skill install", noAsking},
		{"install --force through a pipe", false, []string{"skill", "install", "--force"}, "skill install", noTerminal},
		{"ls through a pipe", false, []string{"skill", "ls"}, "skill ls", noTerminal},
		{"ls --json at a terminal", true, []string{"skill", "ls", "--json"}, "skill ls", noAsking},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := aHome(t)
			standTerminal(t, tc.terminal)
			answerWith(t, "1\n")
			claude := filepath.Join(home, ".claude", "skills")
			agents := filepath.Join(home, ".agents", "skills")
			out, err := runSkill(t, tc.args...)
			want := "where the skills go was not said, and " + tc.why + "; run one of:\n" +
				"  auu " + tc.command + " --target claude    # Claude Code reads " + claude + "\n" +
				"  auu " + tc.command + " --target agents    # Codex reads " + agents + "\n" +
				"or give the base directory with --dir DIR (the skills go in DIR/skills)"
			var e *exitError
			if !errors.As(err, &e) || e.code != exitUsage || err.Error() != want {
				t.Fatalf("%v: %v\nwant exit %d:\n%s", tc.args, err, exitUsage, want)
			}
			if out != "" {
				t.Fatalf("%v printed %q before refusing", tc.args, out)
			}
			for _, d := range []string{filepath.Join(home, ".claude"), filepath.Join(home, ".agents")} {
				if _, err := os.Stat(d); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("%s exists after a refusal: %v", d, err)
				}
			}
		})
	}
}

// At a terminal with no target, install asks once and takes 1, 2, claude
// or agents, a last line with no newline among them, installing under
// that target alone; anything else, an empty line or end of file is no
// choice, refused by its sentence, exit 1, with nothing written (D152).
func TestTheTargetIsAskedAtATerminal(t *testing.T) {
	for _, tc := range []struct {
		answer, target string
	}{
		{"2\n", targetAgents},
		{"claude\n", targetClaude},
		{"1\n", targetClaude},
		{"  AGENTS  \n", targetAgents},
		{"2", targetAgents},
		{"x\n", ""},
		{"\n", ""},
		{"", ""},
		{"3\n", ""},
	} {
		t.Run(strconv.Quote(tc.answer), func(t *testing.T) {
			home := aHome(t)
			standTerminal(t, true)
			answerWith(t, tc.answer)
			claude := filepath.Join(home, ".claude", "skills")
			agents := filepath.Join(home, ".agents", "skills")
			out, err := runSkill(t, "skill", "install")
			prompt := "Where should the skills go?\n" +
				"  1  claude   " + claude + "   read by Claude Code\n" +
				"  2  agents   " + agents + "   read by Codex, and by other agents that read ~/.agents\n" +
				"Target [1/2]: "
			if !strings.HasPrefix(out, prompt) || strings.Count(out, "Where should the skills go?") != 1 {
				t.Fatalf("the prompt:\n%s\nwant it once, at the start:\n%s", out, prompt)
			}
			if tc.target == "" {
				var e *exitError
				if !errors.As(err, &e) || e.code != exitUsage || err.Error() != "no target chosen; nothing installed" {
					t.Fatalf("answer %q: %v, want exit %d and D152's sentence", tc.answer, err, exitUsage)
				}
				for _, d := range []string{filepath.Join(home, ".claude"), filepath.Join(home, ".agents")} {
					if _, err := os.Stat(d); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("%s exists after no choice: %v", d, err)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("answer %q: %v\n%s", tc.answer, err, out)
			}
			want, other := claude, agents
			if tc.target == targetAgents {
				want, other = agents, claude
			}
			if _, err := os.Stat(filepath.Join(want, "auu-connect", "SKILL.md")); err != nil {
				t.Fatalf("answer %q: nothing under %s: %v", tc.answer, want, err)
			}
			if _, err := os.Stat(filepath.Dir(other)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("answer %q wrote under %s too", tc.answer, other)
			}
			if !strings.Contains(out, "installed auu-connect, auu-setup and auu-relay in "+want) {
				t.Fatalf("answer %q: install said:\n%s", tc.answer, out)
			}
		})
	}
}

// An install says, for each target and for --dir, its first line naming
// the directory, whom it is for and the version, a line per file in its
// state, and the last line for that target; --json carries the target,
// the directory, the version and every file.
func TestAnInstallReportsEveryFileAndTheTarget(t *testing.T) {
	home := aHome(t)
	flagDir := t.TempDir()
	const seeThemAgents = "start a new Codex session for it to see them; an agent that reads ~/.agents/skills sees them the same way"
	for _, tc := range []struct {
		args             []string
		dir, forWhom     string
		last, jsonTarget string
	}{
		{[]string{"--target", "claude"}, filepath.Join(home, ".claude", "skills"), " for Claude Code", seeThemClaude, targetClaude},
		{[]string{"--target", "agents"}, filepath.Join(home, ".agents", "skills"), " for Codex and other agents that read ~/.agents", seeThemAgents, targetAgents},
		{[]string{"--dir", flagDir}, filepath.Join(flagDir, "skills"), ", given by --dir", seeThemClaude, targetDir},
	} {
		out, err := runSkill(t, append([]string{"skill", "install"}, tc.args...)...)
		if err != nil {
			t.Fatal(err)
		}
		if want := installLines("installed", tc.dir, tc.forWhom, "written", tc.last); out != want {
			t.Fatalf("%v said:\n%s\nwant:\n%s", tc.args, out, want)
		}
		out, err = runSkill(t, append([]string{"skill", "ls"}, tc.args...)...)
		if err != nil {
			t.Fatal(err)
		}
		if first := tc.dir + tc.forWhom + " " + builtAs() + "\n"; !strings.HasPrefix(out, first) {
			t.Fatalf("ls %v said:\n%s\nwant it to begin %q", tc.args, out, first)
		}
		for _, sub := range []string{"install", "ls"} {
			out, err = runSkill(t, append([]string{"skill", sub, "--json"}, tc.args...)...)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal([]byte(out), &fields); err != nil {
				t.Fatal(err)
			}
			for _, k := range []string{"target", "dir", "version", "skills"} {
				if _, ok := fields[k]; !ok {
					t.Fatalf("%s --json %v has no %q: %s", sub, tc.args, k, out)
				}
			}
			if !strings.HasPrefix(string(fields["skills"]), "[") {
				t.Fatalf("%s --json %v: skills is not a list: %s", sub, tc.args, fields["skills"])
			}
		}
		out, _ = runSkill(t, append([]string{"skill", "install", "--json"}, tc.args...)...)
		var report skillInstallJSON
		json.Unmarshal([]byte(out), &report)
		if report.Target != tc.jsonTarget || report.Dir != tc.dir || report.Version != buildinfo.Version() || len(report.Skills) != 6 {
			t.Fatalf("install --json %v: %+v", tc.args, report)
		}
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
	if first := skills + ", given by --dir " + builtAs() + "\n"; !strings.HasPrefix(out, first) {
		t.Fatalf("ls before an install:\n%s\nwant it to begin %q", out, first)
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
