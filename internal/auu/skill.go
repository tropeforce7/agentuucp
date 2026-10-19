package auu

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/tropeforce7/agentuucp/internal/buildinfo"
	"github.com/tropeforce7/agentuucp/skill"
)

// auu skill: the three Claude Code skills, carried in the binary and
// written out on request, so the copy on a machine is the one that matches
// the auu beside it. For nearly everyone the binary is all they have, and
// a checkout for three files is a source of trouble.

// The states an installed file, and a skill, can be in.
const (
	skillNew       = "new"       // written, there was none
	skillUpdated   = "updated"   // replaced under --force
	skillUnchanged = "unchanged" // already this binary's bytes
	skillKept      = "kept"      // differs and was left alone

	skillInstalled = "installed" // ls: both files this binary's
	skillDiffers   = "differs"   // ls: a file differs or is missing
	skillAbsent    = "absent"    // ls: neither file is there
)

// skillFileJSON is one installed file as --json reports it.
type skillFileJSON struct {
	Name  string `json:"name"`
	Path  string `json:"path"`
	State string `json:"state"`
}

// skillInstallJSON is 'skill install --json'.
type skillInstallJSON struct {
	Target  string          `json:"target"`
	Dir     string          `json:"dir"`
	Version string          `json:"version"`
	Skills  []skillFileJSON `json:"skills"`
}

// skillLsJSON is 'skill ls --json'.
type skillLsJSON struct {
	Target  string          `json:"target"`
	Dir     string          `json:"dir"`
	Version string          `json:"version"`
	Skills  []skillFileJSON `json:"skills"`
}

func cmdSkill(args []string) error {
	if len(args) == 0 {
		return usageErrf("usage: %s skill install|ls|show", prog)
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "install":
		return skillInstall(rest)
	case "ls":
		return skillLs(rest)
	case "show":
		return skillShow(rest)
	default:
		return usageErrf("unknown skill subcommand %q; install, ls or show", sub)
	}
}

// The targets a skills directory is resolved from. claude and agents are
// what --target names; dir is how --dir is reported.
const (
	targetClaude = "claude"
	targetAgents = "agents"
	targetDir    = "dir"
)

// skillTarget is where a skill command acts: the target it was resolved
// from and the skills directory, absolute.
type skillTarget struct {
	kind string
	dir  string
}

// resolveSkillsDir is the one rule install and ls resolve their
// directory by. --dir and --target together are refused, since each names
// a place and one would silently cancel the other (D147). --dir is
// DIR/skills; --target claude is $CLAUDE_CONFIG_DIR, else ~/.claude, then
// skills; --target agents is ~/.agents/skills, whatever $CLAUDE_CONFIG_DIR
// says. With neither the command asks at a terminal, and where it cannot
// ask — no terminal, or --json, whose reader is a program — it refuses
// naming the command for each target and the directory each would use,
// so whoever ran it, a person or their agent, has the next command whole.
// command is what the refusal names, "skill install" or "skill ls"; what
// is the word for what an unanswered prompt leaves undone; cannotAsk is
// why there is no asking, or empty when the command may ask.
func resolveSkillsDir(command, what, target, dir, cannotAsk string) (skillTarget, error) {
	target, dir = strings.TrimSpace(target), strings.TrimSpace(dir)
	switch {
	case dir != "" && target != "":
		return skillTarget{}, usageErrf("--dir and --target name two places; give one")
	case dir != "":
		abs, err := filepath.Abs(dir)
		if err != nil {
			return skillTarget{}, err
		}
		return skillTarget{kind: targetDir, dir: filepath.Join(abs, "skills")}, nil
	case target == targetClaude:
		d, err := claudeSkillsDir()
		return skillTarget{kind: targetClaude, dir: d}, err
	case target == targetAgents:
		d, err := agentsSkillsDir()
		return skillTarget{kind: targetAgents, dir: d}, err
	case target != "":
		return skillTarget{}, usageErrf("unknown --target %q; claude or agents", target)
	}
	claude, err := claudeSkillsDir()
	if err != nil {
		return skillTarget{}, err
	}
	agents, err := agentsSkillsDir()
	if err != nil {
		return skillTarget{}, err
	}
	if cannotAsk != "" {
		return skillTarget{}, usageErrf("where the skills go was not said, and %[5]s; run one of:\n"+
			"  %[1]s %[2]s --target claude    # Claude Code reads %[3]s\n"+
			"  %[1]s %[2]s --target agents    # Codex reads %[4]s\n"+
			"or give the base directory with --dir DIR (the skills go in DIR/skills)", prog, command, claude, agents, cannotAsk)
	}
	kind, err := askSkillTarget(claude, agents)
	if err != nil {
		return skillTarget{}, usageErrf("no target chosen; nothing %s", what)
	}
	if kind == targetClaude {
		return skillTarget{kind: targetClaude, dir: claude}, nil
	}
	return skillTarget{kind: targetAgents, dir: agents}, nil
}

// whyNotAsk is why a skill command may not ask for its target, in the
// words its refusal says, or empty when it may.
func whyNotAsk(asJSON bool) string {
	switch {
	case asJSON:
		return "--json does not ask"
	case !stdinIsTerminal():
		return "there is no terminal to ask at"
	}
	return ""
}

// askSkillTarget puts the one question to a person at a terminal, before
// anything is written. 1, 2, claude or agents is an answer; anything else,
// an empty line or end of file is none, and the command does nothing: the
// command must not guess where a person's skills go, and Enter is not a
// choice (D152). A last line with no newline before end of file is read
// as an answer, as confirm reads one.
func askSkillTarget(claude, agents string) (string, error) {
	w := max(len(claude), len(agents))
	fmt.Println("Where should the skills go?")
	fmt.Printf("  1  claude   %-*s   read by Claude Code\n", w, claude)
	fmt.Printf("  2  agents   %-*s   read by Codex, and by other agents that read ~/.agents\n", w, agents)
	fmt.Print("Target [1/2]: ")
	line, err := stdinLine()
	if err != nil && line == "" {
		fmt.Println()
		return "", errors.New("no answer")
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "1", targetClaude:
		return targetClaude, nil
	case "2", targetAgents:
		return targetAgents, nil
	}
	return "", errors.New("no answer")
}

// claudeSkillsDir is Claude Code's: $CLAUDE_CONFIG_DIR, else ~/.claude,
// then skills, which is the Makefile's rule in the same order. The result
// is absolute, so that a sentence and a --json can name it plainly.
func claudeSkillsDir() (string, error) {
	dir := os.Getenv("CLAUDE_CONFIG_DIR")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", usageErrf("no home directory to put the skills under (%v); pass --dir", err)
		}
		dir = filepath.Join(home, ".claude")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	return filepath.Join(abs, "skills"), nil
}

// agentsSkillsDir is ~/.agents/skills, which Codex reads, and other agents
// that read ~/.agents. $CLAUDE_CONFIG_DIR is Claude Code's alone and does
// not move it.
func agentsSkillsDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", usageErrf("no home directory to put the skills under (%v); pass --dir", err)
	}
	abs, err := filepath.Abs(home)
	if err != nil {
		return "", err
	}
	return filepath.Join(abs, ".agents", "skills"), nil
}

// forWhom is the words a first line says the directory is for.
func (t skillTarget) forWhom() string {
	switch t.kind {
	case targetClaude:
		return " for Claude Code"
	case targetAgents:
		return " for Codex and other agents that read ~/.agents"
	}
	return ", given by --dir"
}

// seeThem is the last line of an install that wrote something: what to
// do for the agent to see the skills.
func (t skillTarget) seeThem() string {
	if t.kind == targetAgents {
		return "start a new Codex session for it to see them; an agent that reads ~/.agents/skills sees them the same way"
	}
	return "restart Claude Code, or start a new session, for it to see them"
}

// builtAs is the version a first line names: "(auu v0.19.0)".
func builtAs() string { return "(" + prog + " " + buildinfo.Version() + ")" }

// skillPaths is what one skill is on disk: its SKILL.md and its own copy
// of the shared reference, since a skill directory has to stand alone.
func skillPaths(skillsDir, name string) (skillPath, refPath string) {
	dir := filepath.Join(skillsDir, name)
	return filepath.Join(dir, "SKILL.md"), filepath.Join(dir, skill.Reference)
}

// embedded is the bytes the binary carries for one skill's two files.
func embedded(name string) (skillMD, ref []byte, err error) {
	if skillMD, err = skill.Files.ReadFile(name + "/SKILL.md"); err != nil {
		return nil, nil, err
	}
	if ref, err = skill.Files.ReadFile(skill.Reference); err != nil {
		return nil, nil, err
	}
	return skillMD, ref, nil
}

// skillInstall writes the skills out. A file already there with the same
// bytes is left alone; one with different bytes — a person's own edit, or
// an older auu's copy — is left alone and named, unless --force replaces
// it. Nothing is overwritten in silence, and nothing that could be
// installed is withheld because one file was edited.
func skillInstall(args []string) error {
	fs := newFlagSet("skill install")
	targetFlag := fs.String("target", "", "claude, for Claude Code's skills directory, or agents, for ~/.agents/skills; asked at a terminal when neither this nor --dir is given")
	dirFlag := fs.String("dir", "", "the base directory to install under, the skills going in DIR/skills; in place of --target")
	force := fs.Bool("force", false, "replace a file that differs from this binary's copy")
	asJSON := fs.Bool("json", false, "machine readable output")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) > 0 {
		return usageErrf("unexpected argument %q", positional[0])
	}
	target, err := resolveSkillsDir("skill install", "installed", *targetFlag, *dirFlag, whyNotAsk(*asJSON))
	if err != nil {
		return err
	}
	dir := target.dir
	out := skillInstallJSON{Target: target.kind, Dir: dir, Version: buildinfo.Version(), Skills: []skillFileJSON{}}
	var kept []string
	written := false
	for _, name := range skill.Names() {
		skillMD, ref, err := embedded(name)
		if err != nil {
			return fmt.Errorf("the binary carries no %s skill: %v", name, err)
		}
		skillPath, refPath := skillPaths(dir, name)
		for _, f := range []struct {
			path string
			data []byte
		}{{skillPath, skillMD}, {refPath, ref}} {
			state, err := placeSkillFile(f.path, f.data, *force)
			if err != nil {
				return err
			}
			out.Skills = append(out.Skills, skillFileJSON{Name: name, Path: f.path, State: state})
			switch state {
			case skillKept:
				kept = append(kept, f.path)
			case skillNew, skillUpdated:
				written = true
			}
		}
	}
	if *asJSON {
		if err := printJSON(out); err != nil {
			return err
		}
	} else {
		printSkillInstall(target, out.Skills, written, len(kept) > 0)
	}
	if len(kept) > 0 {
		return &exitError{code: exitUsage, err: fmt.Errorf("%s from this binary's copy; kept. --force replaces %s",
			differsSentence(kept), itThem(len(kept)))}
	}
	return nil
}

// differsSentence names the kept files: "PATH differs" or "PATH and PATH
// differ".
func differsSentence(paths []string) string {
	if len(paths) == 1 {
		return paths[0] + " differs"
	}
	return plainList(paths) + " differ"
}

// printSkillInstall is the closing lines as a person reads them: a first
// line saying what was done where and for whom, a line for each file
// relative to the directory, and, when anything was written, what to do
// for the agent to see it. The first line is "installed" only when a file
// was written or replaced, "already installed" when every file was this
// binary's, and "not all installed" when nothing was written and a file
// was kept, since "installed" there would be a false word (D157).
func printSkillInstall(target skillTarget, files []skillFileJSON, written, kept bool) {
	first := "installed"
	switch {
	case written:
	case kept:
		first = "not all installed:"
	default:
		first = "already installed:"
	}
	fmt.Printf("%s %s in %s%s %s\n", first, plainList(skill.Names()), target.dir, target.forWhom(), builtAs())
	for _, f := range files {
		rel, err := filepath.Rel(target.dir, f.Path)
		if err != nil {
			rel = f.Path
		}
		fmt.Printf("  %s: %s\n", filepath.ToSlash(rel), fileWords[f.State])
	}
	if written {
		fmt.Println(target.seeThem())
	}
}

// fileWords is a file's state as a person's line says it.
var fileWords = map[string]string{
	skillNew:       "written",
	skillUpdated:   "replaced",
	skillUnchanged: "already current",
	skillKept:      "kept, differs from this binary's copy; --force replaces it",
}

// placeSkillFile puts one file where it goes and says what it did.
func placeSkillFile(path string, data []byte, force bool) (string, error) {
	have, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if err := writeSkillFile(path, data); err != nil {
			return "", err
		}
		return skillNew, nil
	case err != nil:
		return "", err
	case bytes.Equal(have, data):
		return skillUnchanged, nil
	case !force:
		return skillKept, nil
	}
	if err := writeSkillFile(path, data); err != nil {
		return "", err
	}
	return skillUpdated, nil
}

// writeSkillFile writes through a temporary file in the same directory and
// renames it into place, so a reader never sees half a file; 0644 and 0755,
// since a skill is not a secret and Claude Code reads it as the user.
func writeSkillFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".skill-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Chmod(name, 0o644); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		os.Remove(name)
		return err
	}
	return nil
}

// skillLs says, for each skill the binary carries, what the directory
// holds: this binary's copy, an older or edited one, or nothing.
func skillLs(args []string) error {
	fs := newFlagSet("skill ls")
	targetFlag := fs.String("target", "", "claude, for Claude Code's skills directory, or agents, for ~/.agents/skills; asked at a terminal when neither this nor --dir is given")
	dirFlag := fs.String("dir", "", "the base directory to look under, the skills being in DIR/skills; in place of --target")
	asJSON := fs.Bool("json", false, "machine readable output")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) > 0 {
		return usageErrf("unexpected argument %q", positional[0])
	}
	target, err := resolveSkillsDir("skill ls", "listed", *targetFlag, *dirFlag, whyNotAsk(*asJSON))
	if err != nil {
		return err
	}
	dir := target.dir
	out := skillLsJSON{Target: target.kind, Dir: dir, Version: buildinfo.Version(), Skills: []skillFileJSON{}}
	for _, name := range skill.Names() {
		skillMD, ref, err := embedded(name)
		if err != nil {
			return fmt.Errorf("the binary carries no %s skill: %v", name, err)
		}
		skillPath, refPath := skillPaths(dir, name)
		state, err := skillState(skillPath, skillMD, refPath, ref)
		if err != nil {
			return err
		}
		out.Skills = append(out.Skills, skillFileJSON{Name: name, Path: filepath.Dir(skillPath), State: state})
	}
	if *asJSON {
		return printJSON(out)
	}
	fmt.Printf("%s%s %s\n", dir, target.forWhom(), builtAs())
	for _, s := range out.Skills {
		fmt.Printf("%-12s %-10s %s\n", s.Name, s.State, s.Path)
	}
	return nil
}

// skillState is one skill's state on disk against the binary's bytes.
func skillState(skillPath string, skillMD []byte, refPath string, ref []byte) (string, error) {
	present, equal := 0, 0
	for _, f := range []struct {
		path string
		data []byte
	}{{skillPath, skillMD}, {refPath, ref}} {
		have, err := os.ReadFile(f.path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return "", err
		}
		present++
		if bytes.Equal(have, f.data) {
			equal++
		}
	}
	switch {
	case present == 0:
		return skillAbsent, nil
	case equal == 2:
		return skillInstalled, nil
	default:
		return skillDiffers, nil
	}
}

// skillShow prints one skill's SKILL.md, or the reference, from the binary.
func skillShow(args []string) error {
	fs := newFlagSet("skill show")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		return usageErrf("usage: %s skill show %s|reference", prog, strings.Join(skill.Names(), "|"))
	}
	name := positional[0]
	// The messaging skill's old name is answered with its new one rather
	// than kept as an alias: an alias is a path nobody tests (D148).
	if name == "connect" {
		return usageErrf("the connect skill is now auu-connect: %s skill show auu-connect", prog)
	}
	var data []byte
	if name == "reference" {
		data, err = skill.Files.ReadFile(skill.Reference)
	} else {
		known := false
		for _, n := range skill.Names() {
			if n == name {
				known = true
			}
		}
		if !known {
			return usageErrf("no skill %q; the binary carries %s, and reference", name, plainList(skill.Names()))
		}
		data, err = skill.Files.ReadFile(name + "/SKILL.md")
	}
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(data)
	return err
}
