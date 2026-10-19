package auu

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/tropeforce7/agentuucp/internal/buildinfo"
	"github.com/tropeforce7/agentuucp/internal/regular"
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

	legacyOurs    = "legacy"   // a connect directory an earlier auu wrote
	legacyNotOurs = "not-ours" // a connect directory auu did not write as it is
)

// legacyName is the messaging skill's name before v0.19.0, the directory
// an install over an earlier one leaves beside auu-connect.
const legacyName = "connect"

// legacyAgainst is what a file in a connect directory differs from when
// it is no version an earlier auu wrote there.
const legacyAgainst = "any copy auu installed"

// legacyJSON is a connect directory as --json reports it.
type legacyJSON struct {
	Name  string `json:"name"`
	Path  string `json:"path"`
	State string `json:"state"`
}

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
	Legacy  []legacyJSON    `json:"legacy"`
}

// skillLsJSON is 'skill ls --json'.
type skillLsJSON struct {
	Target  string          `json:"target"`
	Dir     string          `json:"dir"`
	Version string          `json:"version"`
	Skills  []skillFileJSON `json:"skills"`
	Legacy  []legacyJSON    `json:"legacy"`
}

// skillRmJSON is 'skill rm --json --yes'.
type skillRmJSON struct {
	Target  string   `json:"target"`
	Dir     string   `json:"dir"`
	Name    string   `json:"name"`
	Removed []string `json:"removed"`
}

func cmdSkill(args []string) error {
	if len(args) == 0 {
		return usageErrf("usage: %s skill install|ls|rm|show", prog)
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "install":
		return skillInstall(rest)
	case "ls":
		return skillLs(rest)
	case "rm":
		return skillRm(rest)
	case "show":
		return skillShow(rest)
	default:
		return usageErrf("unknown skill subcommand %q; install, ls, rm or show", sub)
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

// resolveSkillsDir is the one rule install, ls and rm resolve their
// directory by. --dir and --target together are refused, since each names
// a place and one would silently cancel the other (D147). --dir is
// DIR/skills; --target claude is $CLAUDE_CONFIG_DIR, else ~/.claude, then
// skills; --target agents is ~/.agents/skills, whatever $CLAUDE_CONFIG_DIR
// says. With neither the command asks at a terminal, and where it cannot
// ask — no terminal, or --json, whose reader is a program — it refuses
// naming the command for each target and the directory each would use,
// so whoever ran it, a person or their agent, has the next command whole.
// command is what the refusal names, "skill install", "skill ls" or
// "skill rm NAME"; question is what the prompt asks; what is the word for
// what an unanswered prompt leaves undone; cannotAsk is why there is no
// asking, or empty when the command may ask.
func resolveSkillsDir(command, question, what, target, dir, cannotAsk string) (skillTarget, error) {
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
	kind, err := askSkillTarget(question, claude, agents)
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
func askSkillTarget(question, claude, agents string) (string, error) {
	w := max(len(claude), len(agents))
	fmt.Println(question)
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
	target, err := resolveSkillsDir("skill install", "Where should the skills go?", "installed", *targetFlag, *dirFlag, whyNotAsk(*asJSON))
	if err != nil {
		return err
	}
	dir := target.dir
	out := skillInstallJSON{Target: target.kind, Dir: dir, Version: buildinfo.Version(), Skills: []skillFileJSON{}, Legacy: []legacyJSON{}}
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
	if out.Legacy, err = legacyCopies(dir); err != nil {
		return err
	}
	if *asJSON {
		if err := printJSON(out); err != nil {
			return err
		}
	} else {
		printSkillInstall(target, out.Skills, out.Legacy, written, len(kept) > 0)
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
func printSkillInstall(target skillTarget, files []skillFileJSON, legacy []legacyJSON, written, kept bool) {
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
	for _, l := range legacy {
		fmt.Println(legacyLine(target, l))
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
	target, err := resolveSkillsDir("skill ls", "Which skills directory?", "listed", *targetFlag, *dirFlag, whyNotAsk(*asJSON))
	if err != nil {
		return err
	}
	dir := target.dir
	out := skillLsJSON{Target: target.kind, Dir: dir, Version: buildinfo.Version(), Skills: []skillFileJSON{}, Legacy: []legacyJSON{}}
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
	if out.Legacy, err = legacyCopies(dir); err != nil {
		return err
	}
	if *asJSON {
		return printJSON(out)
	}
	fmt.Printf("%s%s %s\n", dir, target.forWhom(), builtAs())
	for _, s := range out.Skills {
		fmt.Printf("%-12s %-10s %s\n", s.Name, s.State, s.Path)
	}
	for _, l := range out.Legacy {
		fmt.Printf("%-12s %-10s %s\n", l.Name, l.State, l.Path)
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

// legacyCopies is the connect directory under dir, if there is one, as a
// list for --json: legacy when it holds exactly the two files an earlier
// auu wrote, not-ours when it is anything else, which nothing here touches
// (D149). A directory or a file in it that cannot be read is not ours
// either: what it is cannot be told, and neither install nor ls fails
// for it.
func legacyCopies(dir string) ([]legacyJSON, error) {
	path := filepath.Join(dir, legacyName)
	fi, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return []legacyJSON{}, nil
	}
	state := legacyNotOurs
	if err == nil && fi.IsDir() && isLegacyConnect(path) {
		state = legacyOurs
	}
	return []legacyJSON{{Name: legacyName, Path: path, State: state}}, nil
}

// isLegacyConnect reports whether the directory at path holds exactly
// SKILL.md and reference.md, each a version an earlier auu wrote there.
func isLegacyConnect(path string) bool {
	files, bad, err := judgeSkillDir(path, legacyAgainst, skill.Legacy)
	return err == nil && bad == "" && len(files) == 2
}

// legacyLine is what an install says of a connect directory, with the
// command that removes one auu wrote, its target given, since rm without
// one asks or refuses.
func legacyLine(target skillTarget, l legacyJSON) string {
	if l.State == legacyOurs {
		return fmt.Sprintf("%s in %s is the old name of auu-connect, installed by an earlier auu: %s skill rm %s %s removes it",
			legacyName, target.dir, prog, legacyName, target.flags())
	}
	return fmt.Sprintf("%s in %s is not a copy auu installed, or was edited; left alone", legacyName, target.dir)
}

// flags is the target as the command line gives it, a --dir quoted for a
// shell when it holds anything but the plainest characters.
func (t skillTarget) flags() string {
	if t.kind == targetDir {
		return "--dir " + shellWord(filepath.Dir(t.dir))
	}
	return "--target " + t.kind
}

// shellWord is s as one word to a POSIX shell: as it is when every
// character is one no shell treats specially, else in single quotes, a
// quote in it closed, escaped and opened again.
func shellWord(s string) string {
	plain := s != ""
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("/._-:+,@%=", r) || r == filepath.Separator) {
			plain = false
			break
		}
	}
	if plain {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// judgeSkillDir reads a skill directory's entries against what auu writes
// there: each must be SKILL.md or reference.md, a regular file whose
// SHA-256 known accepts. It returns the files' names, or the first entry
// that is not one, with the sentence saying why, against is what a file
// that known refuses differs from. Nothing is read for its meaning; the
// files are only hashed.
func judgeSkillDir(path, against string, known func(file, digest string) bool) (files []string, bad string, err error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, "", err
	}
	for _, e := range entries {
		entry := filepath.Join(path, e.Name())
		if (e.Name() != "SKILL.md" && e.Name() != skill.Reference) || !e.Type().IsRegular() {
			return nil, fmt.Sprintf("%s is not a file auu installed; left alone", entry), nil
		}
		digest, err := fileDigest(entry)
		var mode *regular.ModeError
		if errors.As(err, &mode) {
			return nil, fmt.Sprintf("%s is not a file auu installed; left alone", entry), nil
		}
		if err != nil {
			return nil, "", err
		}
		if !known(e.Name(), digest) {
			return nil, fmt.Sprintf("%s differs from %s; left alone", entry, against), nil
		}
		files = append(files, e.Name())
	}
	return files, "", nil
}

// fileDigest is the SHA-256 of a regular file, in hex, read as it streams.
func fileDigest(path string) (string, error) {
	f, err := regular.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// skillRm removes one skill's directory, on request and only when every
// file in it is one auu wrote: for the three the binary carries, this
// binary's bytes, and for connect, a version an earlier auu installed. A
// copy from an older auu of one of the three differs, and install --force
// then rm is the way (D150, D156). The name is held to the set before it
// is joined to anything. It says what will go and asks; --yes skips the
// asking, and --json, which cannot answer it, needs --yes.
func skillRm(args []string) error {
	fs := newFlagSet("skill rm")
	targetFlag := fs.String("target", "", "claude, for Claude Code's skills directory, or agents, for ~/.agents/skills; asked at a terminal when neither this nor --dir is given")
	dirFlag := fs.String("dir", "", "the base directory the skills are under, in DIR/skills; in place of --target")
	yes := fs.Bool("yes", false, "remove it without asking")
	asJSON := fs.Bool("json", false, "machine readable output; needs --yes")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	removable := append(skill.Names(), legacyName)
	if len(positional) != 1 {
		return usageErrf("usage: %s skill rm %s [--target claude|agents | --dir DIR] [--yes] [--json]", prog, strings.Join(removable, "|"))
	}
	name := positional[0]
	if !slices.Contains(removable, name) {
		return usageErrf("unknown skill %q; %s or %s", name, strings.Join(skill.Names(), ", "), legacyName)
	}
	if *asJSON && !*yes {
		return usageErrf("--json cannot answer the prompt; pass --yes")
	}
	target, err := resolveSkillsDir("skill rm "+name, "Which skills directory?", "removed", *targetFlag, *dirFlag, whyNotAsk(*asJSON))
	if err != nil {
		return err
	}
	path := filepath.Join(target.dir, name)
	fi, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return usageErrf("%s is not installed in %s", name, target.dir)
	}
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return usageErrf("%s is not a directory auu installed; left alone", path)
	}
	known, against := skill.Legacy, legacyAgainst
	if name != legacyName {
		known = func(file, digest string) bool { return digest == embeddedDigest(name, file) }
		against = "this binary's copy"
	}
	files, bad, err := judgeSkillDir(path, against, known)
	if err != nil {
		return err
	}
	if bad != "" {
		return usageErrf("%s", bad)
	}
	// connect goes only as install and ls call it legacy, the pair whole:
	// an empty or half directory is not one auu left as it is.
	if name == legacyName && len(files) != 2 {
		return usageErrf("%s is not a copy auu installed; left alone", path)
	}
	if !*asJSON {
		fmt.Printf("removing %s: %s\n", path, strings.Join(files, ", "))
	}
	if !*yes && !confirm("Remove it?") {
		fmt.Fprintln(os.Stderr, "nothing was removed")
		return &exitError{code: exitUsage, err: errors.New("cancelled")}
	}
	out := skillRmJSON{Target: target.kind, Dir: target.dir, Name: name, Removed: []string{}}
	for _, f := range files {
		p := filepath.Join(path, f)
		if err := os.Remove(p); err != nil {
			return err
		}
		out.Removed = append(out.Removed, p)
	}
	// The directory itself, which is refused if anything appeared in it
	// since it was read: that is not ours to remove.
	if err := os.Remove(path); err != nil {
		return err
	}
	out.Removed = append(out.Removed, path)
	if *asJSON {
		return printJSON(out)
	}
	fmt.Printf("removed %s\n", path)
	return nil
}

// embeddedDigest is the SHA-256, in hex, of one of the files this binary
// writes for a skill, or empty for a file it does not.
func embeddedDigest(name, file string) string {
	skillMD, ref, err := embedded(name)
	if err != nil {
		return ""
	}
	var data []byte
	switch file {
	case "SKILL.md":
		data = skillMD
	case skill.Reference:
		data = ref
	default:
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
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
