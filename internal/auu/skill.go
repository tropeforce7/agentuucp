package auu

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

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
	Dir    string          `json:"dir"`
	Skills []skillFileJSON `json:"skills"`
}

// skillLsJSON is 'skill ls --json'.
type skillLsJSON struct {
	Dir    string          `json:"dir"`
	Skills []skillFileJSON `json:"skills"`
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

// skillsDir is where the skills go: --dir, else $CLAUDE_CONFIG_DIR, else
// ~/.claude, which is the Makefile's rule in the same order. The result
// is absolute, so that a sentence and a --json can name it plainly.
func skillsDir(flag string) (string, error) {
	dir := strings.TrimSpace(flag)
	if dir == "" {
		dir = os.Getenv("CLAUDE_CONFIG_DIR")
	}
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
	dirFlag := fs.String("dir", "", "the Claude Code directory to install under; $CLAUDE_CONFIG_DIR or ~/.claude when not given")
	force := fs.Bool("force", false, "replace a file that differs from this binary's copy")
	asJSON := fs.Bool("json", false, "machine readable output")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) > 0 {
		return usageErrf("unexpected argument %q", positional[0])
	}
	dir, err := skillsDir(*dirFlag)
	if err != nil {
		return err
	}
	out := skillInstallJSON{Dir: dir}
	var kept, changed []string
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
				changed = append(changed, name)
			}
		}
	}
	if *asJSON {
		if err := printJSON(out); err != nil {
			return err
		}
	} else {
		printSkillInstall(dir, out.Skills, changed)
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

// printSkillInstall is the closing lines as a person reads them.
func printSkillInstall(dir string, files []skillFileJSON, changed []string) {
	if len(changed) == 0 {
		fmt.Printf("already installed: %s in %s\n", plainList(skill.Names()), dir)
		return
	}
	var notes []string
	seen := map[string]bool{}
	for _, f := range files {
		if f.State == skillUpdated && !seen[f.Name] {
			notes = append(notes, "(updated "+f.Name+")")
			seen[f.Name] = true
		}
	}
	line := fmt.Sprintf("installed %s in %s", plainList(skill.Names()), dir)
	if len(notes) > 0 {
		line += " " + strings.Join(notes, " ")
	}
	fmt.Println(line)
	fmt.Println("restart Claude Code, or start a new session, for it to see them")
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
	dirFlag := fs.String("dir", "", "the Claude Code directory to look under; $CLAUDE_CONFIG_DIR or ~/.claude when not given")
	asJSON := fs.Bool("json", false, "machine readable output")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) > 0 {
		return usageErrf("unexpected argument %q", positional[0])
	}
	dir, err := skillsDir(*dirFlag)
	if err != nil {
		return err
	}
	out := skillLsJSON{Dir: dir}
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
