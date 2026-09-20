package auu

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The skills name commands, and a skill that names a command which does not
// exist sends an agent to do something impossible. This holds every form in
// every SKILL.md and in the shared reference to what the three programs
// actually dispatch, and the reference's command list to what they
// dispatch, so a command renamed, removed or added fails here rather than
// misleading an agent.

// skillDir is the repository's skill directory, from this package.
const skillDir = "../../skill"

// backticked is one `code span`; a form is the first line inside a fenced
// block or a span, so a multi-line span is read line by line.
var backticked = regexp.MustCompile("`([^`\n]+)`")

// fence marks a fenced block's delimiter.
const fence = "```"

// commandLine is a line that names a command: it begins with one of the
// three program names and a space.
func commandLine(text string) (prog, sub string, ok bool) {
	fields := strings.Fields(strings.TrimSpace(text))
	if len(fields) < 2 {
		return "", "", false
	}
	switch fields[0] {
	case "auu", "auu-admin", "auu-ca":
	default:
		return "", "", false
	}
	// The word after the program, unless it is a flag, which means the
	// program itself was the command (auu --help and the like), or a
	// placeholder for one, which is written in capitals as the usage
	// block writes every placeholder.
	if strings.HasPrefix(fields[1], "-") || fields[1] == strings.ToUpper(fields[1]) {
		return fields[0], "", true
	}
	return fields[0], fields[1], true
}

// skillFiles is every document the skills are made of: each SKILL.md and
// the shared reference.
func skillFiles(t *testing.T) []string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(skillDir, "*", "SKILL.md"))
	if err != nil {
		t.Fatal(err)
	}
	ref := filepath.Join(skillDir, "reference.md")
	if _, err := os.Stat(ref); err == nil {
		matches = append(matches, ref)
	}
	sort.Strings(matches)
	if len(matches) == 0 {
		t.Fatalf("no skills under %s", skillDir)
	}
	return matches
}

// formsIn reads every command form a document names, by file and line: the
// lines of its fenced blocks, and every code span elsewhere.
type form struct {
	file string
	line int
	prog string
	sub  string
	text string
}

func formsIn(t *testing.T, path string) []form {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var (
		out     []form
		inFence bool
	)
	for i, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), fence) {
			inFence = !inFence
			continue
		}
		texts := []string{}
		if inFence {
			// A fenced line is a command, less anything after a comment.
			text := line
			if i := strings.Index(text, "#"); i >= 0 {
				text = text[:i]
			}
			texts = append(texts, text)
		} else {
			for _, m := range backticked.FindAllStringSubmatch(line, -1) {
				texts = append(texts, m[1])
			}
		}
		for _, text := range texts {
			prog, sub, ok := commandLine(text)
			if !ok {
				continue
			}
			out = append(out, form{file: path, line: i + 1, prog: prog, sub: sub, text: strings.TrimSpace(text)})
		}
	}
	return out
}

// dispatched is what each program's dispatch knows, read from the source of
// the switch that runs it — the authority, where the usage text is only a
// description of it. Each entry is one case line's labels: "enrol" and
// "enroll" are one command under two spellings, and documenting either
// documents it.
func dispatched(t *testing.T) map[string][][]string {
	t.Helper()
	known := map[string][][]string{
		"auu":       commandsOf(t, "main.go", "func dispatch(args []string) error {"),
		"auu-admin": commandsOf(t, filepath.Join("..", "..", "cmd", "auu-admin", "main.go"), "func run(args []string) error {"),
		"auu-ca":    commandsOf(t, filepath.Join("..", "..", "cmd", "auu-ca", "main.go"), "func dispatch(cmd string, args []string) error {"),
	}
	for prog, groups := range known {
		if len(groups) < 4 {
			t.Fatalf("%s: found %d commands in its dispatch, which cannot be right", prog, len(groups))
		}
	}
	return known
}

// dispatches reports whether a program dispatches a word.
func dispatches(groups [][]string, word string) bool {
	for _, group := range groups {
		for _, name := range group {
			if name == word {
				return true
			}
		}
	}
	return false
}

// caseValue takes the strings from one `case "a", "b":` line.
var caseValue = regexp.MustCompile(`"([a-z_-]+)"`)

// commandsOf reads the case labels of the switch that follows a function's
// opening line, one group per case line. A label that is a flag, or the
// help word every program answers to, is not a command.
func commandsOf(t *testing.T, path, after string) [][]string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	i := strings.Index(text, after)
	if i < 0 {
		t.Fatalf("%s: no %q", path, after)
	}
	var out [][]string
	for _, line := range strings.Split(text[i:], "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "}" && len(out) > 0 {
			break
		}
		if !strings.HasPrefix(trimmed, "case ") {
			continue
		}
		var group []string
		for _, m := range caseValue.FindAllStringSubmatch(trimmed, -1) {
			if strings.HasPrefix(m[1], "-") || m[1] == "help" {
				continue
			}
			group = append(group, m[1])
		}
		if len(group) > 0 {
			out = append(out, group)
		}
	}
	return out
}

// Every form a skill or the reference names is one the program dispatches.
func TestEverySkillCommandExists(t *testing.T) {
	known := dispatched(t)
	for _, path := range skillFiles(t) {
		for _, f := range formsIn(t, path) {
			groups, ok := known[f.prog]
			if !ok {
				t.Errorf("%s:%d: %q names %s, which is not one of the three programs", f.file, f.line, f.text, f.prog)
				continue
			}
			if f.sub == "" {
				continue // the program with a flag or a placeholder alone
			}
			if !dispatches(groups, f.sub) {
				t.Errorf("%s:%d: %q names %s %s, which %s does not dispatch",
					f.file, f.line, f.text, f.prog, f.sub, f.prog)
			}
		}
	}
}

// undocumented is what the reference deliberately leaves out, each with the
// reason a reader would ask for.
var undocumented = map[string]string{
	"auu completion":    "a shell script for a person's terminal; an agent never needs it",
	"auu agent":         "the agent is the user's own, started by their unlock; the reference says unlock and lock instead",
	"auu __complete":    "the completion helper the shell calls, not a command a person or an agent runs",
	"auu-ca relay":      "issuing a bundle by hand, which the kit does; auu-relay's skill sends the operator to auu-ca kit",
	"auu-ca passphrase": "changing the authority's passphrase, which the operator does at a prompt in their own terminal",
}

// And every command the programs dispatch is in the reference, unless it is
// named above as deliberately left out: a command that exists and is
// documented nowhere is one an agent will never use.
func TestEveryCommandIsInTheReference(t *testing.T) {
	ref := filepath.Join(skillDir, "reference.md")
	named := map[string]bool{}
	for _, f := range formsIn(t, ref) {
		named[f.prog+" "+f.sub] = true
	}
	known := dispatched(t)
	for prog, groups := range known {
		for _, group := range groups {
			covered := false
			for _, cmd := range group {
				if named[prog+" "+cmd] || undocumented[prog+" "+cmd] != "" {
					covered = true
				}
			}
			if !covered {
				t.Errorf("%s: %q is dispatched but not in the reference; document it, or name it in undocumented with the reason",
					ref, prog+" "+group[0])
			}
		}
	}
	// And nothing is excused that no longer exists.
	for key := range undocumented {
		prog, cmd, _ := strings.Cut(key, " ")
		if !dispatches(known[prog], cmd) {
			t.Errorf("undocumented names %q, which %s no longer dispatches", key, prog)
		}
	}
}

// Every exit code a skill or the reference names means what the program
// says it means.
func TestTheExitCodeTablesMatchTheConstants(t *testing.T) {
	want := map[int]string{
		exitUsage:     "usage",
		exitTransport: "relay",
		exitTimeout:   "timed out",
		exitLocked:    "locked",
		exitDamaged:   "damaged",
	}
	// The row of a table: | 4 | … | … |
	row := regexp.MustCompile(`^\|\s*([0-9])\s*\|(.*)$`)
	found := map[string]map[int]bool{}
	for _, path := range skillFiles(t) {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(data), "\n") {
			m := row.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			code, err := strconv.Atoi(m[1])
			if err != nil {
				continue
			}
			if found[path] == nil {
				found[path] = map[int]bool{}
			}
			found[path][code] = true
			if code == 0 {
				continue
			}
			word, ok := want[code]
			if !ok {
				t.Errorf("%s:%d: exit %d is not one this program returns", path, i+1, code)
				continue
			}
			if !strings.Contains(strings.ToLower(m[2]), word) {
				t.Errorf("%s:%d: exit %d is described as %q, which does not say %q",
					path, i+1, code, strings.TrimSpace(m[2]), word)
			}
		}
	}
	// A table that lists some codes lists them all: a skill that stops at
	// 4 leaves an agent with nothing to do at 5.
	for path, codes := range found {
		if len(codes) < 2 {
			continue // not a table of codes
		}
		for code := range want {
			if !codes[code] {
				t.Errorf("%s: its exit-code table has no row for %d", path, code)
			}
		}
	}
}

// The reference is one file, read by every skill, so each skill sends the
// agent to it by the same words and the file is there to read.
func TestEverySkillPointsAtTheReference(t *testing.T) {
	// The words the plan gives, with or without the backticks a skill puts
	// round the file name.
	pointers := []string{
		"reference.md in this skill's directory",
		"`reference.md` in this skill's directory",
	}
	for _, path := range skillFiles(t) {
		if filepath.Base(path) == "reference.md" {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, pointer := range pointers {
			if strings.Contains(string(data), pointer) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s does not send the agent to %q", path, pointers[0])
		}
	}
	if _, err := os.Stat(filepath.Join(skillDir, "reference.md")); err != nil {
		t.Fatalf("the reference is not there: %v", err)
	}
}

// Every skill has the frontmatter the loader reads: a name that is its
// directory's, and a description saying who it is for.
func TestEverySkillHasItsFrontmatter(t *testing.T) {
	for _, path := range skillFiles(t) {
		if filepath.Base(path) == "reference.md" {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		text := string(data)
		if !strings.HasPrefix(text, "---\n") {
			t.Errorf("%s does not begin with frontmatter", path)
			continue
		}
		end := strings.Index(text[4:], "\n---\n")
		if end < 0 {
			t.Errorf("%s: the frontmatter does not end", path)
			continue
		}
		head := text[4 : 4+end]
		want := filepath.Base(filepath.Dir(path))
		if !strings.Contains(head, "name: "+want+"\n") {
			t.Errorf("%s: the frontmatter does not name it %q:\n%s", path, want, head)
		}
		desc := ""
		for _, line := range strings.Split(head, "\n") {
			if strings.HasPrefix(line, "description: ") {
				desc = strings.TrimPrefix(line, "description: ")
			}
		}
		if len(desc) < 40 {
			t.Errorf("%s: the description is %q, which says too little for the loader to choose it", path, desc)
		}
		if !strings.Contains(desc, "Use when") {
			t.Errorf("%s: the description does not say when to use it: %q", path, desc)
		}
	}
}
