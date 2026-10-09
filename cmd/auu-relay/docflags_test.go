package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/testutil"
)

// The documents tell an operator what to type, and a flag they name that the
// relay does not have is a relay that will not start. This holds every
// auu-relay form in the README, the guides and the release notes to the flag
// set registerFlags builds, and the flag table in docs/relay.md section 1 to
// that set both ways, so a flag renamed, removed or added fails here.

// relayDocuments is what an operator reads: the README, every guide under
// docs/ and every release note.
func relayDocuments(t *testing.T) []string {
	t.Helper()
	files := []string{filepath.Join("..", "..", "README.md")}
	for _, glob := range []string{"*.md", filepath.Join("releases", "*.md")} {
		matches, err := filepath.Glob(filepath.Join("..", "..", "docs", glob))
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, matches...)
	}
	sort.Strings(files)
	if len(files) < 10 {
		t.Fatalf("found %d documents, which cannot be right", len(files))
	}
	return files
}

// relayFlagSet is the flag set the relay parses its command line with.
func relayFlagSet() *flag.FlagSet {
	fs := flag.NewFlagSet("auu-relay", flag.ContinueOnError)
	registerFlags(fs)
	return fs
}

// relayForm is one auu-relay command a document names.
type relayForm struct {
	file string
	line int
	text string
}

// codeSpan is one `code span` on a line.
var codeSpan = regexp.MustCompile("`([^`\n]+)`")

// relayFormsIn reads every auu-relay form a document names: each line of a
// fenced block, a line ending in `\` joined to the next as the shell joins
// it, and every code span elsewhere, each cut into its commands by
// testutil.FormPieces. A command whose program is not auu-relay
// (journalctl -u auu-relay, go build -o auu-relay) is not a form.
func relayFormsIn(t *testing.T, path string) []relayForm {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var (
		out     []relayForm
		inFence bool
		joined  string
		start   int
	)
	for i, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			inFence = !inFence
			joined = ""
			continue
		}
		var texts []string
		at := i + 1
		if inFence {
			if c := strings.Index(line, "#"); c >= 0 {
				line = line[:c]
			}
			if joined == "" {
				start = i + 1
			}
			if trimmed := strings.TrimRight(line, " \t"); strings.HasSuffix(trimmed, `\`) {
				joined += strings.TrimSuffix(trimmed, `\`) + " "
				continue
			}
			texts = append(texts, joined+line)
			at = start
			joined = ""
		} else {
			for _, m := range codeSpan.FindAllStringSubmatch(line, -1) {
				texts = append(texts, m[1])
			}
		}
		for _, text := range texts {
			for _, piece := range testutil.FormPieces(text) {
				if fields := strings.Fields(piece); fields[0] == "auu-relay" {
					out = append(out, relayForm{file: path, line: at, text: piece})
				}
			}
		}
	}
	if inFence {
		t.Errorf("%s: a fenced block is never closed, so everything after it was read the wrong way round", path)
	}
	if joined != "" {
		t.Errorf("%s:%d: a line ends in \\ and nothing follows it in its block", path, start)
	}
	return out
}

// unknownFlags is every flag a form names that the set does not have, as a
// sentence each. A word that is not a flag (`auu-relay vX`) is passed over.
func unknownFlags(fs *flag.FlagSet, forms []relayForm) []string {
	var out []string
	for _, f := range forms {
		for _, word := range strings.Fields(f.text)[1:] {
			if !strings.HasPrefix(word, "-") || word == "-" {
				continue
			}
			name, _, _ := strings.Cut(strings.TrimLeft(word, "-"), "=")
			// The flag package answers -h and -help itself.
			if name == "h" || name == "help" || fs.Lookup(name) != nil {
				continue
			}
			out = append(out, fmt.Sprintf("%s:%d: %q names --%s, which auu-relay does not have", f.file, f.line, f.text, name))
		}
	}
	return out
}

// Every flag a document gives auu-relay is one it has.
func TestEveryDocumentRelayFlagExists(t *testing.T) {
	fs := relayFlagSet()
	forms, flags := 0, 0
	for _, path := range relayDocuments(t) {
		found := relayFormsIn(t, path)
		forms += len(found)
		for _, f := range found {
			for _, word := range strings.Fields(f.text)[1:] {
				if strings.HasPrefix(word, "-") {
					flags++
				}
			}
		}
		for _, problem := range unknownFlags(fs, found) {
			t.Errorf("%s; correct the form", problem)
		}
	}
	t.Logf("read %d auu-relay forms naming %d flags", forms, flags)
	// The count is of flags, not forms: the documents name auu-relay alone
	// often, and a reader that found those and no invocation would pass a
	// count of forms while checking nothing.
	if flags < 15 {
		t.Errorf("read %d flags from the documents' auu-relay forms, which cannot be right", flags)
	}
}

// A relay form is read behind a path, sudo and a continuation, and a line
// where auu-relay is not the program is not read at all.
func TestTheRelayFormReaderReadsWhatAnOperatorTypes(t *testing.T) {
	doc := filepath.Join(t.TempDir(), "planted.md")
	text := "Run `bin/auu-relay --listen :8080 --nosuchone` or `auu-relay vX (schema N)`.\n" +
		"```\n" +
		"sudo -u auu /usr/local/bin/auu-relay --config /etc/auu/relay.json \\\n" +
		"    --nosuchtwo=3 \\\n" +
		"    --db relay.db   # --nosuchnever\n" +
		"journalctl -u auu-relay -f\n" +
		"go build -o auu-relay ./cmd/auu-relay\n" +
		"ExecStart=/usr/local/bin/auu-relay --config /etc/auu/relay.json -nosuchthree\n" +
		"```\n"
	if err := os.WriteFile(doc, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	got := unknownFlags(relayFlagSet(), relayFormsIn(t, doc))
	want := []string{
		fmt.Sprintf("%s:1: %q names --nosuchone, which auu-relay does not have", doc, "auu-relay --listen :8080 --nosuchone"),
		fmt.Sprintf("%s:3: %q names --nosuchtwo, which auu-relay does not have", doc,
			"auu-relay --config /etc/auu/relay.json --nosuchtwo=3 --db relay.db"),
		fmt.Sprintf("%s:8: %q names --nosuchthree, which auu-relay does not have", doc,
			"auu-relay --config /etc/auu/relay.json -nosuchthree"),
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("the planted forms read as\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// tableRow is a row of the flag table: its first cell a flag in a code span.
var tableRow = regexp.MustCompile("^\\| `--([a-z0-9-]+)")

// flagTable reads the flags docs/relay.md's section 1 table names, by line,
// from the section's heading to its first subsection.
func flagTable(t *testing.T, path string) map[string]int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	rows := map[string]int{}
	in := false
	for i, line := range strings.Split(string(data), "\n") {
		switch {
		case strings.HasPrefix(line, "## 1. "):
			in = true
		case in && strings.HasPrefix(line, "#"):
			return rows
		case in:
			if m := tableRow.FindStringSubmatch(line); m != nil {
				if _, twice := rows[m[1]]; twice {
					t.Errorf("%s:%d: the table names --%s twice", path, i+1, m[1])
				}
				rows[m[1]] = i + 1
			}
		}
	}
	return rows
}

// tableProblems holds the table to the set both ways: every row a flag, and
// every flag a row.
func tableProblems(path string, rows map[string]int, fs *flag.FlagSet) []string {
	var out []string
	for name, line := range rows {
		if fs.Lookup(name) == nil {
			out = append(out, fmt.Sprintf("%s:%d: the flag table names --%s, which auu-relay does not have; remove the row", path, line, name))
		}
	}
	fs.VisitAll(func(f *flag.Flag) {
		if _, ok := rows[f.Name]; !ok {
			out = append(out, fmt.Sprintf("auu-relay has --%s and the flag table in %s has no row for it; add one", f.Name, path))
		}
	})
	sort.Strings(out)
	return out
}

// The flag table in docs/relay.md section 1 is the relay's flag set: every
// row a flag, every flag a row.
func TestTheRelayFlagTableMatchesTheFlagSet(t *testing.T) {
	path := filepath.Join("..", "..", "docs", "relay.md")
	rows := flagTable(t, path)
	if len(rows) < 20 {
		t.Fatalf("%s: read %d rows of the flag table, which cannot be right", path, len(rows))
	}
	for _, problem := range tableProblems(path, rows, relayFlagSet()) {
		t.Error(problem)
	}
}

// And the comparison fails both ways: a row with no flag, and a flag with no
// row.
func TestTheFlagTableComparisonFailsBothWays(t *testing.T) {
	fs := flag.NewFlagSet("planted", flag.ContinueOnError)
	fs.Bool("listen", false, "")
	fs.Bool("unlisted", false, "")
	got := tableProblems("relay.md", map[string]int{"listen": 3, "gone": 4}, fs)
	want := []string{
		"auu-relay has --unlisted and the flag table in relay.md has no row for it; add one",
		"relay.md:4: the flag table names --gone, which auu-relay does not have; remove the row",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
