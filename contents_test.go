package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Each guide and the README open with a list of their headings, between
// two comments, and the list is what the headings make it. A heading
// renamed, added or moved without its line in the list would leave a
// reader a stale map of the file; this makes that loud. The anchors the
// list links to are the link test's to resolve.

const (
	contentsOpen  = "<!-- contents -->"
	contentsClose = "<!-- /contents -->"
)

// contentsDocs are the documents that carry a contents list: the README and
// the guides under docs/, not the release notes, which are short and read
// top to bottom.
func contentsDocs(t *testing.T) []string {
	t.Helper()
	docs, err := filepath.Glob(filepath.Join("docs", "*.md"))
	if err != nil {
		t.Fatal(err)
	}
	docs = append([]string{"README.md"}, docs...)
	if len(docs) < 2 {
		t.Fatalf("found %d documents for a contents list from %s; the test is not being run from the module root", len(docs), mustCwd())
	}
	return docs
}

// TestEveryDocumentsContentsMatchItsHeadings: the list between the two
// comments in each document is, byte for byte, the one its ## and ###
// headings make. AUU_WRITE_CONTENTS=1 writes the lists instead, before
// the first heading when a document has none yet.
func TestEveryDocumentsContentsMatchItsHeadings(t *testing.T) {
	write := os.Getenv("AUU_WRITE_CONTENTS") == "1"
	for _, doc := range contentsDocs(t) {
		data, err := os.ReadFile(doc)
		if err != nil {
			t.Fatal(err)
		}
		text := string(data)
		want, err := contentsOf(text)
		if err != nil {
			t.Errorf("%s: %v", doc, err)
			continue
		}
		opens, closes := strings.Count(text, contentsOpen), strings.Count(text, contentsClose)
		if opens > 1 || closes > 1 || opens != closes {
			t.Errorf("%s has %d %s and %d %s; want one of each, or none for AUU_WRITE_CONTENTS=1 to write", doc, opens, contentsOpen, closes, contentsClose)
			continue
		}
		start := strings.Index(text, contentsOpen+"\n")
		end := strings.Index(text, contentsClose+"\n")
		if opens == 1 && (start < 0 || end < start) {
			t.Errorf("%s: %s and %s are not two lines of their own, in that order", doc, contentsOpen, contentsClose)
			continue
		}
		if write {
			if start >= 0 {
				text = text[:start] + want + text[end+len(contentsClose)+1:]
			} else if text, err = withContents(text, want); err != nil {
				t.Errorf("%s: %v", doc, err)
				continue
			}
			if err := os.WriteFile(doc, []byte(text), 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if start < 0 || end < start {
			t.Errorf("%s has no contents list between %s and %s; run this test with AUU_WRITE_CONTENTS=1", doc, contentsOpen, contentsClose)
			continue
		}
		if first := firstHeadingAt(text); first < 0 || end > first {
			t.Errorf("%s: the contents list is not before the first heading below the title", doc)
			continue
		}
		got := text[start : end+len(contentsClose)+1]
		if got != want {
			t.Errorf("%s: the contents list is not what its headings make, first at %s; run this test with AUU_WRITE_CONTENTS=1", doc, firstDifference(got, want))
		}
	}
}

// docHeading is one heading outside fenced code: its level, its text as
// written and its anchor, a repeat numbered as GitHub numbers it.
type docHeading struct {
	level  int
	text   string
	anchor string
}

// headingsOf is every heading of a document in order. Every level counts
// toward a repeat's number, as on GitHub, so headingSlugs and this agree.
func headingsOf(text string) ([]docHeading, error) {
	var out []docHeading
	seen := map[string]int{}
	fenced := false
	scan := bufio.NewScanner(strings.NewReader(text))
	scan.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scan.Scan() {
		line := scan.Text()
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			fenced = !fenced
			continue
		}
		if fenced || !strings.HasPrefix(line, "#") {
			continue
		}
		body := strings.TrimLeft(line, "#")
		if body == "" || body[0] != ' ' {
			continue
		}
		h := docHeading{level: len(line) - len(body), text: strings.TrimSpace(body)}
		slug := slugOf(h.text)
		h.anchor = slug
		if n := seen[slug]; n > 0 {
			h.anchor = fmt.Sprintf("%s-%d", slug, n)
		}
		seen[slug]++
		out = append(out, h)
	}
	return out, scan.Err()
}

// contentsOf is the list a document's ## and ### headings make, with the
// two comments around it: each a link to its anchor under its text less
// any trailing punctuation, a ### indented under the ## before it.
func contentsOf(text string) (string, error) {
	headings, err := headingsOf(text)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString(contentsOpen + "\n")
	n := 0
	top := false
	for _, h := range headings {
		indent := ""
		switch {
		case h.level == 2:
			top = true
		case h.level == 3 && top:
			indent = "  "
		case h.level == 3:
		default:
			continue
		}
		fmt.Fprintf(&b, "%s- [%s](#%s)\n", indent, strings.TrimRight(h.text, ".:;,!?"), h.anchor)
		n++
	}
	if n == 0 {
		return "", fmt.Errorf("no ## or ### heading to list")
	}
	b.WriteString(contentsClose + "\n")
	return b.String(), nil
}

// firstHeadingAt is the offset of a document's first ## or ### heading
// below its title, outside fenced code, or -1 when it has none.
func firstHeadingAt(text string) int {
	fenced := false
	at := 0
	for i, line := range strings.SplitAfter(text, "\n") {
		start := at
		at += len(line)
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			fenced = !fenced
			continue
		}
		if fenced || i == 0 {
			continue
		}
		if strings.HasPrefix(line, "## ") || strings.HasPrefix(line, "### ") {
			return start
		}
	}
	return -1
}

// withContents puts the list before a document's first heading below its
// title, after the title and the lede, with a blank line either side.
func withContents(text, contents string) (string, error) {
	at := firstHeadingAt(text)
	if at < 0 {
		return "", fmt.Errorf("no heading below the title to put the contents before")
	}
	head := text[:at]
	if !strings.HasSuffix(head, "\n\n") {
		head += "\n"
	}
	return head + contents + "\n" + text[at:], nil
}

// firstDifference names the first line at which two lists part.
func firstDifference(got, want string) string {
	g, w := strings.Split(got, "\n"), strings.Split(want, "\n")
	for i := 0; i < len(g) || i < len(w); i++ {
		var gl, wl string
		if i < len(g) {
			gl = g[i]
		}
		if i < len(w) {
			wl = w[i]
		}
		if gl != wl {
			return fmt.Sprintf("line %d of the list: %q, want %q", i+1, gl, wl)
		}
	}
	return "the end"
}
