package main

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"unicode"
)

// Every Markdown document in the tree is read, and every relative link in
// it — to a file, to a heading in this file, or to a heading in another —
// must resolve. The README was broken up into documents under docs/ once,
// and a link that named a section by number or by slug would have gone
// quietly wrong with it; this is what makes that loud. Fenced code and
// inline code are not read for links, and a link with a scheme is
// somebody else's to keep.

// mdLink is a Markdown link or image: [text](target), with an optional
// title after the target.
var mdLink = regexp.MustCompile(`!?\[[^\]]*\]\(([^)\s]+)(?:\s+"[^"]*")?\)`)

// mdRefDef is a reference-style definition: [name]: target.
var mdRefDef = regexp.MustCompile(`^\s*\[[^\]]+\]:\s*(\S+)`)

// inlineCode is a code span on one line, which is not read for links.
var inlineCode = regexp.MustCompile("`[^`]*`")

// skipDirs are the directories that are not the documentation: the
// repository's own, build output, and the reviewers' notes when present.
var skipDirs = map[string]bool{".git": true, "bin": true, "dist": true, "reviews": true, "node_modules": true}

func TestEveryDocumentLinkResolves(t *testing.T) {
	var docs []string
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != "." && skipDirs[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(d.Name(), ".md") {
			docs = append(docs, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(docs)
	if len(docs) < 10 {
		t.Fatalf("only %d documents found from %s; the test is not being run from the module root", len(docs), mustCwd())
	}

	// The headings of every document, as slugs, before any link is
	// checked, since a link may point across files.
	slugs := map[string]map[string]bool{}
	for _, doc := range docs {
		s, err := headingSlugs(doc)
		if err != nil {
			t.Fatal(err)
		}
		slugs[doc] = s
	}

	var problems []string
	for _, doc := range docs {
		links, err := relativeLinks(doc)
		if err != nil {
			t.Fatal(err)
		}
		for _, l := range links {
			target, anchor, _ := strings.Cut(l.target, "#")
			file := doc
			if target != "" {
				file = filepath.Clean(filepath.Join(filepath.Dir(doc), target))
				if _, err := os.Stat(file); err != nil {
					problems = append(problems, fmt.Sprintf("%s:%d: %s: no such file %s", doc, l.line, l.target, file))
					continue
				}
			}
			if anchor == "" {
				continue
			}
			known, ok := slugs[file]
			if !ok {
				problems = append(problems, fmt.Sprintf("%s:%d: %s: %s is not a document, so it has no headings", doc, l.line, l.target, file))
				continue
			}
			if !known[anchor] {
				problems = append(problems, fmt.Sprintf("%s:%d: %s: no heading #%s in %s", doc, l.line, l.target, anchor, file))
			}
		}
	}
	for _, p := range problems {
		t.Error(p)
	}
	if len(problems) > 0 {
		t.Logf("checked %d documents", len(docs))
	}
}

// docLink is one link in a document, with the line it is on.
type docLink struct {
	line   int
	target string
}

// relativeLinks is every link in a document whose target is relative: no
// scheme, and not a bare anchor into nothing. Fenced code and inline code
// are skipped.
func relativeLinks(path string) ([]docLink, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []docLink
	fenced := false
	n := 0
	scan := bufio.NewScanner(f)
	scan.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scan.Scan() {
		n++
		line := scan.Text()
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			fenced = !fenced
			continue
		}
		if fenced {
			continue
		}
		line = inlineCode.ReplaceAllString(line, "")
		var targets []string
		for _, m := range mdLink.FindAllStringSubmatch(line, -1) {
			targets = append(targets, m[1])
		}
		if m := mdRefDef.FindStringSubmatch(line); m != nil {
			targets = append(targets, m[1])
		}
		for _, target := range targets {
			target = strings.TrimSuffix(strings.TrimPrefix(target, "<"), ">")
			if strings.Contains(target, "://") || strings.HasPrefix(target, "mailto:") || target == "" {
				continue
			}
			out = append(out, docLink{line: n, target: target})
		}
	}
	return out, scan.Err()
}

// headingSlugs is every heading of a document as GitHub names it in an
// anchor: lower case, code marks and emphasis dropped, every character
// that is not a letter, a digit, a space, a hyphen or an underscore
// dropped, spaces to hyphens, and a repeat suffixed -1, -2 and so on.
// Fenced code is skipped, since a # inside it is not a heading.
func headingSlugs(path string) (map[string]bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string]bool{}
	seen := map[string]int{}
	fenced := false
	scan := bufio.NewScanner(f)
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
		text := strings.TrimLeft(line, "#")
		if text == "" || text[0] != ' ' {
			continue
		}
		slug := slugOf(strings.TrimSpace(text))
		if n := seen[slug]; n > 0 {
			out[fmt.Sprintf("%s-%d", slug, n)] = true
		} else {
			out[slug] = true
		}
		seen[slug]++
	}
	return out, scan.Err()
}

// slugOf is GitHub's anchor for a heading's text.
func slugOf(text string) string {
	text = strings.NewReplacer("`", "", "*", "", "_", "_").Replace(text)
	var b strings.Builder
	for _, r := range strings.ToLower(text) {
		switch {
		case unicode.IsLetter(r), unicode.IsDigit(r), r == '_', r == '-':
			b.WriteRune(r)
		case r == ' ':
			b.WriteRune('-')
		}
	}
	return b.String()
}

func mustCwd() string {
	d, _ := os.Getwd()
	return d
}
