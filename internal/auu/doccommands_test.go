package auu

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

// The documents tell a person what to type, and a command a document names
// that the program does not dispatch is a person typing something
// impossible. This holds every auu, auu-admin and auu-ca form in the README,
// the guides and the release notes to the dispatch, as the skills test holds
// the skills; auu-relay's flags are held in cmd/auu-relay, where its flag set
// is.

// documentFiles is what a person reads: the README, every guide under docs/
// and every release note.
func documentFiles(t *testing.T) []string {
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

// Every command a document names is one its program dispatches.
func TestEveryDocumentCommandExists(t *testing.T) {
	known := dispatched(t)
	read := 0
	for _, path := range documentFiles(t) {
		forms := formsIn(t, path)
		read += len(forms)
		for _, f := range undispatched(known, forms) {
			t.Errorf("%s:%d: %q names %s %s, which %s does not dispatch; correct the form "+
				"(a release note naming a removed command as history has no exemption yet, and one is added when it is needed)",
				f.file, f.line, f.text, f.prog, f.sub, f.prog)
		}
	}
	t.Logf("read %d forms from %d documents", read, len(documentFiles(t)))
	// The documents name hundreds; a reader that finds a handful has stopped
	// reading them.
	if read < 300 {
		t.Errorf("read %d forms from the documents, which cannot be right", read)
	}
}

// A form is read through the separators that put two commands on one line
// and the prefixes that stand in front of a program, so a command behind
// either is held to the dispatch as one written alone is.
func TestADocumentFormIsReadThroughSeparatorsAndPrefixes(t *testing.T) {
	doc := filepath.Join(t.TempDir(), "planted.md")
	text := "Run `auu inbox; auu nosuchone` and `auu inbox && auu watch`.\n" +
		"Or `auu inbox && auu nosuchten` and `auu inbox || auu nosucheleven`.\n" +
		"```\n" +
		"sudo -u auu-expert -H auu nosuchtwo   # a comment, auu nosuchnever\n" +
		"$ auu nosuchthree\n" +
		"sudo -u auu env AUU_HOME=/var/lib/auu auu nosuchfour\n" +
		"AUU_RELAY=personal auu nosuchfive bob\n" +
		"ExecStart=/usr/local/bin/auu nosuchsix\n" +
		"eval \"$(auu nosuchseven zsh)\"\n" +
		"bin/auu-admin nosucheight\n" +
		"auu inbox --json | auu-ca nosuchnine || auu watch\n" +
		"sudo --user auu env -i AUU_HOME=/x auu nosuchtwelve\n" +
		"```\n"
	if err := os.WriteFile(doc, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range undispatched(dispatched(t), formsIn(t, doc)) {
		got = append(got, f.prog+" "+f.sub)
	}
	want := []string{
		"auu nosuchone", "auu nosuchten", "auu nosucheleven", "auu nosuchtwo", "auu nosuchthree", "auu nosuchfour", "auu nosuchfive",
		"auu nosuchsix", "auu nosuchseven", "auu-admin nosucheight", "auu-ca nosuchnine", "auu nosuchtwelve",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("the planted forms read as %q, want %q", got, want)
	}
}
