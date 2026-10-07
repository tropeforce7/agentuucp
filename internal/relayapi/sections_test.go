package relayapi

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strings"
	"testing"
)

// Every body a relay answers with carries sections, and no row inside a
// list does (D28, R3): the walk reads this package's own source, finds
// every struct type, and holds each to the set it is in. A type in no set
// fails by name, since a list of exceptions that goes stale passes the next
// type by.
func TestEveryAnswerBodyCarriesSectionsAndNoRowDoes(t *testing.T) {
	// Rows: what a list holds, and a nested object that is no body.
	rows := map[string]bool{
		"ListedEntry": true, "Courier": true, "StoredMessage": true, "QueuedMessage": true,
		"CertRecord": true, "BlockRecord": true, "MailboxRecord": true, "TokenRecord": true,
		"LimitsView": true,
	}
	// Neither a body nor a row: the door itself, the auth header's fields,
	// and the outer envelope, which is frozen at four fields (D38).
	other := map[string]bool{"Sections": true, "Auth": true, "Carried": true}

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "relayapi.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	var unplaced []string
	ast.Inspect(file, func(n ast.Node) bool {
		spec, ok := n.(*ast.TypeSpec)
		if !ok {
			return true
		}
		st, ok := spec.Type.(*ast.StructType)
		if !ok {
			return true
		}
		name := spec.Name.Name
		found[name] = true
		embeds := false
		for _, f := range st.Fields.List {
			if id, ok := f.Type.(*ast.Ident); ok && len(f.Names) == 0 && id.Name == "Sections" {
				embeds = true
			}
		}
		switch {
		case strings.HasSuffix(name, "Response") || strings.HasSuffix(name, "Answer"):
			if !embeds {
				t.Errorf("answer body %s does not embed Sections", name)
			}
		case strings.HasSuffix(name, "Request"):
			// Requests take the door in the next commit (D37); until then
			// none carries it.
			if embeds {
				t.Errorf("request %s embeds Sections before requests take the door", name)
			}
		case rows[name] || other[name]:
			if embeds {
				t.Errorf("%s is a row or no body and embeds Sections", name)
			}
		default:
			unplaced = append(unplaced, name)
		}
		return true
	})
	sort.Strings(unplaced)
	for _, name := range unplaced {
		t.Errorf("struct type %s is in no set: an answer body (named …Response or …Answer), a request, a row or neither; place it", name)
	}
	for name := range rows {
		if !found[name] {
			t.Errorf("row %s is no longer in relayapi.go; take it out of the list", name)
		}
	}
	if len(found) < 40 {
		t.Fatalf("the walk found %d struct types; it is not reading the file", len(found))
	}
}
