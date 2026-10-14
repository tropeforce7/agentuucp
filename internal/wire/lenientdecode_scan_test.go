package wire

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestEveryLenientDecodeHasItsReason is the source scan for the rule that
// a file or a network body is read through Decode, the strict decoder, and
// never through encoding/json's own Unmarshal or NewDecoder, which take an
// unknown key, a key twice and a key in another case without a word. The
// sweep of ruling 58 counted DisallowUnknownFields sites and so could not
// see a plain json.Unmarshal of a file; channel-settings.json was read
// that way (G17), and so is serve's ledger. This test counts the lenient
// calls themselves: every call site of json.Unmarshal or json.NewDecoder
// in non-test code outside this package must have a row in
// lenientDecodeAllowed naming the function and the reason the lenient
// read is safe, and every row must still have its site. A site with no
// row fails by name with the sentence that says what to do.
//
// A reason is one of: the bytes were decoded strictly before (name the
// line); a probe of key presence before the strict decode of the same
// bytes; an in-process value this program encoded; a compiled-in
// constant; a local unsigned draft held to Validate and signed afresh
// before it leaves. "This program wrote the file" is not a reason on its
// own: a home file is edited and restored by hand, which is how G17
// bites.
//
// The sweep at 30f93dd found thirty sites, seven of them with no reason:
// internal/identity (two UnmarshalJSON methods and their callers; the key
// scan of Decode stops at a type with its own UnmarshalJSON, so a strict
// outer decode does not make them strict), serve's ledger, relay.json,
// cert.json twice over, and channel-settings.json. Each is held here
// until it moves to Decode or is given its reason.
func TestEveryLenientDecodeHasItsReason(t *testing.T) {
	root := moduleRootDir(t)
	fset := token.NewFileSet()
	found := map[string][]string{} // key -> positions
	for _, dir := range []string{"internal", "cmd"} {
		filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			rel, _ := filepath.Rel(root, path)
			rel = filepath.ToSlash(rel)
			if strings.HasPrefix(rel, "internal/wire/") {
				return nil
			}
			f, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				t.Errorf("%s does not parse: %v", rel, err)
				return nil
			}
			for _, decl := range f.Decls {
				fd, ok := decl.(*ast.FuncDecl)
				if !ok || fd.Body == nil {
					continue
				}
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					sel, ok := call.Fun.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					pkg, ok := sel.X.(*ast.Ident)
					if !ok || pkg.Name != "json" || (sel.Sel.Name != "Unmarshal" && sel.Sel.Name != "NewDecoder") {
						return true
					}
					key := rel + " " + funcName(fd) + " json." + sel.Sel.Name
					pos := fset.Position(call.Pos())
					found[key] = append(found[key], fmt.Sprintf("%s:%d", rel, pos.Line))
					return true
				})
			}
			return nil
		})
	}
	sites := 0
	for _, p := range found {
		sites += len(p)
	}
	// The floor was 25 against the sweep's thirty. Commit 6b moved ten of
	// them to Decode, leaving twenty, and added one, eachKeyExactly's
	// walk of the channels object (R24b), so twenty-one stand. The floor
	// stays at 17, as the review ruled: it is a floor under the count, not
	// the count, and says only that the parse reached the tree.
	if sites < 17 {
		t.Fatalf("found %d lenient decode sites; twenty-one stood after commit 6b moved ten of the sweep's thirty to wire.Decode and added eachKeyExactly's walk, so the parse is not reaching the tree", sites)
	}
	var problems []string
	for key, positions := range found {
		if _, ok := lenientDecodeAllowed[key]; !ok {
			problems = append(problems, fmt.Sprintf("%s: %s reads leniently and has no row in lenientDecodeAllowed; read it with wire.Decode, or add the row with the reason the lenient read is safe",
				strings.Join(positions, ","), key))
		}
	}
	for key := range lenientDecodeAllowed {
		if _, ok := found[key]; !ok {
			problems = append(problems, fmt.Sprintf("lenientDecodeAllowed names %s, which has no call site in the tree; remove the row", key))
		}
	}
	sort.Strings(problems)
	for _, p := range problems {
		t.Error(p)
	}
}

// lenientDecodeAllowed is keyed "path function json.Call" and holds the
// reason. The reasons are the sweep's at 30f93dd and are the reviewer's
// to keep.
var lenientDecodeAllowed = map[string]string{
	"internal/auu/damaged_cmds.go reopenOne json.Unmarshal":                "the damaged box holds what failed to open and reopen tries it again as the fetch does; the envelope's own keys are the sealed format's, never read strictly by the listing either (wire.Decode stops at a RawMessage); envelope.Open re-holds v, to, ct and ch, and openOne the channel",
	"internal/kit/kit.go bundleMatches json.Unmarshal":                     "pki.EncodeBundle's output of an in-process value",
	"internal/kit/kit.go renderSettings json.NewDecoder":                   "the compiled-in relay.json template",
	"internal/agent/client.go Client.call json.Unmarshal":                  "a reply frame from the local key agent over the same user's socket; the agent decodes requests strictly (proto.go) and a missing ok reads as a refusal",
	"internal/relay/server.go hasOldKey json.Unmarshal":                    "probe of the old allow key before wire.Decode of the same bytes",
	"internal/relay/channelapi.go Server.handleGetChannels json.Unmarshal": "reads the relay's own SQLite row, not a home file, for the channel names alone; channels.Verify held the document at push, and this read does not verify it again",
	"internal/client/client.go httpError json.Unmarshal":                   "probe of the code key after wire.Decode of the same error body",
	"internal/client/client.go Client.ListWait json.Unmarshal":             "the envelope bytes are a json.RawMessage out of a listing wire.Decode read; envelope.Open re-holds its outer fields v, to, ct and ch; the envelope's own keys are never read strictly",
	"internal/store/encrypt.go sniffIdentity json.Unmarshal":               "probe of key presence that decides plain or locked and refuses a mixed file; the decode it precedes must be strict (Store.locked, Store.plainIdentity)",
	"internal/store/store.go Store.Config json.Unmarshal":                  "the key walk that refuses unknown keys by name; the two calls are the walk and the decode it guards",
	"internal/store/store.go Store.PeekByID json.Unmarshal":                "best-effort read of three fields of a record being removed; a record that will not read leaves no left-behind entry by design",
	"internal/store/card.go Store.Card json.Unmarshal":                     "a local unsigned draft held to Validate and signed afresh before it leaves",
	"internal/store/channels.go Store.Directory json.Unmarshal":            "a local unsigned draft held to Validate and signed afresh before it leaves",
	"internal/store/channelsettings.go eachKeyExactly json.NewDecoder":     "walks channel-settings.json and its channels object key by key, matched exactly since channel names are case-sensitive (R24b): the file's own keys v and channels each taken once and any other refused, a channel named twice refused, anything after the object refused; every value goes through wire.Decode",
	"internal/pki/store.go Store.relayRecord json.Unmarshal":               "probe of required-key presence after unmarshalStrict (wire.Decode) of the same bytes",
	"cmd/auu-relay/config.go checkEmptyCourier json.Unmarshal":             "probe of courier present or absent before wire.Decode of the same raw settings",
	"cmd/auu-relay/config.go checkRemovedKeys json.Unmarshal":              "probe of removed keys and sub-keys before wire.Decode of the same raw settings",
	"cmd/auu-relay/config.go courierSharesSet json.Unmarshal":              "probe of set, null or absent before wire.Decode of the same raw settings",
	"cmd/auu-relay/config.go courierBlockGiven json.Unmarshal":             "probe of a non-empty courier block before wire.Decode of the same raw settings",
}

// funcName is the receiver-qualified name of a function declaration.
func funcName(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return fd.Name.Name
	}
	t := fd.Recv.List[0].Type
	if star, ok := t.(*ast.StarExpr); ok {
		t = star.X
	}
	if id, ok := t.(*ast.Ident); ok {
		return id.Name + "." + fd.Name.Name
	}
	return fd.Name.Name
}

// moduleRootDir is the directory holding go.mod above this test.
func moduleRootDir(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the test")
		}
		dir = parent
	}
}
