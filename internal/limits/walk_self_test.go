package limits

import (
	"go/ast"
	"go/types"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The walk's self-tests, from the second review: a sweep of the real tree
// that does not go through the walk's own reading of a time, and the
// count the floor records. Each asserts; neither only logs.

// ledgerSites is every site the ledger test holds to the tree, with the
// fields a display field is copied into, and the ledger's rows by key.
func ledgerSites(t *testing.T, root string) ([]site, map[string]row) {
	t.Helper()
	ledger, err := os.ReadFile(filepath.Join(root, "internal", "limits", "ledger.txt"))
	if err != nil {
		t.Fatal(err)
	}
	_, sites, _ := checkWith(t, root, string(ledger), capBounds, capSettings, spelledBounds)
	rows, problems := parseLedger(string(ledger))
	for _, p := range problems {
		t.Error(p)
	}
	byKey := map[string]row{}
	for _, r := range rows {
		byKey[r.key] = r
	}
	return sites, byKey
}

// TestTheWalkScansTheRealTree sweeps the real tree by a reading cruder
// than the walk's: every exported field of a struct a decode reaches
// whose type holds a time.Time, every time.Parse, time.ParseInLocation,
// time.Unix, time.UnixMilli and time.UnixMicro, every UnmarshalText,
// UnmarshalJSON and UnmarshalBinary on a time, and every json.Unmarshal
// into a time. Each must be a time site of the walk, and every time site
// must have its row in the ledger: no time field without a row.
func TestTheWalkScansTheRealTree(t *testing.T) {
	root := moduleRoot(t)
	sites, rows := ledgerSites(t, root)
	siteAt := map[string]bool{}
	times := 0
	for _, s := range sites {
		if s.kind != "time" {
			continue
		}
		times++
		siteAt[s.pos.String()] = true
		if _, ok := rows[s.key]; !ok {
			t.Errorf("%s: the time site %s has no row in ledger.txt", s.pos, s.key)
		}
	}
	if times == 0 {
		t.Fatal("the walk found no time site in the tree")
	}

	tr := load(t, root)
	decoded := tr.decoded()
	var unseen []string
	swept := 0
	for _, p := range tr.pkgs {
		for _, obj := range p.info.Defs {
			tn, ok := obj.(*types.TypeName)
			if !ok {
				continue
			}
			key := fullName(tn)
			why, dec := decoded[key]
			if !dec {
				continue
			}
			st, ok := tn.Type().Underlying().(*types.Struct)
			if !ok {
				continue
			}
			for f := range st.Fields() {
				if !f.Exported() {
					continue
				}
				if !timeType(f.Type()) && !strings.Contains(types.TypeString(f.Type(), nil), "time.Time") {
					continue
				}
				swept++
				at := tr.fset.Position(f.Pos()).String()
				if !siteAt[at] {
					unseen = append(unseen, "decoded time field "+key+"."+f.Name()+" "+types.TypeString(f.Type(), nil)+" ("+at+") via "+why)
				}
			}
		}
		for _, f := range p.files {
			ast.Inspect(f, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				fn := calleeFunc(p, call)
				if fn == nil {
					return true
				}
				name := fn.FullName()
				what := ""
				switch {
				case strings.HasPrefix(name, "time.Unix"), strings.HasPrefix(name, "time.Parse"):
					if name == "time.ParseDuration" {
						return true
					}
					what = name
				case fn.Name() == "UnmarshalText", fn.Name() == "UnmarshalJSON", fn.Name() == "UnmarshalBinary":
					sig, _ := fn.Type().(*types.Signature)
					if sig == nil || sig.Recv() == nil || !strings.Contains(types.TypeString(sig.Recv().Type(), nil), "time.Time") {
						return true
					}
					what = name
				case name == "encoding/json.Unmarshal" && len(call.Args) == 2:
					if typ := p.info.TypeOf(call.Args[1]); typ != nil && strings.Contains(types.TypeString(typ, nil), "time.Time") {
						what = "json.Unmarshal into " + types.TypeString(typ, nil)
					}
				}
				if what == "" {
					return true
				}
				swept++
				at := tr.fset.Position(call.Pos()).String()
				if !siteAt[at] {
					unseen = append(unseen, "call "+what+" at "+at)
				}
				return true
			})
		}
	}
	if swept == 0 {
		t.Fatal("the sweep found no time in the tree, so it is not reaching it")
	}
	t.Logf("the walk found %d time sites; the sweep found %d times, %d of them not sites", times, swept, len(unseen))
	sort.Strings(unseen)
	for _, u := range unseen {
		t.Errorf("the walk has no time site for the %s", u)
	}
}

// TestTheWalkCountsTheFloor holds the walk's count, every kind together,
// to the floor exactly: one under is a walk that stopped reaching part
// of the tree, one over is a row added without the floor raised with it.
func TestTheWalkCountsTheFloor(t *testing.T) {
	sites, _ := ledgerSites(t, moduleRoot(t))
	if len(sites) != floor {
		n := map[string]int{}
		for _, s := range sites {
			n[s.kind]++
		}
		t.Fatalf("the walk found %d sites, by kind %v; the floor is %d", len(sites), n, floor)
	}
}
