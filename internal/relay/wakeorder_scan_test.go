package relay

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestAWakeFollowsTheAnswer is the source scan for the rule that a
// handler which wakes a worker or a held listing does so after it has
// written its answer and the state the answer stands for. A wake before
// the answer lets the woken side act, and come back by the network, while
// the handler still holds state it has not written: the early failure
// report of G18 came back to a 404 because handleForward woke the courier
// worker before answering the 201 that the upstream needed to record the
// handover. The rule is order, not timing: no handler flushes, so the
// answer leaves when the handler returns whichever side of it the wake is,
// and the fix for G18 is that a report answered 404 is asked again (R23).
// What the order keeps is that a handler has written its answer, and the
// state behind it, before anything it woke can act. At 30f93dd the test names every handler that wakes before it
// answers; each is held there until it is reordered or given a reason in
// the table below.
//
// The scan is by source order within one function body, which is the
// shape of every handler here: a wake expression is a call whose method
// is wake or Wake; an answer is a call whose method is one of answers, or
// whose name begins refuse or fail, the relay's refusal helpers (commit
// 6c, the reader's low: refuse, refuseUnreadWith and failCode answer too).
// A function in wakeBeforeAnswerAllowed is listed with its reason.
func TestAWakeFollowsTheAnswer(t *testing.T) {
	answers := map[string]bool{"writeJSON": true, "fail": true, "refuseUnread": true,
		"writeRefusal": true, "storageFault": true, "WriteHeader": true}
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var problems []string
	wakes := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("%s does not parse: %v", name, err)
		}
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			var firstWake, lastAnswer token.Pos
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				switch m := sel.Sel.Name; {
				case m == "wake" || m == "Wake":
					wakes++
					if firstWake == token.NoPos || call.Pos() < firstWake {
						firstWake = call.Pos()
					}
				case answers[m] || strings.HasPrefix(m, "refuse") || strings.HasPrefix(m, "fail"):
					if call.Pos() > lastAnswer {
						lastAnswer = call.Pos()
					}
				}
				return true
			})
			if firstWake == token.NoPos || lastAnswer == token.NoPos || firstWake > lastAnswer {
				continue
			}
			if reason, ok := wakeBeforeAnswerAllowed[fd.Name.Name]; ok {
				t.Logf("%s wakes before it answers: %s", fd.Name.Name, reason)
				continue
			}
			w, a := fset.Position(firstWake), fset.Position(lastAnswer)
			problems = append(problems, fmt.Sprintf("%s:%d %s wakes at line %d and answers at line %d: move the wake after the answer, or list it in wakeBeforeAnswerAllowed with the reason",
				filepath.Base(w.Filename), w.Line, fd.Name.Name, w.Line, a.Line))
		}
	}
	if wakes < 6 {
		t.Fatalf("found %d wake calls; the sweep that wrote this test found 8 at 30f93dd, so the parse is not reaching the package", wakes)
	}
	sort.Strings(problems)
	for _, p := range problems {
		t.Error(p)
	}
}

// wakeBeforeAnswerAllowed names the functions that wake before they answer
// on purpose, each with its reason. Empty at the sweep, and at commit 6c,
// where every wake the sweep found was moved after its answer.
var wakeBeforeAnswerAllowed = map[string]string{}
