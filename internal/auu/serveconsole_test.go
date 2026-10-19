package auu

import (
	"os"
	"strings"
	"testing"
)

// runToClosedStdout runs u's command with standard output a file already
// closed, so that every line written to it fails, and answers the run's
// error.
func runToClosedStdout(t *testing.T, u *user, args ...string) error {
	t.Helper()
	u.settle()
	t.Setenv("AUU_HOME", u.home)
	f, err := os.CreateTemp(t.TempDir(), "closed-output")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	old := os.Stdout
	os.Stdout = f
	defer func() { os.Stdout = old }()
	var runErr error
	captureStderr(t, func() { runErr = run(args) })
	return runErr
}

// serve's console lines are its report without --json, and one that cannot
// be written ends the run as the report that cannot be written does under
// --json (57e): at the round's end, after every message of it is answered
// and settled, with the write's own error. They used to be dropped, and
// serve went on writing nowhere. Two asks are answered once each whichever
// way serve reports, and a serve after it, writing again, answers neither a
// second time.
func TestServeEndsWhenItsConsoleLinesCannotBeWritten(t *testing.T) {
	for _, mode := range []string{"console", "json"} {
		t.Run(mode, func(t *testing.T) {
			alice, bob := newExpert(t, modeReadOnly)
			t.Setenv(handlerScript, "echo:an answer")
			first := alice.ask(t, "jostle", "one", "the first")
			second := alice.ask(t, "jostle", "two", "the second")
			args := []string{"serve", "--once"}
			if mode == "json" {
				args = append(args, "--json")
			}
			err := runToClosedStdout(t, bob.user, args...)
			if err == nil || !strings.Contains(err.Error(), "write") {
				t.Fatalf("serve --once to a closed standard output: %v; want the write's error", err)
			}
			var e *exitError
			if asExit(err, &e) {
				t.Fatalf("the write's error came as exit %d; want it as it is, exit 1", e.code)
			}
			led := bob.ledgerOf(t)
			for _, m := range []sentJSON{first, second} {
				if entry := led.Messages[m.ID]; entry == nil || entry.Handled.IsZero() {
					t.Errorf("%s was not settled before the run ended: %+v", m.ID, entry)
				}
			}
			if again := bob.round(t); len(again.Answered) != 0 {
				t.Errorf("a serve after it answered %d again", len(again.Answered))
			}
		})
	}
}

// With nothing to answer, the one line --once writes is that, and a line
// that cannot be written is the run's error.
func TestServeOnceNothingToAnswerThatCannotBeWritten(t *testing.T) {
	_, bob := newExpert(t, modeReadOnly)
	bob.serve(t)
	err := runToClosedStdout(t, bob.user, "serve", "--once")
	if err == nil || !strings.Contains(err.Error(), "write") {
		t.Fatalf("nothing to answer, to a closed standard output: %v; want the write's error", err)
	}
}
