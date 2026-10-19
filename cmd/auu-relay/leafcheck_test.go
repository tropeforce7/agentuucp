package main

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// recordingLog is a logger that keeps what it is told.
type recordingLog struct{ lines []string }

func (l *recordingLog) Info(msg string, args ...any)  { l.add("INFO", msg, args) }
func (l *recordingLog) Warn(msg string, args ...any)  { l.add("WARN", msg, args) }
func (l *recordingLog) Error(msg string, args ...any) { l.add("ERROR", msg, args) }
func (l *recordingLog) add(level, msg string, args []any) {
	l.lines = append(l.lines, level+" "+msg+" "+fmt.Sprint(args...))
}

// A fault in a check of the relay's own certificate ends that check and
// not the relay (S59): renewLeaf's goroutine is outside every HTTP handler,
// so a panic there ended the process. The fault is said once with its
// stack, and the next check, at its time, runs as any does.
func TestAFaultInALeafCheckEndsThatCheck(t *testing.T) {
	calls := 0
	old := renewStep
	renewStep = func(*clientCertParts, time.Time) (bool, error) {
		calls++
		if calls == 1 {
			panic("a fault planted in the renewal")
		}
		return false, nil
	}
	t.Cleanup(func() { renewStep = old })
	log := &recordingLog{}
	now := time.Now()
	// The intermediates were warned of a moment ago, so a check is the
	// renewal alone.
	lastWarned := now
	leafCheck(nil, log, now, &lastWarned)
	leafCheck(nil, log, now.Add(leafCheckInterval), &lastWarned)
	if calls != 2 {
		t.Fatalf("the renewal ran %d times; want the faulted check and the one after it", calls)
	}
	said := strings.Join(log.lines, "\n")
	if n := strings.Count(said, "ended with a fault"); n != 1 || !strings.Contains(said, "a fault planted in the renewal") ||
		!strings.Contains(said, "goroutine ") {
		t.Fatalf("the fault was said %d times, want once with its stack:\n%s", n, said)
	}
}
