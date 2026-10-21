package auu

import (
	"errors"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/channels"
)

// handleProgram puts a regular file at dir/rel for a route's command to
// name, and returns its path. Nothing runs it: check holds a program to
// being a regular file that is there, and no more.
func handleProgram(t *testing.T, dir, rel string) string {
	t.Helper()
	path := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

// writeHandleFile puts a handle file in a directory of its own, beside a
// program at handlers/run.sh that its routes may name relatively, and
// returns the file's path.
func writeHandleFile(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	handleProgram(t, dir, filepath.Join("handlers", "run.sh"))
	path := filepath.Join(dir, handleFile)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// checkHandleFile loads and checks a handle file as check does, without a
// home: the file's own rules, and not serve.json's or the disk's.
func checkHandleFile(path string) (*handleConfig, error) {
	cfg, err := loadHandleConfig(path)
	if err != nil {
		return nil, err
	}
	return cfg, cfg.check()
}

// handleFileWith writes a handle file with one route, "work" on channel
// "work" running handlers/run.sh, the route's fields as given and the
// file's top-level fields as given, and loads and checks it.
func handleFileWith(t *testing.T, top, fields string) (*handleConfig, error) {
	t.Helper()
	path := writeHandleFile(t, `{"v":1`+top+`,"routes":{"work":{"channel":"work","command":["handlers/run.sh"]`+fields+`}}}`)
	return checkHandleFile(path)
}

// check says, for each route, what it would run and where, with every
// default filled in and every path as resolved, then the file's own
// settings and the count; nothing is run and no relay is asked.
func TestHandleCheckSaysWhatItWouldRun(t *testing.T) {
	bob := newUser(t, "bob", startRelay(t))
	importer := handleProgram(t, bob.home, filepath.Join("handlers", "import.sh"))
	path := filepath.Join(bob.home, handleFile)
	file := `{"v":1,"workers_total":3,"routes":{
		"import":{"channel":"documents","command":["handlers/import.sh","--from","a b"],"timeout":"10m","max_reply_bytes":65536},
		"convert":{"channel":"images","command":["` + jsonPath(importer) + `"],"execution":"parallel","max_parallel":3,"idempotent":true}}}`
	if err := os.WriteFile(path, []byte(file), 0o600); err != nil {
		t.Fatal(err)
	}
	var out string
	stderr := captureStderr(t, func() { out = bob.run("handle", "check") })
	jobs := filepath.Join(bob.home, "handle", "jobs")
	want := `convert: channel "images", parallel, up to 3 at once
  command:  "` + strings.ReplaceAll(importer, `\`, `\\`) + `"
  program:  ` + importer + `
  jobs:     ` + filepath.Join(jobs, "convert") + `
  retries:  3, idempotent: a failed attempt is run again
  limits:   timeout 30m0s, max_queued 1000, max_queued_bytes 1073741824, max_log_bytes 1048576, max_reply_bytes no cap, keep_failed 168h0m0s
import: channel "documents", sequential
  command:  "handlers/import.sh" "--from" "a b"
  program:  ` + importer + `
  jobs:     ` + filepath.Join(jobs, "import") + `
  retries:  3, not idempotent: a started attempt that fails is not run again
  limits:   timeout 10m0s, max_queued 1000, max_queued_bytes 1073741824, max_log_bytes 1048576, max_reply_bytes 65536 bytes, keep_failed 168h0m0s

workers_total 3, supervisor_reaps no

` + path + ` is good for 2 routes
`
	if out != want {
		t.Fatalf("check printed:\n%s\nwant:\n%s", out, want)
	}
	// Mail on both channels stays on the relay, which is the default; the
	// channels are named in the routes' order.
	if !strings.Contains(stderr, `"images" and "documents"`) || !strings.Contains(stderr, "channel keep NAME off") {
		t.Fatalf("check said on stderr:\n%s", stderr)
	}
	// The fold probe makes handle/ as serve's makes serve/, and leaves
	// nothing in it: no lock, no ledger, no job.
	if entries, err := os.ReadDir(filepath.Join(bob.home, "handle")); err != nil || len(entries) != 0 {
		t.Fatalf("check left %v under handle/ (%v)", entries, err)
	}
}

// Every refusal section 2 lists, each by the whole sentence a person reads:
// the file, the route and what is wrong, from 'auu handle check' itself.
func TestHandleCheckRefusesEachBadField(t *testing.T) {
	bob := newUser(t, "bob", startRelay(t))
	route := func(fields string) string {
		return `{"v":1,"routes":{"work":{"channel":"work","command":["handlers/run.sh"]` + fields + `}}}`
	}
	nameErr := func(name string) string { return channels.ValidName(name).Error() }
	thread := "0123456789abcdef0123456789abcdef"
	var missingPath string
	for _, row := range []struct {
		name, file string
		// want is the sentence after the file's path and ": ".
		want func(dir string) string
	}{
		{"version", `{"v":2,"routes":{}}`, fixed("v is 2; this auu understands version 1")},
		{"no version", `{"routes":{}}`, fixed("v is 0; this auu understands version 1")},
		{"no routes", `{"v":1,"routes":{}}`, fixed("no routes; a handle file that handles nothing is a mistake, not a setting")},
		{"routes absent", `{"v":1}`, fixed("no routes; a handle file that handles nothing is a mistake, not a setting")},
		{"trailing", route(``) + `{}`, fixed("trailing data after the JSON object")},
		{"null route", `{"v":1,"routes":{"work":null}}`, fixed(`route "work": it is null; a route is an object, with channel and command at least`)},
		{"workers_total below none", `{"v":1,"workers_total":-1,"routes":{"work":{"channel":"work","command":["handlers/run.sh"]}}}`,
			fixed("workers_total is -1; it cannot be fewer than none")},
		{"workers_total above 64", `{"v":1,"workers_total":65,"routes":{"work":{"channel":"work","command":["handlers/run.sh"]}}}`,
			fixed("workers_total is 65, more workers than this auu runs (64 at most)")},
		{"workers_total below max_parallel", `{"v":1,"workers_total":2,"routes":{"work":{"channel":"work","command":["handlers/run.sh"],"execution":"parallel","max_parallel":3}}}`,
			fixed(`workers_total is 2, fewer than route "work"'s max_parallel of 3, which could never all run`)},
		{"route id", `{"v":1,"routes":{"a/b":{"channel":"work","command":["handlers/run.sh"]}}}`,
			fixed(`route "a/b": ` + nameErr("a/b"))},
		{"route id empty", `{"v":1,"routes":{"":{"channel":"work","command":["handlers/run.sh"]}}}`,
			fixed(`route "": ` + nameErr(""))},
		{"route id thread-shaped", `{"v":1,"routes":{"` + thread + `":{"channel":"work","command":["handlers/run.sh"]}}}`,
			fixed(`route "` + thread + `": a name of 32 hex characters is the shape of a message id; rename it`)},
		{"route ids that fold", `{"v":1,"routes":{"Work":{"channel":"a","command":["handlers/run.sh"]},"work":{"channel":"b","command":["handlers/run.sh"]}}}`,
			// The strict decode refuses two keys that fold before check
			// sees them; check's own sentence is TestHandleRouteIdsThatFoldAreRefused's.
			fixed(`key "Work" and key "work", the same under case folding, are both in an object at depth 2`)},
		{"no channel", `{"v":1,"routes":{"work":{"command":["handlers/run.sh"]}}}`,
			fixed(`route "work": channel is required: it is the channel whose asks the route handles`)},
		{"bad channel", `{"v":1,"routes":{"work":{"channel":"x:y","command":["handlers/run.sh"]}}}`, nil},
		{"two routes one channel", `{"v":1,"routes":{"a":{"channel":"work","command":["handlers/run.sh"]},"b":{"channel":"work","command":["handlers/run.sh"]}}}`,
			fixed(`route "b": routes "a" and "b" are both on channel "work"; a channel belongs to one route`)},
		{"no command", `{"v":1,"routes":{"work":{"channel":"work"}}}`,
			fixed(`route "work": command is required: it is the program to run and its arguments, as a list`)},
		{"empty command", `{"v":1,"routes":{"work":{"channel":"work","command":[]}}}`,
			fixed(`route "work": command is required: it is the program to run and its arguments, as a list`)},
		{"blank program", `{"v":1,"routes":{"work":{"channel":"work","command":["  "]}}}`,
			fixed(`route "work": command's first element is empty; it is the program to run`)},
		{"NUL", `{"v":1,"routes":{"work":{"channel":"work","command":["handlers/run.sh","a\u0000b"]}}}`,
			fixed(`route "work": command's element 1 holds a NUL, which no program's argument can carry`)},
		{"program missing", `{"v":1,"routes":{"work":{"channel":"work","command":["handlers/gone.sh"]}}}`,
			func(dir string) string {
				return `route "work": command's program ` + filepath.Join(dir, "handlers", "gone.sh") + ` does not exist`
			}},
		{"program a directory", `{"v":1,"routes":{"work":{"channel":"work","command":["handlers"]}}}`, nil},
		{"program a directory by path", `{"v":1,"routes":{"work":{"channel":"work","command":["./handlers"]}}}`,
			func(dir string) string {
				return `route "work": command's program ` + filepath.Join(dir, "handlers") + ` is not a regular file`
			}},
		{"execution", route(`,"execution":"fast"`), fixed(`route "work": execution "fast" is neither sequential nor parallel`)},
		{"max_parallel below none", route(`,"execution":"parallel","max_parallel":-1`),
			fixed(`route "work": max_parallel is -1; it cannot be fewer than none`)},
		{"max_parallel on sequential", route(`,"max_parallel":2`),
			fixed(`route "work": a sequential route runs one at a time; drop max_parallel or make it parallel`)},
		{"max_parallel above 64", `{"v":1,"workers_total":64,"routes":{"work":{"channel":"work","command":["handlers/run.sh"],"execution":"parallel","max_parallel":65}}}`,
			fixed(`route "work": max_parallel is 65, more than this auu runs at once (64 at most)`)},
		{"timeout", route(`,"timeout":"soon"`), fixed(`route "work": timeout "soon" is not a length of time (30m, 2h, 168h)`)},
		{"timeout zero", route(`,"timeout":"0s"`), fixed(`route "work": timeout is 0s; it must be more than nothing`)},
		{"retries", route(`,"retries":-1`), fixed(`route "work": retries is -1; it cannot be fewer than none`)},
		{"max_queued", route(`,"max_queued":-1`), fixed(`route "work": max_queued is -1; it cannot be fewer than none`)},
		{"max_queued_bytes", route(`,"max_queued_bytes":-1`), fixed(`route "work": max_queued_bytes is -1; it cannot be fewer than none`)},
		{"max_log_bytes", route(`,"max_log_bytes":-1`), fixed(`route "work": max_log_bytes is -1; it cannot be fewer than none`)},
		{"max_log_bytes small", route(`,"max_log_bytes":4095`),
			fixed(`route "work": max_log_bytes is 4095, too small to hold a sentence (4096 at least)`)},
		{"max_reply_bytes", route(`,"max_reply_bytes":-1`), fixed(`route "work": max_reply_bytes is -1; it cannot be fewer than none`)},
		{"keep_failed", route(`,"keep_failed":"a week"`), fixed(`route "work": keep_failed "a week" is not a length of time (30m, 2h, 168h)`)},
		{"keep_failed negative", route(`,"keep_failed":"-1h"`), fixed(`route "work": keep_failed is -1h; it must be more than nothing`)},
	} {
		t.Run(row.name, func(t *testing.T) {
			path := writeHandleFile(t, row.file)
			dir := filepath.Dir(path)
			var want string
			switch row.name {
			case "bad channel":
				want = path + `: route "work": channel "x:y": ` + nameErr("x:y")
			case "program a directory":
				// A bare name is the PATH's; "handlers" is not on it.
				want = path + `: route "work": command's program "handlers" is not on the PATH: `
			default:
				want = path + ": " + row.want(dir)
			}
			out, err := bob.tryRun("handle", "check", "--config", path)
			var exit *exitError
			if !errors.As(err, &exit) || exit.code != exitUsage {
				t.Fatalf("check ended %v, want a usage error\n%s", err, out)
			}
			if row.name == "program a directory" {
				if !strings.HasPrefix(err.Error(), want) {
					t.Fatalf("the refusal is\n%s\nwant it to begin\n%s", err.Error(), want)
				}
			} else if err.Error() != want {
				t.Fatalf("the refusal is\n%s\nwant\n%s", err.Error(), want)
			}
			if out != "" {
				t.Fatalf("a refused file printed:\n%s", out)
			}
		})
	}
	// A key the file does not know, and one that matches only by case, are
	// the strict decode's, each naming the key.
	for _, field := range []string{`"retires":3`, `"Retries":3`} {
		path := writeHandleFile(t, route(`,`+field))
		_, err := bob.tryRun("handle", "check", "--config", path)
		key := strings.Trim(strings.SplitN(field, ":", 2)[0], `"`)
		if err == nil || !strings.HasPrefix(err.Error(), path+": ") || !strings.Contains(err.Error(), key) {
			t.Errorf("%s: %v; want the file and the key named", field, err)
		}
	}
	// A file that is not there at all.
	missingPath = filepath.Join(t.TempDir(), "nothing.json")
	_, err := bob.tryRun("handle", "check", "--config", missingPath)
	want := "no " + missingPath + "; a handle service is one file, and there is none here. Write it and check it with 'auu handle check'"
	if err == nil || err.Error() != want {
		t.Fatalf("a missing file: %v\nwant %s", err, want)
	}
	// And anything but check or run is the usage.
	usage := "usage: auu handle check [--config FILE], or auu handle run [--once] [--backlog] [--config FILE] [--json]"
	for _, args := range [][]string{{"handle"}, {"handle", "start"}, {"handle", "check", "extra"}, {"handle", "run", "extra"}} {
		if _, err := bob.tryRun(args...); err == nil || err.Error() != usage {
			t.Errorf("auu %s: %v; want the usage", strings.Join(args, " "), err)
		}
	}
}

// fixed is a refusal's sentence that does not depend on the file's place.
func fixed(s string) func(string) string { return func(string) string { return s } }

// The strict decode takes null for a *handleRoute as nil, so a route
// written as null is refused by name at load, as a usage error, before
// anything reads it; and the command, as its own process, says it on
// stderr with no panic. An empty object is a route, refused for its
// channel rather than as null.
func TestANullHandleRouteIsRefusedByName(t *testing.T) {
	path := writeHandleFile(t, `{"v":1,"routes":{"codex":null,"work":{"channel":"work","command":["handlers/run.sh"]}}}`)
	sentence := path + `: route "codex": it is null; a route is an object, with channel and command at least`
	defer func() {
		if v := recover(); v != nil {
			t.Errorf("the loader panicked on a null route: %v", v)
		}
	}()
	_, err := loadHandleConfig(path)
	var exit *exitError
	if !errors.As(err, &exit) || exit.code != exitUsage {
		t.Fatalf("the refusal is %v (%T), want a usage error", err, err)
	}
	if err.Error() != sentence {
		t.Fatalf("the refusal is\n%s\nwant\n%s", err.Error(), sentence)
	}

	bob := newUser(t, "bob", startRelay(t))
	stdout, stderr, code := bob.inAnotherProcess("handle", "check", "--config", path)
	if code != exitUsage {
		t.Fatalf("handle check exited %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitUsage, stdout, stderr)
	}
	if !strings.Contains(stderr, sentence) {
		t.Fatalf("stderr is:\n%s\nwant %q in it", stderr, sentence)
	}
	for _, bad := range []string{"panic", "goroutine"} {
		if strings.Contains(stdout+stderr, bad) {
			t.Fatalf("handle check printed %q:\nstdout:\n%s\nstderr:\n%s", bad, stdout, stderr)
		}
	}

	empty := writeHandleFile(t, `{"v":1,"routes":{"codex":{}}}`)
	if _, err := checkHandleFile(empty); err == nil || strings.Contains(err.Error(), "it is null") ||
		!strings.Contains(err.Error(), "channel is required") {
		t.Fatalf("an empty route: %v; want it refused for its channel", err)
	}
}

// TestLimitHandleConfigV: a handle file's v is 1, and every other value is
// refused naming the version this build understands, the type's extremes
// among them.
func TestLimitHandleConfigV(t *testing.T) {
	for _, v := range []int{0, 2, -1, math.MinInt, math.MaxInt} {
		path := writeHandleFile(t, `{"v":`+strconv.Itoa(v)+`,"routes":{}}`)
		_, err := loadHandleConfig(path)
		if err == nil || err.Error() != path+": v is "+strconv.Itoa(v)+"; this auu understands version 1" {
			t.Errorf("v %d: %v; want the refusal naming both versions", v, err)
		}
	}
	for _, text := range []string{`"1"`, `1.5`, `9223372036854775808`} {
		path := writeHandleFile(t, `{"v":`+text+`,"routes":{}}`)
		if _, err := loadHandleConfig(path); err == nil || !strings.Contains(err.Error(), "v") {
			t.Errorf("v %s: %v; want it refused", text, err)
		}
	}
}

// TestLimitWorkersTotal: workers_total is 0, meaning 2, or 1 to 64. A
// negative and the type's minimum are refused as fewer than none, 65 and
// the type's maximum as more than this build runs, and the text forms, one
// past the type's maximum, a string and a fraction, by the decode naming
// the field; 1 and 64 are taken, and a route's max_parallel is held to it.
func TestLimitWorkersTotal(t *testing.T) {
	for _, tc := range []struct{ value, want string }{
		{"-1", "workers_total is -1; it cannot be fewer than none"},
		{strconv.Itoa(math.MinInt), "workers_total is " + strconv.Itoa(math.MinInt) + "; it cannot be fewer than none"},
		{"65", "workers_total is 65, more workers than this auu runs (64 at most)"},
		{strconv.Itoa(math.MaxInt), "workers_total is " + strconv.Itoa(math.MaxInt) + ", more workers than this auu runs (64 at most)"},
		{"9223372036854775808", "workers_total"},
		{`"2"`, "workers_total"},
		{"1.5", "workers_total"},
	} {
		_, err := handleFileWith(t, `,"workers_total":`+tc.value, ``)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("workers_total %s: %v; want %q", tc.value, err, tc.want)
		}
	}
	for value, want := range map[string]int{"0": defaultWorkersTotal, "1": 1, "64": 64} {
		cfg, err := handleFileWith(t, `,"workers_total":`+value, ``)
		if err != nil {
			t.Errorf("workers_total %s: %v; want it taken", value, err)
		} else if cfg.WorkersTotal != want {
			t.Errorf("workers_total %s became %d, want %d", value, cfg.WorkersTotal, want)
		}
	}
	if cfg, err := handleFileWith(t, ``, ``); err != nil || cfg.WorkersTotal != 2 {
		t.Errorf("workers_total left out: %v, %v; want 2", cfg, err)
	}
	// A route's max_parallel at workers_total is taken; one more is not,
	// and neither is the default of 2 under a total of 1.
	if _, err := handleFileWith(t, `,"workers_total":3`, `,"execution":"parallel","max_parallel":3`); err != nil {
		t.Errorf("max_parallel at workers_total: %v", err)
	}
	if _, err := handleFileWith(t, `,"workers_total":3`, `,"execution":"parallel","max_parallel":4`); err == nil ||
		!strings.Contains(err.Error(), "workers_total is 3, fewer than route \"work\"'s max_parallel of 4") {
		t.Errorf("max_parallel one past workers_total: %v", err)
	}
	if _, err := handleFileWith(t, `,"workers_total":1`, `,"execution":"parallel"`); err == nil ||
		!strings.Contains(err.Error(), "workers_total is 1, fewer than route \"work\"'s max_parallel of 2") {
		t.Errorf("a parallel route's default under a total of 1: %v", err)
	}
}

// TestLimitHandleRouteIntegers: a route's max_parallel is 0, meaning the
// default, or 1 to 64, and more than 1 only on a parallel route; its
// retries, max_queued and max_queued_bytes are zero or more, zero meaning
// the default; its max_log_bytes is zero, meaning the default, or 4096 or
// more. Each edge one step apart, the type's minimum and maximum, and the
// text forms past the type's range are held to it.
func TestLimitHandleRouteIntegers(t *testing.T) {
	minInt, maxInt := strconv.Itoa(math.MinInt), strconv.Itoa(math.MaxInt)
	minInt64, maxInt64 := strconv.FormatInt(math.MinInt64, 10), strconv.FormatInt(math.MaxInt64, 10)
	parallel := `,"execution":"parallel"`
	for _, tc := range []struct{ fields, want string }{
		{parallel + `,"max_parallel":-1`, "max_parallel is -1; it cannot be fewer than none"},
		{parallel + `,"max_parallel":` + minInt, "max_parallel is " + minInt + "; it cannot be fewer than none"},
		{parallel + `,"max_parallel":65`, "max_parallel is 65, more than this auu runs at once (64 at most)"},
		{parallel + `,"max_parallel":` + maxInt, "max_parallel is " + maxInt + ", more than this auu runs at once (64 at most)"},
		{parallel + `,"max_parallel":9223372036854775808`, "max_parallel"},
		{`,"max_parallel":2`, "a sequential route runs one at a time"},
		{`,"retries":-1`, "retries is -1; it cannot be fewer than none"},
		{`,"retries":` + minInt, "retries is " + minInt + "; it cannot be fewer than none"},
		{`,"retries":9223372036854775808`, "retries"},
		{`,"max_queued":-1`, "max_queued is -1; it cannot be fewer than none"},
		{`,"max_queued":` + minInt, "max_queued is " + minInt + "; it cannot be fewer than none"},
		{`,"max_queued":9223372036854775808`, "max_queued"},
		{`,"max_queued_bytes":-1`, "max_queued_bytes is -1; it cannot be fewer than none"},
		{`,"max_queued_bytes":` + minInt64, "max_queued_bytes is " + minInt64 + "; it cannot be fewer than none"},
		{`,"max_queued_bytes":9223372036854775808`, "max_queued_bytes"},
		{`,"max_queued_bytes":"1"`, "max_queued_bytes"},
		{`,"max_log_bytes":-1`, "max_log_bytes is -1; it cannot be fewer than none"},
		{`,"max_log_bytes":` + minInt64, "max_log_bytes is " + minInt64 + "; it cannot be fewer than none"},
		{`,"max_log_bytes":1`, "max_log_bytes is 1, too small to hold a sentence (4096 at least)"},
		{`,"max_log_bytes":4095`, "max_log_bytes is 4095, too small to hold a sentence (4096 at least)"},
		{`,"max_log_bytes":9223372036854775808`, "max_log_bytes"},
	} {
		_, err := handleFileWith(t, `,"workers_total":64`, tc.fields)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v; want %q", tc.fields, err, tc.want)
		}
	}
	for _, tc := range []struct {
		fields string
		got    func(*handleRoute) int64
		want   int64
	}{
		{``, func(r *handleRoute) int64 { return int64(r.MaxParallel) }, 1},
		{parallel, func(r *handleRoute) int64 { return int64(r.MaxParallel) }, defaultParallel},
		{`,"max_parallel":1`, func(r *handleRoute) int64 { return int64(r.MaxParallel) }, 1},
		{parallel + `,"max_parallel":64`, func(r *handleRoute) int64 { return int64(r.MaxParallel) }, 64},
		{`,"retries":0`, func(r *handleRoute) int64 { return int64(r.Retries) }, defaultRetries},
		{`,"retries":1`, func(r *handleRoute) int64 { return int64(r.Retries) }, 1},
		{`,"retries":` + maxInt, func(r *handleRoute) int64 { return int64(r.Retries) }, math.MaxInt},
		{`,"max_queued":0`, func(r *handleRoute) int64 { return int64(r.MaxQueued) }, defaultMaxQueued},
		{`,"max_queued":1`, func(r *handleRoute) int64 { return int64(r.MaxQueued) }, 1},
		{`,"max_queued":` + maxInt, func(r *handleRoute) int64 { return int64(r.MaxQueued) }, math.MaxInt},
		{`,"max_queued_bytes":0`, func(r *handleRoute) int64 { return r.MaxQueuedBytes }, defaultMaxQueuedBytes},
		{`,"max_queued_bytes":1`, func(r *handleRoute) int64 { return r.MaxQueuedBytes }, 1},
		{`,"max_queued_bytes":` + maxInt64, func(r *handleRoute) int64 { return r.MaxQueuedBytes }, math.MaxInt64},
		{`,"max_log_bytes":0`, func(r *handleRoute) int64 { return r.MaxLogBytes }, defaultMaxLogBytes},
		{`,"max_log_bytes":4096`, func(r *handleRoute) int64 { return r.MaxLogBytes }, 4096},
		{`,"max_log_bytes":` + maxInt64, func(r *handleRoute) int64 { return r.MaxLogBytes }, math.MaxInt64},
	} {
		cfg, err := handleFileWith(t, `,"workers_total":64`, tc.fields)
		if err != nil {
			t.Errorf("%s: %v; want it taken", tc.fields, err)
			continue
		}
		if got := tc.got(cfg.Routes["work"]); got != tc.want {
			t.Errorf("%s: read as %d, want %d", tc.fields, got, tc.want)
		}
	}
}

// TestLimitMaxReplyBytes: a route's max_reply_bytes is zero, meaning no
// cap, or more. A negative and the type's minimum are refused as fewer than
// none, and the text forms, one past the type's maximum, a string and a
// fraction, by the decode naming the field; zero, one and the type's
// maximum are taken, and check says which it is.
func TestLimitMaxReplyBytes(t *testing.T) {
	minInt64 := strconv.FormatInt(math.MinInt64, 10)
	for _, tc := range []struct{ value, want string }{
		{"-1", "max_reply_bytes is -1; it cannot be fewer than none"},
		{minInt64, "max_reply_bytes is " + minInt64 + "; it cannot be fewer than none"},
		{"9223372036854775808", "max_reply_bytes"},
		{"-9223372036854775809", "max_reply_bytes"},
		{`"1"`, "max_reply_bytes"},
		{"1.5", "max_reply_bytes"},
	} {
		_, err := handleFileWith(t, ``, `,"max_reply_bytes":`+tc.value)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("max_reply_bytes %s: %v; want %q", tc.value, err, tc.want)
		}
	}
	for _, want := range []int64{0, 1, math.MaxInt64} {
		cfg, err := handleFileWith(t, ``, `,"max_reply_bytes":`+strconv.FormatInt(want, 10))
		if err != nil {
			t.Errorf("max_reply_bytes %d: %v; want it taken", want, err)
		} else if got := cfg.Routes["work"].MaxReplyBytes; got != want {
			t.Errorf("max_reply_bytes %d read as %d", want, got)
		}
	}
	bob := newUser(t, "bob", startRelay(t))
	for value, want := range map[string]string{"0": "max_reply_bytes no cap,", "1": "max_reply_bytes 1 bytes,",
		strconv.FormatInt(math.MaxInt64, 10): "max_reply_bytes 9223372036854775807 bytes,"} {
		path := writeHandleFile(t, `{"v":1,"routes":{"work":{"channel":"work","command":["handlers/run.sh"],"max_reply_bytes":`+value+`}}}`)
		var out string
		captureStderr(t, func() { out = bob.run("handle", "check", "--config", path) })
		if !strings.Contains(out, want) {
			t.Errorf("max_reply_bytes %s: check printed\n%s\nwant %q", value, out, want)
		}
	}
}

// TestLimitHandleDurations: a route's timeout and keep_failed are lengths
// of time more than nothing, read from text, and left out are 30m and
// 168h. Zero, a negative, the text one past the type's maximum, a bare
// number and a number in place of the text are refused naming the field;
// one nanosecond and the type's maximum are taken.
func TestLimitHandleDurations(t *testing.T) {
	for _, field := range []string{"timeout", "keep_failed"} {
		for _, tc := range []struct{ value, want string }{
			{`"0s"`, field + " is 0s; it must be more than nothing"},
			{`"-1s"`, field + " is -1s; it must be more than nothing"},
			{`"-9223372036854775808ns"`, field + " is -9223372036854775808ns; it must be more than nothing"},
			{`"9223372036854775808ns"`, field + ` "9223372036854775808ns" is not a length of time`},
			{`"30"`, field + ` "30" is not a length of time`},
			{`30`, field},
		} {
			_, err := handleFileWith(t, ``, `,"`+field+`":`+tc.value)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("%s %s: %v; want %q", field, tc.value, err, tc.want)
			}
		}
		for text, want := range map[string]time.Duration{`"1ns"`: 1, `"9223372036854775807ns"`: math.MaxInt64, `""`: 0} {
			cfg, err := handleFileWith(t, ``, `,"`+field+`":`+text)
			if err != nil {
				t.Errorf("%s %s: %v; want it taken", field, text, err)
				continue
			}
			got := cfg.Routes["work"].timeout
			if field == "keep_failed" {
				got = cfg.Routes["work"].keepFailed
			}
			if want == 0 {
				want = defaultTimeout
				if field == "keep_failed" {
					want = defaultKeepFailed
				}
			}
			if got != want {
				t.Errorf("%s %s read as %v, want %v", field, text, got, want)
			}
		}
	}
	if cfg, err := handleFileWith(t, ``, ``); err != nil || cfg.Routes["work"].timeout != 30*time.Minute ||
		cfg.Routes["work"].keepFailed != 168*time.Hour {
		t.Errorf("the defaults: %v; want 30m and 168h", err)
	}
}

// TestLimitHandleConfigPathsResolveAgainstTheirFile: a route's program
// named with a separator and relatively is resolved against the file's own
// directory, never the working directory a unit started handle in; one
// named absolutely is left as it is; and check finds the one beside the
// file from another directory, where the same relative name names nothing.
func TestLimitHandleConfigPathsResolveAgainstTheirFile(t *testing.T) {
	fileDir := t.TempDir()
	elsewhere := t.TempDir()
	t.Chdir(elsewhere)
	beside := handleProgram(t, fileDir, filepath.Join("handlers", "run.sh"))
	dotted := handleProgram(t, fileDir, "run.sh")
	abs := handleProgram(t, t.TempDir(), "abs.sh")
	// A decoy under the working directory, which nothing must resolve to.
	handleProgram(t, elsewhere, filepath.Join("handlers", "run.sh"))
	path := filepath.Join(fileDir, handleFile)
	file := `{"v":1,"routes":{
		"a":{"channel":"a","command":["handlers/run.sh"]},
		"b":{"channel":"b","command":["./run.sh"]},
		"c":{"channel":"c","command":["` + jsonPath(abs) + `"]}}}`
	if err := os.WriteFile(path, []byte(file), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := checkHandleFile(path)
	if err != nil {
		t.Fatalf("the file checked from another directory: %v", err)
	}
	for route, want := range map[string]string{"a": beside, "b": dotted, "c": abs} {
		got := cfg.Routes[route].program
		if got != want {
			t.Errorf("route %s's program resolved to %q, want %q", route, got, want)
		}
		if rel, err := filepath.Rel(elsewhere, got); err == nil && !strings.HasPrefix(rel, "..") {
			t.Errorf("route %s's program %q resolved under the working directory", route, got)
		}
	}
	// The command's own text is kept as written: it is what the script is
	// given as its name, and what check prints on the command line.
	if got := cfg.Routes["a"].Command[0]; got != "handlers/run.sh" {
		t.Errorf("the command's first element became %q", got)
	}
	// With the program gone from beside the file, the decoy under the
	// working directory is not taken in its place.
	if err := os.Remove(beside); err != nil {
		t.Fatal(err)
	}
	if _, err := checkHandleFile(path); err == nil || !strings.Contains(err.Error(), beside+" does not exist") {
		t.Errorf("the program gone from beside the file: %v; want it refused by its resolved path", err)
	}
}

// A1: a program named with no separator is the PATH's, looked up with
// exec.LookPath at check as git is for serve, so ["python3", "x.py"] is a
// command; one the PATH does not have is refused by name.
func TestABareProgramNameIsLookedUpOnThePath(t *testing.T) {
	bin := t.TempDir()
	name := "auu-handle-test-program"
	file := name
	if runtime.GOOS == "windows" {
		file += ".exe"
	}
	program := handleProgram(t, bin, file)
	t.Setenv("PATH", bin)
	// A file of the same name beside the handle file is not what a bare
	// name means.
	path := writeHandleFile(t, `{"v":1,"routes":{"work":{"channel":"work","command":["`+name+`","import.py"]}}}`)
	handleProgram(t, filepath.Dir(path), file)
	cfg, err := checkHandleFile(path)
	if err != nil {
		t.Fatalf("a bare name on the PATH: %v", err)
	}
	if got := cfg.Routes["work"].program; got != program {
		t.Fatalf("the program resolved to %q, want %q from the PATH", got, program)
	}
	missing := writeHandleFile(t, `{"v":1,"routes":{"work":{"channel":"work","command":["auu-handle-no-such-program"]}}}`)
	_, err = checkHandleFile(missing)
	want := missing + `: route "work": command's program "auu-handle-no-such-program" is not on the PATH: `
	if err == nil || !strings.HasPrefix(err.Error(), want) {
		t.Fatalf("a bare name not on the PATH: %v\nwant it to begin %s", err, want)
	}
}

// Route ids that are one directory where case does not count are refused
// by check, which compares them under strings.EqualFold, whichever way
// round they sort; é composed and decomposed, which check sees as two
// names, are refused by the disk probe under handle/ where the disk takes
// them as one, and taken where it does not. The probe leaves nothing.
func TestHandleRouteIdsThatFoldAreRefused(t *testing.T) {
	two := func(a, b string) string {
		return `{"v":1,"workers_total":2,"routes":{"` + a + `":{"channel":"one","command":["handlers/run.sh"]},"` +
			b + `":{"channel":"two","command":["handlers/run.sh"]}}}`
	}
	// In a file, the strict decode refuses two keys that fold before check
	// is reached, naming both.
	for _, pair := range [][2]string{{"work", "WORK"}, {"Import", "import"}} {
		_, err := checkHandleFile(writeHandleFile(t, two(pair[0], pair[1])))
		if err == nil || !strings.Contains(err.Error(), "the same under case folding") {
			t.Errorf("%q and %q in a file: %v; want the decode's refusal", pair[0], pair[1], err)
		}
	}
	// check holds the routes it is given to the same rule whatever made
	// them, by its own sentence, whichever way round they sort; a pair
	// EqualFold keeps apart is taken.
	program := handleProgram(t, t.TempDir(), "run.sh")
	built := func(a, b string) *handleConfig {
		route := func(name, channel string) *handleRoute {
			return &handleRoute{Channel: channel, Command: []string{program}, Execution: executionSequential, MaxParallel: 1,
				Retries: 3, MaxQueued: 1, MaxQueuedBytes: 1, MaxLogBytes: minMaxLogBytes, name: name, program: program}
		}
		return &handleConfig{V: 1, WorkersTotal: 2, path: "handle.json",
			Routes: map[string]*handleRoute{a: route(a, "one"), b: route(b, "two")}}
	}
	for _, pair := range [][2]string{{"work", "WORK"}, {"Import", "import"}, {"straße", "STRASSE"}} {
		err := built(pair[0], pair[1]).check()
		if !strings.EqualFold(pair[0], pair[1]) {
			if err != nil {
				t.Errorf("%q and %q, which EqualFold keeps apart: %v", pair[0], pair[1], err)
			}
			continue
		}
		first, second := pair[0], pair[1]
		if second < first {
			first, second = second, first
		}
		want := `handle.json: route "` + second + `": routes "` + first + `" and "` + second + `" are one directory where case does not count; rename one`
		if err == nil || err.Error() != want {
			t.Errorf("%q and %q: %v\nwant %s", pair[0], pair[1], err, want)
		}
	}

	composed, decomposed := "caf\u00e9", "cafe\u0301"
	path := writeHandleFile(t, two(composed, decomposed))
	cfg, err := checkHandleFile(path)
	if err != nil {
		t.Fatalf("check, which compares case, refused the two spellings: %v", err)
	}
	handleDir := filepath.Join(t.TempDir(), "handle")
	if err := os.MkdirAll(handleDir, 0o700); err != nil {
		t.Fatal(err)
	}
	folds := diskFolds(t, handleDir, composed, decomposed)
	err = cfg.checkFolds(handleDir)
	if folds {
		if err == nil || !strings.Contains(err.Error(), "are one directory on this filesystem, which takes them as one name; rename one") {
			t.Fatalf("this disk takes the two spellings as one, and checkFolds said: %v", err)
		}
	} else if err != nil {
		t.Fatalf("this disk keeps the two spellings apart, and checkFolds refused them: %v", err)
	}
	t.Logf("the disk under %s folds é composed and decomposed: %v", handleDir, folds)
	if entries, _ := os.ReadDir(handleDir); len(entries) != 0 {
		t.Fatalf("the probe left %v under handle/", entries)
	}
	// Under a home that has no handle/ yet, the probe makes it and leaves
	// it empty, as serve's does.
	fresh := filepath.Join(t.TempDir(), "handle")
	if err := cfg.checkFolds(fresh); err != nil && !folds {
		t.Fatalf("checkFolds under a fresh directory: %v", err)
	}
	if entries, _ := os.ReadDir(fresh); len(entries) != 0 {
		t.Fatalf("the probe left %v under a fresh handle/", entries)
	}
}

// A route on the default channel is taken, and check says on stderr, by
// the route's name, that a reply to one of its acknowledgements lands
// there and is left unhandled; a route elsewhere earns no such line.
func TestARouteOnDefaultIsTakenWithAWarning(t *testing.T) {
	bob := newUser(t, "bob", startRelay(t))
	onDefault := writeHandleFile(t, `{"v":1,"routes":{"inbox":{"channel":"default","command":["handlers/run.sh"]}}}`)
	var out string
	stderr := captureStderr(t, func() { out = bob.run("handle", "check", "--config", onDefault) })
	want := `auu: route "inbox" handles the default channel: a reply to one of its acknowledgements arrives there and is left unhandled, as every reply is` + "\n"
	if !strings.Contains(stderr, want) {
		t.Fatalf("check said on stderr:\n%s\nwant %q in it", stderr, want)
	}
	if !strings.Contains(out, "is good for 1 route\n") {
		t.Fatalf("check printed:\n%s", out)
	}
	elsewhere := writeHandleFile(t, `{"v":1,"routes":{"inbox":{"channel":"documents","command":["handlers/run.sh"]}}}`)
	stderr = captureStderr(t, func() { bob.run("handle", "check", "--config", elsewhere) })
	if strings.Contains(stderr, "handles the default channel") {
		t.Fatalf("a route off default was warned about:\n%s", stderr)
	}
}

// routeIdsAreNotPathsAtCheckFolds is the second half of
// TestLimitAChannelNameIsNotAPathAtCheckFolds: checkFolds joins a route's
// id under its probe directory beneath handle/, and every value of the
// traversal set is refused by channels.ValidName or the shape rule at
// check before checkFolds is reached; a value check takes makes nothing
// beside the probe, and the probe goes.
func routeIdsAreNotPathsAtCheckFolds(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	handleProgram(t, dir, "run.sh")
	for _, v := range pathSet() {
		cfg := &handleConfig{V: 1, WorkersTotal: 2, path: filepath.Join(dir, handleFile),
			Routes: map[string]*handleRoute{v: {Channel: "work", Command: []string{"./run.sh"}, Execution: executionSequential,
				MaxParallel: 1, Retries: 3, MaxQueued: 1, MaxQueuedBytes: 1, MaxLogBytes: minMaxLogBytes,
				name: v, program: filepath.Join(dir, "run.sh")}}}
		if err := cfg.check(); err == nil {
			scratch := t.TempDir()
			handleDir := filepath.Join(scratch, "handle")
			if err := cfg.checkFolds(handleDir); err != nil {
				t.Errorf("checkFolds of %q, which check took: %v", v, err)
			}
			if entries, _ := os.ReadDir(scratch); len(entries) != 1 || entries[0].Name() != "handle" {
				t.Errorf("checkFolds of %q made %v beside handle/", v, entries)
			}
			if entries, _ := os.ReadDir(handleDir); len(entries) != 0 {
				t.Errorf("checkFolds of %q left %v under handle/", v, entries)
			}
		}
	}
}

// check holds the routes to the serve.json in the home: a route on a
// channel serve answers is refused by its sentence, naming both files; a
// channel serve does not answer is taken; a serve.json that will not read
// is refused naming both, since nothing could then say which channels it
// serves; and a home with no serve.json at all is taken.
func TestHandleCheckHoldsItsRoutesToServeJSONInTheHome(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not on the PATH")
	}
	bob := newUser(t, "bob", startRelay(t))
	repo := t.TempDir()
	if out, err := exec.Command("git", "-C", repo, "init", "-q").CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}
	served := filepath.Join(bob.home, serveFile)
	onChannel := func(channel string) string {
		return writeHandleFile(t, `{"v":1,"routes":{"work":{"channel":"`+channel+`","command":["handlers/run.sh"]}}}`)
	}
	check := func(path string) error {
		var err error
		captureStderr(t, func() { _, err = bob.tryRun("handle", "check", "--config", path) })
		return err
	}

	// No serve.json at all.
	if err := check(onChannel("jostle")); err != nil {
		t.Fatalf("a home with no serve.json: %v", err)
	}

	if err := os.WriteFile(served, []byte(`{"v":1,"channels":{"jostle":{"dir":"`+jsonPath(repo)+`","exec":"cat"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	path := onChannel("jostle")
	want := path + `: route "work": channel "jostle" is served by ` + served + `; a channel belongs to one service, serve's or handle's`
	err := check(path)
	var exit *exitError
	if !errors.As(err, &exit) || exit.code != exitUsage || err.Error() != want {
		t.Fatalf("a route on a channel serve.json serves: %v\nwant %s", err, want)
	}
	if err := check(onChannel("documents")); err != nil {
		t.Fatalf("a route on a channel serve.json does not serve: %v", err)
	}

	if err := os.WriteFile(served, []byte(`{"v":1,"channels":{"jostle":{"dir":"`+jsonPath(repo)+`","exec":"cat"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	path = onChannel("documents")
	prefix := path + ": its routes are checked against " + served + ", which will not read: "
	err = check(path)
	if !errors.As(err, &exit) || exit.code != exitUsage || !strings.HasPrefix(err.Error(), prefix) {
		t.Fatalf("a serve.json that will not read: %v\nwant it to begin %s", err, prefix)
	}
}
