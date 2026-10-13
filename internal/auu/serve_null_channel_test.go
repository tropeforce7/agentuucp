package auu

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// nullChannelSentence is what a channel written as null earns, word for
// word: the file, the channel by name, and what a channel is instead. A
// person reading it is looking at the file.
func nullChannelSentence(path, name string) string {
	return path + `: channel "` + name + `": it is null; a channel is an object, with dir and exec at least`
}

// writeServeFile puts a serve file in a directory of its own and returns
// its path.
func writeServeFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "serve.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// The strict decode takes null for a *serveChannel as nil, and the loader
// set the nil channel's name and panicked. Codex's review test, under a name
// that says what it proves, with the sentence asserted.
func TestANullServeChannelIsAConfigErrorNamingTheFileAndTheChannel(t *testing.T) {
	path := filepath.Join(t.TempDir(), "serve.json")
	if err := os.WriteFile(path, []byte(`{"v":1,"channels":{"codex":null}}`), 0600); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if v := recover(); v != nil {
			t.Errorf("config loader panicked on null channel: %v; want named config error", v)
		}
	}()
	_, err := loadServeConfig(path)
	if err == nil {
		t.Fatal("null channel accepted; want config error")
	}
	var exit *exitError
	if !errors.As(err, &exit) || exit.code != exitUsage {
		t.Fatalf("the refusal is %v (%T), want a usage error", err, err)
	}
	msg := err.Error()
	for _, want := range []string{path, `"codex"`, "null"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("the refusal is %q, want %q in it", msg, want)
		}
	}
	if msg != nullChannelSentence(path, "codex") {
		t.Fatalf("the refusal is %q, want %q", msg, nullChannelSentence(path, "codex"))
	}
}

// mixedServeFiles is a valid channel beside a null one, with the null
// sorting first and then last, so the loader meets it whichever it reaches
// first. The valid channel is a real repository and an exec check accepts,
// and alone it loads and checks clean, which the test asserts, so the
// refusal is the null's and nothing else's.
func mixedServeFiles(t *testing.T) (dir string, rows []struct{ name, valid, file string }) {
	t.Helper()
	dir = repo(t)
	for _, valid := range []string{"zulu", "alpha"} {
		rows = append(rows, struct{ name, valid, file string }{
			name:  "null sorts " + map[string]string{"zulu": "first", "alpha": "last"}[valid],
			valid: valid,
			file: `{"v":1,"channels":{"` + valid + `":{"dir":"` + jsonPath(dir) + `","exec":"x"},` +
				`"codex":null}}`,
		})
	}
	return dir, rows
}

func TestANullServeChannelBesideAValidOneIsRefusedByName(t *testing.T) {
	dir, rows := mixedServeFiles(t)
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			// The valid channel alone is good: loaded and checked.
			alone := writeServeFile(t, `{"v":1,"channels":{"`+row.valid+`":{"dir":"`+jsonPath(dir)+`","exec":"x"}}}`)
			cfg, err := loadServeConfig(alone)
			if err != nil {
				t.Fatalf("the valid channel alone: %v", err)
			}
			if err := cfg.check(); err != nil {
				t.Fatalf("the valid channel alone does not check: %v", err)
			}

			path := writeServeFile(t, row.file)
			defer func() {
				if v := recover(); v != nil {
					t.Errorf("config loader panicked on a null channel beside %q: %v", row.valid, v)
				}
			}()
			cfg, err = loadServeConfig(path)
			if err == nil {
				t.Fatalf("a file with a null channel loaded: %+v", cfg)
			}
			var exit *exitError
			if !errors.As(err, &exit) || exit.code != exitUsage {
				t.Fatalf("the refusal is %v (%T), want a usage error", err, err)
			}
			if err.Error() != nullChannelSentence(path, "codex") {
				t.Fatalf("the refusal is %q, want %q", err.Error(), nullChannelSentence(path, "codex"))
			}
			if strings.Contains(err.Error(), row.valid) {
				t.Fatalf("the refusal names the valid channel: %q", err.Error())
			}
		})
	}
}

// serve check, as its own process, so that what a person sees is what is
// asserted: the exit code, the sentence on stderr, and no panic or stack.
func TestServeCheckRefusesANullChannelWithItsSentence(t *testing.T) {
	bob := newUser(t, "bob", startRelay(t))
	_, mixed := mixedServeFiles(t)
	cases := []struct{ name, file string }{
		{"null alone", `{"v":1,"channels":{"codex":null}}`},
	}
	for _, row := range mixed {
		cases = append(cases, struct{ name, file string }{row.name, row.file})
	}
	for _, row := range cases {
		t.Run(row.name, func(t *testing.T) {
			path := writeServeFile(t, row.file)
			stdout, stderr, code := bob.inAnotherProcess("serve", "check", "--config", path)
			if code != exitUsage {
				t.Fatalf("serve check exited %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitUsage, stdout, stderr)
			}
			if !strings.Contains(stderr, nullChannelSentence(path, "codex")) {
				t.Fatalf("stderr is:\n%s\nwant %q in it", stderr, nullChannelSentence(path, "codex"))
			}
			for _, bad := range []string{"panic", "goroutine"} {
				if strings.Contains(stdout+stderr, bad) {
					t.Fatalf("serve check printed %q:\nstdout:\n%s\nstderr:\n%s", bad, stdout, stderr)
				}
			}
		})
	}
}

// The control: an empty object is a channel, not a null, and is refused by
// the rule for its first missing field, not by the null sentence.
func TestAnEmptyServeChannelIsRefusedForItsDirNotAsNull(t *testing.T) {
	path := writeServeFile(t, `{"v":1,"channels":{"codex":{}}}`)
	cfg, err := loadServeConfig(path)
	if err == nil {
		err = cfg.check()
	}
	if err == nil {
		t.Fatal("an empty channel loaded and checked")
	}
	if strings.Contains(err.Error(), "it is null") {
		t.Fatalf("an empty object earned the null sentence: %q", err.Error())
	}
	if !strings.Contains(err.Error(), `channel "codex": dir is required`) {
		t.Fatalf("the refusal is %q, want the dir rule", err.Error())
	}
}
