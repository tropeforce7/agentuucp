package main

import (
	"math"
	"strconv"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/relay"
	"github.com/tropeforce7/agentuucp/internal/token"
)

// TestLimitAdminFlags: mailboxes ls --limit is one or more; token issue
// --uses is within [1, MaxUses] and --expires at least a second. Each is
// read as text by the flag package: zero where zero is not allowed, a
// negative, the type's minimum, one over a ceiling and the type's maximum
// are refused naming the flag and the bound; the text one past the
// type's maximum, a sign inside the digits, a leading space and a digit
// outside ASCII are not numbers; the floor, a plus sign and the ceiling
// are taken.
func TestLimitAdminFlags(t *testing.T) {
	f := newFixture(t, relay.Config{})
	refused := func(t *testing.T, want string, args ...string) {
		t.Helper()
		_, err := f.boss.tryRun(args...)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%v: %v; want %q", args, err, want)
		}
	}
	taken := func(t *testing.T, args ...string) {
		t.Helper()
		if _, err := f.boss.tryRun(args...); err != nil {
			t.Errorf("%v: %v; want it taken", args, err)
		}
	}

	t.Run("limit", func(t *testing.T) {
		for _, v := range []string{"0", "-1", strconv.Itoa(math.MinInt)} {
			refused(t, "--limit must be at least 1, got "+v, "mailboxes", "ls", "--limit", v)
		}
		for _, v := range []string{"9223372036854775808", "1-2", " 1", "\u0661", "1.0"} {
			refused(t, `invalid value "`+v+`" for flag -limit`, "mailboxes", "ls", "--limit", v)
		}
		for _, v := range []string{"1", "+1", strconv.Itoa(math.MaxInt)} {
			taken(t, "mailboxes", "ls", "--limit", v)
		}
	})

	t.Run("uses", func(t *testing.T) {
		max := strconv.Itoa(token.MaxUses)
		for _, v := range []string{"0", "-1", strconv.Itoa(token.MaxUses + 1), strconv.Itoa(math.MinInt), strconv.Itoa(math.MaxInt)} {
			refused(t, "--uses must be between 1 and "+max+", got "+v, "token", "issue", "--note", "x", "--uses", v)
		}
		for _, v := range []string{"9223372036854775808", "1-2", " 1", "\u0661"} {
			refused(t, `invalid value "`+v+`" for flag -uses`, "token", "issue", "--note", "x", "--uses", v)
		}
		for _, v := range []string{"1", "+1", max} {
			taken(t, "token", "issue", "--note", "x", "--uses", v)
		}
	})

	t.Run("expires", func(t *testing.T) {
		for _, v := range []string{"0s", "999ms", "-1s", "-9223372036854775808ns"} {
			refused(t, "--expires must be at least 1s, got ", "token", "issue", "--note", "x", "--expires", v)
		}
		for _, v := range []string{"9223372036854775808ns", "1", "\u0661s", ""} {
			refused(t, `invalid value "`+v+`" for flag -expires`, "token", "issue", "--note", "x", "--expires", v)
		}
		for _, v := range []string{"1s", "+1s", "1000ms"} {
			taken(t, "token", "issue", "--note", "x", "--expires", v)
		}
	})
}
