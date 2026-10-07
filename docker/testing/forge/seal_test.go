package main

import (
	"strings"
	"testing"
)

// seal refuses what it was not given, and a section name the wire's rule
// refuses, before it opens any home.
func TestSealRefusesBeforeOpeningAHome(t *testing.T) {
	home := t.TempDir() + "/no-such-home"
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"--to", "bob", "--section", "x"}, "--home, --to and --section are required"},
		{[]string{"--home", home, "--section", "x"}, "--home, --to and --section are required"},
		{[]string{"--home", home, "--to", "bob"}, "--home, --to and --section are required"},
		{[]string{"--home", home, "--to", "bob", "--section", "Not-A-Name"}, "does not begin with a lowercase letter"},
		{[]string{"--home", home, "--to", "bob", "--section", "x", "extra"}, `unexpected argument "extra"`},
	} {
		err := cmdSeal(c.args)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("seal %v: %v; want %q", c.args, err, c.want)
		}
	}
}
