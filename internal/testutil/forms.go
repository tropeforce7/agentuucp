package testutil

import (
	"path"
	"regexp"
	"slices"
	"strings"
)

// The documents name commands in code spans and fenced blocks, and the tests
// that hold those forms to the programs read them through FormPieces, so
// that every reader cuts a line the same way.

// formSeparator is where a shell line holds more than one command: `;`,
// `&&`, a pipe, and the start of a command substitution, whose closing
// bracket is left on the last word and does not matter to it. `||` is two
// pipes, and the empty piece between them is left out.
var formSeparator = regexp.MustCompile(`;|&&|\||\$\(`)

// assignment is a variable set in front of a command, `AUU_HOME=/x auu`.
var assignment = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

// FormPieces cuts one line of a document into the commands it holds, each
// with what a document writes in front of a program taken off: a prompt
// (`$ `), sudo and its options, env and its settings, a variable set for the
// command, systemd's `ExecStart=`, and a bin directory's path, so that `sudo -u auu env
// AUU_HOME=/x /usr/local/bin/auu inbox` is read as `auu inbox`. A piece that
// is empty once that is gone is left out.
func FormPieces(line string) []string {
	var out []string
	for _, piece := range formSeparator.Split(line, -1) {
		fields := strings.Fields(piece)
		fields = stripPrefixes(fields)
		if len(fields) == 0 {
			continue
		}
		// A program run from a bin directory (bin/auu, ~/go/bin/auu,
		// /usr/local/bin/auu) is that program; any other path, a source
		// directory or a listing's line for one, is not a command. A
		// listing's line for a file in a bin directory is read as a form,
		// and passes while the words after the path name no command.
		if strings.Contains(fields[0], "/") && path.Base(path.Dir(fields[0])) == "bin" {
			fields[0] = path.Base(fields[0])
		}
		out = append(out, strings.Join(fields, " "))
	}
	return out
}

// stripPrefixes takes off the words in front of the program, one kind at a
// time, until the first word is none of them.
func stripPrefixes(fields []string) []string {
	for len(fields) > 0 {
		switch first := fields[0]; {
		case first == "$":
			fields = fields[1:]
		case first == "sudo":
			fields = options(fields[1:], "-u", "-g", "-C", "-D", "-U", "-p", "--user", "--group")
		case first == "env":
			fields = options(fields[1:], "-u", "-C", "--unset", "--chdir")
		case strings.HasPrefix(first, "ExecStart="):
			fields[0] = strings.TrimPrefix(first, "ExecStart=")
			if fields[0] == "" {
				fields = fields[1:]
			}
		case assignment.MatchString(first):
			fields = fields[1:]
		default:
			return fields
		}
	}
	return fields
}

// options takes off the options in front of a command, each of those named
// taking the next word with it, and returns what follows them.
func options(fields []string, takeAWord ...string) []string {
	for len(fields) > 0 && strings.HasPrefix(fields[0], "-") {
		if slices.Contains(takeAWord, fields[0]) {
			fields = fields[min(2, len(fields)):]
			continue
		}
		fields = fields[1:]
	}
	return fields
}
