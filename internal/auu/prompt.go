package auu

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// The prompts a command puts to a person read their answers through one
// reader on standard input, shared for the length of the command.
//
// Each prompt used to make its own bufio.Reader over os.Stdin. On a
// terminal that works, since the tty hands over one line at a time; through
// a pipe — the tests' answer helper, and `docker exec -i` — the first
// reader's buffer takes everything the pipe holds, and a second prompt's
// reader finds end of file and takes its fallback. A command that asks
// twice, `peers fetch` and `knock` (a confirmation, then the local name)
// and `quarantine trust` on a knock (the local name, then the offer to
// push), lost the second answer. The reader is made when os.Stdin is
// first read and remade when os.Stdin is another file, which is how the
// tests hand a command its answers.
var stdin struct {
	reader *bufio.Reader
	file   *os.File
}

// stdinLine reads one line from standard input through the shared reader.
func stdinLine() (string, error) {
	if stdin.reader == nil || stdin.file != os.Stdin {
		stdin.reader = bufio.NewReader(os.Stdin)
		stdin.file = os.Stdin
	}
	return stdin.reader.ReadString('\n')
}

// confirm asks a yes-or-no question at the terminal and reports the answer.
// Anything but y or yes, including an empty line or end of file, is no.
func confirm(question string) bool {
	fmt.Printf("%s [y/N]: ", question)
	line, err := stdinLine()
	if err != nil && line == "" {
		fmt.Println()
		return false
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	default:
		return false
	}
}

// promptName asks for a local name for a peer about to be added, offering
// fallback as the default. A name from the wire — the one on a card, or
// the one a relay registered — is offered and never taken: names are
// local labels, and a person accepts the suggestion or types another. An
// empty answer, end of file, or a line with a break in it takes the
// fallback.
func promptName(fp, fallback string) string {
	fmt.Printf("Local name for %s [%s]: ", fp[:16], fallback)
	line, err := stdinLine()
	if err != nil && line == "" {
		fmt.Println()
		return fallback
	}
	name := strings.TrimSpace(line)
	if name == "" || strings.ContainsAny(name, "\r\n") {
		return fallback
	}
	return name
}
