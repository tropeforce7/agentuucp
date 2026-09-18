package auu

import (
	"fmt"

	"github.com/tropeforce7/agentuucp/internal/buildinfo"
	"github.com/tropeforce7/agentuucp/skill"
)

// versionJSON is what --json prints: the version, and the Claude Code
// skills the binary carries, since they travel with it and a person
// checking an upgrade wants to see both. The relay says its schema beside
// its version; auu has none.
type versionJSON struct {
	Version string   `json:"version"`
	Skills  []string `json:"skills"`
}

// cmdVersion says what this binary was built from. A build with no version
// control information behind it says so rather than inventing a number.
func cmdVersion(args []string) error {
	fs := newFlagSet("version")
	asJSON := fs.Bool("json", false, "machine readable output")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) > 0 {
		return usageErrf("unexpected argument %q", positional[0])
	}
	if *asJSON {
		return printJSON(versionJSON{Version: buildinfo.Version(), Skills: skill.Names()})
	}
	fmt.Printf("%s %s\n", prog, buildinfo.Version())
	return nil
}
