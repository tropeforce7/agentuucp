package auu

import (
	"fmt"

	"github.com/tropeforce7/agentuucp/internal/buildinfo"
)

// versionJSON is what --json prints: one field, because one is what this
// binary knows about itself. The relay says its schema beside its version;
// auu has none.
type versionJSON struct {
	Version string `json:"version"`
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
		return printJSON(versionJSON{Version: buildinfo.Version()})
	}
	fmt.Printf("%s %s\n", prog, buildinfo.Version())
	return nil
}
