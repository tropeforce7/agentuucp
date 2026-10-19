package auu

import (
	"flag"
	"fmt"
	"strconv"
	"strings"

	"github.com/tropeforce7/agentuucp/internal/channels"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// A channel's own rules on the owner's command line: --max-bytes N|none,
// --no-streams or --streams, --no-forwards or --forwards (the
// channel-policy work's commit 3). Any of them set makes the directory
// version 2.

// ruleFlags are the rule flags of channel create and channel update.
type ruleFlags struct {
	maxBytes             *string
	noStreams, streams   *bool
	noForwards, forwards *bool
}

// ruleFlagNames are the five rule flags, as update's "nothing to change"
// names them beside the other three.
var ruleFlagNames = []string{"max-bytes", "no-streams", "streams", "no-forwards", "forwards"}

func addRuleFlags(fs *flag.FlagSet) *ruleFlags {
	return &ruleFlags{
		maxBytes: fs.String("max-bytes", "", "the largest message the channel takes, in wire bytes "+
			"(an envelope, or a sealed stream with its manifest), or none for the relay's own cap"),
		noStreams:  fs.Bool("no-streams", false, "the channel takes no streams"),
		streams:    fs.Bool("streams", false, "the channel takes streams again"),
		noForwards: fs.Bool("no-forwards", false, "the channel takes no mail by way of another relay"),
		forwards:   fs.Bool("forwards", false, "the channel takes mail by way of another relay again"),
	}
}

// anyGiven says whether any rule flag was given.
func (rf *ruleFlags) anyGiven(given map[string]bool) bool {
	for _, name := range ruleFlagNames {
		if given[name] {
			return true
		}
	}
	return false
}

// apply sets the rules given on ch, refusing a pair given both ways.
func (rf *ruleFlags) apply(ch *channels.Channel, given map[string]bool) error {
	if given["no-streams"] && given["streams"] {
		return usageErrf("--no-streams and --streams say opposite things; give one")
	}
	if given["no-forwards"] && given["forwards"] {
		return usageErrf("--no-forwards and --forwards say opposite things; give one")
	}
	if given["max-bytes"] {
		n, err := parseMaxBytes(*rf.maxBytes)
		if err != nil {
			return err
		}
		ch.MaxBytes = n
	}
	if given["no-streams"] {
		ch.NoStreams = *rf.noStreams
	}
	if given["streams"] && *rf.streams {
		ch.NoStreams = false
	}
	if given["no-forwards"] {
		ch.NoForwards = *rf.noForwards
	}
	if given["forwards"] && *rf.forwards {
		ch.NoForwards = false
	}
	return nil
}

// parseMaxBytes reads --max-bytes: none, for the relay's own cap, or a
// whole number of bytes from 1, written in decimal digits alone, so that
// "+1", " 1" and "1e3" are refused rather than read as something else.
// The upper bound is the relays' and the format's, held where the edit is
// checked.
func parseMaxBytes(v string) (int64, error) {
	if v == "none" {
		return 0, nil
	}
	if v == "" || strings.Trim(v, "0123456789") != "" {
		return 0, usageErrf("--max-bytes %q: give a whole number of bytes, in digits, or none for the relay's own cap", v)
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, usageErrf("--max-bytes %s: more than any relay takes; the most is %d", v, relayapi.MaxStreamSize)
	}
	if n == 0 {
		return 0, usageErrf("--max-bytes 0: give a number of bytes from 1, or none for the relay's own cap")
	}
	return n, nil
}

// ruleText is a channel's rules as the RULE column shows them: "-" for
// none, otherwise the size and the two refusals joined with ", ".
func ruleText(ch channelJSON) string {
	var parts []string
	if ch.MaxBytes > 0 {
		parts = append(parts, "≤ "+byteSize(ch.MaxBytes))
	}
	if ch.NoStreams {
		parts = append(parts, "no streams")
	}
	if ch.NoForwards {
		parts = append(parts, "no forwards")
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, ", ")
}

// byteSize writes a size exactly: in GiB, MiB or KiB when it is a whole
// number of them, and in bytes otherwise.
func byteSize(n int64) string {
	for _, u := range []struct {
		size int64
		name string
	}{{1 << 30, "GiB"}, {1 << 20, "MiB"}, {1 << 10, "KiB"}} {
		if n >= u.size && n%u.size == 0 {
			return fmt.Sprintf("%d %s", n/u.size, u.name)
		}
	}
	return fmt.Sprintf("%d bytes", n)
}
