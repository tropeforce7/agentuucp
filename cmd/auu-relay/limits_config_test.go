package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/relay"
)

func TestLimitDefaults(t *testing.T) {
	cfg, err := resolve(t, "")
	if err != nil {
		t.Fatal(err)
	}
	want := relay.DefaultLimits()
	got := cfg.Limits.Relay()
	if got.RequestsPerMinute != want.RequestsPerMinute ||
		got.PostsPerMinute != want.PostsPerMinute ||
		got.PostBytesPerHour != want.PostBytesPerHour ||
		got.UnauthenticatedPerMinute != want.UnauthenticatedPerMinute ||
		got.RegistrationsPerHour != want.RegistrationsPerHour ||
		got.MaxMailboxes != want.MaxMailboxes ||
		got.MailboxMaxMessages != want.MailboxMaxMessages ||
		got.MailboxMaxBytes != want.MailboxMaxBytes ||
		got.RelayMaxBytes != want.RelayMaxBytes ||
		got.MaxOpenUploads != want.MaxOpenUploads ||
		got.MaxInflight != want.MaxInflight ||
		got.MaxWaiting != want.MaxWaiting ||
		got.KnockMaxBytes != want.KnockMaxBytes ||
		got.MaxKnocksWaiting != want.MaxKnocksWaiting ||
		got.KnocksPerHour != want.KnocksPerHour {
		t.Fatalf("the command's defaults have drifted from the relay's:\n got %+v\nwant %+v", got, want)
	}
	if cfg.AccessLog != relay.AccessLogFull {
		t.Fatalf("access_log %q, want %q", cfg.AccessLog, relay.AccessLogFull)
	}
}

func TestLimitsFromFile(t *testing.T) {
	file := writeFile(t, `{
	  "limits": {
	    "requests_per_minute": 10,
	    "posts_per_minute": 5,
	    "post_bytes_per_hour": 1024,
	    "unauthenticated_per_minute": 4,
	    "registrations_per_hour": 3,
	    "max_mailboxes": 2,
	    "mailbox_max_messages": 7,
	    "mailbox_max_bytes": 2048,
	    "relay_max_bytes": 4096,
	    "max_open_uploads": 6,
	    "max_inflight": 9,
	    "max_waiting": 8,
	    "knock_max_bytes": 512,
	    "max_knocks_waiting": 3,
	    "knocks_per_hour": 2
	  },
	  "access_log": "minimal"
	}`)
	cfg, err := resolve(t, file)
	if err != nil {
		t.Fatal(err)
	}
	l := cfg.Limits
	for _, c := range []struct {
		name string
		got  int64
		want int64
	}{
		{"requests_per_minute", l.RequestsPerMinute, 10},
		{"posts_per_minute", l.PostsPerMinute, 5},
		{"post_bytes_per_hour", l.PostBytesPerHour, 1024},
		{"unauthenticated_per_minute", l.UnauthenticatedPerMinute, 4},
		{"registrations_per_hour", l.RegistrationsPerHour, 3},
		{"max_mailboxes", l.MaxMailboxes, 2},
		{"mailbox_max_messages", l.MailboxMaxMessages, 7},
		{"mailbox_max_bytes", l.MailboxMaxBytes, 2048},
		{"relay_max_bytes", l.RelayMaxBytes, 4096},
		{"max_open_uploads", l.MaxOpenUploads, 6},
		{"max_inflight", l.MaxInflight, 9},
		{"max_waiting", l.MaxWaiting, 8},
		{"knock_max_bytes", l.KnockMaxBytes, 512},
		{"max_knocks_waiting", l.MaxKnocksWaiting, 3},
		{"knocks_per_hour", l.KnocksPerHour, 2},
	} {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
	}
	if cfg.AccessLog != relay.AccessLogMinimal {
		t.Errorf("access_log %q", cfg.AccessLog)
	}
}

func TestEveryLimitFlagOverridesTheFile(t *testing.T) {
	file := writeFile(t, `{
	  "limits": {
	    "requests_per_minute": 10,
	    "posts_per_minute": 10,
	    "post_bytes_per_hour": 10,
	    "unauthenticated_per_minute": 10,
	    "registrations_per_hour": 10,
	    "max_mailboxes": 10,
	    "mailbox_max_messages": 10,
	    "mailbox_max_bytes": 10,
	    "relay_max_bytes": 10,
	    "max_open_uploads": 10,
	    "max_inflight": 10,
	    "max_waiting": 10,
	    "knock_max_bytes": 10,
	    "max_knocks_waiting": 10,
	    "knocks_per_hour": 10
	  },
	  "access_log": "full"
	}`)
	cfg, err := resolve(t, file,
		"--limit-requests", "1",
		"--limit-posts", "2",
		"--limit-post-bytes", "3",
		"--limit-unauthenticated", "4",
		"--limit-registrations", "5",
		"--max-mailboxes", "6",
		"--mailbox-max-messages", "7",
		"--mailbox-max-bytes", "8",
		"--relay-max-bytes", "9",
		"--max-open-uploads", "13",
		"--max-inflight", "12",
		"--max-waiting", "11",
		"--knock-max-bytes", "14",
		"--max-knocks-waiting", "15",
		"--knocks-per-hour", "16",
		"--access-log", "minimal")
	if err != nil {
		t.Fatal(err)
	}
	l := cfg.Limits
	for _, c := range []struct {
		name string
		got  int64
		want int64
	}{
		{"requests_per_minute", l.RequestsPerMinute, 1},
		{"posts_per_minute", l.PostsPerMinute, 2},
		{"post_bytes_per_hour", l.PostBytesPerHour, 3},
		{"unauthenticated_per_minute", l.UnauthenticatedPerMinute, 4},
		{"registrations_per_hour", l.RegistrationsPerHour, 5},
		{"max_mailboxes", l.MaxMailboxes, 6},
		{"mailbox_max_messages", l.MailboxMaxMessages, 7},
		{"mailbox_max_bytes", l.MailboxMaxBytes, 8},
		{"relay_max_bytes", l.RelayMaxBytes, 9},
		{"max_open_uploads", l.MaxOpenUploads, 13},
		{"max_inflight", l.MaxInflight, 12},
		{"max_waiting", l.MaxWaiting, 11},
		{"knock_max_bytes", l.KnockMaxBytes, 14},
		{"max_knocks_waiting", l.MaxKnocksWaiting, 15},
		{"knocks_per_hour", l.KnocksPerHour, 16},
	} {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
	}
	if cfg.AccessLog != relay.AccessLogMinimal {
		t.Errorf("access_log %q", cfg.AccessLog)
	}
}

func TestZeroLimitsSurviveTheFile(t *testing.T) {
	// A private relay switches the lot off, and an absent key must not put a
	// default back.
	file := writeFile(t, `{
	  "limits": {
	    "requests_per_minute": 0,
	    "posts_per_minute": 0,
	    "post_bytes_per_hour": 0,
	    "unauthenticated_per_minute": 0,
	    "registrations_per_hour": 0,
	    "mailbox_max_messages": 0,
	    "mailbox_max_bytes": 0,
	    "max_open_uploads": 0,
	    "max_inflight": 0,
	    "max_waiting": 0,
	    "knock_max_bytes": 0,
	    "max_knocks_waiting": 0,
	    "knocks_per_hour": 0
	  }
	}`)
	cfg, err := resolve(t, file)
	if err != nil {
		t.Fatal(err)
	}
	l := cfg.Limits.Relay()
	if l.RequestsPerMinute != 0 || l.PostsPerMinute != 0 || l.PostBytesPerHour != 0 ||
		l.UnauthenticatedPerMinute != 0 || l.RegistrationsPerHour != 0 ||
		l.MailboxMaxMessages != 0 || l.MailboxMaxBytes != 0 || l.MaxOpenUploads != 0 ||
		l.MaxInflight != 0 || l.MaxWaiting != 0 ||
		l.KnockMaxBytes != 0 || l.MaxKnocksWaiting != 0 || l.KnocksPerHour != 0 {
		t.Fatalf("a limit the file set to zero came back with a default: %+v", l)
	}
}

func TestBadLimitsAreRefused(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"negative requests", []string{"--limit-requests", "-1"}, "requests_per_minute"},
		{"negative posts", []string{"--limit-posts", "-5"}, "posts_per_minute"},
		{"negative post bytes", []string{"--limit-post-bytes", "-1"}, "post_bytes_per_hour"},
		{"negative unauthenticated", []string{"--limit-unauthenticated", "-1"}, "unauthenticated_per_minute"},
		{"negative registrations", []string{"--limit-registrations", "-1"}, "registrations_per_hour"},
		{"negative mailboxes", []string{"--max-mailboxes", "-1"}, "max_mailboxes"},
		{"negative mailbox messages", []string{"--mailbox-max-messages", "-1"}, "mailbox_max_messages"},
		{"negative mailbox bytes", []string{"--mailbox-max-bytes", "-1"}, "mailbox_max_bytes"},
		{"negative relay bytes", []string{"--relay-max-bytes", "-1"}, "relay_max_bytes"},
		{"negative open uploads", []string{"--max-open-uploads", "-1"}, "max_open_uploads"},
		{"open uploads over the ceiling", []string{"--max-open-uploads", "1001"}, "max_open_uploads must be at most 1000"},
		{"negative knock bytes", []string{"--knock-max-bytes", "-1"}, "knock_max_bytes"},
		{"negative knocks waiting", []string{"--max-knocks-waiting", "-1"}, "max_knocks_waiting"},
		{"knocks waiting over the ceiling", []string{"--max-knocks-waiting", "1001"}, "max_knocks_waiting must be at most 1000"},
		{"negative knocks per hour", []string{"--knocks-per-hour", "-1"}, "knocks_per_hour"},
		{"knock bytes over max_bytes", []string{"--knock-max-bytes", "8193", "--max-bytes", "8192"}, "knock_max_bytes (8193) must be at most max_bytes (8192)"},
		{"negative inflight", []string{"--max-inflight", "-1"}, "max_inflight"},
		{"negative waiting", []string{"--max-waiting", "-1"}, "max_waiting"},
		{"unknown access log", []string{"--access-log", "verbose"}, "access_log"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := resolve(t, "", c.args...)
			if err == nil {
				t.Fatalf("%v was accepted", c.args)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %q does not name %q", err, c.want)
			}
		})
	}
}

// max_waiting must sit under max_inflight when both are set: a held listing
// keeps an in-flight slot, so holds up to the cap would fill the relay.
// Both edges, and zero on either side is exempt.
func TestMaxWaitingMustBeUnderMaxInflight(t *testing.T) {
	for _, tc := range []struct {
		waiting, inflight string
		ok                bool
	}{
		{"255", "256", true},
		{"256", "256", false},
		{"257", "256", false},
		{"0", "256", true},
		{"64", "0", true},
		{"0", "0", true},
		{"1", "1", false},
		{"1", "2", true},
	} {
		_, err := resolve(t, "", "--max-waiting", tc.waiting, "--max-inflight", tc.inflight)
		if tc.ok && err != nil {
			t.Errorf("max_waiting %s under max_inflight %s was refused: %v", tc.waiting, tc.inflight, err)
		}
		if !tc.ok {
			want := "max_waiting (" + tc.waiting + ") must be under max_inflight (" + tc.inflight + "): a held listing keeps " +
				"an in-flight slot, and holds alone would fill the relay"
			if err == nil || err.Error() != want {
				t.Errorf("max_waiting %s with max_inflight %s: %v, want %q", tc.waiting, tc.inflight, err, want)
			}
		}
	}
	// A negative is said as a negative first: a positive max_waiting is
	// not under a negative max_inflight, and the sentence for that would
	// name the wrong fault.
	if _, err := resolve(t, "", "--max-inflight", "-1", "--max-waiting", "5"); err == nil ||
		!strings.Contains(err.Error(), "max_inflight must not be negative") {
		t.Errorf("a negative max_inflight beside a max_waiting: %v", err)
	}
	// The file is checked the same way as the flags.
	file := writeFile(t, `{"limits": {"max_inflight": 10, "max_waiting": 10}}`)
	if _, err := resolve(t, file); err == nil || !strings.Contains(err.Error(), "max_waiting (10) must be under max_inflight (10)") {
		t.Errorf("the file's max_waiting at max_inflight: %v", err)
	}
}

func TestPrintedConfigCarriesTheLimits(t *testing.T) {
	cfg, err := resolve(t, "", "--limit-posts", "7", "--access-log", "minimal")
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := Encode(&out, cfg.Redacted()); err != nil {
		t.Fatal(err)
	}
	printed := out.String()
	for _, key := range []string{
		"requests_per_minute", "posts_per_minute", "post_bytes_per_hour",
		"unauthenticated_per_minute", "registrations_per_hour", "max_mailboxes",
		"mailbox_max_messages", "mailbox_max_bytes", "relay_max_bytes",
		"max_inflight", "max_waiting", "knock_max_bytes", "max_knocks_waiting",
		"knocks_per_hour", "access_log",
	} {
		if !strings.Contains(printed, key) {
			t.Errorf("--print-config output is missing %q", key)
		}
	}

	// And it round trips: what it prints can be fed straight back in.
	back, err := resolve(t, writeFile(t, printed))
	if err != nil {
		t.Fatalf("the printed configuration does not load again: %v", err)
	}
	if back.Limits.PostsPerMinute != 7 || back.AccessLog != relay.AccessLogMinimal {
		t.Fatalf("the printed configuration did not round trip: %+v", back.Limits)
	}
}
