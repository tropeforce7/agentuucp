package relay

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// A courier is a registered identity of the relay it forwards through, so it
// has an ordinary mailbox there. Nothing on either side reads that mailbox:
// it exists because enrolling is how a relay becomes a user of its
// neighbour. Left ordinary it is a mailbox any registered identity can fill,
// at this relay's expense, so this relay refuses every sender into it —
// which it can do because the mailbox that needs protecting is always at the
// relay whose own couriers file names its owner.
//
// It refuses them as a mailbox whose allow list named nobody would, and in
// that mailbox's words. The signed format cannot spell such a list — an
// empty one admits everybody and Validate refuses a list naming only the
// owner — so the relay holds it for a courier's mailbox itself and says what
// it would say. Nothing on the wire tells the two apart, and that is the
// whole of it: a sentence of its own would make these the routes where a
// stranger holding a fingerprint could ask which relays this one peers with.

// TestACouriersMailboxRefusesEverySender: all four routes that put something
// in a mailbox refuse, in the words a refused sender always gets, and
// nothing is stored.
func TestACouriersMailboxRefusesEverySender(t *testing.T) {
	courier := neighbourID(t, "alpha")
	h := peered(t, []string{"bar"}, []*identity.Identity{courier}, nil)
	h.enroll(courier)
	sender := h.user(t, "alice")
	to := courier.Fingerprint()

	t.Run("a post", func(t *testing.T) {
		status, body := h.do(sender, "POST", "/v1/mailbox/"+to, sealed(t, sender, courier.Public(), "hello"), nil)
		if status != 403 {
			t.Fatalf("status %d: %s", status, body)
		}
		if got := errorText(t, body); got != msgNotAllowed {
			t.Errorf("%q; want %q", got, msgNotAllowed)
		}
		if n, _ := h.queued(to); n != 0 {
			t.Errorf("%d messages stored in a courier's mailbox", n)
		}
	})
	t.Run("a stream open", func(t *testing.T) {
		status, body := h.do(sender, "POST", "/v1/mailbox/"+to+"/streams",
			relayapi.OpenStreamRequest{Size: 1 << 16}, nil)
		if status != 403 {
			t.Fatalf("status %d: %s", status, body)
		}
		if got := errorText(t, body); got != msgNotAllowed {
			t.Errorf("%q; want %q", got, msgNotAllowed)
		}
	})
	// A knock is refused in the words every mailbox that takes no knocks is
	// refused in, which is one sentence for no card, a card that says no
	// and a card that does not verify, because the state of somebody else's
	// card is not a stranger's to learn. A courier pushes no card, so this
	// route answered it before this commit and answers it still.
	t.Run("a knock", func(t *testing.T) {
		status, body := h.do(sender, "POST", "/v1/mailbox/"+to+"/knock",
			sealed(t, sender, courier.Public(), "knock"), nil)
		if status != 403 {
			t.Fatalf("status %d: %s", status, body)
		}
		if got := errorText(t, body); got != relayapi.MsgNoKnocks {
			t.Errorf("%q; want %q, the words every mailbox that takes no knocks gets", got, relayapi.MsgNoKnocks)
		}
		if strings.Contains(errorText(t, body), "courier") {
			t.Error("the knock route named the owner as a courier, which nothing else there says")
		}
		if n, _ := h.queued(to); n != 0 {
			t.Errorf("%d messages stored in a courier's mailbox", n)
		}
	})
	// An upload opened before the operator admitted the owner is the one
	// way past the refusal on the open, so the bytes are refused too,
	// before any of them is read.
	t.Run("an upload opened before the line was added", func(t *testing.T) {
		ordinary := neighbourID(t, "later")
		h2 := peered(t, []string{"bar"}, nil, nil)
		h2.enroll(ordinary)
		from := h2.user(t, "dave")
		status, body := h2.do(from, "POST", "/v1/mailbox/"+ordinary.Fingerprint()+"/streams",
			relayapi.OpenStreamRequest{Size: 1 << 16}, nil)
		if status != 201 {
			t.Fatalf("opening a stream to an ordinary mailbox: %d %s", status, body)
		}
		var opened relayapi.OpenStreamResponse
		if err := json.Unmarshal(body, &opened); err != nil {
			t.Fatal(err)
		}
		// The operator admits that identity as a neighbour's courier.
		writeCouriers(t, h2.server.courier.couriers.path, ordinary)
		status, put, _ := h2.sendRaw(from, "PUT", "/v1/uploads/"+opened.Upload, []byte("some bytes"),
			map[string]string{relayapi.UploadOffsetHeader: "0"})
		if status != 403 {
			t.Fatalf("the upload's bytes: status %d: %s", status, put)
		}
		if got := errorText(t, put); got != msgNotAllowed {
			t.Errorf("%q; want %q", got, msgNotAllowed)
		}
	})

	// And a mailbox that simply has no card answers exactly the same, so
	// the two are not told apart from outside.
	t.Run("the same as any mailbox with no card", func(t *testing.T) {
		ordinary := h.user(t, "carol")
		_, body := h.do(sender, "POST", "/v1/mailbox/"+ordinary.Fingerprint()+"/knock",
			sealed(t, sender, ordinary.Public(), "knock"), nil)
		if got := errorText(t, body); got != relayapi.MsgNoKnocks {
			t.Errorf("a mailbox with no card: %q, want %q", got, relayapi.MsgNoKnocks)
		}
	})
}

// TestAnOrdinaryMailboxIsUnchanged: the refusal is for the identities this
// relay's own couriers file names and for nobody else, so a relay that lists
// nobody — every relay until its operator peers one — behaves exactly as it
// did. Without this the test above would pass on a relay that had stopped
// taking mail altogether.
func TestAnOrdinaryMailboxIsUnchanged(t *testing.T) {
	courier := neighbourID(t, "alpha")
	h := peered(t, []string{"bar"}, []*identity.Identity{courier}, nil)
	h.enroll(courier)
	sender := h.user(t, "alice")
	ordinary := h.user(t, "bob")
	to := ordinary.Fingerprint()

	status, body := h.do(sender, "POST", "/v1/mailbox/"+to, sealed(t, sender, ordinary.Public(), "hello"), nil)
	if status != 200 {
		t.Fatalf("a post to an ordinary mailbox: status %d: %s", status, body)
	}
	if n, _ := h.queued(to); n != 1 {
		t.Errorf("%d messages, want 1", n)
	}
	// The post going through is what carries the claim, now that the
	// refusals say the same thing: a mailbox this relay does not list
	// takes mail, and one it lists does not, and the answer is the only
	// difference a sender can see.
	status, body = h.do(sender, "POST", "/v1/mailbox/"+to+"/knock",
		sealed(t, sender, ordinary.Public(), "knock"), nil)
	if got := errorText(t, body); got != relayapi.MsgNoKnocks {
		t.Errorf("an ordinary mailbox with no card: %q, want %q: %d", got, relayapi.MsgNoKnocks, status)
	}
}

// TestAMailboxBecomesACouriersOnAReload: the couriers file is re-read on its
// modification time, so an operator who admits a neighbour protects that
// neighbour's mailbox from the same moment, without a restart — and one who
// removes the line gives the mailbox back.
func TestAMailboxBecomesACouriersOnAReload(t *testing.T) {
	courier := neighbourID(t, "alpha")
	path := couriersFile(t)
	c, err := NewCourier(CourierConfig{
		Home:           courierHome(t, map[string]string{"bar": "http://127.0.0.1:1"}),
		AuthorizedFile: path, PublicURL: "https://mine.example",
	}, slogDiscard())
	if err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, Config{Courier: c, CourierLimits: DefaultCourierLimits(), Limits: DefaultLimits()})
	quiet(t, h)
	h.enroll(courier)
	sender := h.user(t, "alice")
	to := courier.Fingerprint()

	// Before the line, an ordinary mailbox.
	if status, body := h.do(sender, "POST", "/v1/mailbox/"+to,
		sealed(t, sender, courier.Public(), "one"), nil); status != 200 {
		t.Fatalf("before the line: status %d: %s", status, body)
	}

	// The operator admits the neighbour.
	writeCouriers(t, path, courier)
	status, body := h.do(sender, "POST", "/v1/mailbox/"+to, sealed(t, sender, courier.Public(), "two"), nil)
	if status != 403 {
		t.Fatalf("after the line: status %d: %s", status, body)
	}
	if got := errorText(t, body); got != msgNotAllowed {
		t.Errorf("%q; want %q", got, msgNotAllowed)
	}

	// And takes it out again: the mailbox is ordinary once more, since the
	// set is the file and the file is what the operator edits.
	if err := writeEmpty(path); err != nil {
		t.Fatal(err)
	}
	if status, body := h.do(sender, "POST", "/v1/mailbox/"+to,
		sealed(t, sender, courier.Public(), "three"), nil); status != 200 {
		t.Fatalf("after the line went: status %d: %s", status, body)
	}
}

// writeEmpty leaves a couriers file with no neighbours in it, at a distinct
// modification time so the reload is not at the mercy of the filesystem's
// timestamp resolution.
func writeEmpty(path string) error {
	if err := os.WriteFile(path, []byte("# nobody\n"), 0o644); err != nil {
		return err
	}
	future := time.Now().Add(time.Hour)
	return os.Chtimes(path, future, future)
}

// TestNothingOnTheWireTellsACouriersMailboxApart: the four refusals are
// byte-identical to the ones a mailbox that simply refuses this sender
// gives, which is the whole of what ruling 10b asks for.
//
// A courier's mailbox is a mailbox whose allow list names nobody, and the
// signed format cannot spell such a list, so the relay keeps it. What makes
// that a true description rather than a convenient one is that a sender
// cannot tell the two apart: same status, same body, same header, on every
// route that carries something into a mailbox. A sentence of its own — which
// is what 10a asked for and what this replaced — would have made these the
// routes where a stranger holding a fingerprint learns which relays this one
// accepts forwards from, since before this commit a post to a courier's
// mailbox was simply taken.
func TestNothingOnTheWireTellsACouriersMailboxApart(t *testing.T) {
	courier := neighbourID(t, "alpha")
	h := peered(t, []string{"bar"}, []*identity.Identity{courier}, nil)
	h.enroll(courier)
	sender := h.user(t, "alice")

	// The control: an ordinary mailbox whose owner has pushed an allow list
	// that does not name this sender. That is the thing a courier's mailbox
	// is being described as.
	refuses := h.user(t, "carol")
	other := h.user(t, "dave")
	if status, body, _ := h.pushAllow(refuses, refuses, time.Now(), other.Fingerprint()); status != 204 {
		t.Fatalf("pushing an allow list: %d %s", status, body)
	}

	for _, route := range []struct {
		name string
		call func(to *identity.Identity) (int, []byte)
	}{
		{"a post", func(to *identity.Identity) (int, []byte) {
			return h.do(sender, "POST", "/v1/mailbox/"+to.Fingerprint(),
				sealed(t, sender, to.Public(), "hello"), nil)
		}},
		{"a channel post", func(to *identity.Identity) (int, []byte) {
			return h.do(sender, "POST", "/v1/mailbox/"+to.Fingerprint(),
				sealedTo(t, sender, to.Public(), "hello", "work"), nil)
		}},
		{"a stream open", func(to *identity.Identity) (int, []byte) {
			return h.do(sender, "POST", "/v1/mailbox/"+to.Fingerprint()+"/streams",
				relayapi.OpenStreamRequest{Size: 1 << 16}, nil)
		}},
		{"a knock", func(to *identity.Identity) (int, []byte) {
			return h.do(sender, "POST", "/v1/mailbox/"+to.Fingerprint()+"/knock",
				sealed(t, sender, to.Public(), "knock"), nil)
		}},
	} {
		t.Run(route.name, func(t *testing.T) {
			courierStatus, courierBody := route.call(courier)
			refusedStatus, refusedBody := route.call(refuses)
			if courierStatus != refusedStatus {
				t.Errorf("a courier's mailbox answers %d and a mailbox that refuses this sender "+
					"answers %d", courierStatus, refusedStatus)
			}
			if !bytes.Equal(courierBody, refusedBody) {
				t.Errorf("the bodies differ:\n courier: %s\n refused: %s", courierBody, refusedBody)
			}
		})
	}
}
