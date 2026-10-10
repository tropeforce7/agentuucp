package relay

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
)

// The third adversarial trace (reviews/trace/trace-3-v0.17.0/), F14: a
// courier's mailbox answered the channels route and the watch as an ordinary
// mailbox with no directory, the one mailbox the post refused and these did
// not, which told a stranger which relays this one peers with.

// TestACourierMailboxIsNotToldApartOnTheChannelsRoute: the post, the
// channels GET and the watch answer a courier's mailbox exactly as they
// answer a mailbox whose allow list does not admit the caller.
func TestACourierMailboxIsNotToldApartOnTheChannelsRoute(t *testing.T) {
	courier := neighbourID(t, "alpha")
	h := peered(t, []string{"bar"}, []*identity.Identity{courier}, nil)
	h.enroll(courier)
	stranger := h.user(t, "stranger")
	bob := h.user(t, "bob")
	other := h.fpOf(t, "other")
	if status, body, _ := h.pushAllow(bob, bob, time.Now(), other); status != http.StatusNoContent {
		t.Fatalf("pushing bob's list: %d %s", status, body)
	}
	courierFP, bobFP := courier.Fingerprint(), bob.Fingerprint()

	// The post refuses both in one sentence.
	for _, to := range []*identity.Identity{courier, bob} {
		status, body := h.do(stranger, "POST", "/v1/mailbox/"+to.Fingerprint(), sealed(t, stranger, to.Public(), "x"), nil)
		if status != http.StatusForbidden || errorText(t, body) != msgNotAllowed {
			t.Fatalf("post to %s: %d %s, want 403 %q", to.Fingerprint()[:8], status, body, msgNotAllowed)
		}
	}

	// The channels GET answers the courier's mailbox as it answers the
	// restricted one: the same status, the same words.
	bobStatus, bobBody, _ := h.getDirectory(stranger, bobFP)
	courierStatus, courierBody, _ := h.getDirectory(stranger, courierFP)
	if bobStatus != http.StatusForbidden || errorText(t, bobBody) != msgNotAllowed {
		t.Fatalf("a restricted mailbox's channels: %d %s, want 403 %q", bobStatus, bobBody, msgNotAllowed)
	}
	if courierStatus != bobStatus || errorText(t, courierBody) != errorText(t, bobBody) {
		t.Fatalf("the courier's mailbox answers the channels route %d %q, a restricted mailbox %d %q: the route tells the two apart",
			courierStatus, errorText(t, courierBody), bobStatus, errorText(t, bobBody))
	}

	// The watch half. The courier identity pushes a directory for its own
	// mailbox, which the push allows; carol, an ordinary mailbox with no
	// list, pushes one too.
	carol := h.user(t, "carol")
	carolFP := carol.Fingerprint()
	issued := h.clock.Now()
	if status, body, _ := h.pushDirectory(courier, courier, issued, dflt, bugs); status != http.StatusNoContent {
		t.Fatalf("the courier's push: %d %s", status, body)
	}
	if status, body, _ := h.pushDirectory(carol, carol, issued, dflt); status != http.StatusNoContent {
		t.Fatalf("carol's push: %d %s", status, body)
	}

	// A watch of carol names her at once: her directory is past issue zero.
	status, resp, body := h.list(stranger, peersQuery(at(carolFP, time.Time{}))).answer(t)
	if status != http.StatusOK || len(resp.DirectoriesChanged) != 1 || resp.DirectoriesChanged[0] != carolFP {
		t.Fatalf("a watch of an ordinary peer: %d %s", status, body)
	}

	// A watch of the courier's mailbox, its directory just as far past
	// issue zero, is told nothing, as a watch of bob, who does not admit
	// the stranger, is told nothing.
	for _, fp := range []string{courierFP, bobFP} {
		status, resp, body := h.list(stranger, "wait=300ms&"+peersQuery(at(fp, time.Time{}))).answer(t)
		if status != http.StatusOK || resp.DirectoriesChanged != nil || strings.Contains(string(body), "directories_changed") {
			t.Fatalf("a watch of %s names it: %d %s", fp[:8], status, body)
		}
	}

	// Held, the watch subscribes under neither the courier's mailbox nor
	// bob's, and a newer push by either wakes nothing; a newer push by
	// carol, watched beside them, wakes it and names her alone.
	query := peersQuery(at(courierFP, issued), at(bobFP, time.Time{}), at(carolFP, issued))
	l := h.list(stranger, longHold+"&"+query)
	h.holding(1)
	h.subscribed(dirKey(carolFP), 1)
	for _, fp := range []string{courierFP, bobFP} {
		if n := h.server.notify.waiting(dirKey(fp)); n != 0 {
			t.Fatalf("the stranger is subscribed under %s", fp[:8])
		}
	}
	newer := issued.Add(time.Second)
	if status, body, _ := h.pushDirectory(courier, courier, newer, dflt); status != http.StatusNoContent {
		t.Fatalf("the courier's newer push: %d %s", status, body)
	}
	if status, body, _ := h.pushDirectory(bob, bob, newer, dflt); status != http.StatusNoContent {
		t.Fatalf("bob's push: %d %s", status, body)
	}
	if l.answered() {
		t.Fatal("a push to a mailbox the watch must not name answered the hold")
	}
	if status, body, _ := h.pushDirectory(carol, carol, newer, dflt); status != http.StatusNoContent {
		t.Fatalf("carol's newer push: %d %s", status, body)
	}
	if status, resp, body := l.answer(t); status != http.StatusOK || len(resp.DirectoriesChanged) != 1 || resp.DirectoriesChanged[0] != carolFP {
		t.Fatalf("the held watch's answer: %d %s", status, body)
	}
}
