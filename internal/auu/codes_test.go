package auu

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/client"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// laterKind is a code no build knows: a refusal under it is shown as its
// sentence and acted on no further (ruling 67). Each test below is a row
// pair (ruling 68): the code present and acted on, and the same refusal
// under laterKind, sentence kept, and not acted on.
const laterKind = "later-kind"

func refusal(status int, code, sentence string) *client.HTTPError {
	return &client.HTTPError{Status: status, Code: code, Message: sentence}
}

func TestTheOverBudgetCodeEndsTheWait(t *testing.T) {
	sentence := "rate limited: post_bytes; this stream is 9 bytes and a sender's whole post_bytes_per_hour budget is 8, so " +
		relayapi.MsgWaitingWillNotHelp
	over := refusal(http.StatusTooManyRequests, relayapi.CodeOverBudget, sentence)
	over.RetryAfter = time.Minute
	if _, temporary := relayAskedToWait(over); temporary {
		t.Error("over-budget: read as a wait; want it final")
	}
	later := refusal(http.StatusTooManyRequests, laterKind, sentence)
	later.RetryAfter = time.Minute
	if wait, temporary := relayAskedToWait(later); !temporary || wait != time.Minute {
		t.Errorf("another code: %v, %v; want the minute it asked for", wait, temporary)
	}
}

func TestTheNoKnocksCodeIsAdvised(t *testing.T) {
	if !isNoKnocks(refusal(http.StatusForbidden, relayapi.CodeNoKnocks, relayapi.MsgNoKnocks)) {
		t.Error("no-knocks: not recognised")
	}
	if isNoKnocks(refusal(http.StatusForbidden, laterKind, relayapi.MsgNoKnocks)) {
		t.Error("another code with the no-knocks sentence: recognised; want it said as it came")
	}
}

func TestTheChannelCodesAreRead(t *testing.T) {
	at := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	sentence := `channel "cfp" is not open: opens ` + at.Format(time.RFC3339)
	closed := refusal(http.StatusForbidden, relayapi.CodeChannelClosed, sentence)
	closed.At = at
	if got := channelHint(closed, nil, nil, nil, nil, nil, "cfp"); got == nil || got.Error() != closedSentence(closed, time.Local) {
		t.Errorf("channel-closed: %v; want %q", got, closedSentence(closed, time.Local))
	}
	// A zone that reads the time otherwise says it beside the sentence; UTC,
	// which reads it as the sentence does, does not say it twice.
	kolkata := time.FixedZone("IST", 5*3600+1800)
	if got, want := closedSentence(closed, kolkata), sentence+" (2030-01-01T05:30:00+05:30 here)"; got != want {
		t.Errorf("channel-closed in another zone: %q, want %q", got, want)
	}
	if got := closedSentence(closed, time.UTC); got != sentence {
		t.Errorf("channel-closed in UTC: %q; want the sentence alone, not the same time twice", got)
	}
	later := refusal(http.StatusForbidden, laterKind, sentence)
	later.At = at
	if got := channelHint(later, nil, nil, nil, nil, nil, "cfp"); got != error(later) {
		t.Errorf("another code with the channel-closed sentence: %v; want it as it came", got)
	}
	// no-such-channel present is read through a real relay by
	// TestARefusedChannelIsSaidToBe, which lists the recipient's channels.
	missing := refusal(http.StatusNotFound, laterKind, `no such channel "nope"`)
	if got := channelHint(missing, nil, nil, nil, nil, nil, "nope"); got != error(missing) {
		t.Errorf("another code with the no-such-channel sentence: %v; want it as it came", got)
	}
}

func TestTheNoNeighbourCodeIsExplainedForAReply(t *testing.T) {
	mode := sendMode{reply: true, path: []string{"bar"}}
	sentence := relayapi.MsgNoNeighbour + ` "bar" on this relay`
	if got := replyCannotGoBack(refusal(http.StatusNotFound, relayapi.CodeNoNeighbour, sentence), mode); !strings.Contains(got.Error(), "--via NAME") {
		t.Errorf("no-neighbour: %v; want the advice", got)
	}
	later := refusal(http.StatusNotFound, laterKind, sentence)
	if got := replyCannotGoBack(later, mode); got != error(later) {
		t.Errorf("another code with the no-neighbour sentence: %v; want it as it came", got)
	}
}

func TestTheFullCodesAreTold(t *testing.T) {
	if got := streamFullHint(refusal(507, relayapi.CodeRelayFull, relayapi.MsgRelayFull), "bob"); !strings.Contains(got.Error(), "the relay is out of storage") {
		t.Errorf("relay-full: %v", got)
	}
	if got := streamFullHint(refusal(507, relayapi.CodeMailboxFull, relayapi.MsgMailboxFull), "bob"); !strings.Contains(got.Error(), "bob's mailbox on the relay is full") {
		t.Errorf("mailbox-full: %v", got)
	}
	for _, msg := range []string{relayapi.MsgRelayFull, relayapi.MsgMailboxFull} {
		later := refusal(507, laterKind, msg)
		if got := streamFullHint(later, "bob"); got != error(later) {
			t.Errorf("another code with %q: %v; want it as it came", msg, got)
		}
	}
}

func TestTheStorageErrorCodeIsTheRelays(t *testing.T) {
	var fault *storageFault
	if got := storageFaultHint(refusal(500, relayapi.CodeStorageError, relayapi.MsgStorageError)); !errors.As(got, &fault) {
		t.Errorf("storage-error: %v; want the storage sentence", got)
	}
	later := refusal(500, laterKind, relayapi.MsgStorageError)
	if got := storageFaultHint(later); got != error(later) {
		t.Errorf("another code with the storage sentence: %v; want it as it came", got)
	}
}

func TestTheNewerCodesSayWhenTheHeldOneWasIssued(t *testing.T) {
	issued := time.Date(2026, 10, 7, 9, 30, 0, 0, time.UTC)
	for _, tc := range []struct{ code, sentence string }{
		{relayapi.CodeNewerAllowList, "a newer allow list is already there (issued " + issued.Format(time.RFC3339) + ")"},
		{relayapi.CodeNewerCard, "a newer card is already there (issued " + issued.Format(time.RFC3339) + ")"},
	} {
		held := refusal(http.StatusConflict, tc.code, tc.sentence)
		held.At = issued
		got, ok := newerHeld(held, tc.code)
		if !ok || issuedWhen(got) != "issued "+stampLocal(issued) {
			t.Errorf("%s: %v %q; want the time in this zone", tc.code, ok, issuedWhen(got))
		}
		held.At = time.Time{}
		if issuedWhen(held) != tc.sentence {
			t.Errorf("%s without a time: %q; want the sentence alone", tc.code, issuedWhen(held))
		}
		if _, ok := newerHeld(refusal(http.StatusConflict, laterKind, tc.sentence), tc.code); ok {
			t.Errorf("another code with the %s sentence: read as the newer one held", tc.code)
		}
	}
}
