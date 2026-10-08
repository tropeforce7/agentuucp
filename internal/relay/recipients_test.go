package relay

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/recipients"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/wire"
)

// countOf is the recipient-count section for n, as a client writes it.
func countOf(t *testing.T, n int) relayapi.Sections {
	t.Helper()
	list, err := recipients.CountSection(n)
	if err != nil {
		t.Fatal(err)
	}
	return relayapi.Sections{Sections: list}
}

// rawCount is a recipient-count section with data as given, past the
// client's own rule.
func rawCount(data string) relayapi.Sections {
	return relayapi.Sections{Sections: []wire.Section{{Name: recipients.CountName, Data: json.RawMessage(data)}}}
}

func (h *harness) uploadRows(t *testing.T) int {
	t.Helper()
	var n int
	if err := h.store.db.QueryRow(`SELECT COUNT(*) FROM uploads`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// A stream's open carrying a copy of a message to several is held to
// max_recipients, before anything is looked up, stored or charged: at the
// setting it is taken, one over it is refused 413 with the code and the
// sentence naming both numbers and nothing stored, and the post the
// refusal did not spend is the one the next open takes. A count that breaks
// its own rule is a malformed request, and an open with no count is a
// stream to one, taken as ever.
func TestAStreamOpenIsHeldToMaxRecipients(t *testing.T) {
	h := newHarness(t, Config{Limits: Limits{MaxRecipients: 16, PostsPerMinute: 1}})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	h.register(alice)
	h.register(bob)
	open := func(sections relayapi.Sections) (int, []byte) {
		return h.do(alice, "POST", "/v1/mailbox/"+bob.Fingerprint()+"/streams",
			relayapi.OpenStreamRequest{Sections: sections, Size: 100_000}, nil)
	}

	status, body := open(countOf(t, 17))
	if status != http.StatusRequestEntityTooLarge {
		t.Fatalf("seventeen against sixteen: %d: %s", status, body)
	}
	e := refusal(t, body)
	if want := fmt.Sprintf(relayapi.MsgTooManyRecipients, 17, 16); e.Error != want || e.Code != relayapi.CodeTooManyRecipients {
		t.Errorf("refused with %q, code %q; want %q, code %q", e.Error, e.Code, want, relayapi.CodeTooManyRecipients)
	}
	if n := h.uploadRows(t); n != 0 {
		t.Fatalf("%d uploads after a refused open; want none", n)
	}

	for _, tc := range []struct {
		name, data, says string
	}{
		{"zero", `{"n":0}`, "says 0, which is not 1 to 32"},
		{"thirty-three", `{"n":33}`, "says 33, which is not 1 to 32"},
		{"a field it does not have", `{"n":2,"who":["x"]}`, `unknown field "who"`},
		{"over its size", `{"n":2` + strings.Repeat(" ", recipients.MaxNumberBytes) + `}`, "over the 64 it may be"},
	} {
		// The body is written by hand, since an encoder would compact
		// the padding the last row is about.
		raw := []byte(`{"sections":[{"name":"recipient-count","critical":false,"data":` + tc.data + `}],"size":100000}`)
		status, body := h.do(alice, "POST", "/v1/mailbox/"+bob.Fingerprint()+"/streams", raw, nil)
		e := refusal(t, body)
		if status != http.StatusBadRequest || !strings.HasPrefix(e.Error, "malformed stream request: the recipient-count section") ||
			!strings.Contains(e.Error, tc.says) || e.Code != "" {
			t.Errorf("%s: %d %q code %q; want a malformed request saying %q", tc.name, status, e.Error, e.Code, tc.says)
		}
	}
	if n := h.uploadRows(t); n != 0 {
		t.Fatalf("%d uploads after malformed opens; want none", n)
	}

	// The one post a minute is still there: nothing refused above spent it.
	if status, body := open(countOf(t, 16)); status != http.StatusCreated {
		t.Fatalf("sixteen against sixteen: %d: %s", status, body)
	}
	// And now it is spent, so the budget was one and the open at the
	// setting took it.
	if status, body := open(relayapi.Sections{}); status != http.StatusTooManyRequests {
		t.Fatalf("a second open in the minute: %d: %s", status, body)
	}
}

// The number in force: zero is unlimited, which is the protocol's ceiling,
// so a relay with no setting takes thirty-two and refuses nothing a client
// may send, and one set to one takes a stream to one and refuses two.
func TestTheNumberInForceIsTheCeilingForZero(t *testing.T) {
	for _, tc := range []struct {
		setting   int64
		take      int
		refuse    int
		advertise int
	}{
		{0, relayapi.MaxRecipients, 0, relayapi.MaxRecipients},
		{1, 1, 2, 1},
		{relayapi.MaxRecipients, relayapi.MaxRecipients, 0, relayapi.MaxRecipients},
	} {
		t.Run(fmt.Sprint(tc.setting), func(t *testing.T) {
			h := newHarness(t, Config{Limits: Limits{MaxRecipients: tc.setting}})
			people := ids(t, "alice", "bob")
			alice, bob := people[0], people[1]
			h.register(alice)
			h.register(bob)
			open := func(n int) (int, []byte) {
				return h.do(alice, "POST", "/v1/mailbox/"+bob.Fingerprint()+"/streams",
					relayapi.OpenStreamRequest{Sections: countOf(t, n), Size: 100_000}, nil)
			}
			if status, body := open(tc.take); status != http.StatusCreated {
				t.Fatalf("%d against %d: %d: %s", tc.take, tc.setting, status, body)
			}
			if tc.refuse > 0 {
				if status, body := open(tc.refuse); status != http.StatusRequestEntityTooLarge {
					t.Fatalf("%d against %d: %d: %s", tc.refuse, tc.setting, status, body)
				}
			}
			if got := advertised(t, h); got != tc.advertise {
				t.Errorf("health says %d; want %d", got, tc.advertise)
			}
		})
	}
}

// advertised is the max-recipients section of the health answer.
func advertised(t *testing.T, h *harness) int {
	t.Helper()
	status, body := h.do(nil, "GET", "/v1/health", nil, nil)
	if status != http.StatusOK {
		t.Fatalf("health: %d: %s", status, body)
	}
	var resp relayapi.HealthResponse
	if err := wire.Decode(body, &resp); err != nil {
		t.Fatal(err)
	}
	data, ok := recipients.Find(resp.Sections.Sections, recipients.MaxName)
	if !ok {
		t.Fatalf("the health answer carries no max-recipients section: %s", body)
	}
	n, err := recipients.CheckMax(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range resp.Sections.Sections {
		if s.Critical {
			t.Errorf("section %q is critical; a client from before it would refuse the answer", s.Name)
		}
	}
	return n
}

// A user's forward of a copy of a message to several is held to
// max_recipients on the first relay, where its request was read and after
// the forward's charge, before anything is stored; at the setting it is
// taken.
func TestAUsersForwardIsHeldToMaxRecipients(t *testing.T) {
	h := peered(t, []string{"bar"}, nil, nil)
	user := h.user(t, "sender")
	to := h.fpOf(t, "bob")
	if want := DefaultLimits().MaxRecipients; want != 16 {
		t.Fatalf("the fixture's setting is %d; the test is written for 16", want)
	}

	req := request(sealedFor(to, "ct-seventeen"), []string{"bar"}, nil)
	req.Sections = countOf(t, 17)
	status, _, body := h.forward(user, req)
	if status != http.StatusRequestEntityTooLarge {
		t.Fatalf("seventeen: %d: %s", status, body)
	}
	e := refusal(t, body)
	if want := fmt.Sprintf(relayapi.MsgTooManyRecipients, 17, 16); e.Error != want || e.Code != relayapi.CodeTooManyRecipients {
		t.Errorf("refused with %q, code %q", e.Error, e.Code)
	}
	if msgs, bytes := h.queueCounters(t); msgs != 0 || bytes != 0 {
		t.Fatalf("queue %d/%d after a refused forward; want nothing stored", msgs, bytes)
	}

	req = request(sealedFor(to, "ct-malformed"), []string{"bar"}, nil)
	req.Sections = rawCount(`{"n":0}`)
	status, _, body = h.forward(user, req)
	if e := refusal(t, body); status != http.StatusBadRequest || !strings.HasPrefix(e.Error, "malformed forward request: the recipient-count section says 0") {
		t.Errorf("a count of zero: %d %q; want a malformed forward", status, e.Error)
	}

	req = request(sealedFor(to, "ct-sixteen"), []string{"bar"}, nil)
	req.Sections = countOf(t, 16)
	if status, _, body := h.forward(user, req); status != http.StatusCreated {
		t.Fatalf("sixteen: %d: %s", status, body)
	}
}

// The forward's count is read where its body is, after the charge, as every
// refusal of a forward's body is: a refused forward costs a user one of
// their posts, as a malformed one does. A fresh user posts once refused and
// then has the minute's budget less one: the default thirty a minute is
// twenty-nine more taken and the thirtieth refused.
func TestARefusedForwardCostsAPostAsAMalformedOneDoes(t *testing.T) {
	h := peered(t, []string{"bar"}, nil, nil)
	user := h.user(t, "sender")
	to := h.fpOf(t, "bob")
	budget := int(DefaultLimits().PostsPerMinute)

	req := request(sealedFor(to, "ct-refused"), []string{"bar"}, nil)
	req.Sections = countOf(t, 17)
	if status, _, body := h.forward(user, req); status != http.StatusRequestEntityTooLarge {
		t.Fatalf("seventeen: %d: %s", status, body)
	}
	for i := range budget - 1 {
		req := request(sealedFor(to, fmt.Sprintf("ct%d", i)), []string{"bar"}, nil)
		if status, _, body := h.forward(user, req); status != http.StatusCreated {
			t.Fatalf("forward %d of the %d left: %d: %s", i+1, budget-1, status, body)
		}
	}
	req = request(sealedFor(to, "ct-one-over"), []string{"bar"}, nil)
	if status, _, body := h.forward(user, req); status != http.StatusTooManyRequests {
		t.Fatalf("the forward the refusal's post would have paid for: %d: %s", status, body)
	}
}

// A courier's hand-over is a relay's, whose first relay held its sender
// already, so a count on it is not read: neither one over the setting nor
// one that breaks the rule is refused.
func TestACouriersRecipientCountIsNotRead(t *testing.T) {
	courier := neighbourID(t, "alpha")
	h := peered(t, []string{"bar"}, []*identity.Identity{courier}, nil)
	h.enroll(courier)
	for i, sections := range []relayapi.Sections{countOf(t, relayapi.MaxRecipients), rawCount(`{"n":0}`)} {
		req := request(sealedFor(h.fpOf(t, "bob"), fmt.Sprintf("ct%d", i)), []string{"bar"}, []string{"first"})
		req.Sections = sections
		if status, _, body := h.forward(courier, req); status != http.StatusCreated {
			t.Errorf("a courier's hand-over with %s: %d: %s", sections.Sections[0].Data, status, body)
		}
	}
}

// The administrator's status answer carries the number in force as a
// section beside the limits, and never as a field of them.
func TestTheStatusAnswerSaysMaxRecipientsInASection(t *testing.T) {
	admin := ids(t, "boss")[0]
	h := newHarness(t, Config{AdminFile: adminFile(t, admin), Limits: Limits{MaxRecipients: 5}})
	status, body := h.do(admin, "GET", "/v1/admin/status", nil, nil)
	if status != http.StatusOK {
		t.Fatalf("status: %d: %s", status, body)
	}
	var resp relayapi.AdminStatusResponse
	if err := wire.Decode(body, &resp); err != nil {
		t.Fatal(err)
	}
	data, ok := recipients.Find(resp.Sections.Sections, recipients.MaxName)
	if !ok {
		t.Fatalf("no max-recipients section: %s", body)
	}
	if n, err := recipients.CheckMax(data); err != nil || n != 5 {
		t.Errorf("the section says %d, %v; want 5", n, err)
	}
	if strings.Contains(string(body), `"max_recipients"`) {
		t.Errorf("max_recipients is a field of the answer, which an older auu-admin refuses: %s", body)
	}
}

// Nothing of the count reaches the log, under either access-log mode.
func TestTheCountIsNotLogged(t *testing.T) {
	for _, mode := range []string{AccessLogFull, AccessLogMinimal} {
		t.Run(mode, func(t *testing.T) {
			h := newHarness(t, Config{AccessLog: mode, Limits: Limits{MaxRecipients: 2}})
			people := ids(t, "alice", "bob")
			alice, bob := people[0], people[1]
			h.register(alice)
			h.register(bob)
			for _, n := range []int{2, 3} {
				h.do(alice, "POST", "/v1/mailbox/"+bob.Fingerprint()+"/streams",
					relayapi.OpenStreamRequest{Sections: countOf(t, n), Size: 100_000}, nil)
			}
			logs := h.logs.String()
			if !strings.Contains(logs, "status=413") {
				t.Fatalf("the refused open is not in the log at all, so the test proves nothing:\n%s", logs)
			}
			for _, leak := range []string{"recipient-count", `"n":`, "n=3", "is to 3 recipients"} {
				if strings.Contains(logs, leak) {
					t.Errorf("the log carries %q:\n%s", leak, logs)
				}
			}
		})
	}
}
