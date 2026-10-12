package relay

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/recipients"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// A request body is sorted on the request path alone (G23, R27): on every
// one of the eleven, a critical section this build knows only on answers
// (the maximum) or only on messages and manifests (the list) is refused as
// needing a newer relay, in the relay's own words and with its code, as a
// name nobody registered is; an optional one is taken; and the count,
// known on requests, is taken critical, so the refusal is the path's and
// not every critical section's.
func TestASectionKnownOnlyOnAnotherPathIsUnknownOnARequest(t *testing.T) {
	for _, tc := range requestCases() {
		t.Run(tc.route, func(t *testing.T) {
			next := tc.start(t)
			for _, name := range []string{recipients.MaxName, recipients.Name} {
				t.Run(name+"/critical", func(t *testing.T) {
					req := next(t)
					status, body := req.send(bodyWith(t, req.fields, "sections", fmt.Sprintf(`[{"name":%q,"critical":true,"data":{"max":1}}]`, name)))
					if status != http.StatusBadRequest {
						t.Fatalf("critical %s on a request: %d, want 400: %s", name, status, body)
					}
					e := refusal(t, body)
					if want := fmt.Sprintf(relayapi.MsgNeedsNewer, relayapi.WireLevel, name); e.Error != want {
						t.Errorf("error %q, want %q", e.Error, want)
					}
					if e.Code != relayapi.CodeNeedsNewer {
						t.Errorf("code %q, want %q", e.Code, relayapi.CodeNeedsNewer)
					}
				})
				t.Run(name+"/optional", func(t *testing.T) {
					req := next(t)
					if status, body := req.send(bodyWith(t, req.fields, "sections", fmt.Sprintf(`[{"name":%q,"critical":false,"data":{"max":1}}]`, name))); status != tc.status {
						t.Fatalf("optional %s on a request: %d, want %d: %s", name, status, tc.status, body)
					}
				})
			}
			t.Run(recipients.CountName+"/critical", func(t *testing.T) {
				req := next(t)
				if status, body := req.send(bodyWith(t, req.fields, "sections", fmt.Sprintf(`[{"name":%q,"critical":true,"data":{"n":1}}]`, recipients.CountName))); status != tc.status {
					t.Fatalf("critical %s, known on requests: %d, want %d: %s", recipients.CountName, status, tc.status, body)
				}
			})
		})
	}
}
