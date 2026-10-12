package client

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/recipients"
)

// An answer body is sorted on the answer path alone (G23, R27): on every
// answer body, a critical section this build knows only on requests (the
// count) or only on messages and manifests (the list) refuses the answer
// in the client's own words, as a name nobody registered does; an optional
// one is ignored; and the maximum, known on answers, is taken critical, so
// the refusal is the path's and not every critical section's.
func TestASectionKnownOnlyOnAnotherPathIsUnknownOnAnAnswer(t *testing.T) {
	for _, body := range answerBodies {
		t.Run(reflect.TypeOf(body).Elem().Name(), func(t *testing.T) {
			read := func(raw []byte) error {
				out := reflect.New(reflect.TypeOf(body).Elem()).Interface()
				return answering(t, http.StatusOK, raw).do(context.Background(), "GET", "/v1/x", nil, out, nil)
			}
			for _, name := range []string{recipients.CountName, recipients.Name} {
				err := read(withKey(t, body, "sections", []any{section(name, true)}))
				if want := `answered GET /v1/x with a section it must not be read without (section "` + name + `"); update auu`; !errors.Is(err, ErrMalformedAnswer) || !strings.Contains(err.Error(), want) {
					t.Errorf("critical %s on an answer: %v; want the answer refused naming it", name, err)
				}
				if err := read(withKey(t, body, "sections", []any{section(name, false)})); err != nil {
					t.Errorf("optional %s on an answer: %v; want it ignored", name, err)
				}
			}
			maxSection := map[string]any{"name": recipients.MaxName, "critical": true, "data": map[string]any{"max": 1}}
			if err := read(withKey(t, body, "sections", []any{maxSection})); err != nil {
				t.Errorf("critical %s, known on answers: %v; want it taken", recipients.MaxName, err)
			}
		})
	}
}
