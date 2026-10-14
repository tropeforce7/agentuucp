package client

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/identity"
)

// The health answer's channel-max-bytes section (R19), as the client reads
// it: absent, held as zero, which the owner's command refuses to set a
// rule against; within the rule, taken; outside it or of another shape,
// the answer refused naming the section and never clamped. And an answer
// without it after one with it holds zero again, not the earlier number.
func TestTheHealthAnswersChannelCeiling(t *testing.T) {
	section := func(data string) string {
		return `[{"name":"channel-max-bytes","critical":false,"data":` + data + `}]`
	}
	for _, tc := range []struct {
		name     string
		sections string
		want     int64
		refused  bool
	}{
		{"absent", "", 0, false},
		{"one", section(`{"max":1}`), 1, false},
		{"the protocol's ceiling", section(`{"max":4611686018427387904}`), 4611686018427387904, false},
		{"zero", section(`{"max":0}`), 0, true},
		{"one over the protocol's ceiling", section(`{"max":4611686018427387905}`), 0, true},
		{"negative", section(`{"max":-1}`), 0, true},
		{"not an integer", section(`{"max":1.5}`), 0, true},
		{"a field it does not have", section(`{"max":1,"min":1}`), 0, true},
		{"not an object", section(`1`), 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := answering(t, http.StatusOK, healthWith(tc.sections))
			_, err := c.HealthInfo(context.Background())
			if tc.refused {
				if !errors.Is(err, ErrMalformedAnswer) || !strings.Contains(err.Error(), "the channel-max-bytes section is not the largest max_bytes a channel may name") {
					t.Fatalf("%v; want the health answer refused naming the section", err)
				}
				return
			}
			if err != nil || c.ChannelCeiling() != tc.want {
				t.Fatalf("ceiling %d, %v; want %d", c.ChannelCeiling(), err, tc.want)
			}
		})
	}

	// One relay answering first with the section and then without it.
	var with atomic.Bool
	with.Store(true)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if with.Load() {
			_, _ = w.Write(healthWith(section(`{"max":1000}`)))
			return
		}
		_, _ = w.Write(healthWith(""))
	}))
	t.Cleanup(srv.Close)
	alice, err := identity.Generate("alice")
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(srv.URL, alice, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.HealthInfo(context.Background()); err != nil || c.ChannelCeiling() != 1000 {
		t.Fatalf("with the section: %d, %v", c.ChannelCeiling(), err)
	}
	with.Store(false)
	if _, err := c.HealthInfo(context.Background()); err != nil || c.ChannelCeiling() != 0 {
		t.Fatalf("without it after: %d, %v; want zero, not the earlier number", c.ChannelCeiling(), err)
	}
}
