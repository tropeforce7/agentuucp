package main

import (
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/client"
	"github.com/tropeforce7/agentuucp/internal/relay"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// A relay started with no administrator file refuses every admin route with a
// 403 and the code no-administrators, and auu-admin has to give the same
// advice it gives a stranger. TestNotAnAdministrator cannot show this: it is
// refused with a 401, and adminErr advises on a 401 whatever the code, so only
// a 403 reaches the branch that reads the code. Here the relay is checked to
// answer 403 with that code, so the advice can only have come from the code: a
// relay that wrote the sentence without it would leave the bare refusal.
func TestARelayWithNoAdministratorsIsSaidToHaveNone(t *testing.T) {
	dir := t.TempDir()
	st, err := relay.OpenStore(filepath.Join(dir, "relay.db"), filepath.Join(dir, "messages"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	// newFixture always names an administrator file, so the relay is built
	// here the same way without one.
	srv := httptest.NewServer(relay.NewServer(st, relay.Config{
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}))
	t.Cleanup(srv.Close)

	would := newPersona(t, "would-be", srv.URL)

	// What the relay said, read directly: a 403 carrying the code.
	cl, err := client.New(srv.URL, would.id, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = cl.AdminStatus(t.Context())
	var httpErr *client.HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("status on a relay with no administrators: %v, want a refusal", err)
	}
	if httpErr.Status != http.StatusForbidden || httpErr.Code != relayapi.CodeNoAdministrators {
		t.Fatalf("the relay answered %d with code %q, want %d with %q",
			httpErr.Status, httpErr.Code, http.StatusForbidden, relayapi.CodeNoAdministrators)
	}

	// What auu-admin makes of it.
	_, err = would.tryRun("status")
	if err == nil {
		t.Fatal("a relay with no administrators gave a status report")
	}
	msg := err.Error()
	if !strings.Contains(msg, "not an administrator of "+srv.URL) {
		t.Fatalf("error %q does not say the caller is not an administrator of the relay", msg)
	}
	if !strings.Contains(msg, "auu id export") {
		t.Fatalf("error %q does not say how to fix it", msg)
	}
	var e *exitError
	if !asExit(err, &e) || e.code != exitTransport {
		t.Fatalf("expected exit code %d, got %v", exitTransport, err)
	}
}
