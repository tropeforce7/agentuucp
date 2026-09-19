package auu

import (
	"context"
	"crypto/hpke"
	"crypto/mldsa"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/channels"
	"github.com/tropeforce7/agentuucp/internal/envelope"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/pki"
	"github.com/tropeforce7/agentuucp/internal/relay"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/store"
	"github.com/tropeforce7/agentuucp/internal/stream"
	"github.com/tropeforce7/agentuucp/internal/token"
)

// Nothing the network names is a path until its rule has run, and this one
// test walks every component that becomes part of a path somewhere: a
// fingerprint in a URL, an upload id, a token id, an attachment name, a
// channel name, a relay host, a message id and a thread id. Each row names
// the rule and the point it runs at, and is fed `..`, `../x`, `a/b`, `.`,
// the empty string and a NUL. When a new place turns something from the
// network into a path, add its row here first, before the code; a rule that
// is not in this table is a rule somebody will forget. security.md's
// paragraph on paths lists the same components in the same order.
//
// The second adversarial trace found the thread id missing from the list:
// an admitted peer's `--thread "../../outside"` was joined onto an expert
// host's serve directory.
func TestNothingTheNetworkNamesIsAPath(t *testing.T) {
	values := []string{"..", "../x", "a/b", ".", "", "\x00"}
	names := map[string]string{"..": "dot-dot", "../x": "dot-dot-slash", "a/b": "a-slash-b", ".": "dot", "": "empty", "\x00": "NUL"}

	alice, err := identity.Generate("alice")
	if err != nil {
		t.Fatal(err)
	}
	bob, err := identity.Generate("bob")
	if err != nil {
		t.Fatal(err)
	}
	boss, err := identity.Generate("boss")
	if err != nil {
		t.Fatal(err)
	}
	const anID = "0123456789abcdef0123456789abcdef"
	admins := filepath.Join(t.TempDir(), "admins")
	if err := os.WriteFile(admins, []byte(boss.Public().ExportLine()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv, st, _ := startRelayOnDisk(t, relay.Config{AdminFile: admins})
	for _, id := range []*identity.Identity{alice, bob} {
		if err := st.Register(id.Fingerprint(), id.Public().Bundle(), id.Name, relay.RegisterOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	// Redirects are answers, not something to follow: the mux answers a
	// path with a dot segment by pointing at the cleaned one, and that is
	// the refusal.
	web := srv.Client()
	web.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	// wire sends one signed request with the value as a path segment,
	// escaped as a client escapes it, so that a slash travels as %2F and
	// reaches the handler as one segment. It reports a refusal at the
	// named point (400 with its sentence), or by the mux before any
	// handler (a redirect for a dot segment, 404 for an empty one), and
	// fails the test on any other answer: a 401 would mean the request
	// never reached the point the row names, and a 2xx that it was taken.
	wire := func(as *identity.Identity, method, before, value, sentence string) string {
		t.Helper()
		req, err := http.NewRequest(method, srv.URL+before+url.PathEscape(value), nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := relayapi.SignRequest(as, req, nil); err != nil {
			t.Fatal(err)
		}
		resp, err := web.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		switch {
		case resp.StatusCode == http.StatusBadRequest && strings.Contains(string(body), sentence):
			return "refused at the handler"
		case resp.StatusCode == http.StatusTemporaryRedirect && (value == "." || value == ".."):
			return "redirected by the mux"
		case resp.StatusCode == http.StatusNotFound && value == "":
			return "no route"
		}
		t.Errorf("%s %s%s: %d %s, which is neither the named refusal nor the mux's", method, before, url.PathEscape(value), resp.StatusCode, body)
		return "refused, elsewhere"
	}
	ca := pki.TestStore(t, mldsa.MLDSA44())
	memSource := func(name string) []stream.Source {
		return []stream.Source{{Name: name, Media: "application/octet-stream", Size: 1,
			Open: func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("x")), nil }}}
	}
	body := func(thread string) message.Body {
		return message.Body{Type: message.TypeAsk, Thread: thread, Text: "hello"}
	}
	home, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	aliceClient, err := dial(home, alice, &store.Relay{Name: "r", URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}

	// Each row: what the network names, where its rule runs, and a check
	// that reports the refusal, or "" for accepted. The check runs the rule
	// at the named point; where the value also travels in a URL, the
	// request is sent too, so the route is known to refuse before storage.
	rows := []struct {
		what, where string
		refused     func(v string) string
	}{
		{"a fingerprint in a URL", "relay: the authed wrapper, identity.ValidFingerprint, 400 before the signature is read",
			func(v string) string {
				if identity.ValidFingerprint(v) {
					return ""
				}
				return wire(alice, "GET", "/v1/mailbox/", v, "bad mailbox fingerprint")
			}},
		{"an upload id in a URL", "relay: s.upload, relay.ValidUploadID, 400 before the row is read",
			func(v string) string {
				if relay.ValidUploadID(v) {
					return ""
				}
				return wire(alice, "PATCH", "/v1/uploads/", v, "bad upload id")
			}},
		{"a token id in a URL", "relay: handleAdminRevokeToken, token.ValidID, 400 before the store is asked",
			func(v string) string {
				if token.ValidID(v) {
					return ""
				}
				return wire(boss, "DELETE", "/v1/admin/tokens/", v, "bad token id")
			}},
		{"an attachment name", "message.ValidAttachmentName at Body.Validate and Manifest.Validate; filepath.Base again at the open",
			func(v string) string {
				if message.ValidAttachmentName(v) == nil {
					return ""
				}
				b := body(anID)
				b.Attachments = []message.Attachment{{Name: v, Media: "x", Size: 1, SHA256: strings.Repeat("0", 64), Data: []byte("x")}}
				if b.Validate() == nil {
					return ""
				}
				if _, err := stream.BuildManifest(alice, bob.Public(), anID, stream.Body{Type: "ask", Thread: anID, Text: "x"},
					memSource(v), stream.MinChunkSize); !errors.Is(err, stream.ErrForm) {
					return ""
				}
				return "refused"
			}},
		{"a channel name", "channels.ValidName: at the relay for every post and stream opened (400), at Directory.Validate for every push, and at the client's --channel",
			func(v string) string {
				if channels.ValidName(v) == nil {
					return ""
				}
				d := channels.Directory{V: channels.Version, Owner: bob.Fingerprint(), Issued: time.Now(),
					Channels: []channels.Channel{{Name: v}}}
				if d.Validate() == nil {
					return ""
				}
				if v == "" {
					// On the wire no name is the default channel, which is
					// never a path: serve's channel directories are named
					// by its own file, not by a message.
					return "refused"
				}
				env, _, err := envelope.Seal(alice, bob.Public(), body(anID))
				if err != nil {
					t.Fatal(err)
				}
				if _, err := aliceClient.Post(context.Background(), env, v); err == nil {
					return ""
				}
				return "refused"
			}},
		{"a relay host", "pki: IssueRelay's DNS-name rule, before any record directory is named; safeHost is belt and braces",
			func(v string) string {
				if _, err := ca.IssueRelay([]string{v}, 1, time.Now()); err == nil {
					return ""
				}
				// And no record was filed under it, or under anything.
				if known, err := ca.Relays(); err != nil || len(known) != 0 {
					return ""
				}
				return "refused"
			}},
		{"a message id", "message.ValidID: at envelope.Open (malformed), Manifest.Validate (ErrForm) and store.Save, since it names the record's file",
			func(v string) string {
				if message.ValidID(v) == nil {
					return ""
				}
				env := sealInnerByHand(t, alice, bob.Public(), &envelope.Inner{ID: v, Time: time.Now().UTC(), Body: body(anID)})
				if _, _, err := envelope.Open(bob, env); envelope.Cause(err) != envelope.ErrMalformed {
					return ""
				}
				if _, err := stream.BuildManifest(alice, bob.Public(), v, stream.Body{Type: "ask", Thread: anID, Text: "x"},
					memSource("a"), stream.MinChunkSize); !errors.Is(err, stream.ErrForm) {
					return ""
				}
				if err := home.Save(store.Inbox, &store.Stored{Inner: &envelope.Inner{ID: v, Body: body(anID)}}); err == nil {
					return ""
				}
				return "refused"
			}},
		{"a thread id", "message.ValidID through ValidHeader: at Body.Validate and Manifest.Validate; auu serve checks again before the join, and worktreeFor once more",
			func(v string) string {
				if message.ValidID(v) == nil {
					return ""
				}
				b := body(v)
				if b.Validate() == nil {
					return ""
				}
				if _, err := stream.BuildManifest(alice, bob.Public(), anID, stream.Body{Type: "ask", Thread: v, Text: "x"},
					memSource("a"), stream.MinChunkSize); !errors.Is(err, stream.ErrForm) {
					return ""
				}
				if _, _, err := worktreeFor(t.TempDir(), &serveChannel{name: "c", Mode: modeSideCopy}, v, t.TempDir(), true); err == nil {
					return ""
				}
				return "refused"
			}},
	}
	for _, row := range rows {
		for _, v := range values {
			if got := row.refused(v); got == "" {
				t.Errorf("%s: %s was accepted; the rule is %s", row.what, names[v], row.where)
			}
		}
	}
}

// sealInnerByHand is sealByHand for identities rather than users: the inner
// record exactly as given, signed with the sender's key and sealed to the
// recipient, with the wire constants as literals.
func sealInnerByHand(t *testing.T, from *identity.Identity, to *identity.Public, inner *envelope.Inner) *envelope.Envelope {
	t.Helper()
	toFP := to.Fingerprint()
	inner.From, inner.FromBundle, inner.To = from.Fingerprint(), from.Public().Bundle(), toFP
	innerBytes, err := json.Marshal(inner)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := from.Sign(append([]byte("ccx-sig-v1"+toFP), innerBytes...))
	if err != nil {
		t.Fatal(err)
	}
	ct, err := hpke.Seal(to.KEM, hpke.HKDFSHA256(), hpke.AES256GCM(), []byte("ccx-envelope-v1"+toFP), append(sig, innerBytes...))
	if err != nil {
		t.Fatal(err)
	}
	return &envelope.Envelope{V: envelope.Version, To: toFP, CT: ct}
}
