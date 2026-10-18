package auu

import (
	"bytes"
	"context"
	"crypto/hpke"
	"crypto/mldsa"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
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
	"github.com/tropeforce7/agentuucp/internal/vouch"
)

// Nothing the network names is a path until its rule has run, and this one
// test walks every component that becomes part of a path somewhere: a
// fingerprint in a URL, an upload id, a token id, an attachment name, a
// channel name, a relay host, a message id, a thread id, and a voucher's
// fingerprint. Each row names
// the rule and the point it runs at (for an attachment name, the rule is
// not a refusal but message.SafeName at the write, and the row asserts
// the safe name and the sender's refusal), and is fed the limit guide's
// traversal set: `..`, `../x`, `x/../../y`, `a/b`, an absolute path, a
// backslash form, a drive letter, a Windows device name, a NUL, the empty
// string, `.`, and a name longer than a filesystem allows; and the names
// Windows spells as another (the trace's C-7): a trailing dot and a
// trailing space, a device name with a space, a UNC path and an alternate
// data stream in its two spellings. The rows whose rule is lowercase hex
// are fed as well the upper case of a fingerprint and of an id, and é
// composed and decomposed, which macOS and Windows take as the lower's
// file or as one name; an attachment name, a channel name and a relay
// host may be either, and are held apart where they are written. When a new
// place turns something from the network into a path, add its row here
// first, before the code; a rule that is not in this table is a rule
// somebody will forget. security.md's paragraph on paths lists the same
// components in the same order, and the file-open ledger's network rows
// at the wire name this test.
//
// The second adversarial trace found the thread id missing from the list:
// an admitted peer's `--thread "../../outside"` was joined onto an expert
// host's serve directory. The path trace found the relay's mailbox
// directory reached by two more doors than the GET route this test drove
// (D-C1): the recipient a forward's envelope names, which the forward
// route queues or delivers, and the recipient of an upload, which the
// stream's open writes into a row and the completion reads back and
// places under; each is driven over HTTP, the row's with the value
// planted in relay.db, and nothing appears in the relay's directory or
// beside it.
func TestLimitNothingTheNetworkNamesIsAPath(t *testing.T) {
	long := strings.Repeat("a", 300)
	values := []string{"..", "../x", "x/../../y", "a/b", "/etc/passwd", `..\x`, `C:\x`, "C:x", "CON", "com1.txt", "\x00", "", ".", long,
		"x.", "x ", "CON .txt", "AUX .  ", `\\srv\share`, "foo::$DATA", "a:b"}
	names := map[string]string{"..": "dot-dot", "../x": "dot-dot-slash", "x/../../y": "x-dot-dot-dot-dot-y", "a/b": "a-slash-b",
		"/etc/passwd": "an absolute path", `..\x`: "a backslash form", `C:\x`: "a drive letter", "C:x": "a drive-relative name",
		"CON": "a Windows device name", "com1.txt": "a Windows device name with an extension", "\x00": "NUL", "": "empty", ".": "dot",
		long: "300 bytes", "x.": "a trailing dot", "x ": "a trailing space", "CON .txt": "a device name with a space",
		"AUX .  ": "a device name with dots and spaces after it", `\\srv\share`: "a UNC path", "foo::$DATA": "an alternate data stream",
		"a:b": "a named stream"}

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
	// A relay that takes forwarded mail, from one neighbour, so that the
	// forward route reads an envelope from a user, whose path names a relay
	// still to go, and from a courier, whose empty path is delivery here.
	courier, err := identity.Generate("courier")
	if err != nil {
		t.Fatal(err)
	}
	couriers := filepath.Join(t.TempDir(), "couriers")
	if err := os.WriteFile(couriers, []byte(courier.Public().ExportLine()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := relay.NewCourier(relay.CourierConfig{AuthorizedFile: couriers, PublicURL: "https://mine.example"},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	srv, st, messages := startRelayOnDisk(t, relay.Config{AdminFile: admins, Courier: c, CourierLimits: relay.DefaultCourierLimits()})
	relayDir := filepath.Dir(messages)
	for _, id := range []*identity.Identity{alice, bob, courier} {
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
	// send is wire for a request with a body or with more path after the
	// value: the mux cleans a path with a dot segment or an empty one by
	// pointing at the cleaned one, which is the refusal, and every other
	// answer is the named refusal or a failure of the test.
	send := func(as *identity.Identity, method, path, value string, body []byte, sentence string) string {
		t.Helper()
		req, err := http.NewRequest(method, srv.URL+path, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if err := relayapi.SignRequest(as, req, body); err != nil {
			t.Fatal(err)
		}
		resp, err := web.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		got, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		switch {
		case resp.StatusCode == http.StatusBadRequest && strings.Contains(string(got), sentence):
			return "refused at the handler"
		case resp.StatusCode/100 == 3 && (value == "." || value == ".." || value == ""):
			return "redirected by the mux"
		}
		t.Errorf("%s %s: %d %s, which is neither the named refusal nor the mux's", method, path, resp.StatusCode, got)
		return "refused, elsewhere"
	}
	// forward sends an envelope whose recipient is the value, with the
	// path given, as the caller given; the route's rule is parseCarried's.
	forward := func(as *identity.Identity, v string, path []string) string {
		t.Helper()
		env, err := json.Marshal(relayapi.Carried{V: 1, To: v, CT: []byte("sealed")})
		if err != nil {
			t.Fatal(err)
		}
		body, err := json.Marshal(relayapi.ForwardRequest{Envelope: env, Path: path, Via: []string{}})
		if err != nil {
			t.Fatal(err)
		}
		return send(as, "POST", "/v1/forward", v, body, "envelope to is not a fingerprint")
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
	// complete opens a stream from alice to bob, plants the value as the
	// row's recipient in relay.db, as a restored backup or a hand edit
	// could, and sends the whole stream, which the relay holds only to its
	// shape: the completion is refused, nothing is placed, and the upload
	// is let go so the next value has room.
	db, err := sql.Open("sqlite", filepath.Join(relayDir, "relay.db")+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	complete := func(v string) string {
		t.Helper()
		ctx := context.Background()
		size := int64(stream.HeaderSize + stream.MinChunk0 + stream.TagSize)
		open, err := aliceClient.OpenStream(ctx, bob.Fingerprint(), "", size, 1)
		if err != nil {
			t.Fatal(err)
		}
		defer aliceClient.AbortStream(ctx, open.Upload)
		if _, err := db.Exec(`UPDATE uploads SET to_fp = ? WHERE id = ?`, v, open.Upload); err != nil {
			t.Fatal(err)
		}
		// bob's mailbox goes under the value for the attempt, so that the
		// completion's judgement of the recipient admits alice as it did at
		// the open, and the value reaches the placement.
		if _, err := db.Exec(`UPDATE mailboxes SET fp = ? WHERE fp = ?`, v, bob.Fingerprint()); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := db.Exec(`UPDATE mailboxes SET fp = ? WHERE fp = ?`, bob.Fingerprint(), v); err != nil {
				t.Fatal(err)
			}
		}()
		data := make([]byte, size)
		binary.BigEndian.PutUint32(data[stream.EncSize:], stream.MinChunk0)
		// The judgement admits, so the refusal is the placement's: the
		// row's recipient is no fingerprint, and the relay says it could
		// not store what it was given rather than name a directory by it.
		if _, err := aliceClient.PutStream(ctx, open.Upload, 0, bytes.NewReader(data), size); err == nil || !strings.Contains(err.Error(), "500: storage error") {
			t.Errorf("the completion with the recipient %q: %v; want the placement's refusal", v, err)
			return ""
		}
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM messages`).Scan(&n); err != nil || n != 0 {
			return ""
		}
		return "refused at the completion"
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
		{"a recipient in a stream's open", "relay: the authed wrapper, identity.ValidFingerprint, 400 before a row names it",
			func(v string) string {
				if identity.ValidFingerprint(v) {
					return ""
				}
				body := []byte(`{"size":1000}`)
				return send(alice, "POST", "/v1/mailbox/"+url.PathEscape(v)+"/streams", v, body, "bad mailbox fingerprint")
			}},
		{"a recipient in a forward's envelope", "relay: parseCarried, identity.ValidFingerprint, 400 before the route queues it for a user's path or delivers it for a courier's",
			func(v string) string {
				if identity.ValidFingerprint(v) {
					return ""
				}
				if forward(alice, v, []string{"bar"}) == "" {
					return ""
				}
				return forward(courier, v, []string{})
			}},
		{"a recipient read back from an upload's row", "relay: the completion judges the row's recipient again and placeUpload holds it to identity.ValidFingerprint before the mailbox's directory is named",
			func(v string) string {
				if identity.ValidFingerprint(v) {
					return ""
				}
				return complete(v)
			}},
		{"an upload id in a URL", "relay: s.upload, relay.ValidUploadID, 400 before the row is read",
			func(v string) string {
				if relay.ValidUploadID(v) {
					return ""
				}
				return wire(alice, "PUT", "/v1/uploads/", v, "bad upload id")
			}},
		{"a token id in a URL", "relay: handleAdminRevokeToken, token.ValidID, 400 before the store is asked",
			func(v string) string {
				if token.ValidID(v) {
					return ""
				}
				return wire(boss, "DELETE", "/v1/admin/tokens/", v, "bad token id")
			}},
		{"an attachment name", "message.SafeName at the write, the receiver's; the sender's rule at SealFor and BuildManifest refuses what SafeName would change",
			func(v string) string {
				// The receiver never refuses a name for what it would do as
				// a path: it writes under SafeName, which is a base name the
				// sender's rule takes; the sender's side refuses the value.
				safe := message.SafeName(v)
				if strings.ContainsAny(safe, `/\`) || message.ValidAttachmentName(safe) != nil {
					return ""
				}
				if message.ValidAttachmentName(v) == nil {
					return ""
				}
				if _, err := stream.BuildManifest(alice, bob.Public(), anID, stream.Body{Type: "ask", Thread: anID, Text: "x"},
					memSource(v), stream.MinChunkSize); !errors.Is(err, stream.ErrForm) {
					return ""
				}
				b := body(anID)
				b.Attachments = []message.Attachment{{Name: v, Media: "x", Size: 1, SHA256: strings.Repeat("0", 64), Data: []byte("x")}}
				if _, _, err := envelope.SealFor(alice, bob.Public(), "", b); err == nil {
					return ""
				}
				return "made safe as " + strconv.Quote(safe) + ", and refused at the sender"
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
				env := sealInnerByHand(t, alice, bob.Public(), &envelope.Inner{V: envelope.Version, ID: v, Time: time.Now().UTC(), Body: body(anID)})
				if _, _, err := envelope.Open(bob, env); envelope.Cause(err) != envelope.ErrMalformed {
					return ""
				}
				if _, err := stream.BuildManifest(alice, bob.Public(), v, stream.Body{Type: "ask", Thread: anID, Text: "x"},
					memSource("a"), stream.MinChunkSize); !errors.Is(err, stream.ErrForm) {
					return ""
				}
				if err := home.Save(store.Inbox, &store.Stored{Relay: "relay", Inner: &envelope.Inner{ID: v, Body: body(anID)}}); err == nil {
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
				if _, _, _, err := worktreeFor(t.TempDir(), &serveChannel{name: "c", Mode: modeSideCopy}, v, t.TempDir(), true); err == nil {
					return ""
				}
				return "refused"
			}},
		{"a voucher's fingerprint", "identity.ValidFingerprint: at vouch.Validate, which Parse and Verify run on every vouch a message carries, and again at the store's join, where a kept vouch is named by it",
			func(v string) string {
				d := &vouch.Document{V: vouch.Version, Voucher: v, Subject: bob.Fingerprint(), Bundle: bob.Public().Bundle(), Name: "bob", Issued: time.Now()}
				if d.Validate() == nil {
					return ""
				}
				if err := home.KeepVouch(v, message.Carried{Document: []byte("{}"), Signature: []byte{1}}); err == nil {
					return ""
				}
				if _, err := home.KeptVouch(v); err == nil || errors.Is(err, store.ErrNoVouch) {
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
	// The other half of a case pair and of é: an attachment name is held
	// apart from its pair at the write (TestLimitAttachmentNameIsNotAPathAtExtract)
	// and refused beside it by the sender (TestLimitNamesAreNotPathsAtManifestValidate),
	// a channel name is never a path from the wire, and a relay host is a
	// DNS name in either case; every other row's rule is lowercase hex.
	folds := map[string]string{strings.ToUpper(bob.Fingerprint()): "a fingerprint in upper case", strings.ToUpper(anID): "an id in upper case",
		"\u00e9": "é composed", "e\u0301": "é decomposed"}
	either := map[string]bool{"an attachment name": true, "a channel name": true, "a relay host": true}
	for _, row := range rows {
		if either[row.what] {
			continue
		}
		for v, name := range folds {
			if got := row.refused(v); got == "" {
				t.Errorf("%s: %s was accepted; the rule is %s", row.what, name, row.where)
			}
		}
	}
	// Nothing was placed, and nothing the values name was made in the
	// relay's directory or beside it.
	if n, err := countTree(messages); err != nil || n != 0 {
		t.Errorf("the relay's messages directory holds %d entries after the set (%v)", n, err)
	}
	entries, err := os.ReadDir(relayDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		switch e.Name() {
		case "messages", "relay.db", "relay.db-shm", "relay.db-wal":
		default:
			t.Errorf("a value from the set made %q in the relay's directory", e.Name())
		}
	}
	// Beside it are the test's other temporary directories, which the
	// testing package numbers, and nothing else.
	entries, err = os.ReadDir(filepath.Dir(relayDir))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if _, err := strconv.Atoi(e.Name()); err != nil || !e.IsDir() {
			t.Errorf("a value from the set made %q beside the relay's directory", e.Name())
		}
	}
}

// countTree is the number of files under dir, at any depth.
func countTree(dir string) (int, error) {
	n := 0
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			n++
		}
		return nil
	})
	return n, err
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
