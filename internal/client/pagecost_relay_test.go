package client_test

import (
	"bufio"
	"crypto/mldsa"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	neturl "net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/client"
	"github.com/tropeforce7/agentuucp/internal/clientca"
	"github.com/tropeforce7/agentuucp/internal/envelope"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/relay"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// G4 through a real relay rather than a stand-in: the relay declares its
// listing's length (writeJSON marshals first), so a page of several MiB is
// read into a buffer of its own size and decoded once. A page that carries
// envelopes, unlike the review's page of padding, is decoded into values
// that hold a copy of each envelope beside the buffer they came from, so it
// costs about twice itself live however it is read. The client holds it
// under two and a quarter times the page at once, read either way, and
// under three times in all when the length is declared and four when it is
// not, io.ReadAll's growth on top of the copies (R13b). The
// relay runs in a process of its own, this test binary in helper mode, so
// that what the measure sees is the client's alone and not the relay's
// reading and marshalling of the same page in this heap.
//
// The helper's environment names the directory its store is in; it serves
// until its standard input closes, which is also how it learns this test
// has gone however it ended.
func TestRelayProcessHelper(t *testing.T) {
	dir := os.Getenv("AUU_PAGECOST_RELAY")
	if dir == "" {
		t.Skip("the relay process for TestARealRelaysPageIsTakenWithinR13asBounds")
	}
	st, err := relay.OpenStore(filepath.Join(dir, "relay.db"), filepath.Join(dir, "messages"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	handler := relay.NewServer(st, relay.Config{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	defer handler.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go http.Serve(ln, handler)
	fmt.Printf("relay http://%s\n", ln.Addr())
	io.Copy(io.Discard, os.Stdin)
	ln.Close()
}

// startRelayProcess starts TestRelayProcessHelper and hands back its URL.
func startRelayProcess(t *testing.T) string {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestRelayProcessHelper$", "-test.v")
	cmd.Env = append(os.Environ(), "AUU_PAGECOST_RELAY="+t.TempDir())
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stdin.Close(); cmd.Wait() })
	sc := bufio.NewScanner(out)
	for sc.Scan() {
		if url, ok := strings.CutPrefix(sc.Text(), "relay "); ok {
			go io.Copy(io.Discard, out)
			return url
		}
	}
	t.Fatalf("the relay process never said where it was: %v", sc.Err())
	return ""
}

// G4 through a real relay rather than a stand-in: see TestRelayProcessHelper.
func TestARealRelaysPageIsTakenWithinR13asBounds(t *testing.T) {
	if client.RaceEnabled {
		t.Skip("allocation is measured without the race detector")
	}
	url := startRelayProcess(t)

	join := func(name string) (*identity.Identity, *client.Client) {
		t.Helper()
		id, err := identity.Generate(name)
		if err != nil {
			t.Fatal(err)
		}
		c, err := client.New(url, id, nil)
		if err != nil {
			t.Fatal(err)
		}
		key, err := mldsa.GenerateKey(mldsa.MLDSA65())
		if err != nil {
			t.Fatal(err)
		}
		csr, err := clientca.NewCSR(key, "test-machine", "")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Register(t.Context(), csr); err != nil {
			t.Fatal(err)
		}
		return id, c
	}
	alice, ac := join("alice")
	bob, bc := join("bob")

	// Eight messages of a MiB of text each: a page of about eleven MiB,
	// under the default max_bytes of 16 MiB that sizes the relay's page and
	// the client's hold.
	const n, text = 8, 1 << 20
	for i := range n {
		env, _, err := envelope.Seal(alice, bob.Public(), message.Body{
			Type: message.TypeAsk, Thread: "0123456789abcdef0123456789abcdef", Subject: "s",
			Text: strings.Repeat("x", text-8) + strconv.Itoa(10000000+i),
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ac.Post(t.Context(), env, ""); err != nil {
			t.Fatalf("post %d: %v", i, err)
		}
	}
	// The page's size and its declared length, asked of the relay as the
	// client asks it, before the measure.
	req, err := http.NewRequest("GET", url+"/v1/mailbox/"+bob.Fingerprint()+"?after=0&limit="+strconv.Itoa(relayapi.MaxListLimit), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := relayapi.SignRequest(bob, req, nil); err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("the listing: %d, %v", resp.StatusCode, err)
	}
	page := uint64(len(raw))
	if resp.ContentLength != int64(page) {
		t.Fatalf("the relay declared %d for a page of %d bytes", resp.ContentLength, page)
	}
	if page < 8<<20 {
		t.Fatalf("a page of %d bytes; want several MiB to measure", page)
	}

	// The same page through a proxy that strips its length, so that it
	// comes chunked: a relay withholding its length, read as it comes.
	target, err := neturl.Parse(url)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.FlushInterval = -1
	proxy.ModifyResponse = func(r *http.Response) error {
		r.Header.Del("Content-Length")
		r.ContentLength = -1
		return nil
	}
	ps := httptest.NewServer(proxy)
	t.Cleanup(ps.Close)
	chunked, err := client.New(ps.URL, bob, nil)
	if err != nil {
		t.Fatal(err)
	}
	req, err = http.NewRequest("GET", ps.URL+"/v1/mailbox/"+bob.Fingerprint()+"?after=0&limit="+strconv.Itoa(relayapi.MaxListLimit), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := relayapi.SignRequest(bob, req, nil); err != nil {
		t.Fatal(err)
	}
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	via, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || resp.ContentLength != -1 || !slices.Equal(resp.TransferEncoding, []string{"chunked"}) || len(via) != len(raw) {
		t.Fatalf("through the proxy: %v, Content-Length %d, %v, %d bytes; want the page chunked", err, resp.ContentLength, resp.TransferEncoding, len(via))
	}

	for _, tc := range []struct {
		name  string
		c     *client.Client
		total uint64 // the most TotalAlloc may be, in pages
	}{
		{"declared", bc, 3},
		{"chunked", chunked, 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The live figure is sampled with a collection forced before
			// each sample, so that garbage a collector slowed by the rest of
			// the suite has not reached does not count as live: what the
			// page holds is what the machine keeps.
			var got client.Listing
			var listErr error
			total, peak := client.PageCostMeasureCollected(func() { got, listErr = tc.c.List(t.Context(), 0, relayapi.MaxListLimit) })
			t.Logf("a real relay's page of %d bytes (%d messages, %s): TotalAlloc +%d KiB (%.2fx the page); peak live +%d KiB (%.2fx)",
				page, n, tc.name, total>>10, float64(total)/float64(page), peak>>10, float64(peak)/float64(page))
			if listErr != nil {
				t.Fatal(listErr)
			}
			if len(got.Messages) != n {
				t.Fatalf("the page held %d messages; want %d", len(got.Messages), n)
			}
			if total >= tc.total*page {
				t.Errorf("a page of %d bytes (%s) allocated %d KiB, %.2f times the page; want under %d times",
					page, tc.name, total>>10, float64(total)/float64(page), tc.total)
			}
			if peak*4 >= 9*page {
				t.Errorf("a page of %d bytes (%s) held %d KiB live at its peak, %.2f times the page; want under two and a quarter",
					page, tc.name, peak>>10, float64(peak)/float64(page))
			}
		})
	}
}
