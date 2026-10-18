package pki

import (
	"crypto/mldsa"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestLimitBundleV: a bundle's v is 1, and LoadBundle refuses every other
// value naming the version this build understands, the type's extremes
// among them, before it reads anything else in the file.
func TestLimitBundleV(t *testing.T) {
	store := TestStore(t, mldsa.MLDSA65())
	b, err := store.IssueRelay([]string{"relay.example.com"}, 1, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "bundle.json")
	for _, v := range []int{0, 2, -1, math.MinInt, math.MaxInt} {
		b.V = v
		if err := WriteBundle(path, b); err != nil {
			t.Fatal(err)
		}
		_, err := LoadBundle(path)
		if err == nil || !strings.Contains(err.Error(), "bundle version "+strconv.Itoa(v)+", but this build understands 1") {
			t.Errorf("v %d: %v; want the refusal naming both versions", v, err)
		}
	}
	b.V = BundleVersion
	if err := WriteBundle(path, b); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadBundle(path); err != nil {
		t.Errorf("v 1: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
}

// TestLimitAServerLeafAndARecordNeedAHost: ServerLeaf names the leaf by
// hosts[0] and FindRecord files a new relay under it, and neither checked
// the list as Intermediate and the bundle's load do; every caller passes
// one, so nothing reached it, but the index was the function's to guard
// (P3, the second trace's E-1 and E-2). Both refuse nil and an empty list,
// and take one host.
func TestLimitAServerLeafAndARecordNeedAHost(t *testing.T) {
	s := hierarchy(t)
	l := TestBundleFrom(t, s, []string{"relay.example.com"})
	for _, hosts := range [][]string{nil, {}} {
		if _, err := ServerLeaf(l.ServerInt, hosts, l.Params, time.Now()); err == nil || !strings.Contains(err.Error(), "at least one host") {
			t.Errorf("ServerLeaf(%#v): %v", hosts, err)
		}
		if _, _, err := s.FindRecord(hosts); err == nil || !strings.Contains(err.Error(), "at least one host") {
			t.Errorf("FindRecord(%#v): %v", hosts, err)
		}
	}
	if leaf, err := ServerLeaf(l.ServerInt, []string{"relay.example.com"}, l.Params, time.Now()); err != nil || leaf.Cert.Subject.CommonName != "relay.example.com" {
		t.Errorf("ServerLeaf with one host: %v", err)
	}
	if name, _, err := s.FindRecord([]string{"other.example.com"}); err != nil || name != "other.example.com" {
		t.Errorf("FindRecord with one host: %q, %v", name, err)
	}
}

// TestLimitAHostIsHeldToItsRules: a relay's host names the authority's
// record directory for it, through safeHost, after IssueRelay has held it
// to splitHosts: an address, or a DNS name validDNSName takes. The path
// trace's tracer printed what both did with the limit guide's set
// (ruling 6); this is that set as assertions. validDNSName refuses every
// value of the traversal set, the names Windows spells as another (a
// trailing dot or space, a device name with a space or as a first label,
// a UNC path, an alternate data stream), é composed and decomposed, an
// empty label at either end or between two dots, a hyphen at a label's
// edge, a label over 63 characters and a name over 253, and an address
// with a zone or in brackets, which is neither an address nor a name; it
// takes a name with a label of 63 and one of 253 characters, a name in
// either case, and splitHosts takes an IPv4 and an IPv6 address. safeHost,
// the belt and braces, makes every one of them one segment of the
// characters a DNS name and an address hold and of '_', never empty and
// never beginning with a dot, and leaves a name validDNSName takes as it
// is.
func TestLimitAHostIsHeldToItsRules(t *testing.T) {
	label63 := strings.Repeat("a", 63)
	refused := []string{"..", "../x", "x/../../y", "a/b", "/etc/passwd", `..\x`, `C:\x`, "C:x", "CON", "com1.txt", "\x00", "", ".", strings.Repeat("a", 300),
		"x.", "x ", "CON .txt", "AUX .  ", `\\srv\share`, "foo::$DATA", "a:b", "\u00e9", "e\u0301",
		"con.example.com", "nul", "example.com.", ".example.com", "a..b", "-a.com", "a-.com", strings.Repeat("a", 64) + ".com",
		label63 + "." + label63 + "." + label63 + "." + label63, "fe80::1%eth0", "[::1]"}
	taken := []string{"relay.example.com", "a", "RELAY.Example.com", "xn--e-ufa.example", "a-b.example", label63 + ".com",
		label63 + "." + label63 + "." + label63 + "." + strings.Repeat("a", 61)}
	for _, v := range refused {
		if err := validDNSName(v); err == nil {
			t.Errorf("validDNSName took %q", v)
		}
		if _, _, err := splitHosts([]string{v}); err == nil {
			t.Errorf("splitHosts took %q", v)
		}
	}
	for _, v := range taken {
		if err := validDNSName(v); err != nil {
			t.Errorf("validDNSName refused %q: %v", v, err)
		}
		if got := safeHost(v); got != v {
			t.Errorf("safeHost(%q) = %q; a name validDNSName takes is its own segment", v, got)
		}
	}
	if n := len(taken[len(taken)-1]); n != 253 {
		t.Fatalf("the longest name is %d characters, not 253", n)
	}
	for _, v := range []string{"127.0.0.1", "::1", "2001:db8::1"} {
		if dns, ips, err := splitHosts([]string{v}); err != nil || len(dns) != 0 || len(ips) != 1 {
			t.Errorf("splitHosts(%q): %v, %v, %v; want one address", v, dns, ips, err)
		}
	}
	dir := filepath.Join("records", "relays")
	for _, v := range append(append(refused, taken...), "127.0.0.1", "::1", "2001:db8::1") {
		got := safeHost(v)
		if got == "" || got == "." || got == ".." || strings.HasPrefix(got, ".") {
			t.Errorf("safeHost(%q) = %q, which is no directory of its own", v, got)
		}
		for i := 0; i < len(got); i++ {
			c := got[i]
			if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '.' || c == '-' || c == '_') {
				t.Errorf("safeHost(%q) = %q holds %q", v, got, string(c))
				break
			}
		}
		if filepath.Dir(filepath.Join(dir, got)) != dir {
			t.Errorf("safeHost(%q) = %q is not one segment under %s", v, got, dir)
		}
	}
}
