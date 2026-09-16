package identity

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func TestBundleAndExportRoundTrip(t *testing.T) {
	id, err := Generate("Ada")
	if err != nil {
		t.Fatal(err)
	}
	pub := id.Public()
	if len(pub.Bundle()) != BundleSize {
		t.Fatalf("bundle size %d", len(pub.Bundle()))
	}
	if !ValidFingerprint(pub.Fingerprint()) {
		t.Fatalf("bad fingerprint %q", pub.Fingerprint())
	}

	parsed, err := ParseExportLine(pub.ExportLine())
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Fingerprint() != pub.Fingerprint() {
		t.Fatal("fingerprint changed across export line")
	}
	if parsed.Name != "Ada" {
		t.Fatalf("name %q", parsed.Name)
	}
	if !bytes.Equal(parsed.Bundle(), pub.Bundle()) {
		t.Fatal("bundle changed across export line")
	}

	// Every kind of punctuation a name may hold survives, including the
	// separator itself: the name is everything after the second one.
	pub.Name = "ada.lovelace-x_2"
	again, err := ParseExportLine(pub.ExportLine())
	if err != nil {
		t.Fatal(err)
	}
	if again.Name != "ada.lovelace-x_2" {
		t.Fatalf("name %q", again.Name)
	}

	// No name at all is a shorter line, not a broken one.
	pub.Name = ""
	if strings.Count(pub.ExportLine(), exportSep) != 1 {
		t.Fatalf("a nameless line has the wrong shape: %q", pub.ExportLine()[:30])
	}
	none, err := ParseExportLine(pub.ExportLine())
	if err != nil || none.Name != "" || none.Fingerprint() != pub.Fingerprint() {
		t.Fatalf("nameless line: %v, name %q", err, none.Name)
	}
}

// An export line is one token. That is the point of the format: it pastes
// unquoted and selects with a double-click.
func TestExportLineIsOneToken(t *testing.T) {
	id, err := Generate("a.b-c_d")
	if err != nil {
		t.Fatal(err)
	}
	line := id.Public().ExportLine()
	if strings.ContainsAny(line, " \t\r\n") {
		t.Fatalf("an export line contains whitespace: %q", line[:20])
	}
	if !strings.HasPrefix(line, "ccx2.") {
		t.Fatalf("an export line starts %q", line[:8])
	}
	for _, c := range line {
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9', c == '.', c == '-', c == '_':
		default:
			t.Fatalf("an export line contains %q, which a shell or a terminal may split on", c)
		}
	}
}

// The space-separated ccx1 form has been handed around, so it is still read.
// It is never written.
func TestLegacyExportLineStillParses(t *testing.T) {
	id, err := Generate("alice")
	if err != nil {
		t.Fatal(err)
	}
	pub := id.Public()
	legacy := "ccx1 " + base64.StdEncoding.EncodeToString(pub.Bundle()) + " alice"
	parsed, err := ParseExportLine(legacy)
	if err != nil {
		t.Fatalf("a legacy line was refused: %v", err)
	}
	if parsed.Fingerprint() != pub.Fingerprint() || parsed.Name != "alice" {
		t.Fatalf("legacy line parsed to %s %q", parsed.Fingerprint()[:12], parsed.Name)
	}
	// Without a name, too.
	if p, err := ParseExportLine("ccx1 " + base64.StdEncoding.EncodeToString(pub.Bundle())); err != nil || p.Name != "" {
		t.Fatalf("nameless legacy line: %v, name %q", err, p.Name)
	}
	// A legacy name with a space is held to the same rule as a new one:
	// nothing that reaches authorized_peers may carry whitespace.
	if _, err := ParseExportLine(legacy + " lovelace"); err == nil {
		t.Fatal("a legacy line with a space in its name was accepted")
	}
	// And whatever is written is the new form.
	if strings.HasPrefix(pub.ExportLine(), "ccx1") {
		t.Fatal("ExportLine still writes the legacy form")
	}
}

// Names: the boundary of the length, and one of each character class that
// is refused.
func TestValidName(t *testing.T) {
	good := []string{
		"a", "A", "7", "bunty", "a.b", "a-b", "a_b", "a.b-c_d9", "ops-oncall",
		strings.Repeat("n", MaxNameBytes),
	}
	for _, n := range good {
		if err := ValidName(n); err != nil {
			t.Errorf("valid name %q refused: %v", n, err)
		}
		if _, err := Generate(n); err != nil {
			t.Errorf("Generate refused valid name %q: %v", n, err)
		}
	}
	bad := []string{
		"self", "Self", "SELF", // the word for you
		"", " ", ".a", "-a", "_a", "a b", "a\tb", "a\n", "\nb", "a/b", "a;b", "a$b",
		"a'b", "a\"b", "a(b)", "é", "a\x1b[31m", strings.Repeat("n", MaxNameBytes+1),
	}
	for _, n := range bad {
		if err := ValidName(n); err == nil {
			t.Errorf("bad name %q accepted", n)
		}
		if _, err := Generate(n); err == nil && n != "" {
			t.Errorf("Generate accepted bad name %q", n)
		}
	}
	// An empty name is allowed to Generate: it is an identity with no name,
	// which exports as a line with no name.
	if _, err := Generate(""); err != nil {
		t.Fatalf("Generate refused an empty name: %v", err)
	}
}

func TestFingerprintStableAcrossSeeds(t *testing.T) {
	id, err := Generate("a")
	if err != nil {
		t.Fatal(err)
	}
	j, err := id.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	var restored Identity
	if err := restored.UnmarshalJSON(j); err != nil {
		t.Fatal(err)
	}
	if restored.Fingerprint() != id.Fingerprint() {
		t.Fatal("fingerprint not stable across save and load")
	}
	sig := mustSign(t, &restored, []byte("hello"))
	if !id.Public().Verify([]byte("hello"), sig) {
		t.Fatal("restored key does not sign compatibly")
	}
}

func TestSignVerify(t *testing.T) {
	id, _ := Generate("a")
	other, _ := Generate("b")
	msg := []byte("attack at dawn")
	sig := mustSign(t, id, msg)
	if !id.Public().Verify(msg, sig) {
		t.Fatal("valid signature rejected")
	}
	if other.Public().Verify(msg, sig) {
		t.Fatal("signature verified under the wrong key")
	}
	if id.Public().Verify([]byte("attack at dusk"), sig) {
		t.Fatal("signature verified over the wrong message")
	}
}

func TestParseExportLineRejects(t *testing.T) {
	good, _ := Generate("x")
	line := good.Public().ExportLine()
	_, rest, _ := strings.Cut(line, exportSep)
	field, _, _ := strings.Cut(rest, exportSep)
	bad := []string{
		"",
		"   ",
		"# a comment",
		"ccx1",
		"ccx2",
		"ccx2.",
		"ssh-ed25519 AAAA name",
		"ccx1 not-base64!!",
		"ccx2.not-base64!!",
		"ccx2." + field[:20],                  // truncated bundle
		"ccx3." + field,                       // a version nobody has defined
		"ccx2 " + field,                       // new prefix, old separator
		"ccx1." + field,                       // old prefix, new separator
		"ccx2." + field + ".bad name",         // the name rule, in the new form
		"ccx2." + field + ".-flag",            // a name that would look like a flag
		"ccx2." + field + ".a\nccx2." + field, // a second line smuggled in a name
		"ccx2." + field + "." + strings.Repeat("n", MaxNameBytes+1),
	}
	for _, s := range bad {
		if _, err := ParseExportLine(s); err == nil {
			t.Fatalf("accepted bad line %q", s)
		}
	}
}

func TestParseBundleRejectsWrongSize(t *testing.T) {
	if _, err := ParseBundle(make([]byte, BundleSize-1)); err == nil {
		t.Fatal("accepted short bundle")
	}
}

func TestValidFingerprint(t *testing.T) {
	id, _ := Generate("x")
	cases := map[string]bool{
		id.Fingerprint():                  true,
		strings.ToUpper(id.Fingerprint()): false,
		id.Fingerprint()[:63]:             false,
		id.Fingerprint() + "0":            false,
		strings.Repeat("g", 64):           false,
		"../../etc/passwd":                false,
	}
	for in, want := range cases {
		if got := ValidFingerprint(in); got != want {
			t.Fatalf("ValidFingerprint(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestValidShortID(t *testing.T) {
	id, _ := Generate("x")
	short := id.Public().Short()
	if len(short) != ShortIDLen {
		t.Fatalf("Short() is %d characters, ShortIDLen is %d", len(short), ShortIDLen)
	}
	cases := map[string]bool{
		short:                   true,
		id.Fingerprint():        false, // a whole fingerprint is not a short id
		strings.ToUpper(short):  false,
		short[:15]:              false,
		short + "0":             false,
		strings.Repeat("g", 16): false,
		"../../etc/passwd":      false,
		strings.Repeat("0", 16): true,
	}
	for in, want := range cases {
		if got := ValidShortID(in); got != want {
			t.Fatalf("ValidShortID(%q) = %v, want %v", in, got, want)
		}
	}
}

// BundleSize is a constant, so assert it still matches what the KEM produces.
func TestBundleSizeMatchesKeyMaterial(t *testing.T) {
	id, err := Generate("x")
	if err != nil {
		t.Fatal(err)
	}
	if got := len(id.Public().Bundle()); got != BundleSize {
		t.Fatalf("bundle is %d bytes, BundleSize says %d", got, BundleSize)
	}
	if got := len(id.Public().KEM.Bytes()); got != KEMPublicKeySize {
		t.Fatalf("kem public key is %d bytes, KEMPublicKeySize says %d", got, KEMPublicKeySize)
	}
	seed, err := id.KEM().Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if len(seed) != KEMPrivateKeySize {
		t.Fatalf("kem private key is %d bytes, KEMPrivateKeySize says %d", len(seed), KEMPrivateKeySize)
	}
}

func TestKEMSuiteIsXWing(t *testing.T) {
	// MLKEM768-X25519, a.k.a. X-Wing, from draft-ietf-hpke-pq.
	if got := KEMSuite().ID(); got != 0x647a {
		t.Fatalf("KEM id is 0x%04x, expected 0x647a (MLKEM768-X25519)", got)
	}
}

// A line with a break in it arrives as the wrong length, and the break is
// the likelier explanation than a key of another size: the length error
// asks, when the input shows a newline, and only then. The container
// suite's K25 found a wrapped line reported as too long and nothing more.
func TestAWrappedLineIsSaidToBe(t *testing.T) {
	id, err := Generate("ada")
	if err != nil {
		t.Fatal(err)
	}
	line := id.Public().ExportLine()
	const question = " (was the line wrapped?)"

	// Wrapped in the middle of the key: the first half's length is wrong
	// and the newline is in the input.
	_, err = ParseExportLine(line[:120] + "\n" + line[120:])
	if err == nil {
		t.Fatal("a wrapped line was accepted")
	}
	if !errors.Is(err, ErrLineLength) || !strings.HasSuffix(err.Error(), question) {
		t.Fatalf("a wrapped line gave %q, want the length error asking the question", err)
	}
	if !strings.HasPrefix(err.Error(), "identity: key line is not the length of a key: ") {
		t.Fatalf("error %q does not lead with the fact", err)
	}

	// The same wrong length with no newline in it — a line cut short, or
	// one half of a wrapped line read from a file — does not ask; the
	// reader of the file does.
	_, err = ParseExportLine(line[:120])
	if err == nil || !errors.Is(err, ErrLineLength) || strings.Contains(err.Error(), question) {
		t.Fatalf("a short line with no newline gave %q, want the length error without the question", err)
	}

	// A newline that is not inside the key is trimmed, and the line parses.
	if _, err := ParseExportLine(line + "\n"); err != nil {
		t.Fatalf("a trailing newline was refused: %v", err)
	}
	// And another error with a newline in the input is not given the
	// question, which belongs to the length alone.
	_, err = ParseExportLine("nonsense\nmore")
	if err == nil || strings.Contains(err.Error(), question) {
		t.Fatalf("a line that is not a key at all asked the wrapping question: %v", err)
	}
}

// A file of export lines parses in order with blank and comment lines
// skipped, and a bad line is named by the file's name and its number in the
// file, counting the skipped ones, since that is the line a person opens
// the file to.
func TestParseExportLinesNumbersTheBadLine(t *testing.T) {
	a, _ := Generate("a")
	b, _ := Generate("b")
	data := "# who may administer\n\n" + a.Public().ExportLine() + "\n  \n" + b.Public().ExportLine() + "\n"
	keys, err := ParseExportLines("/etc/auu/admins", []byte(data))
	if err != nil || len(keys) != 2 || keys[0].Name != "a" || keys[1].Name != "b" {
		t.Fatalf("ParseExportLines = %v, %v; want a then b", keys, err)
	}
	_, err = ParseExportLines("/etc/auu/admins", []byte(data+"ssh-ed25519 AAAA nobody\n"))
	if err == nil || !strings.HasPrefix(err.Error(), "/etc/auu/admins line 6: ") {
		t.Fatalf("a bad sixth line: %v, want it named by file and number", err)
	}
	if !strings.Contains(err.Error(), `unknown key type "ssh-ed25519"`) {
		t.Fatalf("the bad line's own error is not carried: %v", err)
	}
	keys, err = ParseExportLines("empty", nil)
	if err != nil || len(keys) != 0 {
		t.Fatalf("an empty file: %v, %v; want no keys and no error", keys, err)
	}
}
