package keyfile

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math"
	"strconv"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/testutil"
)

const secret = "correct horse battery staple"

// cheap is the derivation every test but the two about cost uses.
func cheap() Passphrase { return TestPassphrase(secret) }

// sealed is a valid file over plaintext, at the cheap cost.
func sealed(t *testing.T, plaintext []byte) []byte {
	t.Helper()
	out, err := Encrypt(plaintext, cheap())
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	return out
}

// TestKnownAnswer pins the derivation, so that a change to the order of the
// two functions, to either one's parameters, or to what is fed to the second
// is a failing test rather than a file nobody can open any more.
//
// The Argon2id half is pinned separately and is the plain RFC 9106 function,
// so it can be checked against any other implementation.
func TestKnownAnswer(t *testing.T) {
	salt := []byte("0123456789abcdef")
	full := cost{time: DefaultTime, memory: DefaultMemory, threads: DefaultThreads, iterations: DefaultIterations}

	const wantChained = "8beb35a652ead46907040dde1ae0c45e4cf871c37396361009d8bf941bff7e58"
	got, err := deriveFileKey([]byte(secret), salt, full)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got) != wantChained {
		t.Errorf("the file key for the pinned input is %s, want %s", hex.EncodeToString(got), wantChained)
	}
}

// TestRoundTripRandom seals and opens random content at random lengths, and
// at the lengths a block cipher and an empty input make interesting.
func TestRoundTripRandom(t *testing.T) {
	r, seed := testutil.Seed(t)
	lengths := testutil.Lengths(4096, 16)
	for i := 0; i < 24; i++ {
		lengths = append(lengths, r.IntN(4096))
	}
	for _, n := range lengths {
		plaintext := testutil.Bytes(r, n)
		out := sealed(t, plaintext)
		back, err := Decrypt(out, []byte(secret))
		if err != nil {
			t.Fatalf("length %d did not open: %v (seed %d)", n, err, seed)
		}
		if !bytes.Equal(back, plaintext) {
			t.Fatalf("length %d came back changed (seed %d)", n, seed)
		}
	}
}

func TestAWrongPassphraseIsRefused(t *testing.T) {
	out := sealed(t, []byte("a key"))
	for _, wrong := range []string{
		secret + " ",
		" " + secret,
		strings.ToUpper(secret),
		secret[:len(secret)-1],
		"",
	} {
		_, err := Decrypt(out, []byte(wrong))
		switch {
		case wrong == "" && !errors.Is(err, ErrEmptyPassphrase):
			t.Errorf("an empty passphrase gave %v, want ErrEmptyPassphrase", err)
		case wrong != "" && !errors.Is(err, ErrPassphrase):
			t.Errorf("passphrase %q gave %v, want ErrPassphrase", wrong, err)
		}
	}
}

// TestOneFlippedBitIsRefused vandalises each structurally distinct region of
// the file, one bit at a time. Each region is guarded by a different check,
// and a flip that keeps every length and every encoding intact leaves only
// the cryptography to refuse it.
func TestOneFlippedBitIsRefused(t *testing.T) {
	out := sealed(t, []byte("a key worth stealing"))
	block, _ := pem.Decode(out)
	if block == nil {
		t.Fatal("what Encrypt wrote is not PEM")
	}
	body := block.Bytes
	// The regions of the body, named from the format's constants: GCM puts
	// the nonce first and the tag last.
	for _, region := range []struct {
		name string
		bit  int
	}{
		{"nonce", 0},
		{"nonce, last byte", (nonceSize - 1) * 8},
		{"ciphertext, first byte", nonceSize * 8},
		{"ciphertext, last byte", (len(body) - tagSize - 1) * 8},
		{"tag, first byte", (len(body) - tagSize) * 8},
		{"tag, last byte", (len(body) - 1) * 8},
	} {
		t.Run(region.name, func(t *testing.T) {
			bad := *block
			bad.Bytes = testutil.FlipBit(body, region.bit)
			if _, err := DecryptBlock(&bad, []byte(secret)); !errors.Is(err, ErrPassphrase) {
				t.Errorf("a flipped bit in the %s gave %v, want ErrPassphrase", region.name, err)
			}
		})
	}

	// And the headers. Every one of them either names a function this build
	// checks by name or feeds the derivation, so an altered header is
	// refused by the parser or produces a different key; the additional
	// data is what would catch a header that did neither, and
	// TestEveryHeaderIsInTheAdditionalData is what keeps it able to.
	for name, replacement := range map[string]string{
		hdrKDF:        "PBKDF2-HMAC-SHA256",
		hdrCipher:     "AES-128-GCM",
		hdrTime:       strconv.Itoa(MinTime + 1),
		hdrMemory:     strconv.Itoa(8*MinThreads + 4),
		hdrThreads:    strconv.Itoa(MinThreads + 1),
		hdrIterations: strconv.Itoa(MinIterations + 1),
		hdrSalt:       base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, saltSize)),
	} {
		t.Run("header "+name, func(t *testing.T) {
			bad := *block
			bad.Headers = map[string]string{}
			for k, v := range block.Headers {
				bad.Headers[k] = v
			}
			if bad.Headers[name] == replacement {
				t.Fatalf("the test's replacement for %s is what the file already says", name)
			}
			bad.Headers[name] = replacement
			if _, err := DecryptBlock(&bad, []byte(secret)); err == nil {
				t.Errorf("%s changed to %q was accepted", name, replacement)
			}
		})
	}
}

// TestTruncatedAndExtended: a byte off either end of the body.
func TestTruncatedAndExtended(t *testing.T) {
	out := sealed(t, []byte("a key"))
	block, _ := pem.Decode(out)
	for _, tc := range []struct {
		name string
		body []byte
	}{
		{"a byte off the front", block.Bytes[1:]},
		{"a byte off the back", block.Bytes[:len(block.Bytes)-1]},
		{"a byte added", append(append([]byte{}, block.Bytes...), 0)},
		{"a byte inserted at the front", append([]byte{0}, block.Bytes...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := *block
			bad.Bytes = tc.body
			if _, err := DecryptBlock(&bad, []byte(secret)); err == nil {
				t.Errorf("%s was accepted", tc.name)
			}
		})
	}
}

// TestABodyTooShortToBeAnythingIsRefusedBeforeTheDerivation. A body that
// cannot hold a nonce and a tag is refused on its length, so a file of
// nothing cannot make a reader spend a second deriving a key first.
func TestABodyTooShortToBeAnythingIsRefused(t *testing.T) {
	out := sealed(t, nil)
	block, _ := pem.Decode(out)
	for _, n := range []int{0, 1, nonceSize + tagSize - 1} {
		bad := *block
		bad.Bytes = bytes.Repeat([]byte{0}, n)
		_, err := DecryptBlock(&bad, []byte(secret))
		if err == nil {
			t.Errorf("a %d-byte body was accepted", n)
			continue
		}
		if !strings.Contains(err.Error(), "shorter than a nonce and a tag") {
			t.Errorf("a %d-byte body gave %q, want the length error", n, err)
		}
	}
	// And the shortest body that is not refused on length: it reaches the
	// AEAD, which is the check that should refuse it.
	bad := *block
	bad.Bytes = bytes.Repeat([]byte{0}, nonceSize+tagSize)
	if _, err := DecryptBlock(&bad, []byte(secret)); !errors.Is(err, ErrPassphrase) {
		t.Errorf("a body of exactly a nonce and a tag gave %v, want ErrPassphrase", err)
	}
}

// TestCostBoundaries walks both sides of every edge, one step apart, and the
// values a signed type makes dangerous.
func TestCostBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name string
		p    Passphrase
		ok   bool
	}{
		// Time. One below its floor is zero, which is the documented
		// "use the default" value rather than a refusal, so the step below
		// this edge is minus one and zero has its own test.
		{"time at zero is the default", Passphrase{Time: MinTime - 1}, true},
		{"time at the floor", Passphrase{Time: MinTime}, true},
		{"time at the ceiling", Passphrase{Time: MaxTime}, true},
		{"time over the ceiling", Passphrase{Time: MaxTime + 1}, false},
		{"time at MaxInt", Passphrase{Time: math.MaxInt}, false},
		{"time at MinInt", Passphrase{Time: math.MinInt}, false},
		{"time minus one", Passphrase{Time: -1}, false},
		// Threads. Memory has a floor of eight per thread, so it moves too.
		{"threads at zero is the default", Passphrase{Threads: MinThreads - 1, Memory: 8 * DefaultThreads}, true},
		{"threads at the floor", Passphrase{Threads: MinThreads, Memory: 8}, true},
		{"threads at the ceiling", Passphrase{Threads: MaxThreads, Memory: 8 * MaxThreads}, true},
		{"threads over the ceiling", Passphrase{Threads: MaxThreads + 1, Memory: 8 * (MaxThreads + 1)}, false},
		{"threads at MaxInt", Passphrase{Threads: math.MaxInt}, false},
		{"threads minus one", Passphrase{Threads: -1}, false},
		// Memory, in KiB, with one thread: floor 8, and a multiple of 4.
		{"memory below the floor", Passphrase{Threads: 1, Memory: 4}, false},
		{"memory at the floor", Passphrase{Threads: 1, Memory: 8}, true},
		{"memory not a multiple of four", Passphrase{Threads: 1, Memory: 10}, false},
		{"memory over the ceiling", Passphrase{Threads: 1, Memory: MaxMemory + 4}, false},
		{"memory at MaxInt", Passphrase{Threads: 1, Memory: math.MaxInt}, false},
		{"memory minus one", Passphrase{Threads: 1, Memory: -1}, false},
		// PBKDF2.
		{"iterations at zero is the default", Passphrase{Iterations: MinIterations - 1}, true},
		{"iterations at the floor", Passphrase{Iterations: MinIterations}, true},
		{"iterations over the ceiling", Passphrase{Iterations: MaxIterations + 1}, false},
		{"iterations at MaxInt", Passphrase{Iterations: math.MaxInt}, false},
		{"iterations at MinInt", Passphrase{Iterations: math.MinInt}, false},
		{"iterations minus one", Passphrase{Iterations: -1}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := tc.p
			p.Secret = []byte(secret)
			// Everything unset takes the cheap value rather than the
			// shipped one, so a boundary test costs nothing to run.
			if p.Time == 0 {
				p.Time = MinTime
			}
			if p.Threads == 0 {
				p.Threads = MinThreads
			}
			if p.Memory == 0 {
				p.Memory = 8 * MinThreads
			}
			if p.Iterations == 0 {
				p.Iterations = MinIterations
			}
			// A ceiling that is accepted must not actually be computed:
			// MaxTime passes over 8 KiB is still slow, and MaxThreads is a
			// lot of lanes. costFor is the check under test.
			_, err := costFor(p)
			if tc.ok && err != nil {
				t.Fatalf("%s was refused: %v", tc.name, err)
			}
			if !tc.ok && err == nil {
				t.Fatalf("%s was accepted", tc.name)
			}
			if !tc.ok && !strings.Contains(err.Error(), "keyfile: ") {
				t.Errorf("error %q does not name the package", err)
			}
		})
	}
}

// TestZeroMeansTheDefaultToACallerAndNothingInAFile. Encrypt takes zero as
// "use the default"; a file may not, because a header has to be the count
// that was actually used.
func TestZeroMeansTheDefaultToACallerAndNothingInAFile(t *testing.T) {
	c, err := costFor(Passphrase{Secret: []byte(secret)})
	if err != nil {
		t.Fatal(err)
	}
	want := cost{DefaultTime, DefaultMemory, DefaultThreads, DefaultIterations}
	if c != want {
		t.Errorf("a zero Passphrase resolves to %+v, want %+v", c, want)
	}
	for _, name := range []string{hdrTime, hdrMemory, hdrThreads, hdrIterations} {
		headers := validHeaders()
		headers[name] = "0"
		if _, _, err := parseHeaders(headers); err == nil {
			t.Errorf("a file claiming %s: 0 was accepted", name)
		}
	}
}

// TestTheSaltIsCheckedBeforeItIsDecoded uses the which-check-fired trick: a
// value that is both far too long and not valid base64 must produce the
// length error, because base64 allocates its whole output first.
func TestTheSaltIsCheckedBeforeItIsDecoded(t *testing.T) {
	headers := validHeaders()
	headers[hdrSalt] = strings.Repeat("A", base64.StdEncoding.EncodedLen(MaxSaltSize)+8) + "!!"
	_, _, err := parseHeaders(headers)
	if err == nil {
		t.Fatal("an oversized salt was accepted")
	}
	if !strings.Contains(err.Error(), "longer than") {
		t.Errorf("error is %q; the length check did not fire first", err)
	}
}

func TestSaltSizeBoundaries(t *testing.T) {
	for _, tc := range []struct {
		n  int
		ok bool
	}{
		{MinSaltSize - 1, false},
		{MinSaltSize, true},
		{MaxSaltSize, true},
		{MaxSaltSize + 1, false},
		{0, false},
	} {
		headers := validHeaders()
		headers[hdrSalt] = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, tc.n))
		_, _, err := parseHeaders(headers)
		if tc.ok && err != nil {
			t.Errorf("a %d-byte salt was refused: %v", tc.n, err)
		}
		if !tc.ok && err == nil {
			t.Errorf("a %d-byte salt was accepted", tc.n)
		}
	}
}

func TestHeadersAreExactlyTheOnesWritten(t *testing.T) {
	for _, name := range headerNames {
		headers := validHeaders()
		delete(headers, name)
		_, _, err := parseHeaders(headers)
		if err == nil {
			t.Errorf("a file with no %s header was accepted", name)
			continue
		}
		if !strings.Contains(err.Error(), name) {
			t.Errorf("error %q does not name the missing %s", err, name)
		}
	}
	headers := validHeaders()
	headers["Comment"] = "hello"
	_, _, err := parseHeaders(headers)
	if err == nil || !strings.Contains(err.Error(), "Comment") {
		t.Errorf("an unknown header gave %v, want one naming it", err)
	}
}

func TestAnUnknownFunctionIsNamedRatherThanGuessedAt(t *testing.T) {
	for _, tc := range []struct{ header, value, want string }{
		{hdrKDF, "Argon2i+PBKDF2-HMAC-SHA256", kdfChain},
		{hdrKDF, "scrypt", kdfChain},
		{hdrCipher, "AES-256-CBC", cipherGCM},
		{hdrCipher, "ChaCha20-Poly1305", cipherGCM},
	} {
		headers := validHeaders()
		headers[tc.header] = tc.value
		_, _, err := parseHeaders(headers)
		if err == nil {
			t.Errorf("%s: %s was accepted", tc.header, tc.value)
			continue
		}
		if !strings.Contains(err.Error(), tc.value) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("error %q does not name both what the file said and what this build knows", err)
		}
	}
}

func TestANumberThatIsNotOne(t *testing.T) {
	for _, name := range []string{hdrTime, hdrMemory, hdrThreads, hdrIterations} {
		headers := validHeaders()
		headers[name] = "three"
		_, _, err := parseHeaders(headers)
		if err == nil || !strings.Contains(err.Error(), "not a number") {
			t.Errorf("%s: \"three\" gave %v, want the parse error", name, err)
		}
	}
}

func TestAnEmptyPassphraseIsRefusedInBothDirections(t *testing.T) {
	if _, err := Encrypt([]byte("a key"), Passphrase{}); !errors.Is(err, ErrEmptyPassphrase) {
		t.Errorf("Encrypt with no passphrase gave %v", err)
	}
	out := sealed(t, []byte("a key"))
	if _, err := Decrypt(out, nil); !errors.Is(err, ErrEmptyPassphrase) {
		t.Errorf("Decrypt with no passphrase gave %v", err)
	}
}

func TestTheBlockTypeSaysWhatAFileIs(t *testing.T) {
	out := sealed(t, []byte("a key"))
	if !IsEncrypted(out) {
		t.Error("a file this package wrote is not recognised as encrypted")
	}
	plain := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not really")})
	if IsEncrypted(plain) {
		t.Error("a plain PKCS#8 file is reported as encrypted")
	}
	if IsEncrypted([]byte("not PEM at all")) {
		t.Error("something that is not PEM is reported as encrypted")
	}
	if _, err := Decrypt(plain, []byte(secret)); !errors.Is(err, ErrNotEncrypted) {
		t.Errorf("decrypting a plain file gave %v, want ErrNotEncrypted", err)
	}
}

// TestThePlaintextIsNotInTheFile. The whole point, asserted the way
// DEVELOPMENT.md requires: first show the search can find something that is
// certainly there, then show it cannot find the key.
func TestThePlaintextIsNotInTheFile(t *testing.T) {
	r, seed := testutil.Seed(t)
	plaintext := testutil.Bytes(r, 256)
	out := sealed(t, plaintext)

	// The control: the same bytes, unencrypted, in the same container.
	control := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: plaintext})
	controlBlock, _ := pem.Decode(control)
	if !bytes.Contains(controlBlock.Bytes, plaintext) {
		t.Fatalf("the search cannot find the key even when it is there (seed %d)", seed)
	}

	block, _ := pem.Decode(out)
	if bytes.Contains(block.Bytes, plaintext) {
		t.Errorf("the key is in the encrypted file (seed %d)", seed)
	}
	for _, n := range []int{8, 16, 32} {
		if bytes.Contains(block.Bytes, plaintext[:n]) {
			t.Errorf("the first %d bytes of the key are in the encrypted file (seed %d)", n, seed)
		}
	}
	if bytes.Contains(out, []byte(secret)) {
		t.Errorf("the passphrase itself is in the file (seed %d)", seed)
	}
}

// TestTwoFilesUnderOnePassphraseShareNothing: a fresh salt each time, so two
// files never carry the same ciphertext for the same key.
func TestTwoFilesUnderOnePassphraseShareNothing(t *testing.T) {
	plaintext := []byte("the same key twice")
	first, second := sealed(t, plaintext), sealed(t, plaintext)
	if bytes.Equal(first, second) {
		t.Fatal("two files of the same key are identical: the salt or the nonce is not fresh")
	}
	a, _ := pem.Decode(first)
	b, _ := pem.Decode(second)
	if a.Headers[hdrSalt] == b.Headers[hdrSalt] {
		t.Error("two files share a salt")
	}
	if bytes.Equal(a.Bytes[:nonceSize], b.Bytes[:nonceSize]) {
		t.Error("two files share a nonce")
	}
}

// TestTheShippedCostIsWhatAFileRecords. This one pays the real derivation,
// once, because a default nothing exercises is a default that drifts.
func TestTheShippedCostIsWhatAFileRecords(t *testing.T) {
	out, err := Encrypt([]byte("a key"), Passphrase{Secret: []byte(secret)})
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(out)
	for _, want := range []struct {
		header string
		value  int
	}{
		{hdrTime, DefaultTime},
		{hdrMemory, DefaultMemory},
		{hdrThreads, DefaultThreads},
		{hdrIterations, DefaultIterations},
	} {
		if got := block.Headers[want.header]; got != strconv.Itoa(want.value) {
			t.Errorf("%s is %q in a file written with the defaults, want %d", want.header, got, want.value)
		}
	}
	if block.Headers[hdrKDF] != kdfChain {
		t.Errorf("KDF is %q, want %q", block.Headers[hdrKDF], kdfChain)
	}
	back, err := Decrypt(out, []byte(secret))
	if err != nil || string(back) != "a key" {
		t.Fatalf("a file at the shipped cost did not open: %v", err)
	}
}

// TestEveryHeaderIsInTheAdditionalData is what makes the additional data
// worth having.
//
// Today it is redundant: every header either names a function DecryptBlock
// checks by name or is a parameter of the derivation, so altering one is
// caught without it — removing the additional data entirely breaks no other
// test in this file, which was checked. It exists for the header somebody
// adds later that does neither, and this test is what will cover that header
// on the day it appears, because aad walks whatever the map holds.
func TestEveryHeaderIsInTheAdditionalData(t *testing.T) {
	block, _ := pem.Decode(sealed(t, []byte("a key")))
	covered := string(aad(BlockType, block.Headers))
	if !strings.HasPrefix(covered, BlockType+"\n") {
		t.Errorf("the additional data does not start with the block type: %q", covered)
	}
	for k, v := range block.Headers {
		if !strings.Contains(covered, k+": "+v+"\n") {
			t.Errorf("header %q is not in the additional data:\n%s", k, covered)
		}
	}
	// And it does not depend on map order, which is random in Go.
	for i := 0; i < 8; i++ {
		if again := string(aad(BlockType, block.Headers)); again != covered {
			t.Fatal("the additional data is not the same twice: it depends on map order")
		}
	}
}

// validHeaders is the header set of a real file, for a test that changes one
// thing about it.
func validHeaders() map[string]string {
	c, _ := costFor(TestPassphrase(secret))
	return map[string]string{
		hdrKDF:        kdfChain,
		hdrCipher:     cipherGCM,
		hdrTime:       strconv.Itoa(c.time),
		hdrMemory:     strconv.Itoa(c.memory),
		hdrThreads:    strconv.Itoa(c.threads),
		hdrIterations: strconv.Itoa(c.iterations),
		hdrSalt:       base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, saltSize)),
	}
}

// TestValidHeadersIsValid keeps the helper above honest: every test that
// changes one header depends on the rest being acceptable, and a helper that
// had drifted would make all of them pass for the wrong reason.
func TestValidHeadersIsValid(t *testing.T) {
	if _, _, err := parseHeaders(validHeaders()); err != nil {
		t.Fatalf("the header set the tests build on is refused: %v", err)
	}
	out := sealed(t, []byte("a key"))
	block, _ := pem.Decode(out)
	if len(block.Headers) != len(validHeaders()) {
		t.Errorf("a real file has %d headers, the helper builds %d",
			len(block.Headers), len(validHeaders()))
	}
	for k := range block.Headers {
		if _, ok := validHeaders()[k]; !ok {
			t.Errorf("a real file has header %q, which the helper does not", k)
		}
	}
}

func TestTheFileLooksLikeItsDocumentation(t *testing.T) {
	out := sealed(t, []byte("a key"))
	text := string(out)
	if !strings.HasPrefix(text, "-----BEGIN "+BlockType+"-----\n") {
		t.Errorf("a file starts %q", text[:min(len(text), 60)])
	}
	for _, h := range headerNames {
		if !strings.Contains(text, "\n"+h+": ") {
			t.Errorf("the file has no %s: line:\n%s", h, text)
		}
	}
}
