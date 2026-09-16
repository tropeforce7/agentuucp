// Package testutil holds the few helpers every package's tests need: a seeded
// random source that reports itself, and precise vandalism of bytes.
//
// It exists so that a randomised test failure is reproducible. Go prints
// t.Logf output only for a failing test or under -v, so the seed appears
// exactly when it is wanted and never otherwise.
package testutil

import (
	crand "crypto/rand"
	"encoding/binary"
	"math/rand/v2"
	"os"
	"strconv"
	"testing"
)

// SeedEnv names the environment variable that pins a run's seed.
const SeedEnv = "AUU_TEST_SEED"

// Seed returns a generator for the test and logs the seed that produced it.
//
// A failing randomised test therefore prints the number that reproduces it,
// and AUU_TEST_SEED=<n> replays exactly that run. Include the seed in the
// failure message as well, so it sits beside the assertion that fired.
func Seed(t testing.TB) (*rand.Rand, uint64) {
	t.Helper()
	var seed uint64
	if raw, ok := os.LookupEnv(SeedEnv); ok {
		parsed, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			t.Fatalf("%s=%q is not a uint64: %v", SeedEnv, raw, err)
		}
		seed = parsed
	} else {
		var b [8]byte
		if _, err := crand.Read(b[:]); err != nil {
			t.Fatalf("drawing a seed: %v", err)
		}
		seed = binary.LittleEndian.Uint64(b[:])
	}
	t.Logf("seed %d (rerun with %s=%d)", seed, SeedEnv, seed)
	// Two different streams from one seed, which is what NewPCG wants.
	return rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15)), seed
}

// FlipBit returns a copy of b with bit i inverted, counted from the start.
//
// One flipped bit keeps the length, the encoding and every structural
// property of the input intact, so the only thing left to reject it is the
// cryptography. Derive i from the format's constants, never from a literal.
func FlipBit(b []byte, i int) []byte {
	out := append([]byte(nil), b...)
	out[i/8] ^= 1 << (i % 8)
	return out
}

// FlipByteBit inverts one bit of byte n. It is FlipBit with the arithmetic
// done for the common case of naming a byte offset.
func FlipByteBit(b []byte, n, bit int) []byte { return FlipBit(b, n*8+bit) }

// Bytes returns n random bytes.
func Bytes(r *rand.Rand, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(r.UintN(256))
	}
	return out
}

// Text returns a random printable ASCII string of n bytes. Useful where a
// value must survive JSON and a terminal.
func Text(r *rand.Rand, n int) string {
	const printable = " !#$%&()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
		"[]^_abcdefghijklmnopqrstuvwxyz{|}~"
	out := make([]byte, n)
	for i := range out {
		out[i] = printable[r.IntN(len(printable))]
	}
	return string(out)
}

// Lengths is the set of lengths a length-sensitive test must cover around a
// cap: the empty case, one, the cap and its neighbours, and, when block is
// positive, the AEAD or hash block size and its neighbours. Negative and
// duplicate values are dropped.
func Lengths(cap, block int) []int {
	candidates := []int{0, 1, 2, cap - 1, cap, cap + 1}
	if block > 0 {
		candidates = append(candidates, block-1, block, block+1, 2*block, 2*block+1)
	}
	seen := map[int]bool{}
	var out []int
	for _, n := range candidates {
		if n < 0 || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	return out
}
