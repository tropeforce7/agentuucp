package testutil

import (
	"bytes"
	"testing"
)

func TestFlipBitFlipsExactlyOneBitAndDoesNotAlias(t *testing.T) {
	original := []byte{0x00, 0x00, 0xff}
	got := FlipBit(original, 9)
	if got[1] != 0x02 {
		t.Fatalf("bit 9 gave %#v, want byte 1 == 0x02", got)
	}
	if !bytes.Equal(original, []byte{0x00, 0x00, 0xff}) {
		t.Fatal("FlipBit modified its input")
	}
	// Exactly one bit differs, wherever it is asked for.
	for i := range len(original) * 8 {
		diff := 0
		for j, b := range FlipBit(original, i) {
			for bit := range 8 {
				if b&(1<<bit) != original[j]&(1<<bit) {
					diff++
				}
			}
		}
		if diff != 1 {
			t.Fatalf("FlipBit(%d) changed %d bits, want 1", i, diff)
		}
	}
	if got := FlipByteBit(original, 1, 1); got[1] != 0x02 {
		t.Fatalf("FlipByteBit(1,1) gave %#v", got)
	}
}

func TestSeedHonoursTheEnvironment(t *testing.T) {
	t.Setenv(SeedEnv, "12345")
	r1, seed := Seed(t)
	if seed != 12345 {
		t.Fatalf("seed %d, want the one from the environment", seed)
	}
	r2, _ := Seed(t)
	// The same seed must produce the same stream, or a reported seed is
	// useless for reproducing a failure.
	for range 100 {
		if r1.Uint64() != r2.Uint64() {
			t.Fatal("the same seed produced different streams")
		}
	}
}

func TestSeedIsRandomWithoutTheEnvironment(t *testing.T) {
	seen := map[uint64]bool{}
	for range 8 {
		_, seed := Seed(t)
		seen[seed] = true
	}
	if len(seen) < 8 {
		t.Fatalf("%d distinct seeds from 8 runs; they must not repeat", len(seen))
	}
}

func TestLengths(t *testing.T) {
	got := Lengths(16, 16)
	want := map[int]bool{0: true, 1: true, 2: true, 15: true, 16: true, 17: true, 32: true, 33: true}
	if len(got) != len(want) {
		t.Fatalf("Lengths(16,16) = %v", got)
	}
	for _, n := range got {
		if !want[n] {
			t.Fatalf("unexpected length %d in %v", n, got)
		}
	}
	// A cap of zero must not produce negative lengths.
	for _, n := range Lengths(0, 0) {
		if n < 0 {
			t.Fatalf("Lengths(0,0) produced %d", n)
		}
	}
}
