package keyfile

import (
	"encoding/pem"
	"errors"
	"math"
	"strconv"
	"strings"
	"testing"
)

// TestLimitHeaderNumbers: the four counts a key file's header carries are
// read as text and held to their bounds: zero is refused as no count at
// all, a negative, the type's minimum, one over the ceiling and the
// type's maximum are refused naming the header and the bounds, the text
// one past the type's maximum, a sign inside the digits, a leading space
// and a digit outside ASCII are not numbers, and a leading plus is the
// number.
func TestLimitHeaderNumbers(t *testing.T) {
	bounds := map[string][2]int{
		hdrTime:       {MinTime, MaxTime},
		hdrThreads:    {MinThreads, MaxThreads},
		hdrIterations: {MinIterations, MaxIterations},
	}
	for _, name := range []string{hdrTime, hdrThreads, hdrIterations, hdrMemory} {
		try := func(value string) error {
			headers := validHeaders()
			headers[name] = value
			if name == hdrThreads {
				// Memory's floor moves with the threads.
				headers[hdrMemory] = strconv.Itoa(8 * MaxThreads)
			}
			_, _, err := parseHeaders(headers)
			return err
		}
		if err := try("0"); err == nil || !strings.Contains(err.Error(), name+" is 0") {
			t.Errorf("%s 0: %v; want the refusal naming the header", name, err)
		}
		for _, v := range []string{"-1", strconv.Itoa(math.MinInt), strconv.Itoa(math.MaxInt)} {
			if err := try(v); err == nil || !strings.Contains(err.Error(), name+" must be between") {
				t.Errorf("%s %s: %v; want the refusal naming the bounds", name, v, err)
			}
		}
		for _, v := range []string{"9223372036854775808", "1-2", " 1", "\u0661", "1.0"} {
			if err := try(v); err == nil || !strings.Contains(err.Error(), name+" is not a number") {
				t.Errorf("%s %q: %v; want not a number", name, v, err)
			}
		}
		if b, ok := bounds[name]; ok {
			if err := try(strconv.Itoa(b[1] + 1)); err == nil || !strings.Contains(err.Error(), "must be between") {
				t.Errorf("%s one over the ceiling: %v", name, err)
			}
			for _, v := range []string{strconv.Itoa(b[0]), "+" + strconv.Itoa(b[0]), strconv.Itoa(b[1])} {
				if err := try(v); err != nil {
					t.Errorf("%s %s: %v; want it taken", name, v, err)
				}
			}
		}
	}
	// Memory with one thread: the floor is 8, one under it and one over
	// the ceiling are refused, and the ceiling is taken.
	memory := func(value string) error {
		headers := validHeaders()
		headers[hdrThreads] = "1"
		headers[hdrMemory] = value
		_, _, err := parseHeaders(headers)
		return err
	}
	for _, v := range []string{"4", "7", strconv.Itoa(MaxMemory + 4)} {
		if err := memory(v); err == nil || !strings.Contains(err.Error(), hdrMemory+" must be between") {
			t.Errorf("memory %s: %v; want the refusal naming the bounds", v, err)
		}
	}
	for _, v := range []string{"8", "+8", strconv.Itoa(MaxMemory)} {
		if err := memory(v); err != nil {
			t.Errorf("memory %s: %v; want it taken", v, err)
		}
	}
}

// TestLimitAFileAtTheOldMemoryCeilingIsRefused: the ceiling on the memory
// a file may name was 4 GiB, which a reader set out to allocate before the
// passphrase could be found wrong (S58). It is 1 GiB now, and a file
// naming the old ceiling, which only an edit by hand makes, is refused
// with the value and the ceiling before anything is derived: the test
// returns at once, where the derivation would allocate 4 GiB.
func TestLimitAFileAtTheOldMemoryCeilingIsRefused(t *testing.T) {
	file, err := Encrypt([]byte("a key"), TestPassphrase(secret))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(file)
	if block == nil {
		t.Fatal("no PEM block")
	}
	block.Headers[hdrThreads] = "1"
	block.Headers[hdrMemory] = strconv.Itoa(1 << 22)
	_, err = DecryptBlock(block, []byte(secret))
	if err == nil || errors.Is(err, ErrPassphrase) ||
		!strings.Contains(err.Error(), hdrMemory+" must be between 8 and 1048576 KiB with 1 threads, got 4194304") {
		t.Fatalf("a file at the old ceiling: %v; want the bounds sentence", err)
	}
	if MaxMemory != 1<<20 {
		t.Fatalf("MaxMemory is %d KiB, want 1 GiB", MaxMemory)
	}
}
