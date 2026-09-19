package main

import (
	"fmt"
	"math"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestLimitYearsFlag: --years on relay and on kit is within [1, the
// years the signing authorities have left], read as text by the flag
// package: zero, a negative and the type's minimum are refused naming
// the flag; the text one past the type's maximum, a sign inside the
// digits, a leading space and a digit outside ASCII are not numbers; one
// more year than the authorities have left, a count that wraps AddDate,
// and the type's maximum are refused naming what was asked, when the
// authorities expire and the most --years can be, counted from the
// calendar and not from the count; one, a plus sign, and the most are
// taken.
func TestLimitYearsFlag(t *testing.T) {
	dir, kitOut := initialised(t)
	admin := anAdmin(t, "bunty")
	bin := relayBinary(t)
	relayArgs := func(years string) []string {
		return []string{"relay", "--host", "relay.example.com", "--out", filepath.Join(t.TempDir(), "b.json"), "--years", years}
	}
	kitArgs := func(years string) []string {
		return []string{"kit", "--host", "relay.example.com", "--relay-binary", bin, "--admin", admin, "--out", kitOut, "--years", years}
	}
	for _, args := range []func(string) []string{relayArgs, kitArgs} {
		for _, years := range []string{"0", "-1", strconv.Itoa(math.MinInt)} {
			_, err := run(t, dir, args(years)...)
			if err == nil || !strings.Contains(err.Error(), "--years must be at least 1, got "+years) {
				t.Errorf("%v: %v; want the refusal naming the flag", args(years), err)
			}
		}
		for _, years := range []string{"9223372036854775808", "1-2", " 1", "\u0661", "1.5", ""} {
			_, err := run(t, dir, args(years)...)
			if err == nil || !strings.Contains(err.Error(), `invalid value "`+years+`" for flag -years`) {
				t.Errorf("%v: %v; want the flag package's refusal", args(years), err)
			}
		}
		for _, years := range []string{strconv.Itoa(1<<62 + 1), strconv.Itoa(math.MaxInt)} {
			if _, err := run(t, dir, args(years)...); err == nil || !strings.Contains(err.Error(), "the most --years can be is ") {
				t.Errorf("%v: %v; want the refusal naming the most", args(years), err)
			}
		}
		// The most is what the refusal of a large count says: the last
		// whole year that ends before the signing authorities expire.
		_, err := run(t, dir, args("50")...)
		if err == nil || !strings.Contains(err.Error(), "the most --years can be is ") {
			t.Fatalf("%v: %v; want the refusal naming the most", args("50"), err)
		}
		var most int
		if _, err := fmt.Sscanf(err.Error()[strings.Index(err.Error(), "the most --years can be is ")+len("the most --years can be is "):], "%d", &most); err != nil {
			t.Fatal(err)
		}
		for _, years := range []string{"1", "+1", strconv.Itoa(most)} {
			if _, err := run(t, dir, args(years)...); err != nil {
				t.Errorf("%v: %v; want it taken", args(years), err)
			}
		}
		if _, err := run(t, dir, args(strconv.Itoa(most+1))...); err == nil || !strings.Contains(err.Error(), "the most --years can be is "+strconv.Itoa(most)) {
			t.Errorf("%v: %v; want the refusal naming the most", args(strconv.Itoa(most+1)), err)
		}
	}
}

// TestLimitMLDSAFlag: --mldsa on init is one of 44, 65 and 87, read as
// text: each neighbour, zero, a negative and the type's extremes are
// refused naming the three, and the text one past the type's maximum, a
// sign inside the digits and a digit outside ASCII are not numbers.
func TestLimitMLDSAFlag(t *testing.T) {
	for _, n := range []int{0, -1, 43, 45, 64, 66, 86, 88, math.MinInt, math.MaxInt} {
		_, err := run(t, filepath.Join(t.TempDir(), "ca"), "init", "--name", "Test", "--mldsa", strconv.Itoa(n))
		if err == nil || !strings.Contains(err.Error(), "44, 65 or 87") {
			t.Errorf("--mldsa %d: %v; want the refusal naming the three", n, err)
		}
	}
	for _, v := range []string{"9223372036854775808", "6-5", "\u0664\u0664", "65.0"} {
		_, err := run(t, filepath.Join(t.TempDir(), "ca"), "init", "--name", "Test", "--mldsa", v)
		if err == nil || !strings.Contains(err.Error(), `invalid value "`+v+`" for flag -mldsa`) {
			t.Errorf("--mldsa %q: %v; want the flag package's refusal", v, err)
		}
	}
	for _, v := range []string{"44", "+65", "87"} {
		if _, err := run(t, filepath.Join(t.TempDir(), "ca"), "init", "--name", "Test", "--mldsa", v); err != nil {
			t.Errorf("--mldsa %s: %v; want it taken", v, err)
		}
	}
}
