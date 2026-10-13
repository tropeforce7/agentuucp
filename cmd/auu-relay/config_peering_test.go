package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// noPeering is the part of the refusal that names what is wrong, and
// deleteAdvice the end of it, which names what to do.
const (
	noPeering    = "a peering this relay does not have"
	deleteAdvice = "delete the courier block and the --courier flags"
)

// TestEmptyPeeringPathsCannotActivateCourierNumbers: a home or a file given
// as "" or null is no peering, so a number beside it bounds nothing and is
// refused as a number alone is. Judging by the key's presence took each of
// these four as a peering.
func TestEmptyPeeringPathsCannotActivateCourierNumbers(t *testing.T) {
	for _, setting := range []string{`"home":""`, `"home":null`, `"authorized_file":""`, `"authorized_file":null`} {
		t.Run(setting, func(t *testing.T) {
			cfg, err := resolve(t, writeFile(t, `{"registration":"closed","courier":{`+setting+`,"max_hops":4}}`))
			if err == nil {
				t.Errorf("accepted max_hops=%d with home=%q authorized_file=%q; want no-peering configuration refusal", cfg.Courier.MaxHops, cfg.Courier.Home, cfg.Courier.AuthorizedFile)
			} else if !strings.Contains(err.Error(), noPeering) {
				t.Errorf("%s: %v; want %q", setting, err, noPeering)
			}
		})
	}
}

// TestCourierNumbersAreJudgedOnTheMergedSettings: the refusal reads the
// settings after the file and the flags are merged, so a flag alone is
// refused as a file's number alone is, a flag can give the path the file
// left empty, and a relay that says nothing about couriers, or says null,
// is the ordinary relay.
func TestCourierNumbersAreJudgedOnTheMergedSettings(t *testing.T) {
	t.Run("a flag alone", func(t *testing.T) {
		_, err := resolve(t, "", "--courier-max-hops", "4")
		if err == nil {
			t.Fatal("--courier-max-hops 4 with no peering was taken")
		}
		if !strings.Contains(err.Error(), noPeering) {
			t.Errorf("%v; want %q", err, noPeering)
		}
		if !strings.HasSuffix(err.Error(), deleteAdvice) {
			t.Errorf("%v; want it to end %q", err, deleteAdvice)
		}
	})
	t.Run("a flag gives the home the file left empty", func(t *testing.T) {
		home := t.TempDir()
		cfg, err := resolve(t, writeFile(t, `{"registration":"closed","courier":{"home":"","max_hops":4}}`),
			"--courier-home", home)
		if err != nil {
			t.Fatalf("a home by flag beside the file's empty one: %v; want it taken", err)
		}
		if cfg.Courier.Home != home || cfg.Courier.MaxHops != 4 {
			t.Errorf("home %q, max_hops %d; want %q and 4", cfg.Courier.Home, cfg.Courier.MaxHops, home)
		}
	})
	t.Run("a flag gives the file the file left null", func(t *testing.T) {
		couriers := couriersFile(t)
		cfg, err := resolve(t, writeFile(t, `{"registration":"closed","courier":{"home":null,"max_hops":4}}`),
			"--courier-file", couriers)
		if err != nil {
			t.Fatalf("a couriers file by flag beside a null home: %v; want it taken", err)
		}
		if cfg.Courier.AuthorizedFile != couriers || cfg.Courier.MaxHops != 4 {
			t.Errorf("authorized_file %q, max_hops %d; want %q and 4",
				cfg.Courier.AuthorizedFile, cfg.Courier.MaxHops, couriers)
		}
	})
	t.Run("no courier block and no courier flag", func(t *testing.T) {
		cfg, err := resolve(t, writeFile(t, `{"registration":"closed"}`))
		if err != nil {
			t.Fatalf("the ordinary relay: %v", err)
		}
		if cfg.Courier.set() {
			t.Errorf("the ordinary relay peers: %+v", cfg.Courier)
		}
	})
	t.Run("a null courier block and no courier flag", func(t *testing.T) {
		cfg, err := resolve(t, writeFile(t, `{"registration":"closed","courier":null}`))
		if err != nil {
			t.Fatalf("courier null: %v; want it taken as no block", err)
		}
		if cfg.Courier.set() {
			t.Errorf("courier null peers: %+v", cfg.Courier)
		}
	})
}

// printedCourier is the courier block of cfg as --print-config prints it,
// nil when there is none, with the whole output.
func printedCourier(t *testing.T, cfg Config) (json.RawMessage, string) {
	t.Helper()
	var out bytes.Buffer
	if err := Encode(&out, cfg.Redacted()); err != nil {
		t.Fatal(err)
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(out.Bytes(), &probe); err != nil {
		t.Fatalf("the printed configuration is not JSON: %v\n%s", err, out.String())
	}
	return probe["courier"], out.String()
}

// TestThePrintedConfigLoadsAgainWithOrWithoutAPeering: a relay that peers
// with nobody prints no courier block, since its numbers alone would be
// refused when the output is loaded again; a relay that peers prints its
// block, and what loads again is the same block.
func TestThePrintedConfigLoadsAgainWithOrWithoutAPeering(t *testing.T) {
	t.Run("no peering", func(t *testing.T) {
		cfg, err := resolve(t, "")
		if err != nil {
			t.Fatal(err)
		}
		block, printed := printedCourier(t, cfg)
		if block != nil {
			t.Fatalf("a relay that peers with nobody printed a courier block:\n%s", printed)
		}
		if _, err := resolve(t, writeFile(t, printed)); err != nil {
			t.Fatalf("the printed configuration does not load again: %v\n%s", err, printed)
		}
	})
	t.Run("a peering", func(t *testing.T) {
		cfg, err := resolve(t, "", "--registration", "closed",
			"--courier-home", t.TempDir(), "--courier-file", couriersFile(t),
			"--courier-max-hops", "3", "--courier-forward-ttl", "5h", "--courier-carried-max-rows", "1600")
		if err != nil {
			t.Fatal(err)
		}
		block, printed := printedCourier(t, cfg)
		if block == nil {
			t.Fatalf("a peering relay printed no courier block:\n%s", printed)
		}
		back, err := resolve(t, writeFile(t, printed))
		if err != nil {
			t.Fatalf("the printed configuration does not load again: %v\n%s", err, printed)
		}
		again, _ := printedCourier(t, back)
		if !bytes.Equal(block, again) {
			t.Errorf("the courier block loaded again differs:\nprinted %s\nreloaded %s", block, again)
		}
		if back.Courier.Home != cfg.Courier.Home || back.Courier.AuthorizedFile != cfg.Courier.AuthorizedFile ||
			back.Courier.MaxHops != 3 || back.Courier.ForwardTTL != "5h" || back.Courier.CarriedMaxRows != 1600 {
			t.Errorf("reloaded %+v; want %+v", back.Courier, cfg.Courier)
		}
	})
}
