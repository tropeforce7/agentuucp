package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestAChannelSettingWithoutAKeepIsRefused is Codex's
// TestReviewMalformedRetentionCannotDisableKeeping (G17), landed under a
// name that says what it proves: channel-settings.json was read with
// json.Unmarshal into a plain bool, so an entry with no keep, a null
// entry, a null keep or a misspelt key read as keep off without a word,
// and mail the owner meant to keep for another machine was acknowledged on
// the relay. Each is damaged now, and so is a keep given twice, which
// encoding/json settled by taking the last.
func TestAChannelSettingWithoutAKeepIsRefused(t *testing.T) {
	for _, entry := range []string{`{}`, `null`, `{"keep":null}`, `{"keeep":true}`, `{"keep":true,"keep":false}`} {
		t.Run(entry, func(t *testing.T) {
			s := newStore(t)
			if err := os.WriteFile(s.ChannelSettingsPath(), []byte(`{"v":1,"channels":{"bugs":`+entry+`}}`), 0600); err != nil {
				t.Fatal(err)
			}
			keep, err := s.KeepOnRelay("bugs")
			if !errors.Is(err, ErrDamaged) {
				t.Errorf("keep=%v err=%v; want damaged settings refusal", keep, err)
			}
		})
	}
}

// TestAnExplicitKeepAndAnAbsentChannelReadAsBefore is Codex's
// TestReviewExplicitRetentionAndAbsentChannelControls (G17), the controls
// beside the refusal above: keep on and keep off as written read as
// written, and a channel the file does not name keeps, as it did.
func TestAnExplicitKeepAndAnAbsentChannelReadAsBefore(t *testing.T) {
	s := newStore(t)
	for _, keep := range []bool{true, false} {
		if err := s.SetKeep("bugs", keep); err != nil {
			t.Fatal(err)
		}
		if got, err := s.KeepOnRelay("bugs"); err != nil || got != keep {
			t.Fatalf("got=%v err=%v want=%v", got, err, keep)
		}
	}
	if got, err := s.KeepOnRelay("other"); err != nil || !got {
		t.Fatalf("absent channel: keep=%v err=%v", got, err)
	}
}

// TestARelayRecordWithAMisspeltRatchetKeyIsRefused is the outside
// session's TestAdv3_ARelayRecordWithAMisspeltRatchetKeyReadsAsNoFloor
// (G21), renamed for what it now proves: relay.json holds server_int_spki,
// the floor of the server-intermediate ratchet, and readRelay read it with
// json.Unmarshal, which drops a key it does not know. A record with the key
// misspelt, repeated with an empty value last, or in another case read as a
// record with no floor, so a retired intermediate was accepted again; the
// strict decoder refuses the file as damaged.
func TestARelayRecordWithAMisspeltRatchetKeyIsRefused(t *testing.T) {
	const hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	for _, body := range []string{
		`{"name":"r","url":"https://r.invalid","server_int_spkii":"` + hash + `"}`,
		`{"name":"r","url":"https://r.invalid","server_int_spki":"` + hash + `","server_int_spki":""}`,
		`{"name":"r","url":"https://r.invalid","Server_Int_SPKI":"` + hash + `"}`,
	} {
		t.Run(body[:48], func(t *testing.T) {
			s := newStore(t)
			dir := s.relayDir("r")
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, relayFile), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			r, err := s.readRelay("r")
			if errors.Is(err, ErrDamaged) {
				return
			}
			if err != nil {
				t.Fatalf("readRelay: %v; want the record refused as damaged", err)
			}
			t.Fatalf("the record read without error with floor %q: a misspelt or repeated server_int_spki reads as no floor and a case-variant one is taken without a word; want the file refused as damaged", r.ServerIntSPKI)
		})
	}
}

// strictFileShapes is TestLimitStoredRecordShapes's row for each file in
// the home that commit 6b made strict (R24): relay.json, cert.json met by
// CertFor and by the home's state, identity.json plain and locked, and
// channel-settings.json. Each is written by the program's own writer and
// read back taken, then fed an unknown key, a key given twice, a key that
// matches a field only by case, and a closing brace, a closing bracket
// and a stray letter after the value; each is refused naming the file,
// and the file is byte for byte what it was before the read, since a
// refusal that wrote would be a migration in disguise. Serve's ledger is
// the same rule in internal/auu, TestALedgerThatReadsTwoWaysIsRefusedAndKept.
func strictFileShapes(t *testing.T) {
	for _, tc := range []struct {
		name string
		// home makes the home and answers the file and its reader.
		home func(t *testing.T) (path string, read func() error)
		// key is a top-level key the file holds, twice and in another case.
		key string
	}{
		{"relay.json", func(t *testing.T) (string, func() error) {
			s, _, r, _ := plainHome(t)
			return s.relayPath(r, relayFile), func() error { _, err := s.Relay("work"); return err }
		}, "url"},
		{"cert.json, met by CertFor", func(t *testing.T) (string, func() error) {
			s, _, r, _ := plainHome(t)
			return s.relayPath(r, certFile), func() error { _, err := s.CertFor(r); return err }
		}, "serial"},
		{"cert.json, met by the home's state", func(t *testing.T) (string, func() error) {
			s, _, r, _ := plainHome(t)
			return s.relayPath(r, certFile), func() error { _, err := s.Identity(); return err }
		}, "serial"},
		{"identity.json in its plain form", func(t *testing.T) (string, func() error) {
			s, _, _, _ := plainHome(t)
			return s.path(identityFile), func() error { _, err := s.Identity(); return err }
		}, "name"},
		{"identity.json in its locked form", func(t *testing.T) (string, func() error) {
			noAgent(t)
			s, _, _, _ := plainHome(t)
			if err := s.EncryptHome(cheap(testPassphrase)); err != nil {
				t.Fatal(err)
			}
			return s.path(identityFile), func() error { _, err := s.Identity(); return err }
		}, "name"},
		{"channel-settings.json", func(t *testing.T) (string, func() error) {
			s := newStore(t)
			if err := s.SetKeep("bugs", false); err != nil {
				t.Fatal(err)
			}
			return s.ChannelSettingsPath(), func() error { _, err := s.ChannelSettings(); return err }
		}, "v"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path, read := tc.home(t)
			whole, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := read(); err != nil {
				t.Fatalf("the file as written: %v; want it taken", err)
			}
			var keys map[string]json.RawMessage
			if err := json.Unmarshal(whole, &keys); err != nil || keys[tc.key] == nil {
				t.Fatalf("the file as written has no %q: %v", tc.key, err)
			}
			upper := strings.ToUpper(tc.key[:1]) + tc.key[1:]
			open := bytes.IndexByte(whole, '{') + 1
			insert := func(s string) []byte {
				return append(append(append([]byte(nil), whole[:open]...), s...), whole[open:]...)
			}
			for _, v := range []struct {
				name string
				text []byte
			}{
				{"an unknown key", insert(`"zz_unknown":1,`)},
				{"a key twice", insert(`"` + tc.key + `":` + string(keys[tc.key]) + `,`)},
				{"a key in another case", bytes.Replace(whole, []byte(`"`+tc.key+`"`), []byte(`"`+upper+`"`), 1)},
				{"a closing brace after", append(append([]byte(nil), whole...), '}')},
				{"a closing bracket after", append(append([]byte(nil), whole...), ']')},
				{"a stray letter after", append(append([]byte(nil), whole...), 'x')},
			} {
				if err := os.WriteFile(path, v.text, 0o600); err != nil {
					t.Fatal(err)
				}
				err := read()
				if err == nil || !strings.Contains(err.Error(), path) {
					t.Errorf("%s: %v; want it refused naming %s", v.name, err, path)
				}
				after, rerr := os.ReadFile(path)
				if rerr != nil || !bytes.Equal(after, v.text) {
					t.Errorf("%s: the refusal changed the file (%v)", v.name, rerr)
				}
			}
			if err := os.WriteFile(path, whole, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := read(); err != nil {
				t.Errorf("the file put back as written: %v; want it taken", err)
			}
		})
	}
}

// TestChannelNamesInTheSettingsAreCaseSensitive (R24b): a channel's name
// is case-sensitive, as the directory's is, so channel-settings.json may
// hold "Bugs" and "bugs" side by side and each is a channel with its own
// keep. The strict read walks the channels object itself for this, since
// wire.Decode into a map refuses two keys alike under folding; both orders
// of the two values are read, so neither name can be taking the other's.
func TestChannelNamesInTheSettingsAreCaseSensitive(t *testing.T) {
	for _, upperKeeps := range []bool{false, true} {
		s := newStore(t)
		text := fmt.Sprintf(`{"v":1,"channels":{"Bugs":{"keep":%t},"bugs":{"keep":%t}}}`, upperKeeps, !upperKeeps)
		if err := os.WriteFile(s.ChannelSettingsPath(), []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		set, err := s.ChannelSettings()
		if err != nil {
			t.Fatalf("%s: %v; want two channels", text, err)
		}
		want := map[string]ChannelSetting{"Bugs": {Keep: upperKeeps}, "bugs": {Keep: !upperKeeps}}
		if !maps.Equal(set.Channels, want) {
			t.Fatalf("%s read as %v; want %v", text, set.Channels, want)
		}
		for name, one := range want {
			if keep, err := s.KeepOnRelay(name); err != nil || keep != one.Keep {
				t.Errorf("%s: KeepOnRelay(%q) = %v, %v; want %v", text, name, keep, err, one.Keep)
			}
		}
		if after, err := os.ReadFile(s.ChannelSettingsPath()); err != nil || string(after) != text {
			t.Errorf("%s: the read changed the file (%v)", text, err)
		}
		// Setting one leaves the other as it was, through the writer and
		// back through the reader.
		if err := s.SetKeep("bugs", upperKeeps); err != nil {
			t.Fatal(err)
		}
		if keep, err := s.KeepOnRelay("Bugs"); err != nil || keep != upperKeeps {
			t.Errorf("after setting bugs, Bugs keeps %v, %v; want %v", keep, err, upperKeeps)
		}
		if keep, err := s.KeepOnRelay("bugs"); err != nil || keep != upperKeeps {
			t.Errorf("after setting bugs, bugs keeps %v, %v; want %v", keep, err, upperKeeps)
		}
	}
}

// TestAChannelSettingsFileFromV0170WithAFoldedPairLoads is the upgrade
// case for R24b: v0.17.0 wrote channel-settings.json as json.MarshalIndent
// of ChannelSettings{V, Channels map[string]ChannelSetting{Keep bool}},
// and since a name was case-sensitive then too, a home could hold "Bugs"
// and "bugs" both. The struct is v0.17.0's, copied here rather than taken
// from this build, and the file it writes loads with every channel's keep.
func TestAChannelSettingsFileFromV0170WithAFoldedPairLoads(t *testing.T) {
	type v0170Setting struct {
		Keep bool `json:"keep"`
	}
	type v0170Settings struct {
		V        int                     `json:"v"`
		Channels map[string]v0170Setting `json:"channels"`
	}
	old := v0170Settings{V: 1, Channels: map[string]v0170Setting{
		"Bugs": {Keep: false}, "bugs": {Keep: true}, "BUGS": {Keep: false}, "default": {Keep: false},
	}}
	data, err := json.MarshalIndent(old, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	s := newStore(t)
	if err := os.WriteFile(s.ChannelSettingsPath(), data, 0o600); err != nil {
		t.Fatal(err)
	}
	set, err := s.ChannelSettings()
	if err != nil {
		t.Fatalf("v0.17.0's file:\n%s\n%v; want it loaded", data, err)
	}
	if len(set.Channels) != len(old.Channels) {
		t.Fatalf("read %d channels, want %d: %v", len(set.Channels), len(old.Channels), set.Channels)
	}
	for name, one := range old.Channels {
		if got, ok := set.Channels[name]; !ok || got.Keep != one.Keep {
			t.Errorf("%q read as %+v (present %v); v0.17.0 wrote keep %v", name, got, ok, one.Keep)
		}
	}
	if keep, err := s.KeepOnRelay(""); err != nil || keep {
		t.Errorf("default read as keep %v, %v; v0.17.0 wrote off", keep, err)
	}
	if after, err := os.ReadFile(s.ChannelSettingsPath()); err != nil || !bytes.Equal(after, data) {
		t.Errorf("the load changed the file (%v)", err)
	}
}

// TestAChannelNamedTwiceInTheSettingsIsRefused (R24b): with names matched
// exactly, the same name twice is what the strict read still refuses, the
// second spelt plainly or with an escape that decodes to the same name;
// encoding/json would have taken the last, which is keep off here, and
// acknowledged mail the first said to keep.
func TestAChannelNamedTwiceInTheSettingsIsRefused(t *testing.T) {
	for _, second := range []string{`"bugs"`, `"\u0062ugs"`, `"bug\u0073"`} {
		t.Run(second, func(t *testing.T) {
			s := newStore(t)
			path := s.ChannelSettingsPath()
			text := `{"v":1,"channels":{"bugs":{"keep":true},` + second + `:{"keep":false}}}`
			if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
				t.Fatal(err)
			}
			want := path + ` names the channel "bugs" twice: ` + channelSettingsAdvice
			for _, read := range []struct {
				name string
				do   func() error
			}{
				{"ChannelSettings", func() error { _, err := s.ChannelSettings(); return err }},
				{"KeepOnRelay", func() error { _, err := s.KeepOnRelay("bugs"); return err }},
				{"SetKeep", func() error { return s.SetKeep("other", true) }},
			} {
				err := read.do()
				if err == nil || err.Error() != want {
					t.Errorf("%s: %v; want\n  %s", read.name, err, want)
				}
				if !errors.Is(err, ErrDamaged) {
					t.Errorf("%s: not ErrDamaged: %v", read.name, err)
				}
			}
			if after, err := os.ReadFile(path); err != nil || string(after) != text {
				t.Errorf("the refusal changed the file (%v)", err)
			}
		})
	}
}

// TestAMalformedChannelSettingIsDamagedAndKept: with the channels object
// walked by hand (R24b), each form the strict decoder refused before is
// still refused, as damage naming the file, and the file is byte for byte
// what it was, since a refusal that wrote would decide the keep for the
// owner. A key in another case inside a channel is among them: only the
// channel names are matched exactly, and a setting's own keys keep the
// struct's fold rule.
func TestAMalformedChannelSettingIsDamagedAndKept(t *testing.T) {
	setting := func(name string) string { return `gives the channel "` + name + `" a setting that will not read (` }
	for _, tc := range []struct{ name, text, says string }{
		{"channels an array", `{"v":1,"channels":[]}`, " will not read (channels is not an object): "},
		{"channels a number", `{"v":1,"channels":5}`, " will not read (channels is not an object): "},
		{"channels a string", `{"v":1,"channels":"bugs"}`, " will not read (channels is not an object): "},
		{"a channel's value true", `{"v":1,"channels":{"bugs":true}}`, setting("bugs")},
		{"a channel's value an array", `{"v":1,"channels":{"bugs":[]}}`, setting("bugs")},
		{"a channel's value a string", `{"v":1,"channels":{"bugs":"off"}}`, setting("bugs")},
		{"an unknown key in a channel", `{"v":1,"channels":{"bugs":{"keep":true,"zz":1}}}`, setting("bugs")},
		{"Keep in another case", `{"v":1,"channels":{"bugs":{"Keep":true}}}`, setting("bugs")},
		{"KEEP in another case", `{"v":1,"channels":{"bugs":{"KEEP":false}}}`, setting("bugs")},
		{"keep null", `{"v":1,"channels":{"bugs":{"keep":null}}}`, `gives the channel "bugs" no keep: `},
		{"keep absent", `{"v":1,"channels":{"bugs":{}}}`, `gives the channel "bugs" no keep: `},
		{"a brace after", `{"v":1,"channels":{"bugs":{"keep":true}}}}`, " will not read ("},
		{"a bracket after", `{"v":1,"channels":{"bugs":{"keep":true}}}]`, " will not read ("},
		{"a letter after", `{"v":1,"channels":{"bugs":{"keep":true}}}x`, " will not read ("},
		{"a second object after", `{"v":1,"channels":{"bugs":{"keep":true}}}{"v":1}`, " will not read ("},
		// The file's own keys: anything but v and channels, taken once
		// each and matched exactly, is refused before a channel is read.
		{"channelz for channels", `{"v":1,"channelz":{}}`, ` will not read (json: unknown field "channelz"): `},
		{"an unknown key after channels", `{"v":1,"channels":{},"extra":true}`, ` will not read (json: unknown field "extra"): `},
		{"v twice", `{"v":1,"v":1,"channels":{}}`, ` will not read (key "v" appears twice): `},
		{"channels twice", `{"v":1,"channels":{},"channels":{}}`, ` will not read (key "channels" appears twice): `},
		{"V in another case", `{"V":1,"channels":{}}`, ` will not read (json: unknown field "V"): `},
		{"Channels in another case", `{"v":1,"Channels":{}}`, ` will not read (json: unknown field "Channels"): `},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newStore(t)
			path := s.ChannelSettingsPath()
			if err := os.WriteFile(path, []byte(tc.text), 0o600); err != nil {
				t.Fatal(err)
			}
			keep, err := s.KeepOnRelay("bugs")
			if err == nil {
				t.Fatalf("read as keep %v; want it refused", keep)
			}
			if !errors.Is(err, ErrDamaged) {
				t.Errorf("not ErrDamaged: %v", err)
			}
			if got := err.Error(); !strings.HasPrefix(got, path+" ") || !strings.Contains(got, tc.says) ||
				!strings.HasSuffix(got, ": "+channelSettingsAdvice) {
				t.Errorf("said\n  %s\nwant %s, %q and the advice", got, path, tc.says)
			}
			if after, err := os.ReadFile(path); err != nil || string(after) != tc.text {
				t.Errorf("the refusal changed the file (%v)", err)
			}
		})
	}
}
