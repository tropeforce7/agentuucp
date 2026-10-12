package identity

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/wire"
)

// TestAKeyFileIdentityReadsStrictlyWhereverItIsDecoded: Identity and
// Locked decode their own bytes through wire.Decode (R24), since Decode's
// key scan stops at a type with its own UnmarshalJSON and a strict decode
// of a document around one does not reach inside it. So an unknown key, a
// key given twice and a key that matches only by case are refused whoever
// asks: encoding/json's own Unmarshal, wire.Decode of the value, and
// wire.Decode or json.Unmarshal of a struct that carries one as a field.
// What MarshalJSON writes is taken by every one of those, so no path this
// program has sends a key the strict read refuses (the second suite's
// "suite" key, read back by json.Unmarshal, is TestASecondSuiteWorksEndToEnd's).
func TestAKeyFileIdentityReadsStrictlyWhereverItIsDecoded(t *testing.T) {
	id, err := Generate("ada")
	if err != nil {
		t.Fatal(err)
	}
	plain, err := json.Marshal(id)
	if err != nil {
		t.Fatal(err)
	}
	locked, err := json.Marshal(NewLocked(id))
	if err != nil {
		t.Fatal(err)
	}
	type outerIdentity struct {
		ID *Identity `json:"id"`
	}
	type outerLocked struct {
		ID *Locked `json:"id"`
	}
	readers := []struct {
		name string
		read func(doc []byte) error
	}{
		{"Identity by json.Unmarshal", func(d []byte) error { var v Identity; return json.Unmarshal(d, &v) }},
		{"Identity by wire.Decode", func(d []byte) error { var v Identity; return wire.Decode(d, &v) }},
		{"Identity inside wire.Decode", func(d []byte) error {
			var v outerIdentity
			return wire.Decode([]byte(`{"id":`+string(d)+`}`), &v)
		}},
		{"Identity inside json.Unmarshal", func(d []byte) error {
			var v outerIdentity
			return json.Unmarshal([]byte(`{"id":`+string(d)+`}`), &v)
		}},
	}
	lockedReaders := []struct {
		name string
		read func(doc []byte) error
	}{
		{"Locked by json.Unmarshal", func(d []byte) error { var v Locked; return json.Unmarshal(d, &v) }},
		{"Locked by wire.Decode", func(d []byte) error { var v Locked; return wire.Decode(d, &v) }},
		{"Locked inside wire.Decode", func(d []byte) error {
			var v outerLocked
			return wire.Decode([]byte(`{"id":`+string(d)+`}`), &v)
		}},
		{"Locked inside json.Unmarshal", func(d []byte) error {
			var v outerLocked
			return json.Unmarshal([]byte(`{"id":`+string(d)+`}`), &v)
		}},
	}
	check := func(t *testing.T, name string, read func([]byte) error, whole []byte) {
		t.Helper()
		if err := read(whole); err != nil {
			t.Errorf("%s: what MarshalJSON wrote: %v; want it taken", name, err)
		}
		for _, tc := range []struct{ what, doc, says string }{
			{"an unknown key", strings.Replace(string(whole), `{`, `{"extra":1,`, 1), `unknown field "extra"`},
			{"a key twice", strings.Replace(string(whole), `{`, `{"name":"eve",`, 1), `key "name" appears twice`},
			{"a key in another case", strings.Replace(string(whole), `"name"`, `"Name"`, 1), `key "Name" matches the field "name" only by case`},
		} {
			if err := read([]byte(tc.doc)); err == nil || !strings.Contains(err.Error(), tc.says) {
				t.Errorf("%s: %s: %v; want %q", name, tc.what, err, tc.says)
			}
		}
	}
	for _, r := range readers {
		check(t, r.name, r.read, plain)
	}
	for _, r := range lockedReaders {
		check(t, r.name, r.read, locked)
	}
}
