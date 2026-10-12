package relayapi_test

import (
	"bytes"
	"encoding"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"unicode"

	"github.com/tropeforce7/agentuucp/internal/allowlist"
	"github.com/tropeforce7/agentuucp/internal/card"
	"github.com/tropeforce7/agentuucp/internal/channels"
	"github.com/tropeforce7/agentuucp/internal/envelope"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/pki"
	"github.com/tropeforce7/agentuucp/internal/recipients"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/store"
	"github.com/tropeforce7/agentuucp/internal/stream"
	tok "github.com/tropeforce7/agentuucp/internal/token"
	"github.com/tropeforce7/agentuucp/internal/vouch"
	"github.com/tropeforce7/agentuucp/internal/wire"
)

// decodedTypes is every exported type the tree decodes through wire.Decode,
// at its call sites or through the helpers that take an any: the relay's
// requests and its answers (relay decodeRequest, client.do), the signed
// documents, the envelope's inner, the stream manifest, the recipients
// sections, the token's claims, the bundle and the store's records. The
// unexported ones (the agent's request, serve's settings, the relay's
// settings, the outbox and proxy records) cannot be named from here; the
// source scan below holds every struct in the tree, theirs among them, to
// the shapes on which fieldsOf and encoding/json could part.
var decodedTypes = []any{
	relayapi.AdminStatusResponse{}, relayapi.AllowRequest{}, relayapi.AllowResponse{}, relayapi.Auth{},
	relayapi.BlockRecord{}, relayapi.BlockRequest{}, relayapi.BlocksResponse{}, relayapi.CardRequest{},
	relayapi.CardResponse{}, relayapi.Carried{}, relayapi.CertRecord{}, relayapi.CertRequest{},
	relayapi.CertResponse{}, relayapi.CertsResponse{}, relayapi.ChannelsRequest{}, relayapi.ChannelsResponse{},
	relayapi.Courier{}, relayapi.CouriersResponse{}, relayapi.ErrorResponse{}, relayapi.ForwardFailedRequest{},
	relayapi.ForwardRequest{}, relayapi.ForwardResponse{}, relayapi.HealthResponse{}, relayapi.KeysResponse{},
	relayapi.LimitsView{}, relayapi.ListResponse{}, relayapi.ListedEntry{}, relayapi.ListedResponse{},
	relayapi.MailboxAnswer{}, relayapi.MailboxListResponse{}, relayapi.MailboxRecord{}, relayapi.OpenStreamRequest{},
	relayapi.OpenStreamResponse{}, relayapi.PostResponse{}, relayapi.PutStreamResponse{}, relayapi.QueueResponse{},
	relayapi.QueuedMessage{}, relayapi.RegisterRequest{}, relayapi.RegisterResponse{}, relayapi.RegisterTokenRequest{},
	relayapi.RevokeCertRequest{}, relayapi.RevokeCertResponse{}, relayapi.StoredMessage{}, relayapi.TokenAnswer{},
	relayapi.TokenListResponse{}, relayapi.TokenRecord{}, relayapi.TrustAnchorResponse{},
	allowlist.Document{}, card.Document{}, vouch.Document{}, channels.Directory{}, channels.Channel{},
	envelope.Envelope{}, envelope.Inner{}, message.Body{}, message.Carried{}, message.Attachment{},
	stream.Manifest{}, stream.Attachment{}, stream.Body{},
	recipients.List{}, recipients.Count{}, recipients.Max{},
	tok.Claims{}, pki.Bundle{}, pki.RelayRecord{},
	store.DamagedRecord{}, store.DamagedEntry{}, store.Room{}, store.RoomMember{}, store.Stored{}, store.SentCopy{},
	store.Anchor{}, store.CertRecord{}, store.ChannelSettings{}, store.ChannelSetting{}, store.AdmittedCourier{},
}

var (
	unmarshalerType     = reflect.TypeFor[json.Unmarshaler]()
	textUnmarshalerType = reflect.TypeFor[encoding.TextUnmarshaler]()
)

// decodesItself says encoding/json hands t's value to t's own method, so a
// key inside it is not a field's: UnmarshalJSON, or UnmarshalText, which
// takes a string and refuses an object whatever its keys (x509.OID).
func decodesItself(t reflect.Type) bool {
	p := reflect.PointerTo(t)
	return t.Implements(unmarshalerType) || p.Implements(unmarshalerType) ||
		t.Implements(textUnmarshalerType) || p.Implements(textUnmarshalerType)
}

// reachable is every struct type v's type reaches through fields,
// pointers, slices, arrays and maps, stopping at a type that decodes
// itself, whose keys are its own.
func reachable(t reflect.Type, seen map[reflect.Type]bool) {
	for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice || t.Kind() == reflect.Array || t.Kind() == reflect.Map {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct || seen[t] || decodesItself(t) {
		return
	}
	seen[t] = true
	for i := range t.NumField() {
		reachable(t.Field(i).Type, seen)
	}
}

// candidates is every name a key of t could be: each field's Go name and
// its tag's name, through embedded structs at any depth, so that two
// embedded fields of one name, a tag encoding/json finds invalid, or a
// field it hides are each asked of both.
func candidates(t reflect.Type, out map[string]bool, depth int) {
	if depth > 8 {
		return
	}
	for i := range t.NumField() {
		f := t.Field(i)
		out[f.Name] = true
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name != "" && name != "-" {
			out[name] = true
		}
		ft := f.Type
		if ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}
		if f.Anonymous && ft.Kind() == reflect.Struct {
			candidates(ft, out, depth+1)
		}
	}
}

// knows asks wire.Decode, whose key scan is fieldsOf's, whether name is a
// key of t under case folding: anything but its unknown-field refusal is
// yes, a key that matches only by case among them, which encoding/json
// takes as the field and Decode refuses by name.
func knows(t reflect.Type, name string) bool {
	err := wire.Decode([]byte(`{`+strconv.Quote(name)+`:null}`), reflect.New(t).Interface())
	return err == nil || !strings.HasPrefix(err.Error(), "json: unknown field ")
}

// strictTakes says whether a json.Decoder with DisallowUnknownFields takes
// data into a new t as far as its keys go: nil or an error that is not
// about an unknown field (a type's own UnmarshalJSON refusing null, say).
func strictTakes(t reflect.Type, data []byte) (bool, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	err := dec.Decode(reflect.New(t).Interface())
	return err == nil || !strings.Contains(err.Error(), "unknown field"), err
}

// wire's fieldsOf is now alone in deciding which keys are unknown, since Decode
// no longer runs a decoder with DisallowUnknownFields. Over every struct
// the decoded types reach: each key fieldsOf gives is taken by that
// decoder, asked through wire.Decode since fieldsOf is wire's own and this
// walk cannot live in wire's test binary (recipients, which the decoded
// types link, registers a section, and wire's tests hold the registry
// empty); each name that could be a key, and "zz_unknown", is a key to
// fieldsOf exactly when it is one to that decoder; and wire.Decode refuses
// "zz_unknown" as the decoder did, in its words.
func TestFieldsOfAgreesWithDisallowUnknownFields(t *testing.T) {
	seen := map[reflect.Type]bool{}
	for _, v := range decodedTypes {
		reachable(reflect.TypeOf(v), seen)
	}
	if len(seen) < 60 {
		t.Fatalf("the walk reached %d struct types; it should reach every decoded one", len(seen))
	}
	for st := range seen {
		names := map[string]bool{"zz_unknown": true}
		candidates(st, names, 0)
		for name := range names {
			data := []byte(`{` + strconv.Quote(name) + `:null}`)
			inFields := knows(st, name)
			takes, err := strictTakes(st, data)
			if inFields != takes {
				t.Errorf("%v: key %q: fieldsOf has it %v, json.Decoder with DisallowUnknownFields takes it %v (%v)", st, name, inFields, takes, err)
			}
		}
		data := []byte(`{"zz_unknown":null}`)
		err := wire.Decode(data, reflect.New(st).Interface())
		if err == nil || err.Error() != `json: unknown field "zz_unknown"` {
			t.Errorf("%v: wire.Decode of an unknown key: %v; want json: unknown field \"zz_unknown\"", st, err)
		}
	}
	t.Logf("%d struct types walked", len(seen))
}

// validTag is a plain tag name: letters, digits, '_' and '-'. Go 1.27's
// encoding/json reads a tag of other punctuation its own way (json:"a'b"
// names the field "a", run against the decoder, where v1's isValidTag kept
// the Go name), and fieldsOf takes the tag as written; a name outside this
// set is one the two may read apart, so the scan names it.
func validTag(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !unicode.IsLetter(c) && !unicode.IsDigit(c) && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

// Every struct in the tree that carries a json tag, exported or not: none embeds
// two structs at one depth (where encoding/json drops a name both give and
// fieldsOf keeps the first), and no json tag has a name encoding/json
// refuses. A struct that does either is where the walk above must look
// first, and this names it.
func TestNoStructHasAShapeFieldsOfReadsOtherwise(t *testing.T) {
	root := filepath.Join("..", "..")
	fset := token.NewFileSet()
	var files int
	for _, top := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, top), func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			f, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				return err
			}
			files++
			ast.Inspect(f, func(n ast.Node) bool {
				st, ok := n.(*ast.StructType)
				if !ok {
					return true
				}
				embedded, tagged := 0, false
				for _, fl := range st.Fields.List {
					tag := ""
					if fl.Tag != nil {
						tag, _ = strconv.Unquote(fl.Tag.Value)
					}
					name, _, _ := strings.Cut(reflect.StructTag(tag).Get("json"), ",")
					tagged = tagged || name != ""
					if len(fl.Names) == 0 && name == "" {
						embedded++
					}
					if name != "" && name != "-" && !validTag(name) {
						t.Errorf("%s: a json tag name encoding/json refuses: %q", fset.Position(fl.Pos()), name)
					}
				}
				// A struct with no json tag is not a wire shape: the
				// reader-and-closer literals the client builds embed two
				// interfaces and are never decoded.
				if embedded > 1 && tagged {
					t.Errorf("%s: a struct embedding %d types untagged, whose names fieldsOf and encoding/json may resolve apart", fset.Position(st.Pos()), embedded)
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if files < 100 {
		t.Fatalf("parsed %d files; the walk is not finding the tree", files)
	}
}

type embedA struct {
	ID int
}

type embedB struct {
	ID int
}

type twoIDs struct {
	embedA
	embedB
}

type badTag struct {
	X int `json:"a'b"`
}

// The probe the walk uses sees the reader's two cases where they occur, so
// a pass above means they do not occur in the decoded types, not that the
// probe is blind: two embedded fields of one name at one depth, which
// encoding/json drops and fieldsOf keeps the first of, and a tag name of
// punctuation, which encoding/json reads otherwise than as written.
func TestTheFieldsOfProbeSeesBothShapes(t *testing.T) {
	two := reflect.TypeFor[twoIDs]()
	if !knows(two, "ID") {
		t.Fatalf("Decode refused ID on twoIDs; the probe expects fieldsOf to keep it")
	}
	if takes, err := strictTakes(two, []byte(`{"ID":null}`)); takes {
		t.Errorf("encoding/json took ID on twoIDs (%v); it drops a name two embedded fields give at one depth", err)
	}
	bad := reflect.TypeFor[badTag]()
	if !validTag("max_bytes") || !validTag("ok-1") || validTag("a'b") {
		t.Errorf("validTag does not hold the plain set")
	}
	if !knows(bad, "a'b") {
		t.Errorf("Decode refused a'b on badTag; the probe expects fieldsOf to take the tag as written")
	}
	if takes, err := strictTakes(bad, []byte(`{"a'b":null}`)); takes {
		t.Errorf("encoding/json took a'b on badTag (%v); run here, it names the field otherwise", err)
	}
}
