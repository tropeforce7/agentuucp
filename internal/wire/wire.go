// Package wire is the one door on the wire for what an older build does not
// understand. A sealed message, a relay's answer and a request to a relay may
// carry a list of sections, each a name, a critical flag and a body; a reader
// hands a section it knows to that section's own rule, ignores one it does not
// know that is not critical, and refuses the whole thing, by the section's
// name, for one it does not know that is critical. Everything outside the list
// is decoded strictly, through Decode, so the list is the only place something
// new may go.
//
// The shape follows X.509's extensions and the critical header parameter of
// RFC 7515: a reader that does not know a thing may skip it unless the writer
// said it must not.
//
// The package is standard library only and imports nothing in this tree, so
// the envelope, the stream and relayapi can all use the one rule.
package wire

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"unicode"
)

const (
	// MaxSections is the most sections one list may carry. It is fixed for
	// good (D32): a reader refuses a list over it before it looks at a single
	// entry, so the count is a loop bound nobody else chose.
	MaxSections = 32

	// MaxNameBytes is the longest a section's name may be, in bytes.
	MaxNameBytes = 64

	// MaxKeptBytes is the most of one section a reader keeps when it does
	// not know the section (D32). A known section's size is its own rule's.
	// Nothing here enforces it: Check and Sort read no body, and the reader
	// that keeps an ignored section holds it to this as it keeps it.
	MaxKeptBytes = 16 << 10

	// MaxAPISectionBytes is the most the sections of one request or answer
	// body to or from a relay may come to together, encoded, held by both
	// ends (R4). D32's bounds are for what a message reader keeps; this is
	// the API's, and it fits inside every hold a client keeps of an answer
	// and every cap a relay reads a body under, with room.
	MaxAPISectionBytes = 16 << 10
)

// Section is one entry of a list. All three fields are always written. A
// reader refuses a section whose name or data is absent; data that is
// present and null is data, since a section's rule may give null a
// meaning. A critical flag left out reads as false, the same answer the
// sender's false would give.
type Section struct {
	Name     string          `json:"name"`
	Critical bool            `json:"critical"`
	Data     json.RawMessage `json:"data"`
}

// ErrForm is a list that breaks the shape: too many entries, a name that is
// not a name, a name twice, or a section with no data.
var ErrForm = errors.New("sections are malformed")

// ErrNeedsNewer is a list with a critical section this build does not know.
// The error that carries it is a *NeedsNewerError, which names the section.
var ErrNeedsNewer = errors.New("a critical section needs a newer auu")

// NeedsNewerError names the first critical section this build does not know.
// The name has passed ValidName, so it is lowercase letters, digits and
// hyphens and is safe to print; Error quotes it all the same.
type NeedsNewerError struct {
	Name string
}

func (e *NeedsNewerError) Error() string {
	return fmt.Sprintf("section %q is critical and this build of auu does not know it; it needs a newer auu", e.Name)
}

// Is makes errors.Is(err, ErrNeedsNewer) true of a *NeedsNewerError.
func (e *NeedsNewerError) Is(target error) bool { return target == ErrNeedsNewer }

// ValidName is the one rule for a section's name, run by every writer before
// it sends one and by every reader before it looks at one: 1 to MaxNameBytes
// bytes of lowercase ASCII letters, digits and hyphens, beginning with a
// letter. A name is never a path, a file name or a command; the rule is
// narrow so that it is safe in all of them anyway.
func ValidName(name string) error {
	if name == "" {
		return fmt.Errorf("%w: a section has no name", ErrForm)
	}
	if len(name) > MaxNameBytes {
		return fmt.Errorf("%w: a section's name is %d bytes, at most %d", ErrForm, len(name), MaxNameBytes)
	}
	if c := name[0]; c < 'a' || c > 'z' {
		return fmt.Errorf("%w: section name %q does not begin with a lowercase letter", ErrForm, name)
	}
	for i := 1; i < len(name); i++ {
		c := name[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return fmt.Errorf("%w: section name %q is not lowercase letters, digits and hyphens", ErrForm, name)
		}
	}
	return nil
}

// Check holds a list to its shape: the count first, before any entry is
// looked at, then each entry's name and data, then no name twice. It reads no
// section's body. It runs where the rest of a record's shape is checked,
// which for a sealed record is before the signature; deciding what to do with
// each section is Sort's, and runs only after the signature has verified.
func Check(sections []Section) error {
	if len(sections) > MaxSections {
		return fmt.Errorf("%w: %d sections, at most %d", ErrForm, len(sections), MaxSections)
	}
	seen := make(map[string]bool, len(sections))
	for _, s := range sections {
		if err := ValidName(s.Name); err != nil {
			return err
		}
		if len(s.Data) == 0 {
			return fmt.Errorf("%w: section %q has no data", ErrForm, s.Name)
		}
		if seen[s.Name] {
			return fmt.Errorf("%w: section %q appears twice", ErrForm, s.Name)
		}
		seen[s.Name] = true
	}
	return nil
}

// Path is where a section is read: in a sealed message, in a stream's
// manifest, in a request body or in an answer body. A section is known on
// the paths its feature reads it on and on no other; elsewhere it is held
// to wire.MaxKeptBytes where it is kept, as an unknown one is (D76), but a
// critical one is never refused as needing a newer build, since Sort asks
// whether the name is known at all.
type Path uint8

const (
	OnMessage Path = 1 << iota
	OnManifest
	OnRequest
	OnAnswer
	// AnyPath is every path, for the one question that does not depend on
	// where a section came: whether this build knows the name at all, which
	// is what Sort and a message waiting for a newer build ask, and what a
	// record's load asks of the sections an earlier release kept (R13).
	AnyPath = OnMessage | OnManifest | OnRequest | OnAnswer
)

// known is the sections this build understands, by name, with the paths it
// reads each on, filled by each feature's init. It is empty in a binary
// that links no such feature, as this package's own tests are;
// internal/recipients is the first.
var known = map[string]Path{}

// Known says whether this build understands the named section on any of
// the paths on: a section registered for requests and answers is not known
// on a message, so a message carrying it keeps it only as it keeps one it
// cannot read.
func Known(name string, on Path) bool { return known[name]&on != 0 }

// Register says this build understands the named section on the paths
// given. A feature calls it from its package's init, once, with a name of
// its own choosing and at least one path; a name that is not a name, one
// registered twice, or no path is a mistake in the program and never
// input, so it panics rather than return an error nobody could act on. It
// returns a function that takes the name out again, for a test in another
// package to put the registry back as it found it; a feature's init
// ignores it.
func Register(name string, on Path) (unregister func()) {
	if err := ValidName(name); err != nil {
		panic(fmt.Sprintf("wire.Register: %v", err))
	}
	if on == 0 || on&^AnyPath != 0 {
		panic(fmt.Sprintf("wire.Register: section %q registered on no path this package names", name))
	}
	if known[name] != 0 {
		panic(fmt.Sprintf("wire.Register: section %q registered twice", name))
	}
	known[name] = on
	return func() { delete(known, name) }
}

// Sort splits a list that has passed Check into the sections this build
// knows and the ones it ignores. A section it does not know that is critical
// stops the sort: the error is a *NeedsNewerError naming the first such
// section in the list's order, and nothing of the list is returned.
//
// Sort is what decides that a thing needs a newer auu, so it runs only on a
// record whose signature has verified: an unsigned record is never kept as
// one that needs a newer build, and never puts that advice in front of
// anybody.
func Sort(sections []Section) (knownSections, ignored []Section, err error) {
	for _, s := range sections {
		switch {
		case known[s.Name] != 0:
			knownSections = append(knownSections, s)
		case s.Critical:
			return nil, nil, &NeedsNewerError{Name: s.Name}
		default:
			ignored = append(ignored, s)
		}
	}
	return knownSections, ignored, nil
}

// SizeError is a body's sections over MaxAPISectionBytes, as this build
// encodes them compactly.
type SizeError struct{ Bytes int }

func (e *SizeError) Error() string {
	return fmt.Sprintf("sections of %d bytes, over the %d a body may carry", e.Bytes, MaxAPISectionBytes)
}

// CheckBody is the one rule for the sections of a request or an answer
// body between a client and a relay, or between two relays (D37, R4), run
// by both ends: the list held to Check, then to MaxAPISectionBytes as this
// build encodes it compactly (the body's own cap has already bounded what
// arrived), and then sorted. It returns nil, an error wrapping ErrForm, a
// *SizeError, or the *NeedsNewerError of the first critical section this
// build does not know; each caller says it in its own words. A body is
// sorted here before anything else in it is read, since a body is either
// already authenticated by its request's signature or keeps nothing and
// advises nobody when refused.
func CheckBody(list []Section) error {
	if len(list) == 0 {
		return nil
	}
	if err := Check(list); err != nil {
		return err
	}
	encoded, err := json.Marshal(list)
	if err != nil {
		return err
	}
	if len(encoded) > MaxAPISectionBytes {
		return &SizeError{Bytes: len(encoded)}
	}
	_, _, err = Sort(list)
	return err
}

// ErrTrailing is a value with something after it but white space. Decode
// returns it bare, so that each reader can say it in its own words.
var ErrTrailing = errors.New("trailing data after the value")

// Decode is the one strict decode every reader of the wire calls. A key the
// target does not have is refused, and so are three things encoding/json
// takes without complaint:
//
//   - anything after the value but white space, asked of the decoder as its
//     next token, which must be the end of the input: json.Decoder.More
//     reports false for a stray '}' or ']' and would let either through;
//   - a key given twice in one object, or two keys equal under case
//     folding, of which encoding/json would keep the last;
//   - a key that matches a field of the target only without regard to
//     case, which encoding/json would take as that field.
//
// So one document reads one way, and another reader of it, in this language
// or another, has no second way to read it. The last two are a walk over
// the tokens before the decode, holding the keys of each open object and
// nothing more; a decoder's own error, a syntax error among them, is
// returned as the decoder made it.
func Decode(data []byte, v any) error {
	if err := checkKeys(data, reflect.TypeOf(v)); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return ErrTrailing
	}
	return nil
}

// maxDepth bounds the walk's recursion. encoding/json refuses nesting past
// ten thousand, and so does the walk, leaving the refusal to the decode.
const maxDepth = 10000

// errStop ends a walk that met something the decode will refuse in its own
// words: a syntax error, or nesting past maxDepth.
var errStop = errors.New("stop")

// checkKeys walks the tokens of data with the type the decode will fill, and
// refuses a repeated key and a key that matches a field only by case.
func checkKeys(data []byte, t reflect.Type) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	err := walkValue(dec, t, 0)
	if errors.Is(err, errStop) {
		return nil
	}
	return err
}

var unmarshaler = reflect.TypeFor[json.Unmarshaler]()

// walkValue reads one value. t is the Go type it decodes into, or nil when
// that is not known: inside a type with its own UnmarshalJSON, an
// interface, or a key the target does not have, which the decode refuses.
func walkValue(dec *json.Decoder, t reflect.Type, depth int) error {
	tok, err := dec.Token()
	if err != nil {
		return errStop
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	if depth+1 > maxDepth {
		return errStop
	}
	t = target(t)
	if d == '[' {
		var elem reflect.Type
		if t != nil && (t.Kind() == reflect.Slice || t.Kind() == reflect.Array) {
			elem = t.Elem()
		}
		for dec.More() {
			if err := walkValue(dec, elem, depth+1); err != nil {
				return err
			}
		}
		if _, err := dec.Token(); err != nil {
			return errStop
		}
		return nil
	}
	return walkObject(dec, t, depth+1)
}

// walkObject reads the keys and values of one object, the '{' already read.
func walkObject(dec *json.Decoder, t reflect.Type, depth int) error {
	var fields map[string]reflect.Type
	var mapElem reflect.Type
	if t != nil {
		switch t.Kind() {
		case reflect.Struct:
			fields = fieldsOf(t)
		case reflect.Map:
			mapElem = t.Elem()
		}
	}
	seen := map[string]string{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return errStop
		}
		key, ok := tok.(string)
		if !ok {
			return errStop
		}
		folded := foldKey(key)
		if first, ok := seen[folded]; ok {
			if first == key {
				return fmt.Errorf("key %q appears twice in an object at depth %d", key, depth)
			}
			return fmt.Errorf("key %q and key %q, the same under case folding, are both in an object at depth %d", first, key, depth)
		}
		seen[folded] = key
		var elem reflect.Type
		switch {
		case fields != nil:
			ft, exact := fields[key]
			if !exact {
				for name := range fields {
					if strings.EqualFold(name, key) {
						return fmt.Errorf("key %q matches the field %q only by case, in an object at depth %d", key, name, depth)
					}
				}
			}
			elem = ft
		case mapElem != nil:
			elem = mapElem
		}
		if err := walkValue(dec, elem, depth); err != nil {
			return err
		}
	}
	if _, err := dec.Token(); err != nil {
		return errStop
	}
	return nil
}

// target is the type a value decodes into for the walk's purposes: through
// any pointers, and nil for a type that decodes itself or an interface,
// whose keys are not this walk's to match against fields.
func target(t reflect.Type) reflect.Type {
	for t != nil {
		if t.Implements(unmarshaler) || reflect.PointerTo(t).Implements(unmarshaler) || t.Kind() == reflect.Interface {
			return nil
		}
		if t.Kind() != reflect.Pointer {
			return t
		}
		t = t.Elem()
	}
	return nil
}

// fieldsOf is the keys a struct decodes, by the name encoding/json gives
// each: its tag's name, or the field's own, with an untagged embedded
// struct's fields promoted, a field tagged "-" and an unexported one left
// out.
func fieldsOf(t reflect.Type) map[string]reflect.Type {
	out := map[string]reflect.Type{}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := f.Tag.Get("json")
		if tag == "-" {
			continue
		}
		name, _, _ := strings.Cut(tag, ",")
		if f.Anonymous && name == "" {
			ft := f.Type
			if ft.Kind() == reflect.Pointer {
				ft = ft.Elem()
			}
			if ft.Kind() == reflect.Struct {
				for k, v := range fieldsOf(ft) {
					if _, ok := out[k]; !ok {
						out[k] = v
					}
				}
				continue
			}
		}
		if !f.IsExported() {
			continue
		}
		if name == "" {
			name = f.Name
		}
		out[name] = f.Type
	}
	return out
}

// foldKey is a key with each rune replaced by the least rune of its case
// folding orbit, so that two keys equal under strings.EqualFold have one
// fold key and a map finds the pair at once. ToLower is not a fold: the
// Kelvin sign lowers to k but is its own upper case.
func foldKey(s string) string {
	var b strings.Builder
	for _, r := range s {
		least := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if f < least {
				least = f
			}
		}
		b.WriteRune(least)
	}
	return b.String()
}
