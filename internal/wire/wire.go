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

// known is the sections this build understands, by name. It is empty in this
// release: the door ships before the first thing that uses it.
var known = map[string]bool{}

// Known says whether this build understands the named section.
func Known(name string) bool { return known[name] }

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
		case known[s.Name]:
			knownSections = append(knownSections, s)
		case s.Critical:
			return nil, nil, &NeedsNewerError{Name: s.Name}
		default:
			ignored = append(ignored, s)
		}
	}
	return knownSections, ignored, nil
}

// Decode is the one strict decode every reader of the wire calls: a field the
// target does not have is refused, and so is anything after the value but
// white space. The second check asks the decoder for the next token and
// wants the end of the input, since json.Decoder.More reports false for a
// stray '}' or ']' and would let either through.
//
// It is not a canonical form. encoding/json matches a key to a field without
// regard to case and takes the last of a key given twice, so {"Name":…} and
// a repeated key decode without complaint. What a signature covers is the
// bytes as sent, never this decode of them, and every reader is this one
// parser, so two readers cannot disagree about one document; anything that
// would compare or hash a decoded value must not stand in for the bytes.
func Decode(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing data after the value")
	}
	return nil
}
