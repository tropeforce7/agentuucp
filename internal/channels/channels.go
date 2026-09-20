// Package channels implements a mailbox's directory of channels: the named
// sub-mailboxes an owner defines and a sender chooses between.
//
// A directory is one JSON document signed by the owner's identity key under
// its own domain string, exactly as an enrolment token is signed by an
// administrator's. The relay verifies it against the mailbox's registered
// bundle before storing it and serves the bytes back verbatim, so a sender
// verifies the same bytes against the key it holds for the peer. The relay
// can serve a stale directory, which is the same power as refusing service;
// it cannot invent a channel or edit a description.
//
// A mailbox with no directory has one channel, "default", with no period.
// Nothing here talks to a relay or reads a file: the rules, the signature and
// the period are what both sides share.
//
// The name rule is also a file-name rule for Windows, since a channel is a
// directory on an expert host and an attachment (message.ValidAttachmentName
// shares the pieces) a file on a receiver, and either may be there. The
// device list in WindowsDevice is not the source of that rule: Windows is,
// and on Windows the function asks the OS through filepath.Abs, whose
// GetFullPathNameW rewrites a DOS device name to a \\.\ path. The Windows
// CI job holds the hand list to the OS one way with
// TestLimitTheDeviceListAgreesWithWindows — every name the OS resolves
// to a device must be in the list, and the list may be wider — and logs
// what filepath.Abs answered for each name. Its first run, on
// windows-2025-vs2026 (Windows Server 2025, build 10.0.26100, go1.27.0):
// the resolver rewrote NUL alone, bare and with a trailing space, in
// either case, and left NUL.txt and every other listed name in every
// form as a path under the directory; CreateFile made a regular file
// under CON, nul.txt and com1.txt (the regular package's
// TestLimitADeviceIsRefusedByItsHandle) and under CONIN$, CONOUT$ and
// their .txt forms, the console names it understands and the resolver
// does not rewrite. Older Windows resolves more of the list, and a
// message may land on any of them, so the list is the union across
// versions and the handle check at the open (internal/regular) is the
// safety net for a name the list does not hold.
package channels

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

const (
	// Version is the one directory format this build writes and reads.
	Version = 1

	// Default is the channel a message that names none goes to. It is a
	// name like any other in a directory, and a directory may leave it out.
	Default = "default"

	// signDomain separates a directory's signature from the other five things
	// an identity key signs: requests (ccx-http-v1), messages (ccx-sig-v1),
	// enrolment tokens (ccx-token-v1), stream manifests (ccx-stream-sig-v1)
	// and allow lists (ccx-allow-v1). A signature made for one purpose must
	// not verify for another.
	signDomain = "ccx-channels-v1"
)

// Failures a caller tells apart. The relay answers 401 for ErrSignature and
// 400, with the sentence, for everything else.
var (
	ErrSignature = errors.New("directory signature does not verify")
	ErrForm      = errors.New("directory is malformed")
	ErrOwner     = errors.New("directory owner is not the key that signed it")
)

// Directory is the signed document: every channel of one mailbox.
type Directory struct {
	V     int    `json:"v"`
	Owner string `json:"owner"`
	// Issued orders directories from the same owner: a relay refuses one
	// that is not newer than the one it holds, so two machines of one
	// identity cannot push each other backwards in silence. It is omitted
	// when zero only so that the local, unsigned copy can leave it out; a
	// signed directory always carries it, since Validate requires it.
	Issued   time.Time `json:"issued,omitzero"`
	Channels []Channel `json:"channels"`
}

// Channel is one named sub-mailbox and the period in which it takes mail.
// A bound that is absent is unbounded on that side.
type Channel struct {
	Name        string     `json:"name"`
	Description string     `json:"description"`
	NotBefore   *time.Time `json:"not_before,omitempty"`
	NotAfter    *time.Time `json:"not_after,omitempty"`
}

// ValidName applies the rules for a channel name: valid UTF-8, 1 to
// relayapi.MaxChannelNameBytes bytes, no control, format, private-use, line
// or paragraph separator characters, no white space at either end, no "/",
// and neither "." nor "..". The last three keep a name usable as a directory
// name. Names are compared byte for byte, so "Bugs" and "bugs" are two names.
//
// The error is a sentence beginning "name", for a caller to prefix with what
// the name belongs to.
func ValidName(name string) error {
	if name == "" {
		return errors.New("name is empty")
	}
	if len(name) > relayapi.MaxChannelNameBytes {
		return fmt.Errorf("name is %d bytes; at most %d", len(name), relayapi.MaxChannelNameBytes)
	}
	if !utf8.ValidString(name) {
		return errors.New("name is not valid UTF-8")
	}
	if r, what := ForbiddenRune(name); what != "" {
		return fmt.Errorf("name contains %U, a %s", r, what)
	}
	if first, _ := utf8.DecodeRuneInString(name); unicode.IsSpace(first) {
		return errors.New("name begins with white space")
	}
	if last, _ := utf8.DecodeLastRuneInString(name); unicode.IsSpace(last) {
		return errors.New("name ends with white space")
	}
	if strings.Contains(name, "/") {
		return errors.New(`name contains "/"`)
	}
	// A name is a directory under an expert host's serve directory, and
	// the host may be on Windows: a backslash is a separator there, a
	// colon names a drive or a stream, and a device stem opens the device.
	if strings.Contains(name, `\`) {
		return errors.New(`name contains "\"`)
	}
	if strings.Contains(name, ":") {
		return errors.New(`name contains ":"`)
	}
	// The other six characters Windows forbids in a file name, and a
	// trailing dot, which Windows strips so that "bugs." and "bugs" would
	// be one directory.
	if i := strings.IndexAny(name, WindowsForbidden); i >= 0 {
		// The set is ASCII, so the byte is the character; %q of a byte
		// would print a rune literal where the sentence quotes strings.
		return fmt.Errorf("name contains %q, which Windows forbids in a file name", string(name[i]))
	}
	if strings.HasSuffix(name, ".") && name != "." && name != ".." {
		return errors.New("name ends with a dot, which Windows strips")
	}
	if stem, _, _ := strings.Cut(name, "."); WindowsDevice(stem) {
		return fmt.Errorf("name begins with %s, a device name on Windows", strings.ToUpper(stem))
	}
	if name == "." || name == ".." {
		return fmt.Errorf("name is %q", name)
	}
	return nil
}

// WindowsForbidden is the characters Windows forbids in a file name beyond
// the separators and the colon, which have refusals of their own; a
// channel name and an attachment name are held to it on every platform,
// since either may become a file or a directory on Windows.
const WindowsForbidden = "<>\"|?*"

// WindowsDevice reports whether stem names a device on Windows. On
// Windows it asks the OS: a name the path resolver rewrites to a \\.\
// device path is a device, whatever the list below says, and the list is
// only the fast first answer. On every other platform the list is the
// rule, since a Unix sender must refuse what a Windows receiver could not
// extract, and the Windows CI job holds the list to be no narrower than
// what its OS says (TestLimitTheDeviceListAgreesWithWindows). The list,
// under case folding and ignoring trailing spaces as the resolver does:
// CON, PRN, AUX, NUL, CONIN$ and CONOUT$, and COM and LPT followed by one
// digit 0 to 9 or by one of the superscript digits U+00B9, U+00B2 and
// U+00B3. Microsoft's pages have not agreed on the set: older ones list
// COM1 to COM9 and LPT1 to LPT9, the current one COM0 to COM9 with the
// three superscripts, and Windows Server 2025 resolves NUL alone under a
// directory, so this is the union, since a name nobody can use on some
// Windows is a name nobody needs. COM10 is not a device on any of them.
// A file name is refused for every receiver when its stem is one, since
// a sender cannot know where a message lands; a channel name is refused
// because it is a directory on an expert host.
func WindowsDevice(stem string) bool {
	return listedDevice(stem) || osDevice(stem)
}

// listedDevice is the hand list.
func listedDevice(stem string) bool {
	stem = strings.TrimRight(stem, " ")
	if strings.EqualFold(stem, "CONIN$") || strings.EqualFold(stem, "CONOUT$") {
		return true
	}
	if len(stem) == 3 {
		for _, d := range []string{"CON", "PRN", "AUX", "NUL"} {
			if strings.EqualFold(stem, d) {
				return true
			}
		}
		return false
	}
	if len(stem) < 4 || !(strings.EqualFold(stem[:3], "COM") || strings.EqualFold(stem[:3], "LPT")) {
		return false
	}
	switch rest := stem[3:]; {
	case len(rest) == 1 && rest[0] >= '0' && rest[0] <= '9':
		return true
	case rest == "\u00b9" || rest == "\u00b2" || rest == "\u00b3":
		return true
	}
	return false
}

// ValidDescription applies the rules for a description: valid UTF-8, at most
// relayapi.MaxChannelDescriptionBytes bytes, and the same forbidden
// characters as a name. A line break is a control character and is refused
// here; the command that takes a description folds line breaks to one space
// before it gets this far, so a directory never holds one.
//
// The error is a sentence beginning "description".
func ValidDescription(desc string) error {
	if len(desc) > relayapi.MaxChannelDescriptionBytes {
		return fmt.Errorf("description is %d bytes; at most %d", len(desc), relayapi.MaxChannelDescriptionBytes)
	}
	if !utf8.ValidString(desc) {
		return errors.New("description is not valid UTF-8")
	}
	if r, what := ForbiddenRune(desc); what != "" {
		return fmt.Errorf("description contains %U, a %s", r, what)
	}
	return nil
}

// ForbiddenRune finds the first character of a category a name or a
// description may not hold, and says which category in words: a control
// character, a format character such as a bidi override, a private-use
// character, a line or a paragraph separator, each of which a terminal
// would obey rather than show. Exported for a machine's certificate label,
// which is held to the same set, so the set is written once.
func ForbiddenRune(s string) (rune, string) {
	for _, r := range s {
		if what := Forbidden(r); what != "" {
			return r, what
		}
	}
	return 0, ""
}

// Forbidden is ForbiddenRune for one character: the category's name in
// words when it is one of the five, and nothing otherwise. A message's
// subject and text are held to the same set, the text with a line break
// and a tab allowed back in, so the set is written once.
func Forbidden(r rune) string {
	switch {
	case unicode.Is(unicode.Cc, r):
		return "control character"
	case unicode.Is(unicode.Cf, r):
		return "format character"
	case unicode.Is(unicode.Co, r):
		return "private-use character"
	case unicode.Is(unicode.Zl, r):
		return "line separator"
	case unicode.Is(unicode.Zp, r):
		return "paragraph separator"
	}
	return ""
}

// Validate applies every rule in the format to a directory. The error names
// the channel and the rule, for instance
//
//	channel "bug reports": description is 1031 bytes; at most 1024
func (d *Directory) Validate() error {
	if d.V != Version {
		return fmt.Errorf("v is %d; this build reads %d", d.V, Version)
	}
	if !identity.ValidFingerprint(d.Owner) {
		return errors.New("owner is not a fingerprint")
	}
	if d.Issued.IsZero() {
		return errors.New("issued is missing")
	}
	if len(d.Channels) > relayapi.MaxChannels {
		return fmt.Errorf("the directory has %d channels; at most %d", len(d.Channels), relayapi.MaxChannels)
	}
	seen := make(map[string]bool, len(d.Channels))
	for _, ch := range d.Channels {
		if err := ValidName(ch.Name); err != nil {
			return fmt.Errorf("channel %q: %v", ch.Name, err)
		}
		if seen[ch.Name] {
			return fmt.Errorf("channel %q: listed twice", ch.Name)
		}
		seen[ch.Name] = true
		if err := ValidDescription(ch.Description); err != nil {
			return fmt.Errorf("channel %q: %v", ch.Name, err)
		}
		if ch.NotBefore != nil && ch.NotAfter != nil && ch.NotBefore.After(*ch.NotAfter) {
			return fmt.Errorf("channel %q: not_before %s is after not_after %s",
				ch.Name, stamp(*ch.NotBefore), stamp(*ch.NotAfter))
		}
	}
	return nil
}

// Find returns the channel of that name, or nil.
func (d *Directory) Find(name string) *Channel {
	for i := range d.Channels {
		if d.Channels[i].Name == name {
			return &d.Channels[i]
		}
	}
	return nil
}

// OpenAt says whether the channel takes mail at now, and when not, why: "opens
// T" for one whose period has not begun and "closed T" for one whose period
// has ended, with T in UTC. Both edges are inclusive: a post at not_before
// and one at not_after are both taken. The sentence is the one both sides
// print, so the sender and the relay agree word for word.
func (ch *Channel) OpenAt(now time.Time) (open bool, why string) {
	if ch.NotBefore != nil && now.Before(*ch.NotBefore) {
		return false, "opens " + stamp(*ch.NotBefore)
	}
	if ch.NotAfter != nil && now.After(*ch.NotAfter) {
		return false, "closed " + stamp(*ch.NotAfter)
	}
	return true, ""
}

// stamp renders a bound the way the sentences show it.
func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// Sign fills in the owner from the identity, checks every rule, encodes the
// directory once and signs the encoding under the directory domain. The
// document bytes returned are what the signature covers, and what travels;
// nothing re-encodes them. The caller sets Issued, since it is the caller's
// clock that orders the owner's directories.
//
// Validation comes before signing for the same reason an enrolment token is
// checked before it is issued: an invalid directory should not exist, rather
// than be refused later by a relay the owner has already been told holds it.
func Sign(id *identity.Identity, d *Directory) (doc, sig []byte, err error) {
	if id == nil {
		return nil, nil, errors.New("channels: no signing identity")
	}
	if d.V == 0 {
		d.V = Version
	}
	d.Owner = id.Fingerprint()
	if err := d.Validate(); err != nil {
		return nil, nil, err
	}
	doc, err = json.Marshal(d)
	if err != nil {
		return nil, nil, err
	}
	sig, err = id.Sign(signingBytes(doc))
	if err != nil {
		return nil, nil, err
	}
	return doc, sig, nil
}

// Verify checks a directory's signature with the owner's key, then decodes
// the document strictly, validates it, and requires that it name that key's
// fingerprint as its owner. Nothing it returns has come from bytes the
// signature did not cover.
//
// The signature is checked first so that a caller learns nothing about a
// document's content from a refusal, and so that the JSON decoder never runs
// on bytes nobody vouched for.
func Verify(pub *identity.Public, doc, sig []byte) (*Directory, error) {
	if pub == nil {
		return nil, ErrOwner
	}
	if !pub.Verify(signingBytes(doc), sig) {
		return nil, ErrSignature
	}
	d, err := decode(doc)
	if err != nil {
		return nil, err
	}
	if err := d.Validate(); err != nil {
		return nil, err
	}
	if d.Owner != pub.Fingerprint() {
		return nil, ErrOwner
	}
	return d, nil
}

// signingBytes is the exact input to the signature.
func signingBytes(doc []byte) []byte {
	out := make([]byte, 0, len(signDomain)+len(doc))
	out = append(out, signDomain...)
	return append(out, doc...)
}

// decode reads a document strictly. An unknown field is an error: a signed
// directory is not a place for extensions one side understands and the other
// ignores.
func decode(doc []byte) (*Directory, error) {
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.DisallowUnknownFields()
	var d Directory
	if err := dec.Decode(&d); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrForm, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("%w: trailing data after the document", ErrForm)
	}
	return &d, nil
}
