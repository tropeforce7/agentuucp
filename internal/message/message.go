// Package message defines the plaintext payload carried inside a sealed
// envelope: what one agent actually says to another.
package message

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/tropeforce7/agentuucp/internal/channels"
)

// Message types.
const (
	TypeAsk   = "ask"
	TypeReply = "reply"
	TypeNote  = "note"
	TypeAck   = "ack"
)

const (
	maxNameBytes    = 255
	DefaultMedia    = "application/octet-stream"
	maxSubjectBytes = 4096
)

// Body is the message itself.
type Body struct {
	Type        string       `json:"type"`
	Subject     string       `json:"subject,omitempty"`
	Thread      string       `json:"thread"`
	InReplyTo   string       `json:"in_reply_to,omitempty"`
	Text        string       `json:"text"`
	Attachments []Attachment `json:"attachments,omitempty"`
}

// Attachment is a whole file, carried inline. There is no chunking: a message
// either fits under the relay limit or it is rejected before sending.
type Attachment struct {
	Name   string `json:"name"`
	Media  string `json:"media"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	Data   []byte `json:"data"`
}

// ValidType reports whether t is a known message type.
func ValidType(t string) bool {
	switch t {
	case TypeAsk, TypeReply, TypeNote, TypeAck:
		return true
	}
	return false
}

// IDLen is the length of a message id: 16 random bytes as hex.
const IDLen = 32

// ValidID checks that s has the shape of a message id, which is what
// envelope.NewID makes: exactly 32 bytes, each a lowercase hex digit. A
// thread id is a message id too, the one that opened the thread, and so is
// in_reply_to. The shape is a rule rather than a convention because an id
// becomes a file name on the receiver and a directory name under an
// expert's home: a signature proves who wrote a value, not that the value
// is safe. The one predicate for the store, the stream format and the
// envelope, which each held a copy of it before.
func ValidID(s string) error {
	if len(s) != IDLen {
		return errNotAnID
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return errNotAnID
		}
	}
	return nil
}

var errNotAnID = errors.New("not a message id (32 lowercase hex characters)")

// ValidHeader applies the rules every message's header meets whether the
// message travels inline or as a stream's manifest: a known type, a thread
// id and, when set, an in_reply_to that are message ids, and a subject
// under the limit. Body.Validate and the stream package's Validate both
// call it, so what a message may say about itself is one rule.
func ValidHeader(typ, thread, inReplyTo, subject string) error {
	if !ValidType(typ) {
		return fmt.Errorf("message: unknown type %q", typ)
	}
	if thread == "" {
		return errors.New("message: thread is required")
	}
	if err := ValidID(thread); err != nil {
		return fmt.Errorf("message: thread is %w", err)
	}
	if inReplyTo != "" {
		if err := ValidID(inReplyTo); err != nil {
			return fmt.Errorf("message: in_reply_to is %w", err)
		}
	}
	return ValidSubject(subject)
}

// NewAttachment builds an attachment from a file's base name and contents,
// filling in size, digest, and a best-effort media type.
func NewAttachment(name string, data []byte) (Attachment, error) {
	base := filepath.Base(name)
	sum := sha256.Sum256(data)
	a := Attachment{
		Name:   base,
		Media:  mediaTypeFor(base),
		Size:   int64(len(data)),
		SHA256: hex.EncodeToString(sum[:]),
		Data:   data,
	}
	if err := a.Validate(); err != nil {
		return Attachment{}, err
	}
	return a, nil
}

// MediaTypeFor guesses a media type from a file name. Exported because a
// streamed attachment is described in a manifest long before its bytes exist
// anywhere this package can see them.
func MediaTypeFor(name string) string { return mediaTypeFor(name) }

func mediaTypeFor(name string) string {
	if t := mime.TypeByExtension(strings.ToLower(filepath.Ext(name))); t != "" {
		return t
	}
	return DefaultMedia
}

// ValidAttachmentText is the receiver's rule for an attachment name, the
// part of the message rules that holds for any text: valid UTF-8, one
// line, no NUL, and not over maxNameBytes. Everything else a name might
// be — a path, a device, a character a terminal would obey, a name Windows
// cannot make — is SafeName's to make safe at the write, since a receiver
// never depends on the sender having followed the sender's rule. It runs
// at Body.Validate and Manifest.Validate, on both sides.
func ValidAttachmentText(name string) error {
	if len(name) > maxNameBytes {
		return fmt.Errorf("attachment %q: name longer than %d bytes", name, maxNameBytes)
	}
	if !utf8.ValidString(name) {
		return fmt.Errorf("attachment %q: name is not valid UTF-8", name)
	}
	if strings.ContainsAny(name, "\n\r") {
		return fmt.Errorf("attachment %q: name is more than one line", name)
	}
	if strings.ContainsRune(name, 0) {
		return fmt.Errorf("attachment %q: name contains a null byte", name)
	}
	return nil
}

// ValidAttachmentNames is the sender's rule over a message's names: each
// one SafeName's fixed point, and no two that fold to one file. It runs
// where a message leaves — envelope.Seal and stream.BuildManifest — and
// nowhere on the receiving path.
func ValidAttachmentNames(names []string) error {
	for _, name := range names {
		if err := ValidAttachmentName(name); err != nil {
			return err
		}
	}
	return DistinctAttachmentNames(names)
}

// ValidSubject applies the rules for a subject: valid UTF-8, at most 4096
// bytes, and one line — none of the characters a channel name may not
// hold, which a line break is one of. A subject is printed in a column by
// every listing, and a message is prose: a control or a format character
// in what it says about itself has no honest use.
func ValidSubject(subject string) error {
	if len(subject) > maxSubjectBytes {
		return errors.New("message: subject too long")
	}
	if !utf8.ValidString(subject) {
		return errors.New("message: subject is not valid UTF-8")
	}
	if r, what := channels.ForbiddenRune(subject); what != "" {
		return fmt.Errorf("message: subject contains %U, a %s; a subject is one line", r, what)
	}
	return nil
}

// ValidText applies the rules for a message's text: valid UTF-8, and of
// the characters a channel name may not hold, only a line break and a tab.
// Everything else a terminal would obey rather than show is refused here,
// on both ends and on both paths, and again at Load of a record, which is
// what makes the terminal safe by rule rather than by every printer
// remembering; the printers escape all the same, as the last line and
// not the rule.
func ValidText(text string) error {
	if !utf8.ValidString(text) {
		return errors.New("message: text is not valid UTF-8")
	}
	for _, r := range text {
		if r == '\n' || r == '\t' {
			continue
		}
		if what := channels.Forbidden(r); what != "" {
			return fmt.Errorf("message: text contains %U, a %s", r, what)
		}
	}
	return nil
}

// DistinctAttachmentNames checks that no two attachment names in a message
// are one file on the receiver's disk: none equal byte for byte, and none
// equal under case folding, since macOS by default and Windows spell
// Report.txt and report.txt as one file. Without the second rule an honest
// Linux sender with Makefile and makefile stopped a Mac receiving from that
// relay at all: the second file failed to open and the fetch met the same
// message at every try. The sender runs it, through ValidAttachmentNames,
// so it is told before anything leaves; a receiver does not, since what
// a filesystem folds — case, or Unicode normalisation on APFS — is
// settled at the write by the filesystem's own answer and a numbered
// suffix.
func DistinctAttachmentNames(names []string) error {
	for i, name := range names {
		for _, earlier := range names[:i] {
			if earlier == name {
				return fmt.Errorf("duplicate attachment name %q", name)
			}
			if strings.EqualFold(earlier, name) {
				return fmt.Errorf("attachment names %q and %q are one file where case does not count", earlier, name)
			}
		}
	}
	return nil
}

// ValidDigest is the shape of a SHA-256 written in hex: 64 lowercase hex
// characters, which is what NewAttachment writes and what a slice of the
// first sixteen relies on.
func ValidDigest(s string) error {
	if len(s) != 64 {
		return fmt.Errorf("digest is %d characters, not 64", len(s))
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return errors.New("digest is not lowercase hex")
		}
	}
	return nil
}

// ValidShape is the part of Validate that reads no attachment data: the
// header, the type, the ids and the subject; the text; and each
// attachment's name, media type, digest and size. A record read back from
// the store is held to it at Load, so that a print meets the shape and
// the words it expects without hashing every attachment on every listing;
// Validate, at Open, has already hashed them once. A record that fails it
// was written by hand, or by a version from before a rule, and nothing on
// this machine is from before: it is refused by name and not shown. The
// terminal escaper stands between every word and the screen all the same,
// as the last line and not the rule.
func (b *Body) ValidShape() error {
	if err := ValidHeader(b.Type, b.Thread, b.InReplyTo, b.Subject); err != nil {
		return err
	}
	if err := ValidText(b.Text); err != nil {
		return err
	}
	for i := range b.Attachments {
		a := &b.Attachments[i]
		// The name to what any text is held to, as at Open: the write
		// uses SafeName of it and the terminal escapes it, as for a
		// subject.
		if err := ValidAttachmentText(a.Name); err != nil {
			return err
		}
		if a.Media == "" {
			return fmt.Errorf("attachment %q: empty media type", a.Name)
		}
		if err := ValidDigest(a.SHA256); err != nil {
			return fmt.Errorf("attachment %d: %v", i, err)
		}
		if a.Size < 0 {
			return fmt.Errorf("attachment %d: size %d is negative", i, a.Size)
		}
	}
	return nil
}

// Validate checks an attachment's name is text and that the digest and
// size describe the data actually carried. The name is not held to the
// sender's rule here: this runs on both sides, and a receiver writes the
// file under SafeName of whatever arrived.
func (a *Attachment) Validate() error {
	if err := ValidAttachmentText(a.Name); err != nil {
		return err
	}
	if a.Size != int64(len(a.Data)) {
		return fmt.Errorf("attachment %q: size %d does not match %d bytes of data", a.Name, a.Size, len(a.Data))
	}
	// The digest's shape first, then its value: what Open accepts here is
	// exactly what Load holds a record to, so a digest written in
	// uppercase is refused at the door rather than stored and then found
	// unreadable, which a sender could otherwise do to a mailbox.
	if err := ValidDigest(a.SHA256); err != nil {
		return fmt.Errorf("attachment %q: %v", a.Name, err)
	}
	sum := sha256.Sum256(a.Data)
	if a.SHA256 != hex.EncodeToString(sum[:]) {
		return fmt.Errorf("attachment %q: sha256 does not match data", a.Name)
	}
	if a.Media == "" {
		return fmt.Errorf("attachment %q: empty media type", a.Name)
	}
	return nil
}

// Validate checks the body is well formed before it is sealed or after it is
// opened. An opened message is untrusted input, so this runs on both sides.
func (b *Body) Validate() error {
	if err := ValidHeader(b.Type, b.Thread, b.InReplyTo, b.Subject); err != nil {
		return err
	}
	if err := ValidText(b.Text); err != nil {
		return err
	}
	for i := range b.Attachments {
		if err := b.Attachments[i].Validate(); err != nil {
			return err
		}
	}
	return nil
}

// AttachmentNames is the names in order, for the sender's rule.
func (b *Body) AttachmentNames() []string {
	names := make([]string, 0, len(b.Attachments))
	for i := range b.Attachments {
		names = append(names, b.Attachments[i].Name)
	}
	return names
}
