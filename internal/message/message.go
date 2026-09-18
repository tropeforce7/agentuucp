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

// ValidAttachmentName checks a name is a safe base name: something that can
// become a file in a directory of the receiver's choosing and nothing else.
//
// It is separate from Validate because a streamed attachment's name arrives
// in a manifest, long before its data, and must be judged on its own.
func ValidAttachmentName(name string) error {
	if name == "" {
		return errors.New("attachment: empty name")
	}
	if len(name) > maxNameBytes {
		return fmt.Errorf("attachment %q: name longer than %d bytes", name, maxNameBytes)
	}
	if strings.ContainsAny(name, "/\\") {
		return fmt.Errorf("attachment %q: name must not contain a path separator", name)
	}
	if name == "." || name == ".." {
		return fmt.Errorf("attachment %q: invalid name", name)
	}
	if strings.ContainsRune(name, 0) {
		return fmt.Errorf("attachment %q: name contains a null byte", name)
	}
	// The set a channel name may not hold either: a name is printed in a
	// column by 'auu read', and an escape sequence or a bidi override in
	// it would drive the terminal rather than be shown.
	if !utf8.ValidString(name) {
		return fmt.Errorf("attachment %q: name is not valid UTF-8", name)
	}
	if r, what := channels.ForbiddenRune(name); what != "" {
		return fmt.Errorf("attachment %q: name contains %U, a %s", name, r, what)
	}
	return nil
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
// on both ends and on both paths, which is what makes the terminal safe by
// rule rather than by every printer remembering; the printers escape all
// the same, for a record from before the rule.
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
// message at every try. Both ends run it on both paths, so the sender is
// told before anything leaves. What a filesystem folds beyond case, such
// as Unicode normalisation on APFS, is not foreseen here and is refused
// where the file is opened instead.
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

// Validate checks an attachment's name is a safe base name and that the digest
// and size describe the data actually carried.
func (a *Attachment) Validate() error {
	if err := ValidAttachmentName(a.Name); err != nil {
		return err
	}
	if a.Size != int64(len(a.Data)) {
		return fmt.Errorf("attachment %q: size %d does not match %d bytes of data", a.Name, a.Size, len(a.Data))
	}
	sum := sha256.Sum256(a.Data)
	if !strings.EqualFold(a.SHA256, hex.EncodeToString(sum[:])) {
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
	names := make([]string, 0, len(b.Attachments))
	for i := range b.Attachments {
		if err := b.Attachments[i].Validate(); err != nil {
			return err
		}
		names = append(names, b.Attachments[i].Name)
	}
	if err := DistinctAttachmentNames(names); err != nil {
		return fmt.Errorf("message: %w", err)
	}
	return nil
}
