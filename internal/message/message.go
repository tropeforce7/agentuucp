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
	if !ValidType(b.Type) {
		return fmt.Errorf("message: unknown type %q", b.Type)
	}
	if b.Thread == "" {
		return errors.New("message: thread is required")
	}
	if len(b.Subject) > maxSubjectBytes {
		return errors.New("message: subject too long")
	}
	seen := make(map[string]bool, len(b.Attachments))
	for i := range b.Attachments {
		if err := b.Attachments[i].Validate(); err != nil {
			return err
		}
		name := b.Attachments[i].Name
		if seen[name] {
			return fmt.Errorf("message: duplicate attachment name %q", name)
		}
		seen[name] = true
	}
	return nil
}
