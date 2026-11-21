package auu

import (
	"github.com/tropeforce7/agentuucp/internal/envelope"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/stream"
	"github.com/tropeforce7/agentuucp/internal/wire"
)

// keptSections is what a message keeps of the sections it came with (D31):
// every section this build knows on the path it came on, on, an envelope's
// wire.OnMessage or a stream's wire.OnManifest, whose size is its own
// rule's, and every other at or under wire.MaxKeptBytes, one known only on
// another path among them, as it came, so that a later build on this
// machine can read it. One it does not know there over the size is dropped
// and counted: a section known on a message alone, such as a withdrawal
// note's, is one this build does not know on a manifest, and is held to
// the kept size there as any other is. None is critical and unknown: Open
// and OpenManifest answered that before a record was made.
func keptSections(sections []wire.Section, on wire.Path) (kept []wire.Section, dropped int) {
	for _, s := range sections {
		if !wire.Known(s.Name, on) && len(s.Data) > wire.MaxKeptBytes {
			dropped++
			continue
		}
		kept = append(kept, s)
	}
	return kept, dropped
}

// innerFromManifest is the local record of a stream as an envelope's
// would be, with the attachment metadata pointing at the directory rather
// than carrying the bytes, and the sections kept as an envelope's are. It
// returns how many sections were dropped.
func innerFromManifest(m *stream.Manifest) (*envelope.Inner, int) {
	inner := &envelope.Inner{
		V: m.V, From: m.From, FromBundle: m.FromBundle, To: m.To, ID: m.ID, Time: m.Time,
		Body: message.Body{
			Type: m.Body.Type, Subject: m.Body.Subject, Thread: m.Body.Thread,
			InReplyTo: m.Body.InReplyTo, Text: m.Body.Text,
		},
		Channel: m.Channel,
	}
	for _, a := range m.Attachments {
		inner.Body.Attachments = append(inner.Body.Attachments, message.Attachment{
			Name: a.Name, Media: a.Media, Size: a.Size, SHA256: a.SHA256,
		})
	}
	var dropped int
	inner.Sections, dropped = keptSections(m.Sections, wire.OnManifest)
	return inner, dropped
}
