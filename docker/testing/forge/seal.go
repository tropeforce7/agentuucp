package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/tropeforce7/agentuucp/internal/dial"
	"github.com/tropeforce7/agentuucp/internal/envelope"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/store"
	"github.com/tropeforce7/agentuucp/internal/stream"
	"github.com/tropeforce7/agentuucp/internal/wire"
)

// forge seal is what a newer build would send: one message, or one small
// stream, carrying a section this build has never heard of. No command of
// auu can write one, since auu writes only the sections it knows and it
// knows none; the container suite needs one arriving through a real relay
// to see what the receiver is told. The sealing is envelope.SealSections
// and stream.BuildManifestSections, the posting internal/dial's client,
// exactly as internal/auu/sections_test.go does it in process: nothing here
// is a construction of its own.

// sealPayload is the stream's one attachment. A stream this small is below
// auu's own threshold, which only says when auu chooses one; a reader takes
// a stream of any size.
var sealPayload = []byte("the payload of a stream sealed by a newer build")

func cmdSeal(args []string) error {
	fs := flag.NewFlagSet("seal", flag.ContinueOnError)
	home := fs.String("home", "", "the sender's auu home")
	to := fs.String("to", "", "the recipient: a peer's name or fingerprint, as auu send takes it")
	name := fs.String("section", "", "the section's name")
	crit := fs.Bool("critical", false, "mark the section critical")
	asStream := fs.Bool("stream", false, "seal a stream rather than a message")
	subject := fs.String("subject", "sealed by a newer build", "the subject")
	text := fs.String("text", "sealed by a newer build", "the text")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if *home == "" || *to == "" || *name == "" {
		return fmt.Errorf("--home, --to and --section are required")
	}
	sections := []wire.Section{{Name: *name, Critical: *crit, Data: json.RawMessage(`{}`)}}
	if err := wire.Check(sections); err != nil {
		return err
	}

	s, err := store.Open(*home)
	if err != nil {
		return err
	}
	id, err := s.Identity()
	if err != nil {
		return err
	}
	recipient, err := s.Resolve(*to)
	if err != nil {
		return err
	}
	r, err := s.DefaultRelay()
	if err != nil {
		return err
	}
	ctx := context.Background()
	d := dial.Dialer{Prog: "auu", Note: func(n string) { fmt.Fprintln(os.Stderr, "forge: "+n) }}
	c, err := d.Dial(ctx, s, id, r)
	if err != nil {
		return err
	}
	thread, err := envelope.NewID()
	if err != nil {
		return err
	}

	var relayID int64
	if !*asStream {
		env, _, err := envelope.SealSections(id, recipient, "",
			message.Body{Type: message.TypeAsk, Thread: thread, Subject: *subject, Text: *text}, sections)
		if err != nil {
			return err
		}
		if relayID, err = c.Post(ctx, env, ""); err != nil {
			return err
		}
	} else {
		sources := []stream.Source{{
			Name: "later.bin", Media: "application/octet-stream", Size: int64(len(sealPayload)),
			Open: func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(sealPayload)), nil },
		}}
		messageID, err := envelope.NewID()
		if err != nil {
			return err
		}
		m, err := stream.BuildManifestSections(id, recipient, messageID,
			stream.Body{Type: message.TypeAsk, Thread: thread, Subject: *subject, Text: *text},
			sources, stream.DefaultChunkSize, sections)
		if err != nil {
			return err
		}
		var blob bytes.Buffer
		if err := stream.Seal(&blob, id, recipient, m, sources); err != nil {
			return err
		}
		opened, err := c.OpenStream(ctx, recipient.Fingerprint(), "", int64(blob.Len()))
		if err != nil {
			return err
		}
		if relayID, err = c.PutStream(ctx, opened.Upload, 0, bytes.NewReader(blob.Bytes()), int64(blob.Len())); err != nil {
			return err
		}
	}
	fmt.Println(relayID)
	return nil
}
