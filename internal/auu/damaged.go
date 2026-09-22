package auu

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/tropeforce7/agentuucp/internal/channels"
	"github.com/tropeforce7/agentuucp/internal/client"
	"github.com/tropeforce7/agentuucp/internal/envelope"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/store"
	"github.com/tropeforce7/agentuucp/internal/stream"
)

// Keeping what could not be opened.
//
// A message this key cannot open is nobody's to read, and leaving it queued
// would block the mailbox for ever, so it is acknowledged. It used to be
// acknowledged into nothing. Now the bytes go under damaged/ first, with a
// record saying which relay's message it was, when, and why in a word, so a
// person can ask the sender to send it again or hand the bytes to somebody;
// and the acknowledgement follows the keep, as it follows every save. The
// container suite's M01 and M07 found the message gone with one line about
// it.

// openCause is the word for why an envelope did not open, from the class
// the envelope package puts beneath ErrOpenFailed.
func openCause(err error) string {
	if cause := envelope.Cause(err); cause != nil {
		return cause.Error()
	}
	return "malformed"
}

// streamCause is openCause for a stream: the same four words, from the
// stream package's own failures.
func streamCause(err error) string {
	switch {
	case errors.Is(err, stream.ErrOpenFailed):
		return envelope.ErrNotDecrypted.Error()
	case errors.Is(err, stream.ErrNotForUs):
		return envelope.ErrNotForUs.Error()
	case errors.Is(err, stream.ErrSignature):
		return envelope.ErrBadSender.Error()
	}
	return envelope.ErrMalformed.Error()
}

// sizeCause is the cause for a stream whose signed manifest and the relay's
// listing disagree about its size: the word, and the two numbers, since
// the person reading it can then say which side lied.
func sizeCause(manifest, listed int64) string {
	return fmt.Sprintf("%s: the manifest says the stream is %d bytes on the wire and the relay holds %d",
		envelope.ErrMalformed, manifest, listed)
}

// keepDamaged keeps a message that could not be opened and says so. It
// returns an error only when the keep itself failed, and then the caller
// must not acknowledge: a message is acknowledged once it is safely on local
// disk, and the bytes of one nobody could open are no exception. A message
// that alone exceeds the budget is not kept, which the warning says, and is
// acknowledged, since keeping it was never possible.
func keepDamaged(s *store.Store, r *store.Relay, id int64, received time.Time, data []byte, cause string, res *fetchResult) error {
	kept, _, err := s.KeepDamaged(store.DamagedRecord{
		RelayID: id, Relay: r.Name, Received: received, Cause: cause,
	}, data)
	if err != nil {
		return fmt.Errorf("keeping relay message %d under %s: %w", id, s.DamagedDir(), err)
	}
	res.Unreadable++
	if !kept {
		fmt.Fprintf(os.Stderr, "warning: relay message %d could not be opened (%s); it is %s and was not kept, "+
			"since %s holds at most %s\n",
			id, cause, store.MiB(int64(len(data))), s.DamagedDir(), store.MiB(store.DamagedBudget))
		return nil
	}
	res.Kept++
	// The path KeepDamaged just wrote under, checked the same way there.
	path, err := s.DamagedPath(r.Name, id)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "warning: relay message %d could not be opened (%s) and was kept as %s; "+
		"ask the sender to send it again\n", id, cause, path)
	return nil
}

// filedUnder settles which channel a message is filed under, and whether
// the relay filed it where it was sealed for. sealed is the name inside the
// signature (the inner record's, or the manifest's), outer the name on the
// envelope the relay read, empty for a stream, which has none; the listing
// says where the relay put it, and always says. Absent means default for
// the sealed and the outer names. A disagreement is a message the relay
// filed elsewhere: not obeyed, and said to be.
func filedUnder(sealed, outer string, m client.Message) (channel, filedAs string, agrees bool) {
	name := func(s string) string {
		if s == "" {
			return channels.Default
		}
		return s
	}
	channel = sealed
	if channel == channels.Default {
		channel = ""
	}
	sealedName := name(sealed)
	// The listing first: it is where the relay says it put the message.
	// Then the outer name, which is what the relay routed by; a stream
	// has none.
	if m.Channel != sealedName {
		return channel, m.Channel, false
	}
	if (outer != "" || !m.IsStream()) && name(outer) != sealedName {
		return channel, name(outer), false
	}
	return channel, sealedName, true
}

// knockAgrees reports whether the word the relay listed a row under and
// the type inside the signed record say the same thing about a knock. The
// relay's word decides how the row was let in — a knock went past the
// allow list because the owner's card admits knocks — and the sealed type
// decides how it is shown and what may be done with it, so a row that
// says one thing outside and another inside is obeyed in neither
// direction: it is kept and acknowledged, like a message filed under the
// wrong channel. A relay cannot forge the inside, and a sender cannot
// change the outside, so a disagreement is one of them at fault and the
// receiver need not decide which.
func knockAgrees(kind, typ string) bool {
	return (kind == relayapi.KindKnock) == (typ == message.TypeKnock)
}

// keepMiskinded keeps a message the relay listed under one kind whose
// sealed record is another, with the cause word misfiled, as a message
// filed under the wrong channel is kept. Acknowledged by the caller once
// the keep has succeeded.
func keepMiskinded(s *store.Store, r *store.Relay, id int64, received time.Time, data []byte, kind, typ string, res *fetchResult) error {
	kept, _, err := s.KeepDamaged(store.DamagedRecord{
		RelayID: id, Relay: r.Name, Received: received, Cause: "misfiled",
	}, data)
	if err != nil {
		return fmt.Errorf("keeping relay message %d under %s: %w", id, s.DamagedDir(), err)
	}
	res.Unreadable++
	// Both words are from the wire: the relay's through the client's set
	// of three, the sender's through the message rules, and both are
	// escaped here as every printed word from outside is.
	said := fmt.Sprintf("relay message %d was listed as %q by %s but is sealed as %q",
		id, identity.PrintableText(kind), r.Name, identity.PrintableText(typ))
	if !kept {
		fmt.Fprintf(os.Stderr, "warning: %s; it is %s and was not kept, since %s holds at most %s\n",
			said, store.MiB(int64(len(data))), s.DamagedDir(), store.MiB(store.DamagedBudget))
		return nil
	}
	res.Kept++
	path, err := s.DamagedPath(r.Name, id)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "warning: %s; it was kept as %s\n", said, path)
	return nil
}

// keepMisfiled keeps a message the relay filed under one channel that is
// sealed for another, with the cause word misfiled, and says which relay
// did it. The sender is not to blame and is not asked to send it again.
// Acknowledged by the caller as every kept message is, once the keep has
// succeeded.
func keepMisfiled(s *store.Store, r *store.Relay, id int64, received time.Time, data []byte, filedAs, sealed string, res *fetchResult) error {
	kept, _, err := s.KeepDamaged(store.DamagedRecord{
		RelayID: id, Relay: r.Name, Received: received, Cause: "misfiled",
	}, data)
	if err != nil {
		return fmt.Errorf("keeping relay message %d under %s: %w", id, s.DamagedDir(), err)
	}
	res.Unreadable++
	if sealed == "" {
		sealed = channels.Default
	}
	if !kept {
		fmt.Fprintf(os.Stderr, "warning: relay message %d was filed under %q by %s but is sealed for %q; "+
			"it is %s and was not kept, since %s holds at most %s\n",
			id, filedAs, r.Name, sealed, store.MiB(int64(len(data))), s.DamagedDir(), store.MiB(store.DamagedBudget))
		return nil
	}
	res.Kept++
	path, err := s.DamagedPath(r.Name, id)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "warning: relay message %d was filed under %q by %s but is sealed for %q; it was kept as %s\n",
		id, filedAs, r.Name, sealed, path)
	return nil
}
