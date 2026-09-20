package auu

import (
	"context"
	"fmt"
	"os"

	"github.com/tropeforce7/agentuucp/internal/channels"
	"github.com/tropeforce7/agentuucp/internal/client"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// Mail kept on the relay: which channels keep it, and keeping the marks
// honest against what the relay actually still holds.

// keepFor is this machine's setting for one channel, from the settings
// read once at the start of a fetch. A channel with none keeps, which is
// the default, and the empty name is default's.
func keepFor(settings store.ChannelSettings, channel string) bool {
	name := channel
	if name == "" {
		name = channels.Default
	}
	if one, ok := settings.Channels[name]; ok {
		return one.Keep
	}
	return true
}

// refreshKept checks the marks on what this machine left on one relay
// against what the relay still holds, at the end of a fetch that drained
// it: a message removed from another machine of this identity, or by an
// administrator, stops being marked here.
//
// queued is what the relay said it holds in all. Zero is the whole answer
// and costs no request: nothing this machine left is there any more. Above
// zero, only the span of the ids this machine is asking about is listed,
// with stubs=1, so a mailbox of kept mail is not downloaded again to
// answer a question about its ids.
//
// A failure is said once and never fails the fetch: the mail is already in
// the spool and the cursor has moved, the marks are a hint, and the next
// fetch checks them again.
func refreshKept(ctx context.Context, s *store.Store, c *client.Client, r *store.Relay, queued int64) {
	if err := refreshMarks(ctx, s, c, r, queued); err != nil {
		fmt.Fprintf(os.Stderr, "%s: could not check which messages are still on the relay (%v); "+
			"the marks are checked again next time\n", r.Name, err)
	}
}

// refreshMarks is refreshKept's work, with its error to report.
func refreshMarks(ctx context.Context, s *store.Store, c *client.Client, r *store.Relay, queued int64) error {
	marked, err := markedOn(s, r.Name)
	if err != nil {
		return err
	}
	behind, err := s.LeftBehind(r.Name)
	if err != nil {
		return err
	}
	if len(marked) == 0 && len(behind) == 0 {
		return nil
	}
	// What the relay holds, or does not. An empty mailbox answers the
	// question for every id at once.
	var (
		there = map[int64]bool{}
		err2  error
	)
	if queued > 0 {
		from, to := span(marked, behind)
		if there, err2 = idsOnRelay(ctx, c, from, to); err2 != nil {
			return err2
		}
	}
	for id, records := range marked {
		if there[id] {
			continue
		}
		for _, rec := range records {
			m, err := s.Load(rec.box, rec.id)
			if err != nil {
				return err
			}
			// OnRelay alone. PayloadOnRelay is a statement about this
			// machine — the body was never fetched — and stays true
			// whatever the relay holds: clearing it would turn a
			// quarantined stream's record into one claiming its files
			// are in the directory beside it, which they are not, and
			// 'auu extract' would go looking for them.
			if !m.OnRelay {
				continue
			}
			m.OnRelay = false
			if err := s.Save(rec.box, m); err != nil {
				return err
			}
		}
	}
	var left []int64
	for _, id := range behind {
		if there[id] {
			left = append(left, id)
		}
	}
	if len(left) != len(behind) {
		return s.SetLeftBehind(r.Name, left)
	}
	return nil
}

// record names one stored message: the box it is in and its own id.
type record struct {
	box store.Box
	id  string
}

// markedOn is every record this machine has marked as still on one relay,
// by the relay id it was fetched as. Two records can share a relay id only
// if a home was edited by hand, but the map holds a list either way rather
// than losing one.
func markedOn(s *store.Store, relayName string) (map[int64][]record, error) {
	out := map[int64][]record{}
	for _, box := range []store.Box{store.Inbox, store.Quarantine} {
		msgs, err := s.List(box)
		if err != nil {
			return nil, err
		}
		for _, m := range msgs {
			if !m.OnRelay && !m.PayloadOnRelay {
				continue
			}
			if m.Relay != relayName && m.Relay != "" {
				continue
			}
			out[m.RelayID] = append(out[m.RelayID], record{box: box, id: m.Inner.ID})
		}
	}
	return out, nil
}

// span is the range of relay ids worth asking about: from one before the
// lowest to the highest. A row outside it cannot be one of these, so the
// listing stops there rather than reading a mailbox full of another
// machine's kept mail.
func span(marked map[int64][]record, behind []int64) (from, to int64) {
	first := true
	consider := func(id int64) {
		if first || id < from {
			from = id
		}
		if first || id > to {
			to = id
		}
		first = false
	}
	for id := range marked {
		consider(id)
	}
	for _, id := range behind {
		consider(id)
	}
	return from - 1, to
}

// idsOnRelay is which of the ids in a span the relay still holds, listed
// without the envelopes; a listing that carries one anyway is refused by
// the client as a relay that ignored the parameter.
func idsOnRelay(ctx context.Context, c *client.Client, from, to int64) (map[int64]bool, error) {
	there := map[int64]bool{}
	for after := from; ; {
		page, err := c.ListWait(ctx, client.ListRequest{
			After: after, Limit: relayapi.MaxListLimit, Stubs: true,
		})
		if err != nil {
			return nil, err
		}
		if len(page.Messages) == 0 {
			return there, nil
		}
		for _, m := range page.Messages {
			if m.ID > to {
				return there, nil
			}
			there[m.ID] = true
			after = m.ID
		}
		if page.Messages[len(page.Messages)-1].ID >= to {
			return there, nil
		}
	}
}
