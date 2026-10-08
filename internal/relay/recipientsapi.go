package relay

import (
	"fmt"
	"net/http"

	"github.com/tropeforce7/agentuucp/internal/recipients"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/wire"
)

// maxRecipients is the number in force: the setting, or the protocol's
// ceiling when the setting is zero, which is unlimited here as everywhere.
// auu-relay refuses a setting over the ceiling or below zero at the start;
// the library, built by a test or a caller with no opinion, takes anything
// outside the setting's range as the zero-value Config is taken, as
// unlimited.
func (s *Server) maxRecipients() int {
	if v := s.cfg.Limits.MaxRecipients; v >= 1 && v <= relayapi.MaxRecipients {
		return int(v)
	}
	return relayapi.MaxRecipients
}

// maxRecipientsSection is the max-recipients section the health and the
// administrator's status answers carry: the number in force.
func (s *Server) maxRecipientsSection() []wire.Section {
	sections, err := recipients.MaxSection(s.maxRecipients())
	if err != nil {
		// maxRecipients is within the rule by construction.
		panic(err)
	}
	return sections
}

// holdRecipients holds a request that carries a copy of a message to
// several to this relay's max_recipients (D47, D54): the one place the
// count is read, by the two routes whose request has a body to carry it,
// opening a stream and a user's forward. A plain post is the outer envelope
// alone and carries none, so the relay cannot hold it there; the health
// answer gives the number for a client to hold itself to.
//
// A request with no count is a message to one. A count that breaks its rule
// is a malformed request, in the route's own words; one over the number in
// force is refused 413 with its code, the sentence naming the count and the
// setting. Nothing of the count is kept or logged. It reports whether the
// route may go on, having written the refusal when it may not.
func (s *Server) holdRecipients(w http.ResponseWriter, sections []wire.Section, what string) bool {
	data, ok := recipients.Find(sections, recipients.CountName)
	if !ok {
		return true
	}
	n, err := recipients.CheckCount(data)
	if err != nil {
		s.fail(w, http.StatusBadRequest, fmt.Sprintf("malformed %s: %v", what, err))
		return false
	}
	if max := s.maxRecipients(); n > max {
		s.failCode(w, http.StatusRequestEntityTooLarge, relayapi.CodeTooManyRecipients,
			fmt.Sprintf(relayapi.MsgTooManyRecipients, n, max))
		return false
	}
	return true
}
