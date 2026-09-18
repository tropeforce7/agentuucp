package relay

import (
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/agent"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// TestTheClassifierAgreesWithTheRelay holds the key agent's receive set to
// this relay's route table. For every pattern the relay registers, a
// signing string of the shape the client makes is classified by the agent
// and compared with what the plan says; a pattern the table does not
// mention fails, so a route added here is classified on purpose and a
// route removed here comes out of the table. It lives here rather than in
// the agent's package so that the agent, which every command links, is not
// tested against the relay and its database.
func TestTheClassifierAgreesWithTheRelay(t *testing.T) {
	want := map[string]agent.Scope{
		// Unauthenticated, never signed; send by the classifier because
		// they are not in the set, and never asked of it.
		"GET /v1/health":       agent.ScopeSend,
		"GET /v1/trust-anchor": agent.ScopeSend,

		// The receive set.
		"GET /v1/mailbox/{fp}":           agent.ScopeReceive,
		"GET /v1/mailbox/{fp}/{id}/blob": agent.ScopeReceive,
		"GET /v1/mailbox/{fp}/allow":     agent.ScopeReceive,
		"GET /v1/mailbox/{fp}/channels":  agent.ScopeReceive,
		"GET /v1/mailbox/{fp}/certs":     agent.ScopeReceive,
		"GET /v1/keys/{fp}":              agent.ScopeReceive,
		"DELETE /v1/mailbox/{fp}/{id}":   agent.ScopeReceive,
		"HEAD /v1/uploads/{id}":          agent.ScopeReceive,

		// Everything that originates.
		"POST /v1/register":                        agent.ScopeSend,
		"POST /v1/mailbox/{fp}":                    agent.ScopeSend,
		"POST /v1/mailbox/{fp}/streams":            agent.ScopeSend,
		"PATCH /v1/uploads/{id}":                   agent.ScopeSend,
		"DELETE /v1/uploads/{id}":                  agent.ScopeSend,
		"POST /v1/uploads/{id}/complete":           agent.ScopeSend,
		"PUT /v1/mailbox/{fp}/allow":               agent.ScopeSend,
		"PUT /v1/mailbox/{fp}/channels":            agent.ScopeSend,
		"POST /v1/mailbox/{fp}/certs":              agent.ScopeSend,
		"GET /v1/admin/status":                     agent.ScopeSend,
		"GET /v1/admin/mailboxes":                  agent.ScopeSend,
		"GET /v1/admin/mailboxes/{fp}":             agent.ScopeSend,
		"DELETE /v1/admin/mailboxes/{fp}":          agent.ScopeSend,
		"DELETE /v1/admin/mailboxes/{fp}/messages": agent.ScopeSend,
		"GET /v1/admin/blocks":                     agent.ScopeSend,
		"PUT /v1/admin/blocks/{fp}":                agent.ScopeSend,
		"DELETE /v1/admin/blocks/{fp}":             agent.ScopeSend,
		"GET /v1/admin/certs":                      agent.ScopeSend,
		"DELETE /v1/admin/certs/{serial}":          agent.ScopeSend,
		"POST /v1/admin/tokens":                    agent.ScopeSend,
		"GET /v1/admin/tokens":                     agent.ScopeSend,
		"DELETE /v1/admin/tokens/{id}":             agent.ScopeSend,
	}
	// What the client puts in each wildcard: a fingerprint, a message id,
	// an upload id, a serial. Each is what the relay would accept.
	fill := strings.NewReplacer(
		"{fp}", strings.Repeat("ab", 32),
		"{id}", "12",
		"{serial}", "0123456789abcdef",
	)

	h := newHarness(t, Config{})
	seen := map[string]bool{}
	for _, pattern := range h.server.routes {
		seen[pattern] = true
		scope, ok := want[pattern]
		if !ok {
			t.Errorf("the relay registers %q, which the plan's table does not classify: add it to the table and, if it originates nothing, to the agent's receive set", pattern)
			continue
		}
		method, path, _ := strings.Cut(pattern, " ")
		path = fill.Replace(path)
		msg := relayapi.SigningString(method, path, 1700000000, "AAAAAAAAAAAAAAAAAAAAAA==", nil)
		if got := agent.ScopeOf(agent.OpSign, agent.KeyIdentity, msg); got != scope {
			t.Errorf("%s: the agent classifies it %s, the table says %s", pattern, got, scope)
		}
		// With a query, as wait, peers watch and stubs are sent: the same.
		msg = relayapi.SigningString(method, path+"?wait=60&stubs=true", 1700000000, "AAAAAAAAAAAAAAAAAAAAAA==", nil)
		if got := agent.ScopeOf(agent.OpSign, agent.KeyIdentity, msg); got != scope {
			t.Errorf("%s with a query: the agent classifies it %s, the table says %s", pattern, got, scope)
		}
	}
	for pattern := range want {
		if !seen[pattern] {
			t.Errorf("the table classifies %q, which the relay no longer registers", pattern)
		}
	}
	// A registered route's upload id is hex, and an upload id the relay
	// would refuse is still classified by shape, so the classifier is not
	// leaning on the relay's validation for its answer.
	if got := agent.ScopeOf(agent.OpSign, agent.KeyIdentity,
		relayapi.SigningString("HEAD", "/v1/uploads/not-hex", 1700000000, "AAAA", nil)); got != agent.ScopeReceive {
		t.Errorf("HEAD of an upload the relay would refuse is %s, want receive by shape", got)
	}
}
