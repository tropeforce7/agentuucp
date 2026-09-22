package agent

import (
	"bytes"
	"strings"
)

// An unlock has a scope, and the agent decides what it will do by the
// scope it is in and what it is asked to sign.
//
// The threat is not a stolen key: it is a signature the person never meant.
// While the agent is unlocked, any process running as the user can have it
// sign, and content that subverts an AI can make it originate a message the
// person never saw, signed as them. No confirmation the agent asks for
// in-band helps, because the same process can answer it. The one channel
// an AI cannot drive is a person typing the passphrase, so that is what
// originating needs: a receive-scope unlock opens mail and signs what reads,
// lists, watches and acknowledges, and a send-scope unlock, made with the
// passphrase again and for ten minutes by default, signs everything.
//
// The agent decides by what it is asked to sign under, never by who asks.
// Every construction in this project puts its domain at the front of the
// message, so the decision needs no protocol change: a request signed under
// ccx-http-v1 is receive when its method and path are in the receive set
// below and send otherwise; every other domain under the identity key is
// send, and so is anything the agent does not recognise, because unknown is
// not receive. A machine key signs only the TLS handshake and its own
// certificate request, which originate nothing, and is receive by its name.
//
// Renewing this machine's certificate is receive too, on both of its
// halves: a new machine key made under a cert: name, and the request that
// spends it, POST /v1/mailbox/{fp}/certs. Renewal is maintenance of the
// transport credential, and nothing about it lets a process act as the
// person: the relay issues the certificate to the fingerprint of the
// identity that signed the request and to no other, the request must
// arrive on the live certificate it then retires, it carries no token and
// can enrol no machine, and the new key never leaves the agent. Without
// this a home in receive scope — the default — would be warned on every
// command for the last sixty days and then lose its certificate.
// Enrolment stays send: the same generate, but the request that spends it
// is POST /v1/register, which makes a mailbox or a machine.
//
// Over-strict is the right side. Go's ServeMux serves HEAD through a GET
// pattern, so `HEAD /v1/mailbox/{fp}` reaches the listing on the relay; the
// classifier makes it send, because HEAD is in the set for one path only.
// Nothing sends a HEAD there, and a receive-scope refusal costs a retry with
// a GET, where the other mistake would cost a signature.

// Scope is what an unlock permits.
type Scope string

const (
	// ScopeReceive is the default of 'auu unlock': open mail, sign the
	// transport, and sign the requests that read, list, watch and
	// acknowledge. Nothing that originates.
	ScopeReceive Scope = "receive"
	// ScopeSend is 'auu unlock --send': everything the agent can do.
	ScopeSend Scope = "send"
)

// httpDomain is relayapi's domain for a signed request, with the newline
// that ends the first field. It is spelt here rather than imported so that
// this package, which every command links, does not pull the relay's wire
// types in; TestTheClassifierAgreesWithTheRelay in internal/relay holds the
// two together.
const httpDomain = "ccx-http-v1\n"

// receiveRoutes is the receive set: the requests a receive-scope unlock will
// sign, as the relay registers them. A segment of "*" matches any one
// non-empty path segment. Everything signed under ccx-http-v1 that is not
// here is send: a post, a stream's open, its one PUT per attempt and its
// abort, a directory, an allow list or a card pushed, a certificate issued,
// a registration, and every administrative route. The health check and the key lookup are
// not here because the client does not sign them — the relay verifies no
// signature on either — so they never reach the agent; a signing string
// for one arriving here is not the client's, and is send like anything
// else unknown.
var receiveRoutes = []struct {
	method string
	shape  string
}{
	{"GET", "/v1/mailbox/*"},          // the listing; also wait and peers watch, by query
	{"GET", "/v1/mailbox/*/*/blob"},   // a stream's payload
	{"GET", "/v1/mailbox/*/allow"},    // the owner's own allow list
	{"GET", "/v1/mailbox/*/card"},     // the owner's own card
	{"GET", "/v1/mailbox/*/channels"}, // a directory
	{"GET", "/v1/mailbox/*/certs"},    // this identity's certificates
	{"DELETE", "/v1/mailbox/*/*"},     // acknowledging a message, and auu rm
	{"POST", "/v1/mailbox/*/certs"},   // renewing this machine's certificate; see above
}

// ScopeOf is the scope an operation needs: the pure decision, made from the
// operation, the key it names and, for a signature, the message. The server
// consults it after the locked check and before touching a key.
func ScopeOf(op, key string, message []byte) Scope {
	switch op {
	case OpStatus, OpLock, OpStop, OpDecapsulate, OpExchange:
		return ScopeReceive
	case OpGenerate:
		// A new machine key under a cert: name is renewal's, or enrolment's
		// before the request that makes enrolment send; anything else is
		// not a name generate makes keys under, and is send.
		if strings.HasPrefix(key, CertPrefix) {
			return ScopeReceive
		}
		return ScopeSend
	case OpSign:
		if strings.HasPrefix(key, CertPrefix) || strings.HasPrefix(key, PendingPrefix) {
			return ScopeReceive
		}
		if key == KeyIdentity && isReceiveRequest(message) {
			return ScopeReceive
		}
		return ScopeSend
	default:
		return ScopeSend
	}
}

// isReceiveRequest says whether message is a relayapi signing string for a
// request in the receive set.
//
// The signing string is domain, method, path with its query, timestamp,
// nonce and a body hash, newline-separated. It is taken apart into exactly
// those six, each checked for its shape, and anything else is not a
// request: the relay verifies the same six-part string it rebuilds from the
// request it received, so a string that will not split this way cannot be
// one the relay honours, and refusing it loses nothing. The method is
// matched as the client wrote it, upper-case; a lower-case method is not in
// the set. The query is dropped at the first '?', since what a query says
// changes what a listing returns and never which handler runs.
func isReceiveRequest(message []byte) bool {
	if !bytes.HasPrefix(message, []byte(httpDomain)) {
		return false
	}
	parts := strings.Split(string(message), "\n")
	if len(parts) != 6 {
		return false
	}
	method, pathWithQuery, ts, nonce, sum := parts[1], parts[2], parts[3], parts[4], parts[5]
	if !allOf(ts, isDigit) || ts == "" {
		return false
	}
	if !allOf(nonce, isBase64) || nonce == "" {
		return false
	}
	if len(sum) != 64 || !allOf(sum, isHex) {
		return false
	}
	path, _, _ := strings.Cut(pathWithQuery, "?")
	if path == "" || path[0] != '/' {
		return false
	}
	segments := strings.Split(path[1:], "/")
	for _, r := range receiveRoutes {
		if r.method == method && shapeMatches(r.shape, segments) {
			return true
		}
	}
	return false
}

// shapeMatches compares a path's segments with a shape's: the same number,
// each literal equal, and each "*" a non-empty segment. A segment of "."
// or ".." is refused wherever it stands, because the relay's mux would
// clean and redirect it rather than route it, and a redirect is not a
// request this signature should exist for. A segment with a '%' in it is
// refused too: the relay's mux unescapes each segment before matching, so
// what it routes is not what is written here, and nothing the client sends
// — fingerprints and upload ids in hex, message ids in decimal — needs
// escaping.
func shapeMatches(shape string, segments []string) bool {
	want := strings.Split(shape[1:], "/")
	if len(want) != len(segments) {
		return false
	}
	for i, w := range want {
		got := segments[i]
		if got == "" || got == "." || got == ".." || strings.Contains(got, "%") {
			return false
		}
		if w != "*" && w != got {
			return false
		}
	}
	return true
}

func allOf(s string, ok func(byte) bool) bool {
	for i := 0; i < len(s); i++ {
		if !ok(s[i]) {
			return false
		}
	}
	return true
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func isHex(c byte) bool   { return isDigit(c) || (c >= 'a' && c <= 'f') }
func isBase64(c byte) bool {
	return isDigit(c) || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		c == '+' || c == '/' || c == '-' || c == '_' || c == '='
}
