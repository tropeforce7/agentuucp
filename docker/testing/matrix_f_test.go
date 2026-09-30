//go:build e2e

package e2e

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"
)

// Mail across peered relays: three of them, two operators' worth of
// configuration, and the five things that can happen to a message on the way.
//
// Three relays and not two, because an undeliverable that unwinds needs a hop
// in the middle: with two, the sender's own relay is the one that meets the
// refusal, so its row ends correctly and nothing has to travel. That is why a
// two-relay test let a one-hop defect through in the Go suite, and it is why
// the far end here is dave on relay-c rather than bob on a second relay of his
// own — one identity on several relays is PLAN-MULTIRELAY's subject, where this
// is two operators peering.
var forwardRows = []matrixRow{
	{"F01", "across_and_back", "alice writes to dave two relays away, and he replies along the way it came", f01},
	{"F02", "middle_hop_down", "the middle relay is stopped, the queue waits, and it drains when it comes back", f02},
	{"F03", "courier_line_removed", "the last relay stops accepting from the middle one, and a forward carrying a via is refused", f03},
	{"F04", "a_loop_is_refused", "a loop on one edge dies by the address rule at the first hop that names a relay twice", f04},
	{"F05", "undeliverable_unwinds", "no mailbox at the far end, and the news comes back two hops", f05},
}

// The peering, as data, because the topology is the point: each row is one
// relay dialling another, and the dialling relay's own name for it.
//
// A name is the accepting relay's own. It is one word per relay per neighbour,
// written in both halves of that relay's peering — its courier home, which it
// dials, and its couriers file, which says whom it accepts — because reportBack
// reads a name out of the file and looks it up in the home, and that is the
// whole of what "one name in both places" requires. Two relays need not agree:
// B calls A `ay` while A calls B `bee`, and C calls B `arb` while A calls C
// `cee`. The name in a couriers file is the trailing word of the export line,
// which whoever pastes it may change, so it is the accepting operator's choice
// and not the courier's. Names deliberately unlike the hostnames and unlike
// each other are what makes the family fail if a relay ever wrote the sender's
// name for itself in place of its own.
//
// Three edges, every one mutual. The third, A–C, exists so a loop can go round
// the triangle under names that never repeat, which is the one honest
// hand-built loop that reaches the carried table (ruling 43). Its row lands in
// commit 6a with the fix that loop found (ruling 44); until then the edge is
// configured and unused, and costs nothing, since every edge being mutual keeps
// the relays' starts free of one-way lines.
var peerings = []struct {
	from, to *machine
	name     string // from's own name for to
}{
	{relay, relayB, "bee"},
	{relayB, relay, "ay"},
	{relayB, relayC, "see"},
	{relayC, relayB, "arb"},
	{relay, relayC, "cee"},
	{relayC, relay, "alpha"},
}

// nameFor is one relay's own name for a neighbour, out of the table above.
func nameFor(t *testing.T, from, to *machine) string {
	t.Helper()
	for _, p := range peerings {
		if p.from == from && p.to == to {
			return p.name
		}
	}
	t.Fatalf("%s has no name for %s", from.service, to.service)
	return ""
}

const (
	courierHome  = "/var/lib/auu/courier"
	couriersFile = "/etc/auu/couriers"
)

// peerTheRelays is the worked example: what an operator does by hand to peer
// with another operator, run for three relays and four directed edges.
//
// The order is forced by the code and is the part worth reading. A relay with
// courier.home set refuses to start under open registration, so every relay
// here registers by token. A courier is an ordinary user of the relay it
// forwards to, so it has to enrol there — which means the neighbour must be
// running and accepting registrations before the courier exists. And a relay
// whose settings name a courier home refuses to start until that home holds an
// identity. So the bootstrap cannot be done in one pass:
//
//  1. bring every relay up with no courier block, able to accept registrations;
//  2. create each relay's courier home and enrol its courier at each neighbour
//     it will dial, which is where the local names are chosen;
//  3. write each relay's couriers file with the export lines of the couriers
//     that dial it, which is the half that says who it accepts from;
//  4. add the courier block to each relay's settings and restart.
//
// Steps 2 and 3 are the two halves of a peering and neither implies the other:
// a relay that dials a neighbour it does not accept from is a relay that sends
// but hears nothing back, which the start says out loud and which is a
// configuration an operator may want.
func peerTheRelays(t *testing.T) {
	t.Helper()
	// 1. relay-b and relay-c have nothing yet: a bundle from the operator's
	// authority, the settings, the admin line. relay A already has all three
	// from the cycle and only needs its courier block, in step 4.
	for _, rl := range []*machine{relayB, relayC} {
		// The settings and the admin file before the bundle, which is the
		// guide's own order and not a preference: the entrypoint polls for a
		// delivered bundle every second and exec's the relay the moment one
		// arrives, so a bundle delivered first starts a relay that has no
		// config and exits. That leaves a container with a credential and no
		// settings, which is the one state the harness cannot restore from,
		// since every recovery needs a live container.
		settingsFor(t, rl, "")
		adminLineFor(t, rl)
		// The mark before the bundle, not after: the entrypoint serves within a
		// second of the file landing, so a mark taken afterwards can start past
		// the line it is waiting for.
		m := logMarkOf(rl)
		bundleFor(t, rl)
		waitRelayLogOf(t, rl, m, "serving from an auu-ca bundle", 30*time.Second)
		waitRelayReadyOf(t, rl)
		adoptRelay(t, rl)
	}

	// 2. Each relay's courier: one identity per relay, enrolled at every
	// neighbour that relay dials. One identity on several relays is what a
	// courier home is, so relay-b's courier enrols twice — at A and at C.
	for _, rl := range relays {
		rl.mustRoot(t, "install -d -m 0700 -o auu -g auu "+courierHome)
	}
	for _, p := range peerings {
		token := issueTokenOn(t, p.to)
		home := p.from.asAuu().at(courierHome)
		// The identity's own name is not what any neighbour calls it — each
		// accepting relay writes its own word into its file — so it is named
		// for the relay it belongs to and nothing more.
		r := home.auu("enrol", "--name", p.from.service+"-courier",
			"--label", "courier", "--yes", token)
		expectSays(t, r, 0, "on "+p.to.alias)
		// The relay it just joined is named after that relay's host. The local
		// name is the operator's choice, and this is where it is made. Read
		// back rather than predicted: what a host derives to is a rule that
		// may change, and a fixture that predicted it would break for a
		// reason that had nothing to do with forwarding.
		renameRelayTo(t, home, p.to.alias, p.name)
	}

	// 3. The other half: whom each relay accepts. Its file lists the courier
	// of every neighbour it dials — every edge is mutual — under the same word
	// its home uses for that neighbour, which is the trailing word of the
	// export line rewritten. Pasting the line unedited would give every
	// relay's file the courier's own name, and every relay would then call
	// each neighbour the same thing.
	for _, rl := range relays {
		var lines []string
		for _, p := range peerings {
			if p.from == rl {
				lines = append(lines, withName(courierLineOf(t, p.to), p.name))
			}
		}
		writeCouriersFile(t, rl, lines)
	}

	// 4. Now the settings can name the courier home, and every relay restarts
	// into its peering.
	for _, rl := range relays {
		settingsFor(t, rl, courierHome)
		relayRestartOf(t, rl)
	}

	// dave, on relay-c, is who mail crosses to. He and alice add each other,
	// so what the rows exercise is the crossing and not an allow list.
	token := issueTokenOn(t, relayC)
	expectSays(t, dave.auu("enrol", "--name", "dave", "--label", "laptop", "--yes", token), 0,
		"on "+relayC.alias)
	state.daveLine = strings.TrimSpace(dave.auu("id", "export").stdout)
	var id struct {
		Fingerprint string `json:"fingerprint"`
	}
	jsonOf(t, dave.auu("id", "--json"), &id)
	state.daveFP = id.Fingerprint
	expectSays(t, alice.auu("peers", "add", state.daveLine), 0, "added "+state.daveFP[:16])
	expectSays(t, dave.auu("peers", "add", state.aliceLine), 0, "added "+state.aliceFP[:16])

	// alice admits relay A's view of the courier that carries to her, so a
	// reply from dave is delivered rather than refused: delivery asks her allow
	// list about the neighbour that handed the envelope over, which at her
	// relay is B's courier under the name A gave it.
	if aliceHasAllowList(t) {
		expectSays(t, alice.auu("allow", "add", "--courier", "bee", "--relay", relayName, "--yes"), 0,
			"admitted")
		expectSays(t, alice.auu("allow", "push"), 0, "will now accept mail for you from")
	}
}

// bundleFor issues a bundle for that relay from the operator's one authority
// and delivers it the way the guide does.
//
// One authority for all three, so every user pins one anchor and a message can
// cross without anybody learning a second hash. Three authorities would work
// and would be the arrangement for relays that do not know each other; these
// are two operators who peered on purpose.
func bundleFor(t *testing.T, rl *machine) {
	t.Helper()
	out := "/home/you/bundle-" + rl.service + ".json"
	r := operator.ca("relay", "--host", rl.alias, "--out", out, "--passphrase-file", operatorPass)
	expectCode(t, r, 0)
	copyFile(t, operator, out, rl, "/etc/auu/delivered/relay-bundle.json")
	expectCode(t, operator.exec("", "rm", out), 0)
}

// settingsFor writes that relay's settings: its own public URL, token
// registration, and a courier block when home is not empty.
//
// Token and not open, because the code refuses to start with a courier home
// beside open registration — the forward route is open to every identity with a
// mailbox, so open registration would let a stranger make one and post through
// this relay to its neighbours under its own courier.
func settingsFor(t *testing.T, rl *machine, home string) {
	t.Helper()
	cfg := map[string]any{
		"listen":       ":9443",
		"db":           "/var/lib/auu/relay.db",
		"registration": "token",
		"public_url":   rl.url,
		"access_log":   "minimal",
		"admin": map[string]any{
			"authorized_file": "/etc/auu/admins",
			"token_max_age":   "720h",
		},
		"client_certs": map[string]any{"mode": "off"},
		"tls":          map[string]any{"mode": "files", "bundle_credential": "relay-bundle"},
	}
	if home != "" {
		cfg["courier"] = map[string]any{
			"home":            home,
			"authorized_file": couriersFile,
		}
	}
	body, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	rl.putContent(t, "/etc/auu/relay.json", string(body)+"\n")
	rl.mustRoot(t, "chown root:root /etc/auu/relay.json && chmod 0644 /etc/auu/relay.json")
}

// adminLineFor makes the operator an administrator of that relay, which is an
// export line in a file and needs no mailbox: the admin routes look a caller up
// in the admins file, so the operator administers a relay they are not a user
// of.
func adminLineFor(t *testing.T, rl *machine) {
	t.Helper()
	line := strings.TrimSpace(operator.auu("id", "export").stdout)
	if line == "" {
		t.Fatal("the operator has no export line")
	}
	rl.putContent(t, "/etc/auu/admins", line+"\n")
	rl.mustRoot(t, "chown root:root /etc/auu/admins && chmod 0644 /etc/auu/admins")
}

// issueTokenOn asks that relay's administrator for an enrolment token.
func issueTokenOn(t *testing.T, rl *machine) string {
	t.Helper()
	// --relay after the subcommand: auu-admin registers it per command, as its
	// help says, and reads it as a command name when it comes first.
	//
	// No --anchor here: it names what the token's holder will pin, and its
	// default is whatever this machine pinned for that relay, which
	// adoptRelay has just done. Passing it explicitly would work and would
	// bypass the path an operator actually uses.
	r := operator.admin("token", "issue", "--relay", rl.url, "--note", "courier or user", "--expires", "24h")
	expectSays(t, r, 0, "Send this to them. It is a bearer credential")
	tok := lastLine(r.stdout)
	if !strings.HasPrefix(tok, "ccxt2.") {
		t.Fatalf("the last line from %s is not a token: %q", rl.service, tok)
	}
	return tok
}

// adoptRelay puts a relay in the operator's own home with its anchor pinned,
// which is what an administrator of a second relay has to do before they can
// administer it.
//
// An administrator's authority is a line in the relay's file and needs no
// mailbox, but their *connection* is verified like anybody else's — against the
// anchor their home holds for that relay. A URL the home does not know is dialled
// with no pinned anchor and falls back to system trust, which a relay serving its
// own authority's certificate fails as an unknown authority. That is the error
// this answers, and it is the same anchor for all three relays because one
// authority issued every bundle.
func adoptRelay(t *testing.T, rl *machine) {
	t.Helper()
	expectCode(t, operator.auu("relay", "add", rl.url, "--name", rl.service, "--anchor", anchorHash(t)), 0)
}

// anchorHash is the trust anchor of the one authority every relay here was
// issued from, read from auu-ca rather than from the cycle's recorded state so
// that a matrix-only process has it too.
func anchorHash(t *testing.T) string {
	t.Helper()
	if state.anchor != "" {
		return state.anchor
	}
	state.anchor = find(t, reHex64, operator.ca("show").stdout)
	return state.anchor
}

// renameRelayTo gives a relay in that home the local name its operator chose.
// The name it arrives under is derived from the host; this is where an
// operator's own name for a neighbour is made.
func renameRelayTo(t *testing.T, home *machine, host, local string) {
	t.Helper()
	var listed []struct {
		Name string `json:"name"`
		URL  string `json:"url"`
	}
	jsonOf(t, home.auu("relay", "ls", "--json"), &listed)
	from := ""
	for _, r := range listed {
		if strings.Contains(r.URL, host) {
			from = r.Name
		}
	}
	if from == "" {
		t.Fatalf("no relay for %s in %s: %+v", host, home.home, listed)
	}
	if from == local {
		return
	}
	expectCode(t, home.auu("relay", "rename", from, local), 0)
}

// courierLineOf is that relay's courier's export line, which is what its
// neighbour puts in the couriers file to accept forwards from it.
func courierLineOf(t *testing.T, rl *machine) string {
	t.Helper()
	line := strings.TrimSpace(rl.asAuu().at(courierHome).auu("id", "export").stdout)
	if line == "" {
		t.Fatalf("%s's courier has no export line", rl.service)
	}
	return line
}

// withName is an export line with its trailing name replaced: `ccx2.`, the
// key in base64, `.`, the name. The key is what the fingerprint is over; the
// name after it is plain text, not signed, and the accepting operator's to
// choose. Base64-url has no dots, so the name is everything after the second.
func withName(line, name string) string {
	const prefix = "ccx2."
	key, _, _ := strings.Cut(strings.TrimPrefix(line, prefix), ".")
	return prefix + key + "." + name
}

// keyOf is the key part of an export line, which is what identifies a courier
// whatever name a file gives it.
func keyOf(line string) string {
	key, _, _ := strings.Cut(strings.TrimPrefix(strings.TrimSpace(line), "ccx2."), ".")
	return key
}

// writeCouriersFile puts those export lines in that relay's couriers file, one
// per line, as the operator would.
func writeCouriersFile(t *testing.T, rl *machine, lines []string) {
	t.Helper()
	body := "# the relays this one accepts forwarded mail from\n"
	for _, l := range lines {
		body += l + "\n"
	}
	rl.putContent(t, couriersFile, body)
	rl.mustRoot(t, "chown root:root "+couriersFile+" && chmod 0644 "+couriersFile)
}

// asAuu is that relay's machine spoken to as the auu user, which is who owns
// the courier home and who the relay runs as.
func (m *machine) asAuu() *machine {
	c := *m
	c.user = "auu"
	c.dir = "/var/lib/auu"
	return &c
}

// aliceHasAllowList says whether alice's mailbox is restricted, which the cycle
// leaves it. It decides whether the setup has to admit a courier at all: a
// mailbox with no list admits every registered sender and forwarded mail arrives
// without one, so admitting into it would be a step that proved nothing.
func aliceHasAllowList(t *testing.T) bool {
	t.Helper()
	return strings.Contains(alice.auu("allow", "show").stdout, ": signed")
}

// --- the rows --------------------------------------------------------------

func f01(t *testing.T) {
	// alice addresses dave two relays away: bee is what her relay calls B, and
	// see is what B calls C. She could not have guessed either.
	r := alice.auu("send", "--to", "bee!see!dave", "--subject", "across two relays", "hello from alice")
	expectCode(t, r, 0)
	// It arrives, with the hops it crossed named as dave's own relay and its
	// neighbour name them: arb is what C calls B, ay is what B calls A.
	id := waitForMail(t, dave, "across two relays")
	read := dave.auu("read", id)
	// The hops it crossed, each named by the relay that took it from the one
	// before, nearest the sender first: ay is what B calls A, arb is what C
	// calls B. Two relays' names for two different neighbours, and neither is
	// the name that neighbour calls itself.
	//
	// Nearest the sender first was read off a run rather than predicted, and
	// the prediction was wrong — outermost first, which is how the sentence
	// beside a failed row reads. A via is not that sentence; it is the way
	// back, and the way back starts at the hop nearest the sender.
	expectSays(t, read, 0, "hello from alice", "via:", "ay!arb")
	// And the reply goes back along that address reversed, without being told:
	// arb, then ay, which are C's and B's own names and not alice's.
	expectCode(t, dave.auu("reply", id, "hello back"), 0)
	backID := waitForMailOfType(t, alice, "across two relays", "reply")
	// see is what B calls C, bee is what A calls B.
	expectSays(t, alice.auu("read", backID), 0, "hello back", "via:", "see!bee")
	verdict(t, "ok", "A message crossed two relays and the reply came back along the names each hop had for the hop before it.")
}

func f02(t *testing.T) {
	stop := faultStopRelay(t, relayB)
	// Once, so that a row failing before the restart below still leaves the
	// middle relay up for the rows after it.
	var once sync.Once
	restart := func() { once.Do(stop) }
	defer restart()
	r := alice.auu("send", "--to", "bee!see!dave", "--subject", "the middle was down", "queued while b was stopped")
	expectCode(t, r, 0)
	// Her relay took it and is holding it: the queue says which neighbour it
	// is waiting for and that a try has failed. "waiting" alone is not that —
	// a row not yet offered is waiting too, and her relay offers a new row at
	// once, so with the middle relay up the row would read "waiting" for as
	// long as the hand-over took and the row would pass on a race. "next try"
	// is printed only once a try has failed, which a healthy neighbour never
	// produces.
	waitUntil(t, 30*time.Second, "alice's queue to show a failed try at bee", func() bool {
		out := alice.auu("queue").stdout
		return strings.Contains(out, "bee") && strings.Contains(out, "waiting") && strings.Contains(out, "next try")
	})
	// The drain is asserted before the verdict, since the verdict says it
	// happened.
	restart()
	waitForMail(t, dave, "the middle was down")
	verdict(t, "ok", "The first relay queued the message while the middle one was down, tried and failed, and handed it over when it came back.")
}

func f03(t *testing.T) {
	// The last relay stops accepting from the middle one: B's courier line out
	// of C's couriers file. Ruling 42.
	//
	// C and not B, and that is the whole of what this row is about. The couriers
	// file gates a forward that carries a via, and nothing else: the forward
	// route is open to every registered identity, and a non-courier is refused
	// only for writing a return path it has no right to. A courier forwarding
	// its own users' mail carries no via — the receiving relay adds its name for
	// the poster — so removing A's line from B would let A through as an
	// ordinary user. A run showed exactly that before this row was ruled; what
	// it produced instead was a one-way peering, recorded rather than tested
	// here because its refusal is F05's by another cause.
	//
	// B's forward to C does carry a via — [ay], B's name for the hop before it
	// — so at C, no longer admitting B, it is a return path from an identity
	// with no standing to write one.
	undo := removeCourierLine(t, relayC, relayB)
	defer undo()
	// The reload asserted rather than assumed. A removed line changes the
	// file's size so the check cannot skip it, but reading C's listing through
	// the route is also what makes C re-read the file, so this both forces the
	// reload and shows it happened.
	waitUntil(t, 30*time.Second, "C to stop listing B's courier", func() bool {
		return !strings.Contains(dave.auu("relay", "couriers").stdout, nameFor(t, relayC, relayB))
	})

	mC := logMarkOf(relayC)
	mA := logMarkOf(relay)
	expectCode(t, alice.auu("send", "--to", "bee!see!dave", "--subject", "no longer accepted", "via refused at c"), 0)

	// alice reads it: the refusal came from C, was reported to B and on to A,
	// and her row names both hops by her own relay's names with C's sentence
	// innermost.
	// relayapi.MsgViaIsACouriers, read from the constant and not recalled: a
	// guess of "via is a courier" would have matched only because it happens
	// to be a prefix of the real sentence, which is luck and not an assertion.
	waitForQueueState(t, alice, "via is a courier's to write")
	expectSays(t, alice.auu("queue"), 0, "final", "refused: bee: see: via is a courier's to write")

	// C refused the forward in its own log...
	waitRelayLogOf(t, relayC, mC, "status=400", 30*time.Second)
	// ...and A took a report about it, which is the news crossing back two hops.
	waitRelayLogOf(t, relay, mA, "/v1/forward/failed", 30*time.Second)
	verdict(t, "ok", "With the middle relay's line gone from the last one's couriers file, a forward carrying a via was refused there, "+
		"and the refusal came back two hops to the sender under her own relay's names for each.")
}

func f04(t *testing.T) {
	// A loop on one edge: through B and straight back. At B the via gains ay
	// while the path still holds it, so B's address rule refuses the repeat —
	// one hop before the envelope could return to A and meet the carried table.
	//
	// On a single edge a loop always names its turning relay twice, so it always
	// dies this way. The carried table is reached only by a cycle whose names
	// never repeat, round the triangle under relative names, and that send found
	// a defect: the relay whose envelope came back recorded the refusal as a
	// hand-over, so the message was lost and its sender told it had gone. Ruling
	// 44 fixes that, and the triangle's send lands with the fix in commit 6a.
	//
	// Addressed to bob, who is alice's peer and lives on relay A: --to resolves a
	// recipient through the sender's peer list, and a message cannot be sealed to
	// a name or a bare fingerprint, since the sender needs the key.
	expectCode(t, alice.auu("send", "--to", "bee!ay!bob", "--subject", "an edge loop", "there and back"), 0)
	waitForQueueState(t, alice, "every relay in an address is named once")
	expectSays(t, alice.auu("queue"), 0,
		`refused: bee: address repeats "ay": every relay in an address is named once`)
	verdict(t, "ok", "A loop on one edge was refused by the address rule at the first relay that saw it name a relay twice.")
}

func f05(t *testing.T) {
	// bob has no mailbox on relay-c: he lives on relay A. So the last hop cannot
	// deliver, it tells the middle, and the middle tells the first — which is
	// the row three relays are here for.
	//
	// bob and not an invented name, for the reason F04 gives: a message cannot
	// be sealed to somebody whose key the sender does not hold. A real recipient
	// at the wrong relay is also the honest form of this failure, since it is
	// what a person who typed the wrong path would meet.
	r := alice.auu("send", "--to", "bee!see!bob", "--subject", "undeliverable", "nobody there")
	expectCode(t, r, 0)
	// final is the row's state and refused its code: the words auu queue
	// prints, read off a run. An earlier version waited for "failed", which is
	// neither, and timed out on a row that had already come back.
	waitForQueueState(t, alice, "no such mailbox")
	// What she reads names each hop by the name her own relay's operator chose,
	// outermost first, with the sentence the far relay wrote innermost — which
	// is the shape a failed row's sentence has, and the opposite order to a via.
	expectSays(t, alice.auu("queue"), 0, "final", "refused: bee: see: no such mailbox")
	verdict(t, "ok", "The far relay could not deliver, the news unwound two hops, and the sender read which relay refused and why.")
}

// --- the rows' helpers -----------------------------------------------------

// faultStopRelay stops a relay as a fault and answers the start that undoes it.
// Under AUU_E2E_NOFAULT it does nothing, so the row is run once with the relay
// left up and shown to depend on the stop.
func faultStopRelay(t *testing.T, rl *machine) func() {
	t.Helper()
	if nofault {
		return func() {}
	}
	relayStopOf(t, rl)
	return func() { relayStartOf(t, rl) }
}

// removeCourierLine takes one relay's courier out of another's couriers file
// and answers the undo, so the row leaves the file as it found it.
func removeCourierLine(t *testing.T, on, whose *machine) func() {
	t.Helper()
	// A fault helper, so it does nothing under AUU_E2E_NOFAULT: TESTING.md
	// requires every fault row to be run once with its fault disabled, and a
	// row whose helper ignored the switch would pass that check by not
	// disabling anything — the failure the rule was written after.
	if nofault {
		return func() {}
	}
	before := on.read(t, couriersFile)
	// Matched on the key and not the whole line: the file carries the accepting
	// relay's own name for the courier, not the one its export line was issued
	// with.
	key := keyOf(courierLineOf(t, whose))
	var kept []string
	for _, l := range strings.Split(before, "\n") {
		if strings.TrimSpace(l) != "" && keyOf(l) != key {
			kept = append(kept, l)
		}
	}
	on.putContent(t, couriersFile, strings.Join(kept, "\n")+"\n")
	return func() { on.putContent(t, couriersFile, before) }
}

// waitUntil polls a condition until it holds, or fails naming what it was
// waiting for.
func waitUntil(t *testing.T, d time.Duration, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("waited %s for %s", d, what)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// waitForMail fetches until a subject arrives, and answers that message's id.
//
// It reads the fetch's own JSON rather than a separate listing, because there is
// no separate listing: 'auu inbox' fetches and lists in one command. An earlier
// version of this helper polled 'auu ls', which is not a command at all, so it
// searched the output of a usage error and reported that mail had never arrived
// when it had — the message was in the inbox and the assertion was looking at
// nothing. The queue is printed on failure so the next person sees where the
// message stopped, if it did.
func waitForMail(t *testing.T, who *machine, subject string) string {
	t.Helper()
	return waitForMailOfType(t, who, subject, "")
}

// waitForMailOfType is waitForMail narrowed to one type of message.
//
// A reply keeps the subject of what it answers — it is marked as a reply by its
// type, not by a prefix on the subject — so a row waiting for a reply matches on
// both, or it would take the original if both were ever in one inbox. An earlier
// version of the round-trip row waited for "re: " and the subject, a message
// that is never sent, and reported the reply missing while it sat in the inbox.
func waitForMailOfType(t *testing.T, who *machine, subject, typ string) string {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for {
		var in inboxJSON
		jsonOf(t, who.auu("inbox", "--json"), &in)
		for _, m := range in.Messages {
			if m.Subject == subject && (typ == "" || m.Type == typ) {
				return m.ID
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s never received %q; the sender's queue says:\n%s",
				who.user, subject, alice.auu("queue").stdout)
		}
		time.Sleep(time.Second)
	}
}

// waitForQueueState polls the sender's queue for a row in that state.
func waitForQueueState(t *testing.T, who *machine, state string) {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for {
		if strings.Contains(who.auu("queue").stdout, state) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s's queue never reached %q:\n%s", who.user, state, who.auu("queue").stdout)
		}
		time.Sleep(time.Second)
	}
}
