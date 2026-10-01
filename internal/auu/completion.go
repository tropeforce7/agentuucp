package auu

import (
	"fmt"
	"sort"
	"strings"

	"github.com/tropeforce7/agentuucp/internal/channels"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// Shell completion.
//
// The shell script printed by "auu completion" is small and knows nothing:
// on every tab it runs "auu __complete" with the words on the line and prints
// what comes back. The candidates are made here, from the local store — ids,
// threads, peers — and never from the relay, so a tab is always instant and
// never a network request. Flags come from the commands themselves, through
// parseArgs, so the list cannot go stale.
//
// The protocol between the two is one candidate per line, "value<TAB>
// description", or the single line "__files" meaning "complete file names",
// which only the shell can do.

// A subcommand, as offered when nothing has been typed yet.
type subcommand struct {
	name, describe string
	subs           []subcommand // second words, for commands that have them
}

var subcommands = []subcommand{
	{name: "init", describe: "create your identity"},
	{name: "id", describe: "show your fingerprint, or export your key line", subs: []subcommand{
		{name: "export", describe: "print the line to give a colleague"},
	}},
	{name: "lookup", describe: "ask the relay about a fingerprint, short id or peer"},
	{name: "listed", describe: "who on the relay chose to be listed, verified here"},
	{name: "knock", describe: "one message to somebody who has not admitted you, at a terminal"},
	{name: "vouch", describe: "send a peer your word that you hold another", subs: []subcommand{
		{name: "answer", describe: "whether inbox and wait answer a peer's question by themselves"},
	}},
	{name: "introduce", describe: "a vouch each way between two peers"},
	{name: "enrol", describe: "create an identity and register with an enrolment token"},
	{name: "register", describe: "register your identity with the relay"},
	{name: "token", describe: "inspect an enrolment token", subs: []subcommand{
		{name: "show", describe: "show what a token says"},
	}},
	{name: "cert", describe: "this machine's client certificate", subs: []subcommand{
		{name: "status", describe: "show this machine's certificate"},
		{name: "ls", describe: "list every machine on your identity"},
		{name: "renew", describe: "get a fresh certificate now"},
	}},
	{name: "anchor", describe: "the relay's trust anchor this machine pinned", subs: []subcommand{
		{name: "status", describe: "show what is pinned"},
		{name: "pin", describe: "pin the relay's anchor and keep your identity"},
		{name: "forget", describe: "trust the system roots for this relay again"},
	}},
	{name: "relay", describe: "the relays this home knows", subs: []subcommand{
		{name: "add", describe: "add a relay by URL"},
		{name: "ls", describe: "list relays"},
		{name: "show", describe: "everything this home holds for one relay"},
		{name: "couriers", describe: "the relays one accepts forwarded mail from"},
		{name: "default", describe: "which relay commands use when none is named"},
		{name: "rename", describe: "rename a relay here"},
		{name: "rm", describe: "forget a relay"},
	}},
	{name: "peers", describe: "the people you trust", subs: []subcommand{
		{name: "add", describe: "add a colleague's export line"},
		{name: "ls", describe: "list peers"},
		{name: "rm", describe: "remove a peer"},
		{name: "fetch", describe: "add a peer found on the relay, at a terminal"},
	}},
	{name: "allow", describe: "restrict your relay mailbox to your peers", subs: []subcommand{
		{name: "push", describe: "send your peer list to the relay, signed"},
		{name: "clear", describe: "accept mail from anyone again"},
		{name: "show", describe: "what each relay holds for you, verified with your key"},
	}},
	{name: "card", describe: "whether the relay may list you, and whether you take knocks", subs: []subcommand{
		{name: "push", describe: "sign your card and push it to every relay"},
		{name: "clear", describe: "a card that says neither: not listed, no knocks"},
		{name: "show", describe: "what each relay holds for you, verified with your key"},
	}},
	{name: "channel", describe: "the named sub-mailboxes senders choose between", subs: []subcommand{
		{name: "ls", describe: "list your channels, or a peer's"},
		{name: "create", describe: "add a channel and push the directory"},
		{name: "update", describe: "change a channel's description or period"},
		{name: "close", describe: "close a channel now, or at a time"},
		{name: "delete", describe: "remove a channel; queued mail still arrives"},
		{name: "keep", describe: "leave mail from a channel on the relay, or not"},
		{name: "push", describe: "give every relay the directory as it is here"},
		{name: "pull", describe: "take the directory a relay holds"},
	}},
	{name: "send", describe: "send a message"},
	{name: "reply", describe: "reply to a message, or to a thread"},
	{name: "inbox", describe: "fetch and list mail"},
	{name: "read", describe: "read a message"},
	{name: "queue", describe: "your mail still waiting to leave a relay"},
	{name: "extract", describe: "save a message's attachments"},
	{name: "rm", describe: "remove a message from the relay and from here"},
	{name: "wait", describe: "wait for a reply on a thread"},
	{name: "watch", describe: "return when mail arrives, or a colleague's channels change"},
	{name: "quarantine", describe: "mail from senders not on your list", subs: []subcommand{
		{name: "ls", describe: "list held mail"},
		{name: "show", describe: "show a held message"},
		{name: "trust", describe: "trust its sender and deliver it"},
	}},
	{name: "passphrase", describe: "encrypt this home's keys under a passphrase", subs: []subcommand{
		{name: "set", describe: "encrypt the keys"},
		{name: "change", describe: "change the passphrase"},
		{name: "remove", describe: "put the keys back in the clear"},
	}},
	{name: "unlock", describe: "unlock the keys for a while"},
	{name: "lock", describe: "lock the keys now"},
	{name: "agent", describe: "the process that holds the unlocked keys", subs: []subcommand{
		{name: "start", describe: "start it, detached"},
		{name: "stop", describe: "stop it"},
		{name: "status", describe: "whether it is running and unlocked"},
	}},
	{name: "skill", describe: "the Claude Code skills the binary carries", subs: []subcommand{
		{name: "install", describe: "write them under ~/.claude/skills"},
		{name: "ls", describe: "which of them are installed, and whether they match"},
		{name: "show", describe: "print one without installing it"},
	}},
	{name: "completion", describe: "print a completion script for your shell", subs: []subcommand{
		{name: "zsh", describe: ""},
		{name: "bash", describe: ""},
	}},
}

// cmdCompletion prints the script for a shell.
func cmdCompletion(args []string) error {
	if len(args) != 1 {
		return usageErrf("usage: %s completion zsh|bash", prog)
	}
	switch args[0] {
	case "zsh":
		fmt.Print(strings.ReplaceAll(zshCompletion, "auu", prog))
	case "bash":
		fmt.Print(strings.ReplaceAll(bashCompletion, "auu", prog))
	default:
		return usageErrf("no completion for %q; zsh and bash are supported", args[0])
	}
	return nil
}

// candidate is one thing the shell may offer.
type candidate struct{ value, describe string }

// cmdComplete answers the shell. args are the words after the program name,
// the last of them the word under the cursor, which may be empty.
func cmdComplete(args []string) error {
	for _, c := range complete(args) {
		if c.describe == "" {
			fmt.Println(c.value)
		} else {
			fmt.Printf("%s\t%s\n", c.value, c.describe)
		}
	}
	return nil
}

// filesMarker tells the shell to complete file names itself.
var filesMarker = []candidate{{value: "__files"}}

func complete(args []string) []candidate {
	if len(args) == 0 {
		args = []string{""}
	}
	cur := args[len(args)-1]
	if len(args) == 1 {
		return matching(cur, subcommandCandidates(subcommands))
	}
	cmd := args[0]
	words := args[1:]

	// Commands with a second word: offer it, then continue past it.
	path := []string{cmd}
	for _, sc := range subcommands {
		if sc.name == cmd && len(sc.subs) > 0 {
			if len(words) == 1 {
				return matching(cur, subcommandCandidates(sc.subs))
			}
			path = append(path, words[0])
			words = words[1:]
		}
	}
	cur = words[len(words)-1]
	prev := ""
	if len(words) >= 2 {
		prev = words[len(words)-2]
	}

	if strings.HasPrefix(cur, "-") {
		var out []candidate
		for _, f := range flagsFor(path) {
			out = append(out, candidate{"--" + f.name, f.usage})
		}
		return matching(cur, out)
	}
	if strings.HasPrefix(prev, "-") {
		name := strings.TrimLeft(prev, "-")
		for _, f := range flagsFor(path) {
			if f.name == name && !f.isBool {
				return shown(cur, matching(cur, valuesFor(name)))
			}
		}
	}
	return shown(cur, matching(cur, positionalsFor(path, words)))
}

// shown is how ids are offered: by their first twelve characters, which is
// how every listing shows them, unless more than that has been typed, in
// which case the whole id is completed. Matching happened on the whole id
// either way.
func shown(cur string, all []candidate) []candidate {
	if len(cur) > 12 {
		return all
	}
	return shorten(all)
}

// flagsFor asks a command for its flags by running it with the sentinel.
func flagsFor(path []string) []flagInfo {
	var got []flagInfo
	flagSink = &got
	defer func() { flagSink = nil }()
	_ = run(append(append([]string{}, path...), flagsSentinel))
	return got
}

// valuesFor is what may follow a flag that takes a value.
func valuesFor(flag string) []candidate {
	switch flag {
	case "to":
		out := []candidate{{"self", "a note to yourself"}}
		return append(out, peers()...)
	case "peer":
		out := []candidate{{"self", "your own channels, changed from another machine"}}
		return append(out, peers()...)
	case "event":
		return []candidate{{eventMessage, "a message arriving"}, {eventDirectory, "a colleague's channels changing"}}
	case "thread":
		return threads()
	case "reply-to":
		return messages(store.Inbox, store.Sent)
	case "relay":
		return relayCandidates()
	case "attach", "body-file", "out", "config":
		return filesMarker
	case "type":
		return []candidate{{"ask", "a question, expecting an answer"}, {"note", "for information"}}
	}
	return nil
}

// positionalsFor is what a command takes after its flags. words are the
// ones typed after the command and its subcommand, the one being completed
// last, for the few commands whose second positional is not its first.
func positionalsFor(path []string, words []string) []candidate {
	switch strings.Join(path, " ") {
	case "channel keep":
		if len(words) >= 2 {
			return []candidate{
				{"on", "mail is kept on the relay after it is fetched"},
				{"off", "mail is removed from the relay once it is fetched"},
			}
		}
		return ownChannels()
	case "read":
		return messages(store.Inbox, store.Sent, store.Quarantine)
	case "extract":
		return messages(store.Inbox, store.Sent)
	case "rm":
		return messages(store.Inbox, store.Sent, store.Quarantine)
	case "reply":
		return append(messages(store.Inbox), threads()...)
	case "quarantine show", "quarantine trust":
		return messages(store.Quarantine)
	case "peers rm":
		return peers()
	case "relay default", "relay rename", "relay rm", "relay show":
		return relayCandidates()
	case "peers add", "enrol":
		return filesMarker[:0] // an export line or a token: nothing to offer
	}
	return nil
}

// ownChannels is this home's own channel names, default included, for the
// commands that take one. A home with no directory has default alone; a
// directory that will not read offers nothing rather than failing a
// completion.
func ownChannels() []candidate {
	out := []candidate{{channels.Default, "the channel a sender who names none posts to"}}
	s, err := openStore()
	if err != nil {
		return out
	}
	d, found, err := s.Directory()
	if err != nil || !found {
		return out
	}
	for _, ch := range d.Channels {
		if ch.Name == channels.Default {
			continue
		}
		out = append(out, candidate{ch.Name, ch.Description})
	}
	return out
}

func subcommandCandidates(subs []subcommand) []candidate {
	out := make([]candidate, 0, len(subs))
	for _, s := range subs {
		out = append(out, candidate{s.name, s.describe})
	}
	return out
}

// matching keeps the candidates that start with what has been typed.
func matching(cur string, all []candidate) []candidate {
	var out []candidate
	for _, c := range all {
		if strings.HasPrefix(c.value, cur) {
			out = append(out, c)
		}
	}
	return out
}

// messages lists ids across boxes, oldest last, each once.
func messages(boxes ...store.Box) []candidate {
	s, err := openStore()
	if err != nil {
		return nil
	}
	var (
		out  []candidate
		seen = map[string]bool{}
	)
	for _, box := range boxes {
		msgs, err := s.List(box)
		if err != nil {
			continue
		}
		for _, m := range msgs {
			if seen[m.Inner.ID] {
				continue
			}
			seen[m.Inner.ID] = true
			from := s.PeerName(m.Inner.From)
			if from == "" {
				from = m.Inner.From[:12]
			}
			out = append(out, candidate{
				value:    m.Inner.ID,
				describe: fmt.Sprintf("%s — %s (%s)", orNone(identity.PrintableText(m.Inner.Body.Subject)), identity.Printable(from), box),
			})
		}
	}
	return out
}

// threads lists the threads in the inbox and sent, described by their latest
// subject.
func threads() []candidate {
	s, err := openStore()
	if err != nil {
		return nil
	}
	latest := map[string]*store.Stored{}
	for _, box := range []store.Box{store.Inbox, store.Sent} {
		msgs, err := s.List(box)
		if err != nil {
			continue
		}
		for _, m := range msgs {
			t := m.Inner.Body.Thread
			if cur, ok := latest[t]; !ok || store.LaterThan(m, cur) {
				latest[t] = m
			}
		}
	}
	var out []candidate
	for t, m := range latest {
		out = append(out, candidate{t, "thread: " + orNone(identity.PrintableText(m.Inner.Body.Subject))})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].value < out[j].value })
	return out
}

// shorten cuts ids to their first twelve characters, leaving anything else.
func shorten(all []candidate) []candidate {
	for i := range all {
		if len(all[i].value) == 32 {
			all[i].value = all[i].value[:12]
		}
	}
	return all
}

// relayCandidates offers the relays this home knows, by name.
func relayCandidates() []candidate {
	s, err := openStore()
	if err != nil {
		return nil
	}
	relays, err := s.Relays()
	if err != nil {
		return nil
	}
	defaultName := ""
	if def, err := s.DefaultRelay(); err == nil {
		defaultName = def.Name
	}
	var out []candidate
	for _, r := range relays {
		describe := r.URL
		if r.Name == defaultName {
			describe += " (default)"
		}
		out = append(out, candidate{r.Name, describe})
	}
	return out
}

func peers() []candidate {
	s, err := openStore()
	if err != nil {
		return nil
	}
	list, err := s.Peers()
	if err != nil {
		return nil
	}
	var out []candidate
	for _, p := range list {
		if p.Name != "" {
			out = append(out, candidate{p.Name, p.Short()})
		}
	}
	return out
}

// The scripts. Each calls back into the program for candidates; "auu" is
// replaced with whichever name the program was installed under.

const zshCompletion = `#compdef auu

# Completion for auu, printed by "auu completion zsh". The candidates come
# from "auu __complete", which reads your local store and never the relay.
#
# To install, either
#   eval "$(auu completion zsh)"
# in ~/.zshrc, or write this to a file named _auu somewhere in $fpath.

_auu() {
  local -a lines pairs
  local line value desc
  lines=("${(@f)$(auu __complete "${words[@]:1:$((CURRENT-1))}" 2>/dev/null)}")
  if [[ ${lines[1]} == __files ]]; then
    _files
    return
  fi
  for line in "${lines[@]}"; do
    [[ -z $line ]] && continue
    value=${line%%$'\t'*}
    desc=${line#*$'\t'}
    [[ $desc == $line ]] && desc=""
    desc=${desc//:/\\:}
    if [[ -n $desc ]]; then
      pairs+=("${value}:${desc}")
    else
      pairs+=("$value")
    fi
  done
  (( ${#pairs} )) && _describe -t auu 'auu' pairs
}

if [[ $funcstack[1] == _auu ]]; then
  _auu "$@"
else
  # A stock zsh has not loaded its completion system, and compdef does not
  # exist until it has. Load it if nobody else has.
  if (( ! $+functions[compdef] )); then
    autoload -Uz compinit && compinit
  fi
  compdef _auu auu
fi
`

const bashCompletion = `# Completion for auu, printed by "auu completion bash". The candidates come
# from "auu __complete", which reads your local store and never the relay.
#
# To install, either
#   eval "$(auu completion bash)"
# in ~/.bashrc, or write this to /etc/bash_completion.d/auu.

_auu() {
  local cur="${COMP_WORDS[COMP_CWORD]}"
  local line
  local -a lines
  while IFS= read -r line; do
    lines+=("$line")
  done < <(auu __complete "${COMP_WORDS[@]:1:COMP_CWORD}" 2>/dev/null)
  COMPREPLY=()
  if [[ "${lines[0]}" == __files ]]; then
    COMPREPLY=($(compgen -f -- "$cur"))
    return
  fi
  for line in "${lines[@]}"; do
    [[ -z "$line" ]] && continue
    COMPREPLY+=("${line%%$'\t'*}")
  done
}
complete -F _auu auu
`
