# An expert host: `auu serve`

An expert is an agent that knows one project and answers questions about it
over AgentUUCP. It runs on a machine that holds the project's checkout, it
listens to one channel of its owner's mailbox, and it answers each message
by running a program — Claude Code, in the case this was built for — in a
git worktree of that checkout, and sending back what the program printed.

One machine can be an expert for several projects: one channel each.

`auu serve` runs until it is stopped, holding on the relay between rounds.
`auu serve --once` is one round, for a timer or a person.

## The file

`serve.json`, in the home beside `config.json`, hand-written by the owner:

```json
{
  "v": 1,
  "channels": {
    "jostle": {
      "dir": "/home/expert/src/jostle",
      "exec": "/home/expert/bin/serve-claude.sh",
      "mode": "read-only",
      "before": "/home/expert/bin/jostle-up.sh",
      "after": "/home/expert/bin/jostle-down.sh",
      "timeout": "30m",
      "max_turns": 50,
      "retries": 3,
      "thread_ttl": "168h"
    }
  },
  "proxy": {
    "key_file": "/etc/auu-expert/key",
    "listen": "127.0.0.1:0",
    "upstream": "https://api.anthropic.com"
  }
}
```

| field | what it is |
|-------|------------|
| `dir` | **required.** The checkout the worktrees are made from. It must be a git repository; serve never writes in it. |
| `exec` | **required.** The program that answers. It is run through the platform shell, so a line with arguments, a pipeline or a redirection is what you wrote. |
| `mode` | `read-only` (the default) or `side-copy`. See below. |
| `before` | A program run just before the handler. A failure means the handler does not run and the message is tried again. |
| `after` | A program run just after it, however it ended. A failure means the answer does not go out, so this is where a side copy's tests belong. |
| `timeout` | How long the handler, and each hook, may take. Default `30m`. |
| `max_turns` | How many messages serve will answer on one thread. Default `50`, which is also what `0` means: the file cannot tell an absent number from a zero one. A reply counts on the thread of the message it answers; one that names another thread is not serve's, and is left in the inbox with a line on standard error saying so. |
| `retries` | How many times a message may fail before serve gives up on it. Default `3`, and `0` means the same. |
| `thread_ttl` | How long a thread's state is kept after its last message. Default `168h`. |

`proxy` is the key-holding proxy, one section for the whole file, and is
its own section below. A file without it hands the handler no key at all.

A path in the file that is not absolute — a channel's `dir`, the proxy's
`key_file` or `control`, and the same two in the split proxy's own file —
is relative to the directory the file is in, not to wherever `auu serve`
was started from: `"dir": "src/jostle"` in `/home/expert/.auu/serve.json`
is `/home/expert/.auu/src/jostle`. `exec`, `before` and `after` are
command lines the shell runs, and the shell resolves them as it always
does, with the worktree as the working directory. `auu serve check`
prints every path as it resolved it.

Unknown fields are refused by name: a misspelled one that silently did
nothing would be a channel nobody was serving. So is a field in another
case than this guide's (`"Exec"` for `exec`), a field given twice, and
anything after the closing brace, each of which the JSON reader would
otherwise take without a word. The split proxy's own file is read the same
way.

`auu serve check` reads the file, checks every directory and program it
names, and prints what it would serve, without touching a key, a relay or
the network:

```
$ auu serve check
jostle: read-only in /home/expert/src/jostle
  exec:    /home/expert/bin/serve-claude.sh
  limits:  timeout 30m0s, max_turns 50, retries 3, thread_ttl 168h0m0s

proxy: key from /etc/auu-expert/key (108 bytes), listen 127.0.0.1:0, upstream https://api.anthropic.com

/home/expert/.auu/serve.json is good for 1 channel
```

Run it after every edit. A file with a mistake in it stops the whole
service rather than one channel of it, which is deliberate: an expert that
silently answered for three projects out of four would be worse.

## The two modes

**`read-only`** is an expert that answers questions. Its channel has one
worktree, shared by every thread, and that is what lets the handler keep one
warm session for the channel: the tour of the code is paid for once. At each
new thread's first message the worktree is moved to whatever the checkout's
HEAD is then, so the expert follows the project without anybody writing a
hook. Untracked scratch — the test file the agent wrote to try something —
survives that move. A tracked edit does not, and in this mode it was never
going to be returned to anyone.

**`side-copy`** is an expert that works. Every thread gets a worktree of its
own, made from HEAD at the thread's first message and reused for every
message after, so a thread is a conversation over one copy.

Its reply carries the thread's whole change so far, attached as
`THREAD12.patch`, and one sentence at the end of the text saying so. The
patch is taken as `git add -A && git diff --cached --binary BASE` in the
worktree, where BASE is the commit the worktree was made from — recorded
when it was made and read back from a file, never asked of git again, so a
handler that commits in its own worktree cannot move what the change is
measured against. It is cumulative on purpose: every turn's patch is the
whole of the thread's work, so the latest reply is always the complete one
and an asker need keep only the last. Apply it to a clone at BASE:

```
auu extract MESSAGE-ID --out .
git apply THREAD12.patch
```

Three things follow from `git add -A`. What the handler committed is in the
patch, and so is what it merely wrote. What `.gitignore` hides is not. A
handler that writes its answer into an ignored path will find it does not
travel. And a file that is not text travels too, since the diff is taken
with `--binary`.

A handler that changes files and prints nothing sends nothing at all: exit
0 with no output is "nothing to say", so the message is settled, no reply
goes out, and the work waits in the worktree until the thread is swept. The
patch goes with an answer. It is not an answer by itself.

There is no limit on how large a patch may be. A big one becomes a stream
rather than being refused. What it meets in the end is the asker's
mailbox: an enormous diff fills it, the send fails, and after `retries` the
message is left unanswered for the owner to look at. A side-copy expert
that can produce diffs that large wants an `after` hook that refuses one,
which is the same hook that runs the tests.

A thread's worktree is let go of when the thread has been idle for
`thread_ttl`. A read-only channel's is not, and lasts as long as the
channel is in the file.

A worktree is not a container. Two threads cannot collide over files, but
they can over anything else the project uses: a fixed port, a named
container, a shared database, a lock file in `/tmp`. If a project needs one
of those, the `before` and `after` hooks are where it is started and stopped,
and a channel that cannot share is a channel to serve `read-only`.

## What the handler is given

The message's text arrives on standard input. Everything else is in the
environment:

| variable | what it is |
|----------|------------|
| `AUU_MESSAGE_ID` | the message being answered |
| `AUU_THREAD_ID` | its thread |
| `AUU_IN_REPLY_TO` | what it answers, empty for an ask |
| `AUU_TYPE` | `ask` or `reply` |
| `AUU_SUBJECT` | the subject |
| `AUU_FROM` | the sender's fingerprint |
| `AUU_FROM_NAME` | the sender's name in your peer list |
| `AUU_RECIPIENTS` | for a message to several, everybody it went to, as fingerprints separated by spaces in the sender's order, the expert among them and the sender only if they sent themselves a copy; empty for a message to one. The expert answers the sender alone. The shipped wrapper, `serve-claude.sh`, does not read it |
| `AUU_CHANNEL` | the channel being served |
| `AUU_RELAY` | the relay the message came through, by name — which is what `auu` itself reads that variable as |
| `AUU_TURN` | 1 for the ask, 2 for the first follow-up, and so on |
| `AUU_MODE` | `read-only` or `side-copy` |
| `AUU_WORKTREE` | the worktree, which is also the working directory |
| `AUU_BASE` | the commit the worktree stands on |
| `AUU_THREAD_DIR` | a directory of the thread's own, for state the handler keeps |
| `AUU_CHANNEL_DIR` | the same for the channel |
| `AUU_ATTACHMENTS` | where the sender's files were put, or empty |
| `ANTHROPIC_BASE_URL` | with a proxy configured: `http://127.0.0.1:PORT/TOKEN`, where to send Anthropic API requests for this invocation |
| `ANTHROPIC_API_KEY` | with a proxy configured: the same token, a placebo, since Claude Code refuses to run with no key at all |

The files an asker attached are unpacked into a directory of the message's
own under the thread's, each checked against the digest the message carries
as it is written, and `AUU_ATTACHMENTS` names it. A log, a failing test or a
stack trace is the usual thing to send an expert. They are the asker's
files: read them, do not run them.

What the handler prints on standard output is the reply. Exit 0 having
printed nothing means "nothing to say": the message is settled and no reply
goes out. Any other exit is a failure. The message stays unread, the
attempt is counted, and the next round tries again until `retries` runs out.

A reply is held to the same rule as a typed message — prose, with line
breaks and tabs — and a Windows line ending is folded to a line break
first, so a handler on Windows or any tool in text mode there is an honest
answer. A lone carriage return, or any other control character, fails the
round with the rule's sentence, recorded as that message's failure.

The two hooks get the same environment less `AUU_SUBJECT`,
`AUU_ATTACHMENTS` and the proxy's two variables, and nothing on standard
input: they are not shown the message. `after` also gets `AUU_STATUS`,
which is the handler's exit status as a number, or `timeout`, or `before`
when the handler never ran because the before hook failed. A hook's output
is never a reply.

Everything a hook or a handler writes to its standard error is printed to
serve's own, with the thread's short id in front of each line. It is printed
when the program has finished rather than as it goes: serve gives each
program a file rather than a pipe, because a pipe held open by something the
handler started would make the wait after a timeout never end.

Each program is killed with everything it started when the timeout
comes — on Unix through a process group of its own, on Windows by walking
the process tree with `taskkill /T` — so a session the handler started does
not outlive it.

## Which messages are answered

- An **ask** on a served channel.
- A **reply to something serve itself sent**, which is a follow-up. A reply
  arrives on your default channel rather than the one the ask was addressed
  to — a channel is the receiver's sorting, not a property of a thread — so
  what decides is the thread, not the channel it came in on.
- Nothing else. A note, an acknowledgement, a reply to a message somebody
  wrote by hand, a vouch, a question asking whether you trust a key, and
  anything in quarantine are all left alone. Serve's own rounds never answer
  a question, even with `auu vouch answer on`: a vouch is the person's
  word, and the rounds are the expert's. A handler that runs `auu inbox`
  itself is `auu inbox`, and answers as it would. Who may ask
  is the peer list, and `auu allow push` is what keeps strangers off the
  relay.
- And never more than `max_turns` messages on one thread, which is what
  stops two experts pointed at each other from talking for ever. The
  thread is the one serve sent its reply on: a follow-up that names
  another thread than the reply it answers was sent on is not serve's,
  since a count on a thread the sender names would start over each time.

A thread id is a message id, 32 lowercase hex characters, and serve makes
the thread's directory and its worktree's path from it. A message whose
thread id is anything else — a peer's `--thread "../../outside"` — is
refused as malformed when it is opened, kept under `damaged/` and
acknowledged, and never reaches serve. A record in the spool with one,
which only a hand could have written, is that message's failure in the
ledger and the round goes on to the next.

`serve/ledger.json` in the home is the record of what has been answered, and
it is the only thing that decides. The mark that a message has been read is
not: an owner reading their own expert's mail must not silently kill an
answer. A message is marked read when its reply goes out, since the reply is
the acknowledgement.

**The first start does not answer old mail.** With no ledger, everything in
the inbox is written down as skipped and a sentence says how many. If it is
a new expert whose mail is waiting for it, `auu serve --once --backlog`
answers it instead. That belongs to a first start alone, and later it is
refused.

**Mail on a served channel stays on the relay.** Every channel keeps its
mail there until it is removed, so that a second machine of the same
identity reads it too, and an expert answering all year would fill its own
mailbox and start refusing its askers. `serve check` and `serve` both say so
by name. Run `auu channel keep jostle off` on an expert host, or `auu rm`
what has gathered.

## Running it

```
auu serve                       # the service: rounds, holding on the relay between them
auu serve --once                # one round, then stop
auu serve --once --json         # the same, reported as one object
auu serve check                 # read the file and say what it would serve
auu serve ls                    # what is served, and the threads it is holding
```

Without `--once` it runs until it is stopped. A round is a fetch and then
every pending message. Between rounds it holds a listing open on every relay
the home is on, so a message is answered when it arrives rather than at the
next poll. A relay that cannot hold one is asked every twenty seconds, which
is the same interval `auu watch` uses and is not a setting: a relay that can
hold answers at once, and one that cannot is not made faster by asking
harder.

It stops on `SIGTERM` or an interrupt, which is what a service manager
sends, and exits 0. A handler that is running when the signal arrives is
stopped with it, and its message is left exactly as it was — nothing
written down, nothing sent — so the next serve picks it up. It also stops,
at exit 2, when every relay's watch has ended for a reason no interval will
change. A relay that is merely down is not one of those: serve says so once
and waits for it to come back.

`--config FILE` reads a file somewhere else.

Exit 0 is a round in which everything was answered, or a service that was
stopped; 1 is a bad file, or a `--once` round that left something
unanswered; 2 is a relay that could not be reached, or another serve already
running in this home; 4 is a home whose keys are locked, or unlocked only to
receive.

One serve runs per home, held by `serve/lock`. The owner's own `auu inbox`
is not blocked by it: that has a lock of its own, per relay, and waits.

The keys must be usable without anybody there, and usable to send: every
reply originates, so an expert is the one thing that runs in send scope
unattended, by design. Either leave the home unencrypted on a machine that
is nobody's desktop, or unlock it once — `auu unlock --send --ttl 0` and
`auu agent start` — and let the agent hold it until `auu lock`. Serve
refuses to start with the keys locked, or unlocked only to receive (a plain
`auu unlock`), in one sentence each, and never prompts: a person at a
terminal is told the unlock to make. Under a send scope that will end — an
`auu unlock --send` without `--ttl 0`, ten minutes by default — it starts
and says when it will stop. A lock that arrives in the middle of a run —
the agent's time ran out, somebody ran `auu lock` or `auu lock --send` —
stops it at exit 4 without counting anything against the message it was
answering.

### Under systemd

An expert host with an account of its own — a system user whose key is
unencrypted, which is the shape for a machine that reboots unattended —
runs as an ordinary system unit. `docs/creating-experts.md` section 7 sets
that up from the account to the day-two commands.

What follows is the other shape: a person's own account with an encrypted
key, where it must be a **user** unit. The agent's socket lives under
`XDG_RUNTIME_DIR`, which a user unit has and a `User=` system unit does
not, so a system unit would not find the keys. In
`~/.config/systemd/user/auu-serve.service`:

```ini
[Unit]
Description=AgentUUCP expert host
After=network-online.target

[Service]
ExecStart=%h/bin/auu serve
Restart=always
RestartSec=30

[Install]
WantedBy=default.target
```

```
loginctl enable-linger expert     # or the service stops when they log out
systemctl --user enable --now auu-serve
journalctl --user -u auu-serve -f
```

Lingering is the step people forget: without it a user unit runs only while
that user has a session, so the expert would answer for as long as somebody
was logged in and no longer. With an encrypted home, `auu unlock --send
--ttl 0` and `auu agent start` have to happen before the unit starts. A
machine that reboots unattended cannot do that for itself — which is the
argument for leaving an expert host's home unencrypted and locking down
the machine instead.

## What it is holding

```
auu serve ls
auu serve ls --json
```

One line per channel with its mode and its checkout, the channel's worktree
where it has one, and under it every thread serve has answered on: its id,
how many turns it has had, when it was last touched, and its worktree in
`side-copy`. It reads the file and the ledger and nothing else — no key, no
relay — so it is safe to run against a home whose service is busy.

Threads do not last for ever. A thread nothing has touched for its
channel's `thread_ttl` (a week by default) has its state directory deleted
and, in `side-copy`, its worktree removed. The sweep runs when serve starts
and after every round. A read-only channel's own worktree and directory are
never swept: they are the channel's, and they hold the warm session's
memory of the project. Nothing that is still work is swept — a message
being tried again, or a reply written and waiting for a relay to come back,
is exactly the state the next round needs — and the ledger keeps a swept
thread's ids, so nothing is answered twice. A thread whose channel has since
been taken out of the file is swept on the default week, since state under
the home should not grow for ever because somebody stopped serving
something.

## Making a good expert

**Write the project's tour down.** The largest cost in answering a question
about a codebase is not the answer, it is the first ten minutes of looking
around: what lives where, how the pieces fit, where the tests are, what the
words mean here. A session that has to rebuild that every time spends most
of what it has on it. A document the project's `CLAUDE.md` points at gives
every session — warm or cold — the same tour for a few thousand tokens, and
it is worth more than anything serve can do for you.

**Let the session stay warm.** A `read-only` channel has one worktree and
one session for the whole channel, which is why: the tour is paid for once
and carried, compacted, into every ask after it. The cost is that one
asker's question is in the context when the next is answered, which for a
project expert is the point and for anything confidential is not. A
`side-copy` thread gets its own session, since its work is its own.

**Say what the expert is for in the channel's description.** It is what an
asker reads before they write, and `auu channel ls PEER` is how they read
it. "Questions about the parser, read-only" sets an expectation that the
reply then meets.

**Narrow the tools.** The wrapper is where an agent's flags live, and the
tool list is the operator's to cut down. `Edit` and `Write` are a side
copy's tools, since a side copy's whole point is a change to send back. A
read-only expert still writes — a scratch test, a bit of output to read —
but it writes through the shell in its own worktree, and nothing it writes
leaves the machine. `auu` and `auu-admin` must never be in any expert's
list, since the reply goes out through serve and nowhere else.

**Let the hooks do the setup.** Fetching the base, starting a service the
tests need, stopping it again, refusing a change that does not build: all of
that belongs in `before` and `after`, where it is written once in the
project's own language, rather than in a prompt that asks an agent to
remember it every time.

## The proxy

A handler that answers with Claude Code needs an Anthropic API key, and
what it reads is untrusted mail: a crafted ask can have the key printed
into a reply and carried back over the relay, and in side-copy mode the
model has a shell besides. So with a `proxy` section in the file the
handler never holds the key. Serve reads it once at start, from the first
line of `key_file`, keeps it in memory, and never puts it in the
environment of anything it runs or in a log. It runs a reverse proxy on
loopback, at `listen` (a port of the kernel's choosing by default; anything
but a loopback address is refused at `check`, since a proxy reachable off
the host is the key on the network), and forwards to `upstream` over TLS
with the system roots (`https://` unless the upstream is on this host too,
which the tests use).

For each invocation of the handler, serve draws a token — 32 bytes from the
kernel's randomness, 43 characters of base64url — and hands the handler two
variables and nothing else about the key:

```
ANTHROPIC_BASE_URL=http://127.0.0.1:PORT/TOKEN
ANTHROPIC_API_KEY=TOKEN
```

Claude Code appends `/v1/messages` and the rest to the base URL and sends
the key it was given in `x-api-key`, which is the placebo. The proxy takes
a request whose first path element is a live token, strips it, drops every
`x-api-key` and `authorization` header the request carried, sets
`x-api-key` to the real key, and forwards it, streaming the answer back as
it arrives, so a server-sent event passes chunk by chunk. A request with no
token, an unknown one or a dead one is `404` with one sentence and nothing
is forwarded.

The token is live from just before the handler starts until just after it
exits, and dies before the `after` hook runs, so the hooks never hold one.
The URL is worthless off the host, since the proxy is loopback, and
worthless after the invocation, since the token is dead. Serve is serial, so
one token is live at a time in the ordinary case; the proxy refuses to issue
a seventeenth.

Whatever serve inherited under `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`
or `ANTHROPIC_BASE_URL` — a unit still handing it the real key — is dropped
from every program's environment, and `check` says so by name.

The proxy logs requests, never contents: one line per request on serve's own
standard error with the token's first eight characters, the method, the path
after the token, the upstream's status, the bytes each way and the time
taken; a refusal logs the same with the reason (`no token`, `unknown
token`, `revoked token`); a mint and a revocation log the token's first
eight characters. No header, no body, no key.

`auu serve check` prints `proxy: key from PATH (N bytes), listen
127.0.0.1:0, upstream https://api.anthropic.com` — the key's size and
nothing else of it — and refuses a missing or empty key file, a listen off
the host, a plain-http upstream off the host, and a section that names
neither `key_file` nor `control`, each by name.

What one user id cannot protect, said plainly: with the proxy in-process,
serve and the handler run as the same account, so a file serve can read,
the handler can read. The proxy therefore keeps the key out of the
handler's environment, out of every reply, and out of anything a model does
with what it was given. It does not stop a handler with a shell that knows
the file's path and is told to `cat` it. Two things narrow that: the key
file's path is in `serve.json`, which the handler can also read, so the
defence is not obscurity; and the model's shell is only there in side-copy
mode. For a host where that is not enough, the proxy runs apart, as
another account, with the key out of the handler's reach altogether. That
is the split proxy below.

The outbound connection honours `HTTPS_PROXY` from serve's environment, as
a host behind a corporate proxy needs. The key travels inside TLS to
Anthropic whichever way the connection goes.

### The split proxy

`auu serve proxy [--config FILE]` is the same proxy as its own process,
meant to run as a second system account (`auu-proxy`) under its own unit,
with a file of its own — `/etc/auu-proxy/proxy.json` unless `--config`
names another — that holds the section's keys at the top level:

```json
{
  "v": 1,
  "key_file": "/etc/auu-proxy/key",
  "control": "/run/auu-proxy/control.sock",
  "listen": "127.0.0.1:0",
  "upstream": "https://api.anthropic.com",
  "allow_uids": [],
  "allow_group": ""
}
```

`key_file` and `control` are both required there, the key file readable by
the proxy's account alone. `listen` and `upstream` are as above. The
expert's `serve.json` then carries `"proxy": {"control":
"/run/auu-proxy/control.sock"}` and nothing else: not the key file's path,
not who may ask, so the handler, which can read that file, learns nothing
of the key from it. `key_file` beside `control` in the expert's file is
refused, as are `listen`, `upstream` and the allow keys, which belong to
the proxy's own file.

`control` is a Unix socket, mode 0660 in a directory 0750, on which a
caller asks for a token. Who may ask is decided by the kernel's own
account of the caller: its uid is in `allow_uids`, or its primary group is
`allow_group`, or that group is among the groups the account database
lists for it; with neither key set, the proxy's own primary group. Any
other caller is closed before a byte is read, and logged with its uid and
pid. Being able to reach the socket at all is the file mode's business.
The proxy gives the socket, and the directory when it is the proxy's, to
`allow_group` at start — the callers' group, never the proxy's, since a
caller put in the proxy's group could read the key file. The proxy's unit
puts it in the callers' group so that it may.

The protocol is one line each way, and `nc -U` speaks it: `PING` answers
`OK`. `MINT` answers `OK http://127.0.0.1:PORT/TOKEN`, and the token lives
for as long as that connection does. A `REVOKE TOKEN` on it ends it early,
and so does simply closing it, so a serve that dies mid-invocation takes
its token with it. A second `MINT` on one connection, or anything else, is
`ERR` and a close.

Every mint is logged on the proxy's own standard error with the caller's
uid and pid, and its requests and refusals are logged there too, in the
lines above. Serve's own log says only that it asked, and where.

The handler, being the same uid as serve, can also ask the socket for a
token. What that buys is more use of the same key, never the key.

`auu serve` with `control` set in its file asks the socket for a token per
invocation, on a connection it holds for the run and closes after, and
runs no proxy of its own. `auu serve check` then says `proxy: control PATH
(answering)`, or `(nobody is listening; auu serve will fail each message
until it is: ...)` with the dial's reason. A socket nobody answers on, or
one that refuses serve's uid, is the message's failure — `the proxy's
control socket PATH: ...` in the round's report and the ledger — tried
again next round like any other, and serve goes on.

`docs/creating-experts.md` section 7.6a is the account, the unit and the
file, end to end.

What the proxy does not do: it does not read or alter request or response
bodies, count tokens, or enforce a budget. A per-channel or per-day budget
from the `usage` fields of responses is a natural next plan and is named
here as one, not built. It does not serve anything but the token-prefixed
paths, and it does not do OAuth sign-in, Bedrock or Vertex: an expert behind
the proxy uses an API key. The two variables take precedence over an
interactive sign-in in Claude Code, so an expert signed in that way is
simply not given them, which is what a file without a `proxy` section does.
The wrapper reads nothing new; a channel whose handler is not Claude Code
sees the two variables and may ignore them.

## Serve cannot sandbox the handler

The handler runs as whoever runs serve, and `auu` finds its keys from the
home's path rather than from anything serve could withhold. So a handler
that runs `auu` speaks as the owner: it can send mail, read the whole spool,
and answer on any channel. A tool allow list in a wrapper is advice to one
particular program, not a boundary. If the expert must be contained, contain
it the way anything else is contained: a separate Unix account with its own
home and its own identity, or a container. Everything the expert can read,
it can be asked about. The peer list is the whole of the access control,
and anyone on it can ask anything.

Messages are data, not instructions. A handler that acts on what a message
tells it to do is a handler that does what the sender wants rather than what
its owner wants. A wrapper around an agent should say so to the model in as
many words, and tell it to stay inside the worktree whatever it is asked.
The wrapper this repository ships for Claude Code does both.
