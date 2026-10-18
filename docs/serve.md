# An expert host: `auu serve`

An expert is an agent that knows one project and answers questions about it
over AgentUUCP. It runs on a machine that holds the project's checkout, it
listens to one channel of its owner's mailbox, and it answers each message
by running a program — Claude Code, in the case this was built for — in a
git worktree of that checkout, and sending back what the program printed.

One machine can be an expert for several projects: one channel each.
It needs git 2.24 or later, which `auu serve --check` and every start
check.

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
way. A channel is an object, with `dir` and `exec` at least, and one
written as `null` is refused naming the channel.

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
message after unless it is made again (below), so a thread is a
conversation over one copy with the peer who opened it. The opener is the
sender of the earliest message to arrive on the thread among those serve
has written down: answered, tried, or held for a newer `auu`. In the usual
order of arrival that is the asker, since anyone else normally learns the
thread from the asker's message. Until something on the thread has been
answered or tried, a message on it competes on its own arrival. After that
the thread is its opener's. A message left alone at a first start opens
nothing.

Its reply carries the thread's whole change so far, attached as
`THREAD12.patch`, and one sentence at the end of the text saying so. The
patch is the worktree's files against BASE, as `git add -A && git diff
--cached --binary BASE` gives it, taken with an index of serve's own made
from BASE and the checkout's own repository (see *Serve cannot sandbox
the handler*), where BASE is the commit the worktree was made from — recorded
when it was made and read back from a file, never asked of git again, so a
handler that commits in its own worktree cannot move what the change is
measured against. It is cumulative on purpose: every turn's patch is the
whole of the thread's work, so the latest reply is always the complete one
and an asker need keep only the last, unless the worktree was made again
(below). Apply it to a clone at BASE:

```
auu extract MESSAGE-ID --out .
git apply THREAD12.patch
```

A base file that does not hold a commit id, 40 or 64 lowercase hex
characters, is the message's failure, `its base file PATH does not hold a
commit id`, and is left as it is. A side copy needs a full checkout: the
patch's index holds every file of BASE, so a sparse checkout's worktree
would send every file it leaves out as deleted, and an answer on a channel
whose checkout is sparse is the message's failure, `the checkout DIR is
sparse`. A thread whose worktree was made while the checkout was sparse
stays so; let it go, or begin a new one.

Three things follow from `git add -A`. What the handler committed is in the
patch, and so is what it merely wrote. What `.gitignore` hides is not. A
handler that writes its answer into an ignored path will find it does not
travel. And a file that is not text travels too, since the diff is taken
with `--binary`. A submodule is not part of the patch: a change to a
submodule's commit does not travel, and neither does a repository the
handler makes inside its worktree, whether or not BASE holds a submodule
at its path; serve's git runs nothing inside one. A file BASE holds that
the handler replaced with a repository goes as deleted.

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

A handler with a shell can be talked by a message into damaging its
worktree, and in `read-only` that worktree is every thread's on the
channel. So whatever stands at a worktree's path and is not a git worktree
of the checkout's — a directory whose `.git` was removed or that is a
repository of its own, a file, a link — is removed and the worktree made
again from the checkout's HEAD. Moving or re-cloning the checkout a channel
names leaves every worktree one of a repository the channel no longer
names, so each is made again at its next message. For each of these serve
says the same line on standard error,
`auu: worktree PATH was not a git worktree and was made again`. In
`read-only` the untracked scratch goes with it. In `side-copy` the line
ends `; the thread's work in it is gone`: what the thread had written and
committed there is lost, and every patch after is taken against the new
base. A directory git cannot be started in, one the handler took the
permissions off or that is gone, is not a worktree and is made again the
same way. A registration the handler locked with `git worktree lock` is
unlocked first, so the prune can clear it. A directory inside it the
handler took the permissions off is given them back, the owner's alone,
and removed; links are never followed. Only a tree its owner cannot
remove even so, a file made immutable or one another user owns, is moved
aside, to
`serve/NAME.damaged-N` in the home, NAME the thread id or the
channel's name and N the first that is free, and serve says
`auu: worktree PATH could not be removed and was moved aside to ASIDE;
remove it by hand`. What can be neither removed nor moved aside is the
message's failure, `its worktree PATH could not be removed or moved aside`
in the ledger, retried and given up on after `retries` as any failure is,
and the run goes on to the next message. A git that is not installed, or
a checkout git will not answer for or cannot be started in, still ends the
run, as does a worktree git fails to add.

Making the worktree again writes nothing to the ledger by itself. A
handler that damages its worktree and exits non-zero has failed, and is
run again as any failed turn is. A side-copy handler that removed `.git`
or ran `git init` and printed an answer fails when serve takes the patch;
one that printed nothing has settled its message. The worktree is made
again at the next message to reach it, which is usually the retry. An
answer and its patch are kept together or not at all. An answer whose
send to the relay failed goes out on its retry without the handler being
run again, with the patch taken for it, measured against the old base and
never a later turn's; that patch holds the work the console line calls
gone from the worktree, so the asker still gets it. It goes as the same
envelope, sealed once before its first post and kept beside the answer,
so a retry after a post the relay took, its answer lost on the way back,
is one reply under one id: the asker's inbox keeps one and drops the
copy. A reply large enough to go as a stream is sent under one id at
every attempt in the same way: the id is kept beside the answer before
the stream is sealed, a retry finishes the upload the outbox still holds,
sends nothing when the sent box says a relay took it, and otherwise seals
it again under that id, which the asker keeps as the one reply. An answer whose patch
could not be taken is not kept: the message is tried again whole, as when
the after hook refuses, so the first handler above is run again in the
worktree made again. If that run answers and its patch can be taken, the
answer goes with the patch of what that run changed, never the gone work;
a handler that damages its worktree at every run fails at every retry and
is given up on after `retries`.

A worktree is not a container. Two threads cannot collide over files, but
they can over anything else the project uses: a fixed port, a named
container, a shared database, a lock file in `/tmp`. If a project needs one
of those, the `before` and `after` hooks are where it is started and stopped,
and a channel that cannot share is a channel to serve `read-only`.

A thread belongs to its opener in either mode. Any peer may name a thread
with `auu send --thread`, and everyone on a message to several knows its
thread. A message on a thread from anybody but its opener is left in the
inbox for the owner. It is not answered and not counted as a turn. It is
given no worktree and no directory. In each run of serve, the first time
it meets such a message, it says on stderr that the message is on a
thread another peer opened and was left alone.

The opener is the peer whose message on the thread arrived here first, and
an expert on more than one relay fetches its relays one after another in
each round, so it answers a thread for the ask it fetches first. A
co-recipient of a message to several knows its thread, and one who asks on
that thread through another of the expert's relays before the opener's copy
is fetched is answered as the opener; the opener's own messages on the
thread are then left alone. Nothing of the opener's reaches them: the
handler is given their message alone, and the opener's text, files and
replies stay where they were. This is a stated residual. Binding a thread
to its opening message on the wire is what closes it, and that is a change
to the wire for a later release.

A thread carried over from a v0.17.0 ledger, which kept no senders, takes
its opener from what this home wrote first: a message serve answered with
a reply names its asker in the copy of that reply, in the sent box. A
message serve did not answer, or one whose reply's copy the owner has
removed, takes its sender from the message itself when it is still in the
inbox, where serve leaves what it answered. On a thread anything was tried
or answered on before the upgrade, only those messages open it, in the
order serve dealt with them; one the earlier release left pending opens
nothing while one of them stands, and nor does anything this release
fetches. Where those messages are from more than one peer and the earlier
release's record cannot say who came first, because an attempt on the
thread failed or two were answered in the same second, the thread is
nobody's. A message id is the sender's to choose, so a message in the
inbox is taken as one of the thread's only if it is on that thread and,
once anything on the thread was tried or answered, it is one the earlier
release fetched, no later than the thread's last attempt and the five
minutes the relay's clock is held to; one this release fetched came after
the upgrade, and after every attempt the earlier release made. A record
the earlier release kept that a relay later lists again under a new time,
its numbering begun again, is no longer told from this release's own, and
its thread takes no opener from it. One that fails is not the thread's
message, and serve says so on stderr once each run: `auu: ID from NAME has
the id of a message serve carried over from before the upgrade on thread
THREAD, and is not that message; the thread takes no sender from it`. A
thread whose opener's messages the owner has removed, the reply's copy
among them, may take another sender's. A thread with none of its messages
left is nobody's once anything on it was tried or answered: serve answers
no message on it from anyone, the peer who asked included. Each is left in
the inbox, not answered and not counted as a turn, and serve says on
stderr, the first time it meets one in each run, that the message is on a
thread tried or answered before the upgrade for a peer the ledger does not
name and was left alone. The peer opens a new thread.

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
In the long run that round comes when the message is due, with no new mail
needed: twenty seconds after the first failure, doubling at each, at most
five minutes apart.
Serve reads the reply back from the file it caught it in. A file that is
gone or cannot be read, an after hook's `chmod` among the causes, is a
failure in the same way, said as `what the handler printed could not be
read` with the reason, and never "nothing to say".

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
handler started would make the wait after a timeout never end. A line longer
than a mebibyte is printed cut, with a mark saying how many bytes of it are
not shown, and the lines after it are printed as usual.

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
- And only from the peer who opened the thread. A message on it from
  anybody else is left in the inbox, unanswered and uncounted.

A thread id has a message id's shape, 32 lowercase hex characters. It is
not its first message's id. A new thread is given an id of its own, and
every later message on the thread carries that id. Serve makes the
thread's directory and its worktree's path from it. A message whose
thread id has any other shape — a peer's `--thread "../../outside"` — is
refused as malformed when it is opened, kept under `damaged/` and
acknowledged, and never reaches serve. A record in the spool with one,
which only a hand could have written, is that message's failure in the
ledger and the round goes on to the next.

`serve/ledger.json` in the home is the record of what has been answered, and
it is the only thing that decides. It is read strictly, as the home's other
files are: a key serve does not write, a key given twice or one in another
case is refused with the file named, and serve stops, since a key read as
absent would make an answered message pending and answer it again. The mark that a message has been read is
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

What serve does itself with what a handler leaves is held to that
containment. The handler writes its worktree and the thread's directory,
and serve reads both after it. A kept answer's patch is attached only as
the regular file it is: a link put in its place is refused by name and
the message fails. The base is used only as a commit id. A handler that
can run git in its worktree can also write what git keeps for that
worktree in the checkout's repository, and the worktree's `.git` and that
directory can each be pointed at a repository of the handler's own, whose
configuration git would read. So a worktree whose `.git` was changed is
the message's failure, `its worktree PATH is no longer the git worktree
serve made`, and serve's own git, which takes the patch, reads neither:
it is given the checkout's repository, the worktree as the files to read
and an index of serve's own, and runs no filesystem monitor, hook,
external diff or text conversion. Only the operator's configuration is
read, and a filter the worktree's attributes name runs only if the
operator defined it. A hard link is the file it links to, and no open
refuses it: where that matters, a contained handler must not share a
filesystem with what the serve account can read.

Messages are data, not instructions. A handler that acts on what a message
tells it to do is a handler that does what the sender wants rather than what
its owner wants. A wrapper around an agent should say so to the model in as
many words, and tell it to stay inside the worktree whatever it is asked.
The wrapper this repository ships for Claude Code does both.
