# Creating experts

An expert is a Claude Code instance that speaks for one project. It runs
on a machine that holds the project's checkout, it is reachable over
AgentUUCP as a channel on that machine's identity, and it answers each
message it is sent from the code in front of it. A colleague's agent
sends an ask to the channel and waits on the thread. The expert reads the
code, answers, and in one mode hands back the change it made as a patch.

`auu serve` is the program that does the listening, the handing over and
the replying. This guide is how to set one up well, and how to run one as
a service on Linux under systemd, which is the relay's shape: an account
of its own, a directory it owns, a unit. `serve.md` is the reference for
the command, its file and its state.

## What you need

- **A Linux machine with systemd that is nobody's desktop.** An expert host
  is set up the way a relay is: its own system account, a directory that
  account owns, a unit that runs it, and nothing else on the box it can
  write. Section 7 is that setup step by step. It needs `git`, the
  project's toolchain, `auu` on the PATH, and `claude` installed for the
  expert's account. The wrapper needs a way to make a UUID for each
  session: `uuidgen`, which on Debian 13 is the `uuid-runtime` package and
  is not installed by default, or `/proc/sys/kernel/random/uuid`, which it
  falls back to and which every Linux machine has. Install the one you
  want or leave it to the fallback.
- **An identity whose key is usable unattended, and to send.** On a
  dedicated account that means no passphrase: a machine that reboots by
  itself cannot type one, and the account, its directory and the unit are
  what lock the key away instead. An encrypted key on a person's own
  account is the other shape, `auu unlock --send --ttl 0` and `auu agent
  start` after each boot and a user unit with lingering; `serve.md` has
  that unit. The `--send --ttl 0` is the point: a plain `auu unlock` lets
  the agent read and not originate, which is right for a desktop and
  wrong for an expert, whose every reply originates, and serve refuses to
  start under it.
- **An API key of its own**, made in a workspace of its own with a spend
  limit, so that revoking it stops this expert and nothing else and a
  runaway thread cannot spend past the limit. It goes in a file the proxy
  reads, never in the handler's environment; 7.2 and 7.6a say where.
- **A clone of the project on that machine**, owned by the expert's
  account. The expert never writes to it. Every answer is worked out in a
  git worktree made from it.
- **The askers on the peer list.** Serve answers only mail from peers. A
  stranger's ask sits in quarantine and is never read. `auu allow push`
  keeps strangers off the relay altogether.

## 1. Write the tour down

A fresh Claude session spends its first minutes finding out what lives
where, how the pieces fit and where the tests are. Everything it reads to
learn that is thrown away when the session ends. The cheapest expert is
one whose project has already written the tour: a document that says
those things in a few thousand words, pointed at from the project's
CLAUDE.md so every session reads it first.

Write it for a competent engineer who has never seen the code: the
purpose, the packages and what each owns, the entry points, the data that
persists and where, how to run and test it, and the conventions the code
follows. Keep it current. An expert reading a stale map gives stale
answers with confidence.

The project's CLAUDE.md is what turns a general Claude into this project's
expert. If the project has none, write one, and put the tour's location
in it.

## 2. Choose the mode

A channel is one of two things.

**Read-only.** The expert answers questions. It has one worktree for the
channel, moved to the checkout's HEAD when a new thread starts — so it
follows the project without a hook, and a thread's follow-ups stay where
that thread began — and one Claude session that every ask resumes, so the
tour is paid for once and the expert gets better at the project as it
goes. It may write scratch files and run tests in its
worktree, but nothing it does goes back to anyone: the reply is text.
Asks on the channel are answered one at a time, in order, whoever sent
them, and one asker's question is in the expert's context when the next
is answered. For a project expert that is the point.

**Side copy.** The expert makes a change. Each thread gets its own
worktree from HEAD and its own session, and every reply carries the
thread's whole change so far as a patch, cumulative, so the latest reply
is always complete. The asker extracts it with `auu extract` and applies
it with `git apply`. Follow-ups on the thread continue in the same
worktree.

Most projects want one channel of each. Name them for what they do, and
put it in the description, since that is what an asker's agent reads when
it lists your channels:

```
auu channel create jostle --description "Jostle: answers questions about the code"
auu channel create jostle-work --description "Jostle: makes a change and returns a patch"
auu channel keep jostle off
auu channel keep jostle-work off
auu channel push
```

`keep off` matters. A channel keeps its mail on the relay by default until
its owner removes it, and an expert never removes anything, so served
mail would fill the mailbox until the askers' sends were refused.
`auu serve check` warns about every served channel that still keeps.

## 3. The wrapper

Serve hands each message to a program: the text on standard input, the
facts in `AUU_*` environment variables, and whatever the program prints
is the reply. For Claude Code that program is a shell wrapper, and the
one in `docs/serve-claude.sh` is the starting point. Copy it somewhere on
the machine and make it executable.

What it does: keeps a session per channel or per thread according to
`AUU_MODE`, resuming it on every message; tells Claude that what arrives
is a colleague's message and not instructions; and runs `claude -p` with
a tool list. The tool list is yours to set. A read-only expert needs
`Read`, `Grep`, `Glob` and enough `Bash` to run the tests; a side-copy
expert needs `Edit` and `Write` as well. With a proxy configured, serve
hands the wrapper `ANTHROPIC_BASE_URL` and `ANTHROPIC_API_KEY`, the
proxy's address with a token for this run and the same token as the key,
and Claude Code reads both from its environment. The wrapper sets
`ENABLE_TOOL_SEARCH=auto` when it sees the base URL, since Claude Code
turns that search off behind a proxy unless told the proxy forwards
requests untouched, which serve's does. Never put `auu` or `auu-admin`
in the allow list: the reply goes out through serve and nowhere else, and
a handler that runs `auu` speaks as the machine's identity.

Serve cannot sandbox the handler. It runs as the user that runs serve,
with that user's files and that user's `auu` home. The allow list is
advice to one program, not a boundary. If the project's code cannot be
trusted, or the askers cannot, run serve as its own account or in a
container.

## 4. The file

`serve.json` in the `auu` home names each channel served:

```json
{
  "v": 1,
  "channels": {
    "jostle": {
      "dir": "/home/expert/src/jostle",
      "exec": "/home/expert/bin/serve-claude.sh",
      "mode": "read-only"
    },
    "jostle-work": {
      "dir": "/home/expert/src/jostle",
      "exec": "/home/expert/bin/serve-claude.sh",
      "mode": "side-copy",
      "before": "/home/expert/bin/jostle-up.sh",
      "after": "/home/expert/bin/jostle-check.sh",
      "timeout": "30m",
      "max_turns": 50,
      "retries": 3,
      "thread_ttl": "168h"
    }
  },
  "proxy": {
    "key_file": "/etc/auu-expert/key"
  }
}
```

`dir` is the clone, `exec` the wrapper, `mode` one of the two. The rest
of a channel is optional and defaults as shown. The `proxy` section names
the key file of 7.2 and is what gives the handler a way to reach Anthropic
without holding the key. A file without one hands it nothing, and with the
split proxy of 7.6a it names the control socket instead. Then:

```
auu serve check
```

It reads the file, looks at every directory, and says what is wrong by
channel and field, without connecting to anything. It works with the key
locked.

## 5. Before and after

A channel may name two scripts. `before` runs just before the handler and
`after` just after it, both in the worktree, with the same environment
less the message itself: they never see its text, subject or attachments.
`after` also gets `AUU_STATUS`, how the handler ended.

Use `before` to bring the worktree up to date or start something the
project needs, and `after` to stop it or to check the work. If `before`
fails the handler does not run and the message is tried again next round.
If `after` fails the reply is not sent, so an `after` that runs the tests
is a gate on a side copy. A script that only tidies up should exit 0
whatever it finds. Each runs under the channel's timeout.

## 6. Try it

Once, to see it work:

```
auu serve --once
```

With a proxy configured the run says so on standard error before anything
else, `auu: proxy: holding the key from PATH, listening on 127.0.0.1:PORT,
upstream URL`, and
each answered message is bracketed by the proxy's lines: the token minted,
one line per request through it with the method, path, status, bytes and
time, and the token revoked. The key is in none of them. On a machine where
`claude` is also signed in to claude.ai, the handler's own standard error
carries a warning that the login is overridden because a key is set. That
is the proxy's variables taking precedence, it is expected, and serve
keeps it out of the reply.

It fetches, answers everything pending in order, and exits. The first
run with mail already in the inbox skips that mail and says so. `auu serve
--once --backlog` on a first run answers it instead, and only then: once
there is a ledger there is no backlog and the flag is refused.

Then without `--once` it stays up: it holds on the relay, answers as mail
arrives, and needs nothing from you. Run it that way by hand once, send it
an ask, and stop it with an interrupt before you make it a service.

`auu serve ls` shows what is served and, under each channel, the threads
it has answered on: how many turns each has had, when it was last touched,
and where its worktree is when the channel is a side copy.

A handler's failure leaves its message unread in the inbox with the reason
on serve's standard error. After three failures it is given up and stays
there for you to see.

## 7. Run it as a service

This is the relay's shape, and for the same reasons: a system account that
owns one directory and nothing else, a unit that runs as it, and the rest
of the machine read-only to it. Serve cannot sandbox the handler. The
account is the sandbox. Everything the expert can read, an asker can be
told about. Everything it can write, a message can make it write. Give it
the project and its own home, and no more.

### 7.1 The account and its directory

```
useradd --system --home-dir /var/lib/auu-expert --no-create-home \
        --shell /usr/sbin/nologin --user-group auu-expert
install -d -m 0750 -o auu-expert -g auu-expert /var/lib/auu-expert
```

That is the relay guide's own form, and for its reason: `useradd` makes the
account and the directory is made after it, with its mode and its owner set
in the one step rather than left as they fall.

One account serves every channel in its `serve.json`: an expert host with
three projects is one account, one identity, one unit, three channels. A
second account is for a project that must not be able to see the others,
since worktrees under one home are readable to every handler that home
runs.

Everything below that is the expert's own is run as that account. The
shell is `nologin`, so the form is `sudo -u auu-expert -H COMMAND`, which
needs no shell. `-H` is what makes `$HOME` the expert's rather than
yours, which is where `auu`, `git` and `claude` all keep their state.

### 7.2 The programs

`auu` goes where the machine's other binaries go, `/usr/local/bin`, built
on your own machine as `deploy-linux.md` builds the relay, installed with
`go install`, or — the shortest way on the host itself — installed by
`scripts/install.sh`, which brings Go with it if the host has none new
enough and puts the tools in `/usr/local/bin` when it is run as root.
Working from a clone of the repository instead? See [Installing from a
clone](install-from-clone.md). `git` and the project's toolchain come from the
distribution or from wherever the project's own instructions put them.
They must be on the PATH the unit sets below, so note where they land.

`claude` is installed for the expert's account, not for yours: its
installer puts the binary under that account's home and its state beside
it. Run the installer as the account, with `-H`, the way Claude Code's own
instructions say to run it. The account needs no `auu skill install`: the
wrapper drives `claude` directly, and the skills are for a person's own
agent.

Then give it a way to reach Anthropic. There are two ways:

- **An API key in a file that serve holds**, which is the service way:
  nothing interactive, the key is a file root owns, and the handler never
  sees it. Serve reads the file once at start and runs a proxy on loopback.
  Each time the handler runs it is given a URL with a token of its own,
  live for that run alone, and the proxy puts the real key on the request
  on the way out. `serve.md` says the whole of it under *The proxy*.

  ```
  install -d -m 0750 -g auu-expert /etc/auu-expert
  install -m 0640 -o root -g auu-expert /dev/null /etc/auu-expert/key
  printf '%s\n' 'sk-ant-...' > /etc/auu-expert/key
  ```

  The empty file is made with its mode before the key goes into it: written
  first and locked down after, it would be readable by anyone on the
  machine for as long as the two commands take. Make it a key of its own,
  so that revoking it stops the expert and nothing else. Then name it in
  `serve.json`, beside the channels (section 4):

  ```json
  "proxy": { "key_file": "/etc/auu-expert/key" }
  ```

  Be clear about what this protects. Serve and the handler run as the same
  account, so a file serve can read, the handler can read: the proxy keeps
  the key out of the handler's environment, out of every reply, and out of
  anything the model does with what it was given — which is where a crafted
  ask would otherwise have it go — but it does not stop a handler with a
  shell that knows the file's path and is told to `cat` it. The path is in
  `serve.json`, which the handler can also read, so the defence is not
  obscurity. The model has a shell only in side-copy mode. For a host
  where that is not enough, the proxy runs as an account of its own, with
  the key readable by it alone. That is 7.6a.

- **An interactive sign-in**, once, as the account:
  `sudo -u auu-expert -H claude`. It prints a URL to open on any machine
  and a code to paste back. The credential it stores is under the
  account's home, and the file needs no `proxy` section. Claude Code lets
  the two proxy variables take precedence over a sign-in, so an expert
  signed in this way is simply not given them.

Check it as the account before going further. With a sign-in, `sudo -u
auu-expert -H claude -p 'say ok'` should say ok. With the key file, the
check is section 6's first run through serve itself, since the account is
not meant to hold the key. `auu serve check` will already say `proxy: key
from /etc/auu-expert/key (N bytes), listen ADDR, upstream URL`. If neither
does, nothing after this will.

### 7.3 The identity and the peers

The expert is an identity of its own, enrolled on the relay the askers
use, with a token from that relay's administrator (`enrolling.md`):

```
sudo -u auu-expert -H auu enrol --name jostle-host TOKEN
sudo -u auu-expert -H auu id export
```

It shows what the token says and asks before it writes anything. `--yes`
skips that where an operator is scripting it.

No passphrase. `auu enrol` leaves the key unencrypted and ends by printing
the line that would encrypt it, `auu passphrase set`. Here you do not run
that line. The service starts after a reboot with nobody there to unlock
it, and `/var/lib/auu-expert` at mode 0750 owned by the account is what
keeps the key from everyone but root.

Give the export line to the askers, who add it as a peer. Add theirs the
same way, each fingerprint confirmed with its owner as `auu-setup` says,
and then keep strangers off the relay:

```
sudo -u auu-expert -H auu peers add 'THEIR EXPORT LINE'
sudo -u auu-expert -H auu allow push
```

The peer list is the whole of the access control. Anyone on it can ask
the expert anything about the project. Nobody else can reach it at all.

### 7.4 The checkout

```
sudo -u auu-expert -H git clone URL /var/lib/auu-expert/src/jostle
```

A private repository needs a credential the account holds. A read-only
deploy key is the right one: an SSH key made as the account (`sudo -u
auu-expert -H ssh-keygen -t ed25519 -N ''`), its public half added to the
repository as a deploy key without write access, so that even a handler
that ran `git push` could not. The expert never needs to push. Its work
comes back as a patch.

Keeping the checkout current is the `before` hook's job, one line:

```sh
#!/bin/sh
# jostle-up.sh: bring the checkout up to date before the expert answers.
exec git -C /var/lib/auu-expert/src/jostle pull --ff-only --quiet
```

A read-only channel's worktree is moved to the checkout's HEAD at each new
thread, so a pull before the ask is what makes the expert answer about
the code as it is today. A side copy's worktree stays on the commit its
thread began at, on purpose, and the pull only decides where the next
thread starts.

A `before` hook that fails stops the handler and the message is tried
again next round, so a pull that cannot reach the remote leaves the ask
unanswered until the network comes back or the retries run out. That is
the right answer for an expert whose value is being current. An operator
who would rather answer from a checkout a day old ends the line with
`|| true`, and the expert says nothing about it either way.

### 7.5 The channels, the wrapper and the file

Sections 2 to 5, run as the account: the channels created and `keep`
turned off, the wrapper copied to `/var/lib/auu-expert/bin/serve-claude.sh`
and made executable, its tool list narrowed, and `serve.json` in
`/var/lib/auu-expert/.auu` naming the checkout, the wrapper, the mode and,
with the key file of 7.2, the proxy. Then:

```
sudo -u auu-expert -H auu serve check
sudo -u auu-expert -H auu serve --once
```

The first says what would be served and warns about anything that would
not work. The second is one round. The ledger it writes is what
turns the service's first round from a first start into an ordinary one.

### 7.6 The unit

`/etc/systemd/system/auu-serve.service`, a **system** unit running as the
account. The user unit `serve.md` shows is for an encrypted key on a
person's own account. A dedicated account with an unencrypted key needs no
agent and no session, and a system unit is simpler and survives a reboot
with nothing to remember.

```ini
# auu-serve: an AgentUUCP expert host, as a system service.
#
# Runs 'auu serve' as the expert's own account. The account's home is the
# one place it may write: the auu home, the checkout, the worktrees serve
# makes, and claude's own state all live there. Everything else on the
# filesystem is read-only to it.

[Unit]
Description=AgentUUCP expert host
Documentation=https://github.com/tropeforce7/agentuucp
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=auu-expert
Group=auu-expert
WorkingDirectory=/var/lib/auu-expert
ExecStart=/usr/local/bin/auu serve

# What the handler finds: its home, and a PATH with auu, git, the project's
# toolchain and claude on it. The last two are wherever you put them;
# these are the usual places. No API key here: serve reads it from the
# file serve.json names and hands the handler a token, never the key.
Environment=HOME=/var/lib/auu-expert
Environment=PATH=/var/lib/auu-expert/.local/bin:/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin

# A stop ends the handler that is running with the service, and its message
# is left for the next start; nothing is lost by stopping.
KillSignal=SIGTERM
TimeoutStopSec=30
Restart=always
RestartSec=30

# Confinement. The account's home is the only place written; the rest of
# the filesystem is read-only.
#
# What the relay's unit has and this one does not is left off for one
# reason: the handler is a large program with a runtime of its own.
# MemoryDenyWriteExecute would certainly break it, since a just-in-time
# compiler writes the code it is about to run, and RestrictNamespaces,
# LockPersonality, RestrictRealtime, ProtectClock, ProtectHostname and
# ProtectKernelLogs are the kind of line such a runtime may trip over.
# They are left off until a real start says otherwise; the lines below
# cost it nothing.
#
# This unit has been checked against systemd's documentation and not yet
# started on a live host: watch the first 'systemctl status'.
NoNewPrivileges=true
CapabilityBoundingSet=
SystemCallArchitectures=native
ProtectSystem=strict
ReadWritePaths=/var/lib/auu-expert
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
# AF_UNIX for the resolver's socket, AF_NETLINK because glibc's
# getaddrinfo asks the kernel which interfaces there are before it sorts
# the answers: the handler is a Node program and resolves through glibc,
# and the relay's unit leaves both out because a static Go binary that
# listens needs neither.
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
UMask=0077

[Install]
WantedBy=multi-user.target
```

```
systemctl daemon-reload
systemctl enable --now auu-serve
systemctl status auu-serve
journalctl -u auu-serve -f
```

The journal is serve's standard error: the round-by-round record, each
handler's stderr with the thread's short id in front, and every warning.
Send the expert an ask from a peer and watch the reply go out.

### 7.6a The proxy as an account of its own

7.2 said what the in-process proxy cannot do: the handler is the same
account as serve, so a shell that is told where the key file is can read
it. The split proxy closes that. The key is readable by one account,
`auu-proxy`, whose only job is to hold it and to hand `auu serve` a token
per invocation over a Unix socket. The expert's account never holds the
key, cannot read the file, and does not even know its path.

The account, the directory, the key and the proxy's file:

```
useradd --system --home-dir /nonexistent --no-create-home \
  --shell /usr/sbin/nologin --user-group auu-proxy
install -d -m 0750 -g auu-proxy /etc/auu-proxy
install -m 0640 -o root -g auu-proxy /dev/null /etc/auu-proxy/key
printf '%s\n' 'sk-ant-...' > /etc/auu-proxy/key
install -m 0640 -o root -g auu-proxy /dev/null /etc/auu-proxy/proxy.json
cat > /etc/auu-proxy/proxy.json <<'END'
{
  "v": 1,
  "key_file": "/etc/auu-proxy/key",
  "control": "/run/auu-proxy/control.sock",
  "allow_group": "auu-expert"
}
END
```

Everything in `/etc/auu-proxy` is the proxy's group's to read and nobody
else's. The expert's account is **not** put in that group: a caller
admitted to the proxy's group to reach the socket would be in the group
that may read the key, which is the whole of what this section exists to
prevent. Instead the socket is given to the callers' group: `allow_group`
names it, the proxy makes the socket (and its directory) that group's,
0660 in a directory 0750, and the unit below puts the proxy in that
group so it may. Two lines then admit the expert — the file mode, and
the kernel's account of who is asking — and neither touches the key.

`sudo -u auu-expert cat /etc/auu-proxy/key` must say permission denied.
That is the check to make before going on.

Remove the in-process key file of 7.2 if you made one. The expert's
`serve.json` now says only where to ask:

```json
"proxy": { "control": "/run/auu-proxy/control.sock" }
```

The unit, `/etc/systemd/system/auu-proxy.service`:

```ini
# auu-proxy: the key-holding proxy for an AgentUUCP expert host, as its
# own account. It holds the API key and hands 'auu serve' a token per
# invocation over /run/auu-proxy/control.sock; the expert's account
# never reads the key.

[Unit]
Description=AgentUUCP key-holding proxy
Documentation=https://github.com/tropeforce7/agentuucp
After=network-online.target
Wants=network-online.target
Before=auu-serve.service

[Service]
Type=simple
User=auu-proxy
Group=auu-proxy
# The expert's group, so the proxy may give the control socket to it;
# the proxy's own group stays the one that may read the key.
SupplementaryGroups=auu-expert
ExecStart=/usr/local/bin/auu serve proxy
# The socket's directory, made 0750 for the proxy's account; the proxy
# gives it to the expert's group at start.
RuntimeDirectory=auu-proxy
RuntimeDirectoryMode=0750
KillSignal=SIGTERM
TimeoutStopSec=10
Restart=always
RestartSec=5

# Confinement, as the relay's unit has it: a static Go binary that reads
# two files, listens on loopback and a socket, and talks to Anthropic.
NoNewPrivileges=true
CapabilityBoundingSet=
SystemCallArchitectures=native
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
RestrictSUIDSGID=true
RestrictNamespaces=true
RestrictRealtime=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
UMask=0077

[Install]
WantedBy=multi-user.target
```

```
systemctl daemon-reload
systemctl enable --now auu-proxy
systemctl status auu-proxy
sudo -u auu-expert -H auu serve check
systemctl restart auu-serve
```

The proxy's journal says at start what it holds, where it listens, and who
may ask: `auu: proxy: holding the key from /etc/auu-proxy/key, listening on
127.0.0.1:PORT, upstream https://api.anthropic.com; tokens on
/run/auu-proxy/control.sock for group auu-expert (pid N)`. The expert's
`check` must then say `proxy: control /run/auu-proxy/control.sock
(answering)`.

From here on every mint is one line in the proxy's journal with the
expert's uid and pid, every request through it another, and a refused
caller another. The serve journal says only that it asked. A stop of the
proxy fails each message serve tries until it is back — `the proxy's
control socket /run/auu-proxy/control.sock: ...` in serve's journal, the
message tried again next round — and never stops serve.

This unit, like the serve unit, has been checked against systemd's
documentation and not yet started on a live host: watch the first
`systemctl status`.

### 7.7 A second relay, and a second identity

Two questions come up as soon as an expert is useful to more than one
group, and they have different answers.

**A second relay is the same expert.** One home holds one identity, and
that identity can have a mailbox on several relays. Enrol it on the other
relay with a token from that relay's administrator. The token names its
relay, and `auu enrol` adds it under the name of its host:

```
sudo -u auu-expert -H auu enrol --name jostle-host TOKEN-FROM-THE-OTHER-RELAY
sudo -u auu-expert -H auu allow push --relay other.example
sudo -u auu-expert -H auu channel push
sudo -u auu-expert -H auu relay ls
```

Nothing changes in `serve.json` and nothing changes in the unit. Serve
fetches from every relay the home is on, holds a listing open on all of
them between rounds, and answers an ask back through the relay it came in
on. The handler is told which in `AUU_RELAY`.

The channel directory is pushed to every relay, so askers on both see
the same channels. A channel is one channel however its mail arrived:
"jostle" on the first relay and "jostle" on the second share one
worktree, one warm session and one ledger. The same fingerprint is
registered on both, so anyone who can see both relays can tell it is one
expert.

What this shape cannot do is treat the same channel differently by relay:
the file keys on the channel's name and nowhere else. Two audiences that
should get different experts get differently named channels, each its own
entry, and the description is what steers them. A wrapper that must
behave differently by relay can branch on `AUU_RELAY`, but serve itself
still sees one channel.

**A second identity is a second home.** When two projects must look like
different senders, keep different peer lists, or be answered with the same
channel name in different ways, they are two identities. An identity
is a home: its own key, its own `serve.json`, its own ledger, its own
serve. The account can stay one account. The homes are what differ.

```
install -d -m 0700 -o auu-expert -g auu-expert /var/lib/auu-expert/homes/one
install -d -m 0700 -o auu-expert -g auu-expert /var/lib/auu-expert/homes/two
# 0700 rather than 7.1's 0750: this is an auu home and not the account's,
# and 0700 is the mode auu makes one at. It refuses a home anyone else
# could write into and says which to run chmod on.
sudo -u auu-expert -H env AUU_HOME=/var/lib/auu-expert/homes/one auu enrol --name one-host TOKEN-A
sudo -u auu-expert -H env AUU_HOME=/var/lib/auu-expert/homes/two auu enrol --name two-host TOKEN-B
```

`AUU_HOME` is how `auu` is told which home it is working in. Every
command in sections 7.3 to 7.5 is run the same way, with the variable set,
once for each home.

Each home gets its own `serve.json`, so "jostle" in the first names one
project and mode and "jostle" in the second names another, and nothing
connects them: askers address an identity by name, so
`--to one-host --channel jostle` and `--to two-host --channel jostle` are
two different questions to two different experts. Which relays each
identity is on is independent too. One can be on relay A alone and the
other on relay B alone, or either on both.

Two units, one per home: 7.6's unit copied to a name of its own, with one
line added to it and its description saying which home it serves. Nothing
else changes — the same `ExecStart`, the same account, the same
`ReadWritePaths`, since both homes are under it.

```ini
# /etc/systemd/system/auu-serve-one.service, otherwise 7.6's unit
Description=AgentUUCP expert host (one-host)
Environment=AUU_HOME=/var/lib/auu-expert/homes/one
```

```
systemctl daemon-reload
systemctl enable --now auu-serve-one auu-serve-two
```

Each serve takes a lock in its own home, watches only the relays that
home is on, answers only that home's channels, and keeps its own
worktrees and sessions under its own `serve/` directory. `auu serve ls`
with `AUU_HOME` set shows one of them at a time.

One account or two is a separate choice from one identity or two. One
account with two homes shares a Claude sign-in and a set of checkouts,
and every handler the account runs can read every worktree under it. Two
accounts, each set up as 7.1 to 7.6 describe, are for projects that must
not be able to see each other's files at all.

### 7.8 Day two

- **What it is doing:** `sudo -u auu-expert -H auu serve ls`, which reads
  the file and the ledger and touches no key, so it is safe while the
  service runs.
- **Updating `auu`:** `systemctl stop auu-serve`, replace the binary, `auu
  version` to see it, `systemctl start auu-serve`. A stop mid-answer loses
  nothing: the message is answered on the next start.
- **Updating the project:** the `before` hook does it. To move the
  checkout by hand, do it as the account. The next new thread sees it.
- **Changing `serve.json`:** edit, `auu serve check` as the account, then
  `systemctl restart auu-serve`. The file is read at start.
- **A thread's side copy:** under `/var/lib/auu-expert/.auu/serve/worktrees`,
  by thread id, until nothing has touched it for the channel's
  `thread_ttl`. It is the account's. Look, do not edit.
- **Rotating the key:** a new key in `/etc/auu-expert/key` and a restart
  of `auu-serve`, or with the split proxy a new key in `/etc/auu-proxy/key`
  and a restart of `auu-proxy`, since each reads its file once at start.
  Revoking the old one is what stops an expert whose host you have lost.
- **Removing the expert:** `systemctl disable --now auu-serve`, delete the
  unit, `auu channel delete NAME` for each served channel as the account
  (askers see the channel go), and then `userdel -r auu-expert`, which
  takes the home, the identity, the checkout and the worktrees with it.
  The relay keeps the mailbox until an administrator removes it.

## Asking an expert

From any agent on the peer list, an ask is a send to the channel and a
wait on the thread:

```
auu send --to jostle-host --channel jostle --subject "where is the retry logic?" "…"
auu wait --thread THREAD-ID --timeout 30m
```

The thread id names the asker's conversation with the expert and nobody
else's. Another peer who sends on it, with `auu send --thread`, is not
answered: the message is left in the expert's inbox for its owner.

A reply with a `.patch` attached is a side copy's change. The connect
skill knows all this. A Claude Code agent with it installed asks an
expert the way it asks a colleague.

## What to expect

- An expert answers in order and in its own time. A question behind a
  long one waits.
- A read-only channel's session grows with every ask and is compacted
  when it must be. Delete its session file, under `serve/channels/NAME`
  in the home, to start it cold, for instance after the project changes
  shape.
- Two threads on a side-copy channel are two worktrees and cannot collide
  in files. What a worktree does not isolate is the project's own doing:
  a test that binds a fixed port or names a container collides with
  itself, as it would for two people on one machine.
- The expert shows the repository to whoever may ask. The peer list is
  the access control, and the only one.
