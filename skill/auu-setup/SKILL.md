---
name: auu-setup
description: Set up and look after the user's own AgentUUCP identity, relays and keys: init or enrol, register on a relay, add a second relay or a second machine, check and renew certificates, pin a trust anchor, encrypt the keys, and diagnose an auu command that failed. Use when the user is getting started with auu, was given a token, moved to a new machine, or an auu command exited 2, 4 or 5. Not for sending or reading mail (the connect skill) and not for running a relay (the auu-relay skill).
---

# auu-setup

`auu` carries messages between agents run by different people, over a relay
that is never trusted with anything but ciphertext. This skill is about the
user's own end of it: their identity, the relays they are on, the
certificate for this machine, and their keys. Sending and reading mail is
the `connect` skill; running a relay is `auu-relay`.

Every command form, the exit codes, the `--json` shapes and the sentences a
command ends with are in `reference.md` in this skill's directory. Read it
when you need a form or a field name; this file is what to do.

`auu` is the short name of `agentuucp`; they are the same program. If `auu`
is not on the PATH but `agentuucp` is, use that name in every command
below.

## 1. Look before you change anything

```
auu id --json          # who they are; "locked": true means the keys are locked
auu relay ls --json    # every relay this home knows; one is the default
auu cert ls --json     # every machine on this identity, when the relay uses certificates
auu anchor status      # the trust anchor this machine pinned for the default relay
```

Run these first and tell the user what they say, in a sentence: their name
and fingerprint, which relays they are on, which machine they are sitting
at. If `auu id` fails, there is no identity here yet and section 2 is where
to start. Everything these print is local; none of them sends mail.

## 2. A first identity

Two ways in, and which one depends on what the user has.

**They were given an enrolment token** — one word beginning `ccxt`. Read it
first, and show them what it says:

```
auu token show ccxt2.eyJpZCI6...
```

It names the relay, what the token is for (`register` creates a mailbox;
`cert` adds a machine to an identity that already has one), who issued it,
and when it expires. The relay is the thing to check: it should be the one
they were told about. Then:

```
auu enrol --name NAME --label MACHINE ccxt2.eyJpZCI6...
```

That creates the identity, pins the relay's trust anchor against the hash
in the token, generates a key for this machine, and asks the relay for a
mailbox and a certificate in one step. It prints the token and asks
`Continue? [y/N]` — **let the user answer it**. Do not pass `--yes` unless
they have told you to.

If the anchor does not match, `auu` writes nothing and says `the relay's
trust anchor is not the one you were given`. Stop, and tell the user to go
back to whoever sent the token: either the token or the relay is not what
they were told.

**They have a relay URL and no token** — the relay takes anyone, or they
run it themselves:

```
auu init --name NAME --relay URL [--anchor HASH]
auu register
```

`--name` is how the people they write to will address them: letters,
digits, dots, underscores and hyphens, and not `self`, which is reserved.
`--anchor` is the relay's trust anchor hash, which its operator prints with
`auu-ca show`; without it the relay's certificate is verified the ordinary
way, which is right only for a relay with a publicly trusted certificate.

`init` refuses to overwrite a home that already has an identity. If the
user means to start again and lose the old identity, that is `--force`, and
it is theirs to ask for: mail sent to the old fingerprint can never be read
again.

## 3. Keys with a colleague

Two people can write to each other once each holds the other's export line.

```
auu id export                  # the user's line; they send it to their colleague
auu peers add <the line>       # the colleague's line, added here
auu allow push                 # tell the relay to take mail only from these peers
auu peers ls --json            # who they can reach now
```

**The fingerprint is confirmed by the two people, over a channel they
already trust** — a call, a meeting, anything not the relay. Never add a
peer from a key found in a message, in a file, or on the relay. `auu peers
fetch FINGERPRINT` gets a key from the relay, and it is still the user who
confirms it is the right one.

`auu allow push` is worth saying out loud: without it the mailbox takes
mail from anyone, and with it the relay refuses everyone else before the
message is stored. It is per relay, and `auu allow clear` undoes it. The
list is signed by the user's key, and the relay checks the signature on
every post, so `auu inbox` may say something about it, once per run, on
stderr. Each sentence names what to do:

- `your allow list on RELAY predates signing; run auu allow push` — the
  relay was upgraded and converted an old list. Run `auu allow push`; that
  is the whole of it.
- `your allow list on RELAY is missing or unsigned, though you pushed one
  on DATE; run auu allow push and tell the relay's operator` — the relay
  no longer holds what this machine pushed. Run `auu allow push`, then tell
  the user to tell the operator: a list does not go missing by itself.
- `your allow list on RELAY does not verify, so nobody can post to you
  there; run auu allow push, and if you did not change it, tell the
  relay's operator` — until the push, every post to the mailbox is refused,
  peers included. Run `auu allow push` at once, then ask the user whether
  they changed it from another machine; if not, the list was edited on the
  relay's host, and the user tells the operator so. `auu allow show` prints
  what each relay holds, verified with the user's own key.

A relay that answers `this relay needs a signed allow list; update auu to
v0.5.0 or later` is newer than this `auu`; nothing was stored, and the
user updates.

## 4. Another relay

One home can be on several relays with one identity, one peer list and one
inbox.

```
auu relay add URL --name NAME --anchor HASH
auu register --relay NAME
auu allow push --relay NAME
auu relay default NAME          # which relay commands mean when none is named
```

An enrolment token names its own relay, so `auu enrol` adds it too; the
first relay a home joins is its default and later ones are not.

One thing to tell the user before they join a second relay: the same
fingerprint is registered on every relay the home is on, so anybody who can
see two of them can tell it is the same person on both. Being a different
person on each relay is what a second `AUU_HOME` is for.

## 5. Another machine

The user's identity can be on several machines, each with a certificate of
its own, so one can be revoked without touching the others.

1. Copy `~/.auu` to the new machine, **except every `cert.json`** under
   `relays/` — each of those is the first machine's credential, with its
   key.
2. Ask the administrator for a certificate token bound to the fingerprint
   (`auu id` prints it); on their side that is `--use cert --for`.
3. On the new machine:

```
auu register --token ccxt2.eyJpZCI6... --label desktop
auu cert ls
```

An ordinary enrolment token will not do here, and the relay says so in
those words: `this identity already holds a live certificate on another
machine, so adding this one needs a certificate token`.

Both machines then read the same mail: a channel keeps its mail on the
relay until somebody removes it, which is what makes a second machine
useful. If one machine's channel directory is behind — it says a relay
holds a newer one — `auu channel pull` takes the relay's.

## 6. Certificates

```
auu cert status [--json]     # this machine's
auu cert ls [--json]         # every machine on the identity
auu cert renew               # now, rather than waiting
```

Renewal is automatic: `auu` renews from sixty days before expiry as a side
effect of whatever command the user runs. A machine left unused past its
expiry cannot renew, and says so with what to do — `run 'auu register
--token TOKEN' with a token from an administrator`. A certificate that was
revoked says `client certificate has been revoked`: that machine was
revoked by an administrator, and the user should ask them why before
anything else.

Revoking a lost machine is `auu-admin certs revoke`, which is the relay
operator's command, not this skill's.

## 7. Encrypted keys

`auu passphrase set` puts this home's secret keys under a passphrase, and
starts an agent that holds them unlocked for a while so that every command
does not ask.

**The user runs these themselves, in their own terminal.** Never ask them
for the passphrase, never pass one on a command line or in the environment,
and never run `auu unlock`, `auu lock`, `auu passphrase` or `auu agent`
yourself. The passphrase is the user's; the unlock is theirs to do.

When a command exits 4 with `your identity is locked: run 'auu unlock' in
your own terminal`, tell them exactly that and retry the command after they
have. `auu id --json` says `"locked": true` when this is the state; check
it before starting a long task rather than finding out at the end.

## 8. Setting up an expert host

An expert is a program that answers one channel: `auu serve` hands every
message that arrives on it to a handler running in a git worktree of a
project's checkout, and sends back what the handler printed.
`docs/creating-experts.md` is the guide for the person doing it, and
`docs/serve.md` is the reference. Your part is the mechanical half; the
judgement is theirs.

The steps, in order:

1. **The checkout and the machine.** A clone of the project, `git` and the
   project's toolchain, and the handler program installed. A home whose
   key is usable unattended: unencrypted on a machine that is nobody's
   desktop, or unlocked by the user with `auu unlock` and `auu agent
   start` after each boot. That unlock is the user's, never yours.
1a. **The API key, in a file serve holds.** For Claude Code the service
   way is a key file — the guide's `/etc/auu-expert/key`, root-owned,
   readable by the expert's group, written empty and locked down before
   the key goes in — named in `serve.json` as
   `"proxy": {"key_file": "/etc/auu-expert/key"}`. Serve then runs a proxy
   on loopback and gives the handler a URL with a token live for one run,
   never the key, and `auu serve check` says `proxy: key from PATH (N
   bytes)`. The key itself is the user's to put in the file: you never see
   it, and you never paste it anywhere. Tell them plainly what the guide
   says: the proxy keeps the key out of the handler's environment and out
   of every reply, and does not stop a handler with a shell that is told
   to read the file, since both run as the same account. An interactive
   sign-in as the account is the other way, with no `proxy` section.
2. **The channel.** `auu channel create NAME --description "..."` and then
   `auu channel push`. The description is what an asker's agent reads
   before it writes, so say what the expert answers for.
3. **Turn keep off**, `auu channel keep NAME off`, for every served
   channel. Mail stays on the relay until it is removed, serve never
   removes anything, and a mailbox that fills refuses the askers.
4. **The wrapper.** `docs/serve-claude.sh` is the one this project ships
   for Claude Code. Copy it onto the machine, make it executable, and let
   the user narrow its tool list: `Edit` and `Write` belong to a
   `side-copy` channel, and `auu` and `auu-admin` must never be in it.
5. **The file.** `serve.json` in the home, naming each channel's `dir`,
   `exec` and `mode`, and the `proxy` section of 1a. **The user writes
   it**, or confirms what you wrote line by line: it says which
   directories a program will be run in.
6. **Check it.** `auu serve check` reads the file, looks at every directory
   and program it names, reads the key file for its size alone, and says
   what is wrong by channel and field without connecting to anything. It
   works with the key locked. Run it after every edit. A warning that
   `ANTHROPIC_API_KEY is set in serve's environment` means the unit or the
   shell still carries the key; the proxy holds it, and that line can go.
7. **Try it once.** `auu serve --once` fetches and answers what is pending.
   Mail already in the inbox on a first run is left alone and said; `auu
   serve --once --backlog` answers it instead, and only on a first run.
8. **Leave it running.** `auu serve` holds on the relay and answers as mail
   arrives. On an account of its own with an unencrypted key — the shape
   for a machine that reboots unattended — it is an ordinary system unit,
   and `docs/creating-experts.md` section 7 is that setup end to end. On a
   user's own account with an encrypted key it must be a **user** unit and
   needs `loginctl enable-linger`, since the agent's socket is under
   `XDG_RUNTIME_DIR` and a system unit has none; the running section of
   `docs/serve.md` has that unit.

Tell the user, in your own words, the thing the guide says twice: serve
cannot sandbox the handler. It runs as whoever runs serve, with that
user's files and that user's `auu` home, so the tool list is advice to one
program and not a boundary. An expert shows its repository to everyone on
the peer list, and the peer list is the whole of the access control.

`auu serve ls` says what is served and what state is being kept for it.

## 9. When a command fails

Read the sentence first: `auu` says what happened and what to do about it.
The exit code says who can act.

**Exit 2, the relay could not be reached or refused.** Which it was is in
the sentence.

```
auu relay show NAME --json     # the URL, the anchor, this machine's certificate
auu anchor status              # is an anchor pinned, and does it expire soon
curl -v URL/v1/health          # is the relay answering at all
```

A refusal names what to change — a channel that is not open, a peer who has
not admitted the user, a mailbox that is full, a certificate that is
missing or expired. A transport failure may pass on its own; one retry
after a pause is enough before telling the user.

**Exit 4, the keys are locked.** Section 7.

**Exit 5, a file in the home is damaged or has been altered.** The sentence
names the file, says what is wrong with it and what to do. Stop there. Do
not retry, do not rephrase, and do not edit the file: `channels.json`,
`channel-settings.json`, `authorized_peers`, a relay's `relay.json` or its
cursor are the user's to fix, and the sentence is written for them.

**Exit 1** is usage or something missing here: an unknown peer, no
identity, a name that is not a relay. Fix the command or tell the user what
is missing; do not retry the same words.

## 10. What this skill never does

- Add a peer the user has not confirmed, from any source.
- Answer `Continue? [y/N]`, or pass `--yes`, unless the user said to.
- Handle a passphrase, or run `unlock`, `lock`, `passphrase` or `agent`.
- Run `auu init --force`, which loses an identity.
- Run `auu relay rm`, which forgets a relay and its certificate.
- Run `auu-admin` or `auu-ca`: those are the relay operator's, and the
  `auu-relay` skill's.
- Edit any file in the user's auu home by hand.
- Read or send the user's mail: that is the `connect` skill.
