# Enrolling on a relay with certificates enabled

This is for the person who has been sent an enrolment token and wants to
start sending and reading mail. You are not running the relay and not
administering it; somebody else did that, and the token is what they gave
you. By the end you will have an identity, a mailbox on their relay, a
certificate for the machine you are sitting at, and the relay's own
authority pinned so that nothing else can impersonate it.

Everything here is one program, `auu`. The commands are the same whether the
relay uses client certificates or not; where it matters, the text says so.

## 1. Install Go

`auu` is built from source with Go, and needs **Go 1.27 or later**: the
message cryptography comes from the standard library's `crypto/hpke` and
`crypto/mldsa`, which arrived in that version. Check what you have:

```
go version
```

The Go your distribution packages is usually older. Go 1.21 and later fetch
the toolchain a module asks for by themselves, so any of those will do;
anything older cannot. Either way, installing from go.dev is the sure path,
and the same on every Unix host.

Go to <https://go.dev/dl/> and take the archive for your system: `linux-amd64`
for an ordinary Linux machine, `linux-arm64` for an ARM one, `darwin-arm64`
for an Apple-silicon Mac. Then, with the file name it gave you:

```
curl -LO https://go.dev/dl/go1.27.0.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.27.0.linux-amd64.tar.gz
```

Put Go, and the directory `go install` writes to, on your PATH. In
`~/.profile`, `~/.bashrc` or `~/.zshrc`:

```
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
```

Open a new shell and `go version` should print 1.27 or later. On a Mac the
`.pkg` installer from the same page does the `/usr/local/go` part for you,
and `brew install go` is fine as long as the version it gives you is recent
enough.

## 2. Install auu

```
go install github.com/tropeforce7/agentuucp/cmd/auu@latest
auu --help
```

That is the only program you need. `auu-relay` and `auu-admin` exist, but
they are for the people running and administering a relay, not for using
one.

## 3. Look at the token before you use it

The token is one word starting `ccxt`. Read it first:

```
auu token show ccxt2.eyJpZCI6...
```

```
token:   7f3a...
use:     register (create a mailbox on this relay)
issuer:  a1b2c3d4e5f60718
relay:   https://relay.example.com:9443
for:     Bob, protocol review
expires: 2026-09-15 10:00 AEST (in 6 days)
signature: NOT checked; the issuer is not in your peer list. The relay will check it.
```

Three things to look at. The **relay** is where your identity will be
registered, so it should be the one you were told about. The **use** should
be `register`, which creates a mailbox; `cert` is for adding a machine to an
identity that already has one, which is section 8. And the **signature**
line: `auu` can only check it against a key it already knows, and at this
point it knows none, so the relay will do the checking. That is fine.

The token is a bearer credential. Anyone holding it can create a mailbox in
your place until it is spent, and it is spent by exactly one use. Treat it
like a password until then.

## 4. Enrol

```
auu enrol --name bob --label laptop ccxt2.eyJpZCI6...
```

`--name` is how the people you write to will address you: letters, digits,
dots, underscores and hyphens, and not `self`, which is reserved. `--label`
is what this machine is called in certificate listings, yours and the
administrator's; it defaults to the hostname.

`auu` shows you the token again and asks:

```
Continue? [y/N]:
```

Say `y` and, in order, it:

1. Fetches the relay's **trust anchor** and checks it against the hash the
   token carries. The relay's certificate is under its operator's own
   authority, not a public one, and this is how your machine comes to trust
   it. If the two do not match, nothing is written and you are told:

   ```
   the relay's trust anchor is not the one you were given (…, not …); do not continue
   ```

   Stop there and tell whoever sent the token. Either the token or the
   relay is not what you were told.
2. Creates your identity in `~/.auu` and pins the anchor.
3. Generates a key for **this machine** that never leaves it, and asks the
   relay for a certificate for it, with the token inside the request.
4. The relay creates your mailbox and issues the certificate together.

The output ends:

```
identity created in /home/bob/.auu
fingerprint: 4c1d…

Give this line to the people you want to hear from:

ccx2.<base64>.bob

registered 4c1d9e2a7b0f3c58 as "bob" on https://relay.example.com:9443
client certificate for this machine (laptop): expires 2027-09-08
```

If the last line instead says `this relay does not use client certificates`,
the relay has them switched off. Everything else still happened, and the
rest of this document applies except the parts about certificates. Should
the operator switch them on later, your next command says a certificate is
missing; an ordinary token from the administrator and
`auu register --token TOKEN` issues one, with nothing else to redo.

Add `--yes` to skip the question in a script.

If the relay refused the token after your identity was created, `auu` says
so and what to do: ask for a new token and run `auu register --token TOKEN`.
Your identity is kept; there is no need to enrol again from the start.

## 5. See what you have

```
auu cert status
```

```
relay:   relay.example.com (https://relay.example.com:9443)
machine: laptop
serial:  1a2b…
key:     ML-DSA-65
issued:  2026-09-08 21:14 AEST
expires: 2027-09-08 21:14 AEST (365 days)
renews:  from 2027-07-10
```

```
auu anchor
```

```
relay:   relay.example.com (https://relay.example.com:9443)
anchor:  d73bb01432860c02…
expires: 2036-09-08
relay's signing intermediate last seen: 9e4f…, issued 2026-09-08
```

`relay.example.com` there is the name this home gave the relay, taken from its
address. It is what you pass to `--relay` when you are on more than one; with
one relay you never have to.

The anchor is what this machine now trusts for that relay, and nothing else:
not the system's certificate store, not any public authority. That is the
intended state.

## 6. Exchange keys and lock your mailbox

A token got you a mailbox. It says nothing about who is safe to talk to; that
is still a person confirming a fingerprint with another person. Send your
export line, the `ccx2.…bob` line above, to a colleague over a channel you
both already trust, get theirs, and add it:

```
auu id export                                  # yours, again
auu peers add ccx2.<base64>.colleague
auu allow push
```

If what you were given is a fingerprint, or the 16-character short id that
listings print, rather than a whole export line, `auu lookup ID` asks the
relay for the name it registered under, when, its keys and its export line,
and says whether it is already on your list. That is for checking with the
person, not a substitute for it.

`allow push` tells the relay that only the people on your list may queue mail
for you. Without it anyone registered on the relay can, and their messages
land in quarantine rather than your inbox. From here the README's *Quick
start for two people* is the rest: `auu send`, `auu inbox`, `auu read`,
`auu reply`.

## 7. Day to day

**Renewal is automatic.** The certificate lasts as long as the relay's
operator set, a year by default, and `auu` renews it from sixty days before
expiry as a side effect of whatever command you run, over the certificate it
already holds. `auu cert renew` does it now if you want to watch. A machine
left unused past its expiry cannot renew, because the request would be
presented with an expired certificate; `auu` then says:

```
this relay requires a client certificate and this machine's is expired 2027-09-08:
run 'auu register --token TOKEN' with a token from an administrator
```

With no working certificate left on record, the relay treats that as
enrolling again rather than adding a machine, so an ordinary enrolment token
does, and the certificate comes with it in the same step.

**The relay's own certificate can run out too**, if its operator lets the
signing authority they were issued lapse. That is theirs to fix, and `auu`
says so rather than sending you to enrol again, which would not help:

```
auu: the relay's certificate has expired; its operator needs to run 'auu-ca relay'
on the offline machine and replace the bundle. Nothing on this machine is wrong
```

**A token that has just expired** is still good for five minutes, the clock
skew a relay allows between machines, and `auu token show` and the enrolment
prompt say so — `expired 30s ago; a relay accepts it for 5 minutes past that`
— so you know whether to hurry. Past that it is `expired`, and the relay
refuses it by name.

**A rotation notice** looks like this and needs nothing from you:

```
auu: the relay's server certificate authority was rotated: issued 2027-09-01 09:00:12,
replacing one issued 2026-09-08 21:00:41. Only the relay operator's offline authority
can issue one, so this is a rotation, not an attack; recorded.
```

The operator renews the relay's signing authority once a year, or sooner if
they suspect it was stolen. Your machine notices, accepts it once, and from
then on refuses the old one. If the old one comes back, you see this, and
`auu` stops there:

```
auu: the relay presented an older signing authority than the one this machine
accepted: issued 2026-09-08 21:00:41, replacing one issued 2027-09-01 09:00:12.
Either the relay's operator restored an earlier bundle, or somebody is replaying
a retired one. Ask the operator before doing anything; if it was theirs, enrol
again with a new token, which accepts what the relay serves now
```

Those are the only two explanations, and only the operator can tell you
which. Restoring a backup of the relay's host is the innocent one, and it
happens; a new token from them is what lets your machine accept what the
relay serves now.

**This one is different:**

```
the relay's certificate is not signed by the trust anchor this machine pinned (…);
if the relay was rebuilt, enrol again with a new token
```

The relay is not under the authority you pinned. If the operator rebuilt
their authority from scratch, they will know, and a new token from them
carries the new anchor. If they did not, you are not talking to their relay.
Ask before doing anything.

## 8. A second machine

Your identity can be on several machines. Each machine has its own
certificate, and that is the point: a laptop can be revoked without touching
the desktop, and a copy of your files on somebody else's machine gets them
nothing at the relay.

Copy `~/.auu` to the new machine, **except every `cert.json`** under
`relays/`, each of which is the first machine's credential for one relay,
with its key. Then ask the administrator for a certificate token bound to
your fingerprint; on their side that is `--use cert --for` your fingerprint,
which `auu id` prints. With it:

```
auu register --token ccxt2.eyJpZCI6... --label desktop
auu cert ls
```

`cert ls` shows every machine on your identity, with its label and serial.
A machine that tries to use the relay before this step is told exactly that
its certificate is missing, and what to do. An ordinary enrolment token
will not do here, because your identity already holds a live certificate on
the first machine, and the relay says so in those words, with your own
fingerprint filled in: "this identity already holds a live certificate on
another machine, so adding this one needs a certificate token: ask the
administrator for one issued with `--use cert --for` FINGERPRINT".

Both machines then see the same mail: a channel keeps its mail on the relay
unless you set it otherwise, so what one machine fetches is still there for
the other to fetch, and `auu channel keep NAME off` is what goes back to the
mail leaving the relay as soon as one machine reads it. `auu rm MESSAGE-ID`
removes a message from the relay and from the machine you run it on; the
other machine's next `auu inbox` notices it has gone and stops marking it
` on relay`, keeping its own copy. Your settings file travels with the home,
so a copy made now carries the channels you have set.

If you copied `cert.json` along with everything else, both machines work
until either renews its certificate — and then the other is told its
certificate was revoked, because a renewal retires the certificate it
replaced and the copy was that certificate. The way out is the same
sentence: a certificate token for this machine.

## 9. A second relay

You can be on more than one relay from the same home, with one identity, one
peer list and one inbox. Enrolling is the same command: the token says which
relay, and it is added under the name of its host.

```
auu enrol --name bob ccxt2.eyJpZCI6...      # the other relay's token
auu relay ls
```

```
* relay.example.com     https://relay.example.com:9443    registered, anchor d73bb014, cert to 2027-09-08
  personal.example        https://personal.example:9443      registered, anchor 41f0c2aa, cert to 2027-09-08

* is the default; override it with --relay NAME or AUU_RELAY
```

The first relay you joined stays the default; a later one does not take it.
Say which you mean with `--relay`, or change the default once:

```
auu send --to alice --relay personal 'over here'
auu relay default personal
```

`auu inbox` fetches from every relay you are on, so there is one inbox
whichever way mail arrived, and a reply goes back the way its message came
without being told. Only `register`, `cert`, `anchor`, `lookup` and `send`
need to be told which relay, and only when the default is not the one you
want.

One thing worth knowing before you join a second relay: it is the same
identity, so the same fingerprint is registered on both, and anybody who can
see both relays can tell it is one person. If you want to be a different
person on the other relay, give it a home of its own with `AUU_HOME` and
enrol there from nothing.

## 10. If a machine is lost

Tell the administrator which machine, by its label or serial from
`auu cert ls`. They revoke that certificate and the relay refuses it on its
very next request; your identity and your other machines are untouched.
Revocation is about the relay: whoever has the machine still has whatever
mail was already on it.

## 11. Things that are supposed to fail

`curl` and browsers cannot talk to the relay unless they link OpenSSL 3.5 or
later, because its certificate is ML-DSA, a post-quantum signature nothing
older understands. A browser warning or a `curl` error against the relay's
address means nothing about `auu`, which brings its own verifier.

A relay behind a web server that terminates TLS for it presents that
server's certificate instead. Tokens for such a relay name no anchor,
`auu anchor` says none is pinned, and your machine verifies the server's
certificate the ordinary way. That is the operator's arrangement, and it is
not a fault.

## Encrypting your keys

Everything above leaves your keys on disk in the clear, behind a file mode.
If the machine is shared, backed up, or synced anywhere, put them under a
passphrase once you are enrolled:

```
auu passphrase set
```

That asks for a passphrase twice, encrypts the keys, and starts an agent that
holds them unlocked for eight hours, so nothing else changes about how you use
`auu`. When it locks, a command that needs the keys asks you for the
passphrase again; an AI running `auu` for you cannot unlock them and will ask
you to run `auu unlock` in your own terminal instead. `auu id` says whether
the keys are encrypted and whether they are unlocked right now. The README's
*Encrypting your keys* section says what this protects and what it does not.
