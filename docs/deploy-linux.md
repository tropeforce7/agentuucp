# Deploying a relay on Linux

This puts an AgentUUCP relay on a Linux server as a system service: its own
user, its own state directory, a certificate it obtains and renews itself, and
a systemd unit that confines it to the little it needs. The host needs
systemd 250 or later as PID 1 — Debian 12 or 13, Ubuntu 24.04 or later,
Fedora, RHEL 9 and its rebuilds; the reason is in step 3a — and the commands
below are the ones every one of those has, with the package and firewall
commands given for both families where they differ. It takes about fifteen
minutes on a fresh host, and assumes you have a DNS name pointing at the
machine and can reach it on the port you choose; the settings below use 9443.

Where things end up:

```
/usr/local/bin/auu-relay               the binary, owned by root
/etc/auu/relay.json                    settings; owned by root, nothing secret in it
/etc/auu/admins                        who may administer; owned by root, the relay only reads it
/etc/auu/relay-bundle.cred             the relay's signing keys, sealed to this host; ciphertext
/var/lib/auu/                          state, owned by auu, mode 0700:
    relay.db                             mailboxes and counters
    messages/                            one file per stored message
    clientca/                            nothing; the authority is in the bundle
/etc/systemd/system/auu-relay.service
```

The two files under `docs/systemd/` are the unit and the settings as used
below, ready to copy.

## 0. Install Go 1.27 or later, on your own machine

The relay is built on your own machine in step 1 and copied to the host, so
the host never needs Go. Your machine does, and it needs Go 1.27 or later,
for `crypto/hpke` and `crypto/mldsa` in the standard library. See what you
have:

```
go version
```

The Go a distribution packages is usually a year or more behind, so on Linux
take the official archive from [go.dev/dl](https://go.dev/dl/) instead. Pick
the file for the processor in *this* machine, the one you build on, which
`uname -m` names as in step 1: `linux-amd64` for `x86_64`, `linux-arm64`
for `aarch64`. With the version current at the time of writing:

```
curl -fsSLO https://go.dev/dl/go1.27.1.linux-amd64.tar.gz
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.27.1.linux-amd64.tar.gz
export PATH=/usr/local/go/bin:$PATH        # and the same line in ~/.bashrc or ~/.zshrc
go version                                 # go version go1.27.1 linux/amd64
```

The `rm -rf` is Go's own instruction: unpacking a new archive over an old
tree leaves stale files behind. On macOS, `brew install go` or the package
from the same page; on Windows, the installer from the same page. Any newer
Go is fine. A Go older than 1.27 but from 1.21 on will fetch 1.27 by itself
the first time it builds this module, which is slower once and then the
same, so an older Go is not fatal; one older than 1.21 is, and says so.

On a Linux machine, `scripts/install.sh` does all of this for you, installing
Go only when what is there is below 1.27, and `--relay` has it build
`auu-relay` as well as the client tools; the README's install section has
its curl line.

## 1. Build the binary, on your own machine

The relay is pure Go with no C dependencies, so it cross-compiles to a single
static binary and the server needs no Go toolchain at all; section 0 puts Go
on your own machine.

A binary is built for one kind of processor and will not run on another:
a relay built for an Intel or AMD server is a file the ARM processor in a
Raspberry Pi or a Graviton instance cannot execute, and the other way round,
and Linux says only `Exec format error` when you try. So find out which the
host is first, from the host itself:

```
ssh you@relay.example.com uname -m
```

`x86_64` is Intel or AMD, and Go calls it `amd64`. `aarch64` is ARM, and Go
calls it `arm64`. Then build on your own machine for that processor, whatever
your own machine is, and copy the result across.

For an Intel or AMD host, one that said `x86_64`:

```
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o auu-relay ./cmd/auu-relay
scp auu-relay you@relay.example.com:
```

For an ARM host, one that said `aarch64`:

```
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o auu-relay ./cmd/auu-relay
scp auu-relay you@relay.example.com:
```

The only difference is `GOARCH`. From a clone, `make relay-linux` is the
first of these and `make relay-linux ARCH=arm64` the second, each putting
the binary under `bin/linux_amd64/` or `bin/linux_arm64/` so the two never
overwrite each other. To check what you built before you copy it, `file
auu-relay` names the processor, and on the host `./auu-relay --version`
either prints the version or fails with the error above.

Without a clone, `go install` can build it straight from the module; when
cross-compiling, Go puts the result under a platform directory rather than
in `GOBIN`:

```
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go install github.com/tropeforce7/agentuucp/cmd/auu-relay@latest
scp "$(go env GOPATH)/bin/linux_amd64/auu-relay" you@relay.example.com:
```

For ARM, `GOARCH=arm64` and the directory is `linux_arm64`.

On the server itself, `scripts/install.sh --relay` builds the same binary
there and installs Go first if the host has none new enough — one command
where these are three, for an operator who would rather not cross-compile.
The README's install section has its curl line.

You do not need `auu-admin` on the server. Administration happens from an
administrator's own machine, signed with their own key; the server only holds
the list of who is allowed.

## The short way: a kit

Steps 2 to 7 below can be done by a script instead: `auu-ca kit` packs the
relay binary, the settings and the administrator file written for your host,
the systemd unit, the relay's signing bundle and an installer into one
archive, and `install.sh` on the host does what the steps do, printing each
command before it runs it, and refuses a host that already has a relay. It
needs systemd 250 or later as PID 1: Debian 12 or 13, Ubuntu 24.04 or later,
Fedora, RHEL 9 and its rebuilds. On anything else it says so and stops, and
the steps below are the way. **The host also needs `unzip`**, which a
minimal install does not have: `apt install unzip`, or `dnf install unzip`,
before the recipe below; `python3 -m zipfile -e FILE .` unpacks the archive
too, if python3 is there and unzip is not.

Two things come first, on your own machine: the authority from step 3a,
made once with `auu-ca init`, and the first administrator's export line,
since a relay that admits nobody without a token needs somebody to issue
them. The administrator prints their line on their own machine, as step 5
describes; the relay does not exist yet, so `auu init` takes no `--relay`
here, and an identity that already exists just prints its line:

```
auu init --name bunty                 # once, on the administrator's machine
auu id export > admins                # one line per administrator, in this file
```

Then the kit, and the recipe `auu-ca kit` prints when it has written it:

```
make relay-linux                                      # bin/linux_amd64/auu-relay; ARCH=arm64 for ARM
auu-ca kit --host relay.example.com --relay-binary bin/linux_amd64/auu-relay \
  --admin @admins --out relay.example.com.zip             # the authority's passphrase
scp relay.example.com.zip you@relay.example.com:        # your ssh password
ssh -t you@relay.example.com 'unzip -oq relay.example.com.zip && sudo sh auu-relay-kit/install.sh'
ssh you@relay.example.com 'rm -r relay.example.com.zip auu-relay-kit'
rm relay.example.com.zip
```

| flag | what it is | default |
|---|---|---|
| `--host NAME\|IP` | a name or address the relay answers to, as `auu-ca relay` takes it; the first is `public_url`'s | required, repeatable |
| `--relay-binary FILE` | the relay built for the host: a static Linux build for amd64 or arm64, which `make relay-linux` makes; anything else is refused by name | required |
| `--out FILE` | the archive, written mode 0600 | required |
| `--admin LINE\|@FILE` | an administrator's export line, or a file of them, `#` and blank lines skipped; a `token` relay needs at least one | none, repeatable |
| `--listen ADDR` | step 4's `listen`; `public_url` is the first host and this port, so the two cannot disagree | `:9443` |
| `--registration open\|token\|closed` | step 4's `registration` | `token` |
| `--client-certs off\|required` | step 4's `client_certs.mode` | `off` |
| `--without-bundle` | leave the bundle out and issue nothing, for moving it another way | |
| `--years N` | how long the intermediates live, as `auu-ca relay` | `1` |
| `--dir DIR`, `--passphrase-file PATH` | the authority's directory and passphrase, as `auu-ca relay` | |

`auu-ca kit` prints the archive's files with their hashes and the recipe
above, and reminds you that the host needs `unzip`. `unzip -o` replaces a
kit still unpacked there from last time without asking — without it, unzip's
"replace?" prompt arrives on the terminal `sudo` is about to ask on, and
what you type for one goes to the other. The python form unpacks without
the files' modes, which the script does not depend on. The kit's own README
says all of this again, for whoever has the archive and nothing else.

The archive holds the bundle, so it is handled exactly as `relay-bundle.json`
is in step 3a: written 0600, copied, used, deleted at both ends, and
`auu-ca show` warns about it until it is gone from your machine. The
script seals the bundle to the host and deletes the plaintext before it
starts the relay. `--without-bundle` leaves it out, for moving the bundle
some other way; the script then installs everything else, stops before
starting the relay, and prints the `systemd-creds encrypt` and `systemctl
enable --now` lines to run once the bundle is on the host.

Once the relay is up, the administrator points their own machine at it,
pinning its trust anchor — `auu-ca kit` printed the hash, and the script
prints it again when it is done — and checks; this is step 5's
`auu init --relay --anchor` for an identity that already exists:

```
auu relay add https://relay.example.com:9443 --name work --anchor HASH
auu-admin status
```

Step 8 invites the first user. The script is `internal/kit/install.sh` in
the repository, and `scripts/kit-check.sh` runs it, fresh and as `update`
(see *Day two*), under a real systemd in CI on every push.

## 2. Create the user and the directories

Everything below is on the server, as root.

```
useradd --system --home-dir /var/lib/auu --no-create-home --shell /usr/sbin/nologin --user-group auu
install -d -m 0700 -o auu -g auu /var/lib/auu
install -d -m 0755 /etc/auu
```

`--system` gives a low uid, no password and no login; `--user-group` makes a
group of the same name; `useradd` is the form every distribution has, where
`adduser` differs between them, and `/usr/sbin/nologin` is on all of them
(`command -v nologin` says where). The home directory is the state directory,
and it must be `0700`: the relay refuses to start if its message directory
is writable by anyone else, because a file dropped in there would be a
message it never received.

## 3. Install the binary

```
install -o root -g root -m 0755 auu-relay /usr/local/bin/auu-relay
auu-relay --help | head -1
```

Root-owned and not writable by `auu`, so a compromised relay cannot replace
itself.

## 3a. Make the certificate authority, on your own machine

Not on the server. `auu-ca` holds the keys the whole deployment rests on, and
the reason it is a separate program is so that "do not put this on the relay"
is enforced by not installing it there.

```
auu-ca init --name "Your Organisation"
```

`init` asks for a passphrase, twice, and encrypts every private key it writes
under it. Keep it somewhere that is not the backup of this directory: without
it the authority is gone and every machine enrols again under a new anchor.
`relay` asks for it too, once a year; `show` never does. For an unattended
run, `--passphrase-file PATH` reads the first line of a file, and standard
input is read when it is not a terminal.

`init` prints the trust anchor's hash. Keep that too: it is what an enrolment
token carries and what a machine pins, and `auu-ca show` prints it again.

Now issue the relay its bundle and put it on the server, one prompt at a
time:

```
auu-ca relay --host relay.example.com --out relay-bundle.json    # the authority's passphrase
scp relay-bundle.json you@relay.example.com:                      # your ssh password
ssh -t you@relay.example.com 'sudo systemd-creds encrypt --name=relay-bundle relay-bundle.json \
  /etc/auu/relay-bundle.cred && rm relay-bundle.json'             # ssh again, then sudo
rm relay-bundle.json
```

The bundle is the relay's two signing keys, in the clear, which is why the
file is deleted at both ends the moment the sealed credential exists — and
why `auu-ca show` nags about the local copy until you do. `auu-ca` writes it
mode 0600 and `scp` keeps that mode. A kit (*The short way*, above) holds
the same bundle inside its archive, and `show` warns about that file the
same way. If you would rather it never touched a
disk at all, there is a form for that below. Do not shorten any of this to
`auu-ca relay --out - | ssh … sudo …`: the two sides of a pipe start
together and both ask on the terminal at once, and ssh reports your correct
password wrong three times while `auu-ca` waits for a passphrase it never
quite gets.

Five things about the `systemd-creds` command:

- `--name=relay-bundle` binds the ciphertext to that credential ID. systemd
  will refuse to load it under any other name, so the name must be the one in
  `relay.json` (`tls.bundle_credential`) and in the unit
  (`LoadCredentialEncrypted=`). The shipped copies of both say `relay-bundle`.
- Without `--with-key=`, `systemd-creds` chooses for you: the host key and
  the TPM2 together when the machine has a TPM2, the host key alone when it
  does not. The host key is `/var/lib/systemd/credential.secret`, root-only,
  made on first use.
- It needs root on the server, which is what `sudo` is for, and `sudo` needs
  a terminal to ask you on, which is what `ssh -t` is for.
- It reads the credential from standard input when the input is `-`, which
  is how the bundle can be sealed without a file anywhere: `auu-ca relay
  --out -` puts the bundle on standard output and everything meant for you
  on standard error, and then, still one prompt at a time,
  `bundle=$(auu-ca relay --host relay.example.com --out -)`, then
  `printf '%s\n' "$bundle" | ssh you@relay.example.com 'umask 077 && cat >
  /dev/shm/relay-bundle.json'`, then `unset bundle`, then the `ssh -t … sudo
  systemd-creds encrypt` line above with `/dev/shm/relay-bundle.json` in
  place of `relay-bundle.json`. `/dev/shm` is memory; `rm` it as above. The
  one-line pipe is right only when ssh is by key and `sudo` asks nothing.
- The result, `/etc/auu/relay-bundle.cred`, is ciphertext, written by root
  at mode 0644. That is fine as it is — without the host key it decrypts for
  nobody, root included — and `chmod 0600` costs nothing if you prefer it.
  The relay never reads it directly, and needs no access to it.

`systemd-creds` and `LoadCredentialEncrypted=` arrived in systemd 250, which
is the one requirement this guide puts on the host: Debian 12 ships 252 and
13 ships 257, Ubuntu 24.04 255, Fedora and RHEL and CentOS Stream 9 252 or
later, and this guide was run to the end on Debian 13 and Ubuntu 24.04 —
`scripts/systemd-check.sh` is that run, steps 2 to 7 on a throwaway host as
root, and CI repeats it on every push. Ubuntu 22.04 has systemd 249 and no
`systemd-creds` at all: on it, use the plain file below until 24.04. A
host without systemd takes the plain file too. On the RHEL family,
SELinux has not been tried.

For a relay that is not under systemd, or whose secrets are managed some
other way, `auu-ca relay --out relay-bundle.json` writes a plain file, `scp`
and `install -o auu -g auu -m 0600` put it at `/etc/auu/relay-bundle.json`,
and the settings name it as `tls.bundle`. The command then tells you to
delete the file from your own machine, and `auu-ca show` warns for as long
as it is still there: it holds live signing keys, and your backups must not.

The bundle does **not** hold the trust anchor's key, or either offline
authority's; a test asserts that by searching it for their bytes. Back up the
`auu-ca` directory — it is the one thing that cannot be reissued.

## 4. Write the settings

```
install -o root -g root -m 0644 relay.json /etc/auu/relay.json
```

with `relay.json` being `docs/systemd/relay.json`, edited for your name and
address:

```json
{
  "listen": ":9443",
  "db": "/var/lib/auu/relay.db",
  "registration": "token",
  "public_url": "https://relay.example.com:9443",
  "access_log": "minimal",
  "admin": {
    "authorized_file": "/etc/auu/admins",
    "token_max_age": "720h"
  },
  "client_certs": {
    "mode": "off"
  },
  "tls": {
    "mode": "files",
    "bundle_credential": "relay-bundle"
  }
}
```

`tls.bundle_credential` is the name the credential was sealed under in step
3a; the relay looks for it in the directory systemd fills at start and refuses
to start, naming the `LoadCredentialEncrypted=` line it expected, if it is not
there. A plain file is `"bundle": "/etc/auu/relay-bundle.json"` instead;
give one or the other, never both.

The relay makes its own certificate, so it needs no particular port and no
public certificate authority. `listen` above can be anything; 443 is not
special any more, and the unit below runs the relay without the capability to
bind it. Whatever the port, **`public_url` must name it too**, as `:9443` does
above: tokens carry `public_url` and machines connect to it, and the relay
warns at startup when the two disagree. **Its host must be one the bundle was
issued for**, a `--host` from step 3a: machines verify the relay's
certificate against the name they connect by, and the certificate is minted
for the bundle's hosts, so a bundle for another host would lock every user
out. The relay refuses to start instead, naming the host `public_url`
carries, the host the bundle was issued for, and the `auu-ca relay` command
that issues a bundle for the right one. Nothing goes in front of the relay:
it terminates TLS itself, and a reverse proxy is not supported.

Four of those are choices rather than facts about your host, and a fifth is
a limit worth knowing about:

- **`registration: "token"`** means nobody gets a mailbox without an invitation
  an administrator signed. It is the right default for a relay you are putting
  on the public internet. `open` lets anyone register; `closed` stops new
  mailboxes while the existing ones keep working.
- **`access_log: "minimal"`** logs the route rather than the path and omits
  the caller. In `full` mode the journal records who is writing to whose
  mailbox, which is the social graph; on a relay shared beyond one team, do not
  keep that.
- **`client_certs.mode`** is `off` here. Set it to `required` and the relay
  issues each machine a certificate of its own when it enrols, and refuses any
  request that does not present a live one. It is a second credential per
  machine, not per person: it is what lets you revoke a stolen laptop without
  touching its owner's identity. It costs each user an extra token when they
  add a second machine, and switching it on later costs each existing user one
  ordinary token. See *Client certificates* below, and the README section of
  that name for what it does and does not protect.
- **`limits.max_waiting`**, 64 unless you set it, caps how many listings
  the relay holds open at once for `auu watch` and `auu wait`, which ask it
  to answer only when mail arrives rather than at once. A held listing
  keeps one of the `max_inflight` request slots (256) for as long as it is
  held, up to a minute, so `max_waiting` must sit well under `max_inflight`
  or watchers alone could fill the relay; the defaults leave 192 slots for
  everything else, and the relay refuses to start when `max_waiting` is
  not under `max_inflight`, naming both. Over the cap the relay does not refuse anyone: the next
  listing that asks to be held is answered at once, as a relay without the
  feature would answer it, and the watcher asks again at its interval.


Now check the file, **as the `auu` user**:

```
sudo -u auu auu-relay --config /etc/auu/relay.json --print-config
```

Expect exactly this refusal:

```
auu-relay: tls.bundle_credential is "relay-bundle" but CREDENTIALS_DIRECTORY is not set: the relay is not running under a unit with LoadCredentialEncrypted=relay-bundle:... in it
```

The bundle is a credential, and credentials exist only inside the running
service, so outside the unit this is the right answer. It is also the last
check the relay makes: every other refusal — an unknown key, a directory with
the wrong mode, an administrator file it cannot read — comes before it, so
any *other* message is a real problem with the file. Do not run this as root.
Resolving the settings creates the message directory if it is missing, and
one created by root is one the service cannot write to. To see the printed
settings anyway, add `--tls-mode off --tls-bundle-credential ''` — and
`--client-certs off` if you have turned them on — which leaves the bundle out
of the picture for this one run; the bundle itself is checked at step 7, from
the journal.

## 5. Name the first administrator

The relay decides who may administer it by a file of public keys, the way
`sshd` decides who may log in. Each administrator prints their own line on
their own machine:

```
auu init --name bunty --relay https://relay.example.com:9443 --anchor HASH
auu id export
```

with `HASH` as `auu-ca init` printed it in step 3a. That pins the relay's
anchor, without which no connection to it can be verified: its certificate is
under your own authority, and no system root knows it. An identity that
already exists pins with `auu anchor pin HASH` instead, and keeps the export
line you have already put on the relay.

An administrator does not have to be a user of the relay, so there is no
`register` step and no chicken-and-egg. Put the line in the file on the server:

```
install -o root -g root -m 0644 /dev/null /etc/auu/admins
editor /etc/auu/admins
```

```
# /etc/auu/admins
ccx2.<base64>.bunty
```

The file must not be writable by group or others — anyone who can write it can
appoint themselves — and the relay refuses to start if it is. The relay loads
it at start and re-reads it whenever it changes, so adding or removing an
administrator later is an edit, not a restart; the journal shows
`administrators loaded count=1` at start and `administrators reloaded count=N`
at each edit, which is also how you would notice an edit that was not yours.

## 6. Install the unit and start it

```
install -o root -g root -m 0644 auu-relay.service /etc/systemd/system/auu-relay.service
systemctl daemon-reload
systemctl enable --now auu-relay
systemctl status auu-relay
```

with `auu-relay.service` being `docs/systemd/auu-relay.service`. What it does,
so that you can judge any change to it:

- **`LoadCredentialEncrypted=relay-bundle:/etc/auu/relay-bundle.cred`**: at
  start, systemd unseals the bundle from step 3a into a directory only this
  service can see, and tells the relay where in `$CREDENTIALS_DIRECTORY`. The
  ID before the colon is the one `systemd-creds encrypt --name=` was given and
  the one `relay.json` names; all three must agree, and a test in the
  repository holds the two shipped files to it. The credentials directory is
  inside the service's own mount namespace and needs no `ReadOnlyPaths=`.
- **`User=auu`** with **`AmbientCapabilities=CAP_NET_BIND_SERVICE`**: ports 80
  and 443 are bound with one capability, and nothing runs as root.
- **`StateDirectory=auu`** at mode `0700`: systemd creates `/var/lib/auu`,
  owns it for the service, and makes it the only writable path. The database,
  the database and the message files live under it.
- **`ProtectSystem=strict`** with **`ProtectHome=true`**: the rest of the
  filesystem is read-only. `/etc/auu` is readable, which is all the relay ever
  does with it.
- **`RestrictAddressFamilies=AF_INET AF_INET6`**: it can open network sockets
  and nothing else.
- **`TimeoutStopSec=30`**: on `stop` the relay finishes the requests it is
  handling and then exits; systemd waits that long before killing it. A
  listing a watcher asked the relay to hold open is answered first, with
  what it has, so a stop never waits on one.

If the host runs a firewall, open the port: with ufw, `ufw allow 9443/tcp`;
with firewalld, `firewall-cmd --permanent --add-port=9443/tcp &&
firewall-cmd --reload`; or the equivalent nftables rule. Nothing here needs
80 or 443.

## 7. Check it

```
journalctl -u auu-relay -f
```

The first lines say what registration mode it is in, how many administrators
it found, and its limits. The `relay starting` line says where the bundle
came from:

```
journalctl -u auu-relay | grep bundle_source
```

expecting `bundle_source=credential`, with `cert=` naming a path under
`/run/credentials/auu-relay.service/`. Three names have to agree, and each
way they can disagree fails differently. If the relay did not start at all
and the journal says `CREDENTIALS_DIRECTORY is not set`, the unit is missing
its `LoadCredentialEncrypted=` line. If it says `no such file or directory`
under that directory, the ID in the unit and `tls.bundle_credential` in
`relay.json` differ. If the relay never ran and systemd itself says `Failed
to set up credentials: Protocol error` and `status=243/CREDENTIALS`, the
name the file was sealed under (`systemd-creds encrypt --name=`) and the ID
in the unit differ; seal it again under the right one. Then, from anywhere:

```
curl -v https://relay.example.com:9443/v1/health
```

The first request after a start takes a few seconds, because that is when the
certificate is fetched; after that it is instant. `/v1/health` is exempt from
every rate limit, so monitoring can hit it as often as it likes. From the
administrator's machine:

```
auu-admin status
```

That request is signed with the administrator's key and answered only if the
line in `/etc/auu/admins` matches. A `403` means the export line and the file
disagree; check for a stray character.

## 8. Invite the first user

```
auu-admin token issue --note "Bob, protocol review" --expires 168h
```

Send Bob the token however you like, and point him at
[`docs/enrolling.md`](enrolling.md), which takes him from installing Go to a
second machine. On his machine:

```
auu enrol --name bob TOKEN
```

That creates his identity and his mailbox in one step, with the relay
recorded in his settings. After that he swaps export lines with the people he
wants to talk to, exactly as in the README's quick start; a token gets you a
mailbox and says nothing about who is safe to talk to.

## Client certificates

With `"client_certs": {"mode": "required"}`, the relay issues each machine a
certificate from the client signing intermediate in its bundle — the same
bundle it serves TLS from, so there is nothing more to create and nothing more
to back up. It logs the anchor, and when the intermediates expire, at startup:

```
journalctl -u auu-relay | grep -e "auu-ca bundle" -e "client certificates required"
```

The ML-DSA parameter set is the authority's, chosen once by `auu-ca init
--mldsa` — 44, 65 or 87, default 65 — and every machine's key must match it.
Changing it means a new authority and every machine enrolling again.

A lost or stolen signing intermediate is not a disaster: run the pipeline
from step 3a again on your own machine and restart the relay, as *Day two*
describes, and every machine already enrolled keeps working. Only the
`auu-ca` directory needs backing up.

Enrolment is unchanged for the first machine: a `register` token creates the
mailbox and the certificate together, in one step. Switching certificates on
for a relay that already has users costs each of them one such token: their
next command says a certificate is missing, and `auu register --token TOKEN`
with an ordinary `register` token issues it, because a mailbox with no live
certificate is enrolling, not adding a machine. Nothing else has to be redone.
A user's *second* machine needs a token of its own:

```
auu-admin certs ls                     # who has how many machines
auu-admin token issue --use cert --for FINGERPRINT --note "Bob's desktop"
auu-admin certs revoke SERIAL --reason "laptop stolen"
```

A revocation takes effect on that machine's very next request. There is no
list to distribute: every request already looks the caller up, and the
certificate's serial is looked up beside it.

## Day two

**Logs** go to the journal. `journalctl -u auu-relay --since today` for a
look, `-p warning` for only what went wrong. One line per request in the
access log, at the detail `access_log` allows. A line for `GET
/v1/mailbox/{fp}` with `status=200` and a `dur=` of many seconds — `dur=30s`
or thereabouts, never above a minute — is a listing the relay held open for
a watcher until mail arrived or the hold ran out, not a stalled request: a
stall is cut off by the timeouts and shows as an error, and a held listing
is a watcher's ordinary request answered late on purpose. One that says
`limit=waiting` on the same `status=200` line was asked to be held and
answered at once instead, because `max_waiting` listings were already
held, or two were already held for that identity.

**Once a year**, the relay's signing intermediates expire. `auu-ca show` on
your own machine says when — and asks for no passphrase, so checking the date
costs nothing. For the last sixty days the relay says so in the journal once a
day. The renewal is the same as issuing was, needs the authority's passphrase,
and nobody re-enrols:

```
auu-ca relay --host relay.example.com --out relay-bundle.json
scp relay-bundle.json you@relay.example.com:
ssh -t you@relay.example.com 'sudo systemd-creds encrypt --name=relay-bundle relay-bundle.json \
  /etc/auu/relay-bundle.cred && rm relay-bundle.json && sudo systemctl restart auu-relay'
rm relay-bundle.json
```

The same steps as the first time, then a restart: the relay unseals the new
credential at start and nothing is cached anywhere. Do the same, without
waiting, if you think the relay has been compromised. A relay installed
from a kit rotates the same way, or with a new kit: `auu-ca kit` for the
host again issues fresh intermediates, and `sh install.sh update` seals
them over the old credential and restarts.

**Upgrading** is a new kit and one word:

```
sudo sh auu-relay-kit/install.sh update
```

with the kit made, copied and unpacked as in *The short way*; `auu-ca kit`
prints the recipe with `update` in it when it already knows the host.
`update` stops the relay and copies its database, binary, unit, settings,
administrators and credential into `/var/lib/auu/backups/<time>/`, with a
`RESTORE` file there holding the commands that put each back; it never
puts them back itself, and the backups are yours to remove. Then it
replaces the binary and the unit, seals the kit's bundle over the old
credential when the kit has one, and replaces `relay.json` and `admins`
only if you have not edited them since the last kit: the script keeps
`/etc/auu/kit.manifest`, the last kit's file list with hashes, so "edited
since" is a hash it can check. An edited file is kept, the kit's copy is
written beside it as `/etc/auu/relay.json.kit` or `/etc/auu/admins.kit`,
and the script says so, so a limit you raised or an administrator you
added survives an upgrade and the kit's version is there to compare. A
kit that names no administrator never replaces an `admins` that names
one. Every step of `update` is idempotent — the user made if missing, the
directories made if missing, the unit put back if gone — so the same
command repairs a relay whose unit or binary has gone, or one that
systemd has stopped restarting, and a kit whose bundle has already been
sealed can be run again. `update` is for a relay installed from a kit or
in the credential form; a plain-file relay takes the guide's manual
upgrade below — on one, `update` stops at the settings check after the
stop, naming the cause, with the backup lines.

Without a kit, upgrading is replacing the binary and restarting:

```
install -o root -g root -m 0755 auu-relay /usr/local/bin/auu-relay
systemctl restart auu-relay
```

Either way the relay migrates its own database on start and says so in the
log, as `database migrated` with `from=` and `to=`; the script prints that
line through. Take the backup below before an upgrade that mentions a
schema change — `update` takes one of the database itself, but not of
the message files, which an update does not touch.

The release that added channels takes the database from schema version 5 to
6. It rebuilds the `messages` and `uploads` tables to record the channel a
message was posted to, filing every existing row under `default`, and adds
the two tables that hold the directories owners push. Mail in flight, the
counters and the message id sequence are untouched, and the change runs in
one transaction, so a restart that dies part way leaves the old version to
be migrated at the next start. Nothing changes for anyone until an owner
pushes a directory.

**Backups** are small, because the relay holds only what is in transit and
cannot read any of it. What is worth keeping is the `auu-ca` directory on your
own machine, from which the relay's bundle can always be reissued. What is
worth keeping on the server is `/var/lib/auu` — if you want mail in flight to
survive a rebuild — as `relay.db` and `messages/` **together**. One without
the other is an index pointing at files that are not there; the relay repairs
that at the next start by dropping the rows, but the mail is gone. The other
way round, `messages/` without `relay.db`, is a lost database, and the relay
refuses to start rather than sweep the mail away: the log says
`/var/lib/auu/relay.db is new but /var/lib/auu/messages holds mail for 2
mailboxes: the database was lost`, and you either restore `relay.db` from the
backup or move `messages/` aside to start the relay empty. The database is in
WAL mode, so copy it with the service stopped, or with
`sqlite3 /var/lib/auu/relay.db ".backup /root/relay.db"` (`apt install
sqlite3`, or `dnf install sqlite`), which is safe while it runs.

What a copy of the server's disk yields, now that the bundle is a sealed
credential: with the credential sealed to the host key alone, the bundle is
recoverable by anyone holding both `/etc/auu/relay-bundle.cred` and
`/var/lib/systemd/credential.secret` — so back up `/etc/auu` freely, and
never back up `/var/lib/systemd/credential.secret`, which systemd itself says
not to. With a TPM2 in the machine, the bundle is recoverable on that machine
and no other, and a disk image is certificates and ciphertext. What neither
protects against is root on the running relay, or the relay process's own
memory; those were never in scope, and the disposable intermediates are the
answer to them — rotate, as above.

**Limits** are the defaults in the README's *Limits* table unless the settings
say otherwise, and at those defaults a two gigabyte file is refused. If your
users send large things, raise `limits.post_bytes_per_hour` and
`limits.mailbox_max_bytes`; both are per person, so they are a decision about
how much of the disk one person may fill. Watch `df /var/lib/auu` — every
message is a file there until it is collected. A user's mail now stays after
they have read it, until they remove it with `auu rm`: a channel keeps its
mail unless its owner says otherwise, which is what lets their second machine
read the same mail, so `limits.mailbox_max_messages` and
`limits.mailbox_max_bytes` are what a mailbox holds rather than what is in
flight, and both may want raising. A sender refused for a full mailbox is
told the recipient must run `auu rm`.

**Removing a relay** is `systemctl disable --now auu-relay`, then
`rm -r /var/lib/auu /etc/auu /etc/systemd/system/auu-relay.service` and
`userdel auu`. Users' identities are on their own machines and
unaffected; only mail still in transit is lost.
