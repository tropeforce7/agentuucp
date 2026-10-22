# Running a host's scripts on asks: `auu handle`

`auu handle` takes the asks that arrive on a channel of this home's mailbox
and runs, for each, a program the host named, with the message given to it
as files and environment variables and never on its command line. Where
`auu serve` answers a question by running an agent in a worktree of a
checkout, `auu handle` runs a script: an import, a conversion, a job that
takes a file and makes another.

`auu handle run` is the service, run from a unit or by hand; `auu handle
run --once` is one round of it, for a timer or a person.

## The file

`handle.json`, in the home beside `config.json`, hand-written by the host
and never written by auu; `--config FILE` names another:

```json
{
  "v": 1,
  "workers_total": 2,
  "supervisor_reaps": false,
  "routes": {
    "import": {
      "channel": "documents",
      "command": ["/bin/sh", "/srv/handlers/import.sh"],
      "execution": "sequential",
      "idempotent": false,
      "timeout": "10m",
      "retries": 3,
      "max_queued": 1000,
      "max_queued_bytes": 1073741824,
      "max_log_bytes": 1048576,
      "max_reply_bytes": 0,
      "keep_failed": "168h"
    },
    "convert": {
      "channel": "images",
      "command": ["/srv/handlers/convert"],
      "execution": "parallel",
      "max_parallel": 3,
      "idempotent": true
    }
  }
}
```

The routes are keyed by the route's id, as `serve.json`'s channels are by
name. An id is a directory name under the home's `handle/`, so it is held
to the rule a channel name is held to, and is refused when it has the shape
of a message id, 32 hex characters. Two ids that are one directory where
case does not count are refused, and so are two that the disk under
`handle/` takes as one name, such as `é` written composed and decomposed on
macOS.

| field | what it is |
|-------|------------|
| `v` | **required.** `1`. |
| `workers_total` | How many jobs run at once across every route. Default `2`, which is also what `0` means; at most `64`, and no fewer than any route's `max_parallel`. |
| `supervisor_reaps` | The host's word that the service manager ends every process of the service with it, as systemd's default `KillMode=control-group` does. Default `false`. |
| `routes` | **required.** At least one route. A route written as `null` is refused by name. |

Each route:

| field | what it is |
|-------|------------|
| `channel` | **required.** The channel whose asks the route handles. It is held to the channel name rule. One channel belongs to one route, and a channel `serve.json` in the home serves cannot be a route's. A route on `default` is taken with a warning: a reply to one of its acknowledgements arrives on `default` too, and is left unhandled, as every reply is. |
| `command` | **required.** The program and its arguments, as a list, never through a shell. A first element with a separator in it is a path, and a relative one is relative to the file's own directory, not to the directory handle was started in; one with no separator is a name looked up on the `PATH`, so `["python3", "import.py"]` is a command. The program must be there as a regular file; no element may hold a NUL. Whether it can be run is not checked, since Windows has no executable bit; a program that cannot be run says so in its own words at its first attempt. |
| `execution` | `sequential` (the default), one job at a time in the order they were taken, or `parallel`. |
| `max_parallel` | How many of the route's jobs run at once. Default `1` for a sequential route, which can have no other, and `2` for a parallel one; `0` means the default; at most `64`. |
| `idempotent` | Whether an attempt that started and failed may be run again. Default `false`. |
| `timeout` | How long one attempt may take. Default `30m`. |
| `retries` | How many times a job is tried before it fails. Default `3`, and `0` means the same. |
| `max_queued` | How many of the route's jobs may wait. Default `1000`, and `0` means the same. |
| `max_queued_bytes` | How many bytes of the route's asks may wait. Default 1 GiB, and `0` means the same. |
| `max_log_bytes` | How much of a script's output is kept. Default 1 MiB, and `0` means the same; at least `4096`. |
| `max_reply_bytes` | How large a script's reply may be. Default `0`, which is no cap. |
| `keep_failed` | How long a failed job's files are kept. Default `168h`. |

A duration is Go's text for one, `30m`, `2h` or `168h`, and must be more
than nothing. A number below zero is refused by name, in every field. The
file is read strictly: a key it does not know, a key twice, two keys the
same under case folding and anything after the object are each refused, so
a misspelled setting is an error and not a route run otherwise than its
host wrote.

## Checking it

```
auu handle check [--config FILE]
```

reads the file, holds it to every rule above, and says what it would run,
without touching a key, a relay or the network: it is what a host runs
after editing the file. For each route, in the order of their ids, it
prints the channel and how the route runs, the command as written, the
program as resolved, the directory its jobs will be kept in, its retries
and whether it is idempotent, and its limits with the defaults filled in:

```
convert: channel "images", parallel, up to 3 at once
  command:  "/srv/handlers/convert"
  program:  /srv/handlers/convert
  jobs:     /home/host/.auu/handle/jobs/convert
  retries:  3, idempotent: a failed attempt is run again
  limits:   timeout 30m0s, max_queued 1000, max_queued_bytes 1073741824, max_log_bytes 1048576, max_reply_bytes no cap, keep_failed 168h0m0s
import: channel "documents", sequential
  command:  "/bin/sh" "/srv/handlers/import.sh"
  program:  /bin/sh
  jobs:     /home/host/.auu/handle/jobs/import
  retries:  3, not idempotent: a started attempt that fails is not run again
  limits:   timeout 10m0s, max_queued 1000, max_queued_bytes 1073741824, max_log_bytes 1048576, max_reply_bytes no cap, keep_failed 168h0m0s

workers_total 2, supervisor_reaps no

/home/host/.auu/handle.json is good for 2 routes
```

A file that breaks a rule is refused, exit 1, in one sentence naming the
file, the route and what is wrong, and nothing is printed on standard
output. On standard error, check says which routes' channels keep their
mail on the relay, which every channel does unless its owner says
otherwise, and names `auu channel keep NAME off`, as `auu serve check`
does.

## What it keeps

`handle/ledger.json` in the home is handle's record of every job it has
taken, one per ask, keyed by the message's id, with a number for each
admission and a state: `queued`, `preparing`, `running`, `succeeded`,
`failed`, `interrupted`, `skipped` or `removed`. It is the only thing that
says an ask is work. `auu handle run` reads it at its start and writes it
before and after every step a job takes.

It is read strictly. A ledger that is there and will not read, or that
breaks one of its rules, is refused by name and never replaced: a key it
does not know, a job that is not under a message's id, a route that is not
a route's name, a channel that is not a channel's, a thread, a reply or a
second reply that is not a message's id, a route's revision that is not
sixteen lowercase hex characters, a state outside the eight, a sender that is
not a fingerprint, a job said to be skipped by anyone but `first-start`
or `operator`, or by either when it is not skipped, a count below zero,
an admission's number spent twice or not below `next_seq`, or an attempt
counted with no start. The sentence ends `it is the record of
every job handle has taken, so fix it or move it aside knowing that the
asks in the inbox are then met as at a first start: skipped, or run again
with --backlog`. A job the ledger has as `running` when it is read is
`interrupted`, since the run that started it is gone.

## Running it

```
auu handle run [--once] [--backlog] [--config FILE] [--json]
```

runs rounds until it is stopped, holding on the relays between them;
with `--once` it runs one round and stops. It reads the file first,
holding it to every rule `check` holds it to, and takes `handle/lock`, so
there is one `handle run` in a home at a time; another is refused, exit
2. Every reply originates, so a home under a passphrase needs the agent
unlocked to send, `auu unlock --send --ttl 0`, which lasts until `auu
lock`; locked, or unlocked only to receive, the run is refused at exit 4
before anything is fetched. A round fetches from every relay, takes up
the asks in the inbox, in the inbox's order, and runs the jobs that are
runnable now, each to the end of its attempt.

Only asks are a route's work: a message of type `ask`, on a route's
channel, that has no job yet. Every reply, note, acknowledgement and
vouch is left alone, whoever sent it, so no loop can form between a handle
and a serve, or two handles; a stranger's message is in quarantine and
never in the inbox. A stream waiting on the relay for a newer auu is
neither taken nor skipped, and is said once a run; the round after the
upgrade brings it in and takes it.

**A route's first round.** A route that has never run, or that has been
moved to another channel, is at its first round on its channel. Every ask
already in the inbox there, those the round's own fetch brought among
them, is written down as skipped by the first start and left alone, and
one sentence says how many, so that a route set up today does not run a
year of mail at once. `--backlog` runs them instead, and is refused when
no route in the file is at its first round.

**The order.** Each ask taken is given the next admission number, `seq`,
and a route's jobs run in that order whatever happens to the records
after. A sequential route runs one job at a time: a job that failed for
review is its head, and the jobs behind it wait until the operator moves
it. A parallel route's failure holds nothing, and it runs up to its
`max_parallel` jobs at once, each in an attempt directory of its own. No
more than `workers_total` scripts run at once across every route, and the
routes are offered a worker in turn, in the order of their ids, one job
each, so that a busy route does not take every worker from the others. A
job whose retry is not yet due holds no worker.

**A job's files.** A job has two directories:

```
handle/jobs/<route>/<message id>/
  original/                  the asker's files, unpacked once and checked against their digests
  message.json  body.txt     the job's own, attempt 0
  attempt-1/
    input/message.json       this attempt's
    input/body.txt
    input/attachments/       a fresh copy of original/
    work/                    the working directory, empty
    tmp-XXXXXXXX/            the attempt's temporary directory
      output/
      output/attachments/
handle/kept/<route>/<message id>/
  stdout-1.txt  stderr-1.txt the attempt's two streams
```

The script is told the first and never the second. It runs in `work/`,
with the body on standard input, `message.json` naming the message field
by field, and these in its environment, as well as `AUU_MESSAGE_ID`,
`AUU_THREAD_ID`, `AUU_IN_REPLY_TO`, `AUU_TYPE`, `AUU_FROM`,
`AUU_FROM_NAME`, `AUU_RECIPIENTS`, `AUU_CHANNEL`, `AUU_RELAY` and
`AUU_SUBJECT` as serve gives them:

| variable | what it is |
|---|---|
| `AUU_JOB_ID` | `ROUTE/MESSAGE-ID` |
| `AUU_ATTEMPT` | the attempt's number, from 1 |
| `AUU_ATTACHMENTS` | the attempt's `input/attachments`, or empty for a message with none |
| `AUU_MESSAGE_JSON` | the attempt's `input/message.json` |
| `AUU_WORK_DIR` | `work/` |
| `AUU_TEMP_DIR` | the attempt's `tmp-XXXXXXXX/`, which `TMPDIR` names too (and `TMP` and `TEMP` on Windows) |
| `AUU_OUTPUT_DIR` | its `output/` |
| `AUU_OUTPUT_ATTACHMENTS` | its `output/attachments/` |

`ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN` and `ANTHROPIC_BASE_URL` are
never passed on, and handle says once at its start when its environment
has them. `message.json` is written with every key present: `attachments`
lists each file by the sender's name, the name it was written under and
the path of this attempt's copy, with its media type, size and SHA-256.
`time` is the sender's stamp and `arrived` this machine's.

Nothing from the message is ever on the command line: the command is the
program and the arguments the file gives, run with no shell, and what the
message says reaches the script as files and variables alone. That is a
promise about the command line and no more: a script that puts a variable
into a command of its own puts the sender's words there. A POSIX shell
script quotes every one (`"$AUU_SUBJECT"`) and never `eval`s one, and a
Windows batch file, which expands `%AUU_SUBJECT%` as text before it parses
the line, reads them with delayed expansion (`!AUU_SUBJECT!`) or from
`message.json` instead. A program named without a separator is looked up
on the `PATH` at each launch.

**How a job ends.** A script that exits 0 has succeeded. One that exits
otherwise, or runs past the route's `timeout`, has failed, its reason the
first line the script wrote on standard error; each line it wrote there is
copied to handle's own standard error, with the route and the message's
short id in front. A started attempt may have done its work before it
failed, so on a route that is not `idempotent` a failed job is in review
at once and never run again. On an `idempotent` route it is run again at
serve's backoff, a fresh copy of the asker's files given to each attempt,
up to the route's `retries` attempts in all, and the last is in review. A
retry is decided again when it is due, under the file as it is then: a
route made not `idempotent`, or given fewer `retries`, since the failure
does not run the job again, and it is in review. A failure before the script
starts, such as files that will not unpack or a program not on the
`PATH`, is tried again at serve's backoff, up to the route's `retries`,
and is then in review without having run. An ask the owner removes from
the inbox is `removed`, whether its job was waiting or running; one whose
record is there and cannot be read is a failure, never a removal. A fault
of the host's, a directory that cannot be made or a ledger that cannot be
written, ends the run with the job where it was. A run that stops while a
job is being prepared leaves it `preparing`, and the next round prepares
it afresh from the inbox.

**Interruption and the stop.** `SIGTERM` or an interrupt stops a run: the
script that is running is killed with everything it started, handle waits
for them, and the job is written `interrupted`, killed by the service's
own stop, before the run ends, exit 0. There is no grace period: a script
that needs to finish what it began has its route's `timeout` for that. A
run that went away without stopping, killed from outside or with its
machine, leaves its job `running`, and the next start finds it and writes
it `interrupted`, not killed by the service. At the next round an
interrupted job on an `idempotent` route with attempts left is queued
again only when its script is known gone: the service's own stop killed
it, or `supervisor_reaps` is set, the host's word that the service manager
ends every process of the service with it, as systemd's default
`KillMode=control-group` does. `supervisor_reaps` is read from the file
as it is at that round, and is the host's word about the service as it
ran: set it only for a service whose manager ended the group when it
went. Every other interrupted job is in review, its reason saying why. A
child that calls `setsid` leaves the group and outlives every kill, the
service's own stop's included. A stop that comes before a job's script
has started leaves the job queued, with no attempt counted.

**Between rounds.** The service holds on every relay for mail on its
routes' channels, and on nothing else: an ask on a channel no route takes
does not wake it. The hold also ends when the earliest retry, failure
before launch or reply whose send failed falls due, counting on a
sequential route only its head, never sooner than one of serve's
intervals from now; and when a new operator's request, a `.json` file,
lands in `handle/ops/`, which it looks for every two seconds. A round fetches
first, so mail that arrived while it held is taken up whatever woke it. A
fetch that reaches no relay is said once, and the service waits for one
to come back; under `--once` it is the round's failure, exit 2.

`--once` exits 1 when a job failed in its round. Either form exits 0 when
stopped, 1 for a file that will not check, 2 when another `handle run`
holds the home, and 4 when the keys are locked or unlocked only to
receive, at the start or when that happens under the running service; in
that last case the job's reply is kept and the next run sends it without
running the script again. With `--json` the service writes one line for
each round that did something, the round's `skipped` and `jobs`.

**The reply.** Each job that ends, succeeded or failed for review, gets one
reply, on the ask's thread, to the ask's verified sender, by the relay it
came through. Its first line is handle's, and says how the job ended and
which attempt of how many the route allows for that kind of end; a
started attempt on a route that is not `idempotent` is one of one:

```
handle: succeeded (exit 0, attempt 1 of 1)
handle: failed (exit 3, attempt 1 of 1)
handle: failed (timeout after 10m0s, attempt 1 of 1)
handle: failed (interrupted, attempt 1 of 1)
handle: failed (could not prepare: the files it sent could not be unpacked: …, attempt 3 of 3)
handle: skipped by the operator (exit 3, attempt 1 of 3)
handle: skipped by the operator (not run)
handle: succeeded (exit 0, attempt 2, run again by the operator)
```

A failure before the script started names where in the home it failed as
`AUU_HOME`, and a program that could not be started is called the route's
program, never by where the home or the program is on this machine, since
the line goes to the asker.

When the script left `reply.txt` in its `output/` directory, a blank line
and its text follow, with Windows line endings folded. The file is read
once, after every process the script started has been killed, from the
attempt's own `output/` whatever the script has done to its name, as a
regular file and never through a link, no more than the route's
`max_reply_bytes`, and held to the text rule a message's words are held
to; one that fails any of these is left out, and the line `the script's
reply.txt was not included: REASON` follows the first instead. The job's
outcome stands whatever the script wrote. What the script printed on its
two streams is a log, and never a reply. A run that stops between a job's
end and the composing of its reply has kept nothing the script wrote; the
next round sends the first line with `the script's reply.txt and files
were not kept: the run stopped before they were`.

**Files back.** Every regular file the script leaves in
`output/attachments/` is attached to the reply, under its own name, in
name order, so two runs agree. Each is copied into handle's own directory
for the job when the reply is composed, and the reply is sealed from
those copies, so nothing the script, or anything it left running, does
afterwards changes what is sent. A file whose name the sender's rule
would refuse (a control character, a separator, a leading dot, a Windows
device name such as `CON`), one whose name is another's where case does
not count, a directory, and a link are each left out, and the reply says
so in a line of its own naming the file and why. The route's
`max_reply_bytes` bounds the script's text and its files together: files
are taken in name order while the whole stays within it, and one that
would pass it is left out and said. An empty `output/attachments/`
attaches nothing and says nothing. A reply over the stream threshold goes
as a stream; one the asker's relay refuses, a channel that takes no
streams or a full mailbox, is the reply's failure, tried again as any
other.

A script that puts a file of the account's into `output/attachments/` by
a hard link sends it: a hard link is the file it names, and the script
runs as the account. Contain a script that must not be able to send what
the account can read, as the paragraph below says.

The reply is composed once, into handle's own directory for the job, and
sealed once: a send that fails is tried again from what was kept, never
from anything the script can reach, and one that may have reached the
relay goes again as the same message under the same id, so the asker
holds one reply. A send that fails, the asker no longer a peer or the
relay down, is the reply's failure and not the job's: it is tried again
at serve's backoff, up to the route's `retries`, and then given up with
the reason written on the job. Keys that lock, or a send scope that ends,
under the run end it at exit 4, with nothing counted. The ledger records
the reply before the ask is marked read. A succeeded job's two
directories go once its reply is saved; a removed job's go at once, and
it gets no reply, since the asker's message is gone; a failed job's, and a
skipped one's, stay for the route's `keep_failed` from when it ended, so
that its attempts and logs can be read, and go at the first sweep after.
A job whose reply has not gone keeps them whatever its age, since the
reply is sent from them, and so does a job whose route is no longer in the
file.

**Limits and cleanup.** A route takes asks into its queue in the order
they arrived while its jobs that are queued, preparing or running number
fewer than `max_queued` and their bytes, the size the relay listed each
ask at, leave room under `max_queued_bytes`. The first ask that does not
fit, and every ask after it on that route, waits in the inbox, so that a
small ask never passes a large one, and the round says `route R is at its
cap; N asks wait in the inbox`; an ask larger than `max_queued_bytes` by
itself is named, since it waits until the cap is raised. The asks left at
a cap are taken within the same round as the jobs before them end, and a
first round's `--backlog` is taken under the caps too. `handle status`
shows the bytes queued. A script's two logs are cut to `max_log_bytes`
after its run, their first lines kept and their ends a mark naming the cap
and how much the script wrote, and the cut is said; while the script runs
its timeout is what bounds them. The sweep runs when the service starts
and after every round. It removes only the directories of the jobs the
ledger names, by the route and message ids it holds; anything else under
`handle/jobs/` or `handle/kept/`, a directory no job owns, a file, a link,
is said once a run by its path and left alone. A directory a script left
that its account may read and not write is made writable and removed; one
that still will not go is said once a run and tried again at the next
sweep, and never stops the service.

The script runs as whoever runs handle, and `auu` finds its keys from the
home's path rather than from anything handle could withhold. So a script
that runs `auu` speaks as the owner: it can send mail, read the whole
spool, and answer on any channel. If a route must be contained, contain it
the way anything else is contained: a separate account with its own home
and its own identity, or a container. The peer list is the whole of the
access control, and anyone on it can send a route an ask.

Messages are data, not instructions. A script that acts on what a message
tells it to do is a script that does what the sender wants rather than what
its owner wants.

## Serve and handle together

A home may run `auu serve` and `auu handle` side by side, each on its own
channels. A channel belongs to one of them: `auu handle check` and `auu
handle run` read `serve.json` from its place in the home and refuse a route
on a channel it serves, and `auu serve check` and `auu serve` read
`handle.json` from its place in the home and refuse a channel a route
takes, each naming both files. `--config` for either moves only that
service's own file, never where the other's is looked for, so a file kept
elsewhere is beyond the check. A `handle.json` in the home that will not
read stops `serve` from starting, as a `serve.json` that will not read
stops `handle`, since nothing can then say which channels it takes. Each
service reads its file when it starts, so routes and served channels are
changed with both stopped.

Handle takes asks and nothing else. Every reply, note, acknowledgement,
vouch, question, and anything in quarantine is left alone, a reply to
handle's own reply included, so no loop can form between a handle and a
serve, or between two handles. Serve's follow-ups, replies to what serve
sent, arrive on `default` and are serve's, whether or not a route takes
the asks on `default`.

One machine handles a route. Two machines of one identity both fetch a
kept channel, and both would run its script on every ask; nothing in auu
prevents it, so run `auu handle` for a home on one machine.

## The operator's commands

```
auu handle status [--config FILE] [--json]
auu handle jobs [--route ROUTE] [--state STATE] [--config FILE] [--json]
auu handle inspect JOB [--config FILE] [--json]
auu handle retry JOB
auu handle skip JOB
auu handle pause ROUTE
auu handle resume ROUTE
```

`JOB` is a job's message id, or four or more of its first characters.
`status`, `jobs` and `inspect` read the file and the ledger and nothing
else, so they answer while a service runs. `status` says whether a service
holds the home, and for each route its channel, how it runs, whether it is
paused, its jobs counted by state, when the oldest queued one arrived, the
attempts running and since when, the next retry, the job in review that
holds a sequential route with its reason, and how many replies could not
be sent. `jobs` is one line per job in admission order. `inspect` is one
job whole: its entry, the attempt directories still there, each attempt's
two logs with their first line, and its replies. A reason, a log's line
and a revision are shown escaped, since a script or a message may have
shaped them.

`retry`, `skip`, `pause` and `resume` change the ledger. With no service
running, the command takes the home's lock and changes it at once, saying
what it did. With a service running, it writes the request as a file
under `handle/ops/` and says it is queued for the running service, which
applies it at the start of its next round; the file landing ends the
service's hold, so that is within a few seconds. A request the round
cannot read as one is moved to `handle/ops/damaged/` and said; one it
reads and refuses is said and removed. Requests are applied in the order
they were made.

- `retry` runs a `failed` or `interrupted` job again, the operator's word
  letting it run once more whatever the route allows. A job whose reply
  could not be sent, its sends spent, has the reply sent again instead,
  and its script is not run again. A retry of a job whose reply has gone
  sends nothing more while it fails, and one more reply, saying the
  attempt was the operator's, if it then succeeds. The reply kept for the
  attempt before is removed, so the next is composed afresh; a retry of a
  job whose reply may be on the relay already, its answer lost, is refused
  until the next round has sent it. A retry of a job interrupted by a run
  that went away is the operator's word that its script is gone.
- `skip` ends a job that is not succeeded, skipped, removed or running,
  and its reply, saying how its last attempt ended or that it was not run,
  goes at the next round, unless one went already. A sequential route held
  by a job in review is moved on by its `retry` or its `skip`.
- `pause` holds a route's launches: its asks are taken into the ledger and
  none is run until `resume`. A route that has not had its first round has
  nothing to pause.
