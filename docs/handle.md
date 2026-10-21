# Running a host's scripts on asks: `auu handle`

`auu handle` takes the asks that arrive on a channel of this home's mailbox
and runs, for each, a program the host named, with the message given to it
as files and environment variables and never on its command line. Where
`auu serve` answers a question by running an agent in a worktree of a
checkout, `auu handle` runs a script: an import, a conversion, a job that
takes a file and makes another.

This version runs the routes a round at a time, with `auu handle run
--once`. A job runs to its end, but no reply is sent to the asker yet, and
the ask is not marked read: a host who runs it meanwhile sees the asks
taken into the ledger, their scripts run, and nothing else.

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
a route's name, a channel that is not a channel's, a thread or a reply
that is not a message's id, a state outside the eight, a sender that is
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
auu handle run --once [--backlog] [--config FILE] [--json]
```

is one round. It reads the file, holding it to every rule `check` holds it
to, and takes `handle/lock`, so there is one `handle run` in a home at a
time; another is refused, exit 2. It fetches from every relay, then
takes up the asks in the inbox, in the inbox's order, and runs the jobs
that are runnable now, each to the end of its attempt, and stops.

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
it. A parallel route's failure holds nothing. This version runs one job at
a time across every route; `max_parallel` and `workers_total` are read and
checked, and not yet used.

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
otherwise, or runs past the route's `timeout`, has failed, and the job is
in review, its reason the first line the script wrote on standard error;
each line it wrote there is copied to handle's own standard error, with
the route and the message's short id in front. A failure before the script
starts, such as files that will not unpack or a program not on the
`PATH`, is tried again at serve's backoff, up to the route's `retries`,
and is then in review without having run. An ask the owner removes from
the inbox is `removed`, whether its job was waiting or running; one whose
record is there and cannot be read is a failure, never a removal. A fault
of the host's, a directory that cannot be made or a ledger that cannot be
written, ends the run with the job where it was. A run that stops while a
job is being prepared leaves it `preparing`, and the next round prepares
it afresh from the inbox; a job a run left `running` is `interrupted`.
`--once` exits 1 when a job failed in its round.

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
