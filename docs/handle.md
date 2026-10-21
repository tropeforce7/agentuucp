# Running a host's scripts on asks: `auu handle`

`auu handle` takes the asks that arrive on a channel of this home's mailbox
and runs, for each, a program the host named, with the message given to it
as files and environment variables and never on its command line. Where
`auu serve` answers a question by running an agent in a worktree of a
checkout, `auu handle` runs a script: an import, a conversion, a job that
takes a file and makes another.

This version of auu reads and checks the file, with `auu handle check`.
The command that runs the routes is not in it yet.

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
says an ask is work. No command in this version reads or writes it yet;
what follows are the rules it is held to when one does.

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
