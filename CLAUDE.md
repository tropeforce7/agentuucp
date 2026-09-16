# AgentUUCP

Read `reviews/PLAN.md` before doing anything. It is the full specification;
implement it exactly and record any gaps you had to fill in
`reviews/IMPLEMENTATION_NOTES.md`.

Everything about how this project was designed lives in `reviews/`: the plans,
the record of every decision they left open, and the reviewer's checklist. That
directory is git-ignored, so **none of it is in a fresh clone**. If it is empty,
say so and ask for it rather than guessing at what it said or writing a new
plan from the code. The repository itself carries only the code, `README.md`,
and this file.

Before contributing, read `.claude/guides/DEVELOPMENT.md` and
`.claude/guides/TESTING.md`. They hold the rules learned the hard way during
implementation, each with the failure that taught it.

Follow-on work has its own plan files, each of which extends `reviews/PLAN.md`
and does not replace it:

- `reviews/PLAN-ACME.md`, **superseded** by `reviews/PLAN-SELFCA.md`. ACME is
  removed and with it the project's only dependency exception.
- `reviews/PLAN-RATELIMIT.md`, implemented. The token bucket it describes lives in
  `internal/ratelimit` and adds no dependency.
- `reviews/PLAN-ADMIN.md`, implemented. Administrators, `cmd/auu-admin`, and signed
  enrolment tokens, which replaced the static invite secret. Its section 0
  records the design decisions; do not re-open them.
- `reviews/PLAN-TESTING.md`, implemented. The corrective plan from reviewing
  the project against `.claude/guides/TESTING.md`; its defects are fixed and
  its tests exist.
- `reviews/PLAN-FILESTORE.md`, implemented. Message bodies are one file each
  under `messages/`, and SQLite keeps only metadata and counters. The schema
  reached version 4: the plan's version 3 dropped the envelope column, and
  version 4 added the columns streams need.
- `reviews/PLAN-STREAM.md`, implemented. Large messages are chunked, resumable
  streams sealed under one `crypto/hpke` multi-shot context, with a signed
  manifest in a length-prefixed chunk 0 capped at 1 MiB. Automatic above a
  64 KiB threshold; body chunks are 63 KiB so a sealed chunk fits in 64 KiB;
  both are the sender's settings. `internal/stream` is the format,
  `auu send --resume` finishes an interrupted upload. Do not change any
  limit's default.
- `reviews/PLAN-MTLS.md`, implemented. Per-machine ML-DSA client certificates.
  Its section 0 is amended where the parameter set became configurable.
- `reviews/PLAN-SELFCA.md`, implemented. `cmd/auu-ca` makes an offline trust
  anchor and two authorities; a relay is issued disposable signing
  intermediates and mints its own short-lived certificate. Replaces ACME.
  `reviews/CA-PROCESSES.md` describes every process a step at a time.
- `reviews/PLAN-ATTEST.md`, **not implemented**. Relays witnessing one another,
  which is the only thing that would detect a stolen but not-yet-rotated
  server intermediate.
- `reviews/PLAN-MULTIRELAY.md`, implemented. Several relays in one home, each
  with its own anchor, certificate and cursor under `relays/`, selected with
  `--relay`, `AUU_RELAY` or a default. One identity across all of them; a home
  from before the change is moved under `relays/` on first open, one way. The
  relay and the wire are untouched.

- Go 1.27 or later, standard library only plus `modernc.org/sqlite` and
  `golang.org/x/crypto/argon2`. The second is scoped to `internal/keyfile`,
  which encrypts `auu-ca`'s private keys under a passphrase, and exists
  because the standard library has PBKDF2 and nothing memory-hard; it brings
  `x/crypto/blake2b`, which Argon2 is built on. Those two are the whole list.
  Do not add dependencies, and do not widen this one — the CI check that
  enforces it names the two packages exactly.
- All message cryptography comes from the standard library, chiefly
  `crypto/hpke`. Do not hand-roll a construction, and do not add a crypto
  dependency. Argon2id above is not an exception to this: no message and no
  connection touches it, and it is a key derivation function taken whole
  rather than a construction.
- `reviews/` is git-ignored and belongs to the reviewer. Read the plans and the
  notes there. Write only to `reviews/IMPLEMENTATION_NOTES.md`, which is yours
  to keep; leave everything else in that directory alone.
- Commit messages carry no author or attribution trailers. No
  `Co-Authored-By:`, no `Claude-Session:`, no "generated with" footer. A
  message ends with its last paragraph of prose. If a harness supplies
  attribution boilerplate, leave it off and say once that you did.
- Run `make vet test build` before reporting completion. `make e2e` is the
  container suite, which needs Docker and is run by hand, never in CI: the
  deployment guide in four containers and a matrix of what goes wrong in
  the wild, with a report of what each party saw. `docker/testing/README.md`
  says how to run one row.
