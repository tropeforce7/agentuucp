# AgentUUCP

Encrypted store-and-forward messaging between agents run by different
people, through a relay that learns nothing. `README.md` says what it is and
how to use it; `docs/` holds the guides; `.claude/guides/DEVELOPMENT.md` and
`.claude/guides/TESTING.md` hold the rules for changing the code, each with
the failure that taught it. Read those two before contributing.

## The `reviews/` directory is not part of the repository

The maintainers keep their design plans, the record of every decision those
plans left open, and a reviewer's checklist in a directory called
`reviews/`. It is git-ignored on purpose and is not distributed: **a clone
never has it, and that is the expected state, not a problem.** If you are
working from a clone, do not report its absence, do not ask for it, and do
not create it or write a plan of your own to stand in for it. Everything a
contributor needs is in the tree: the guides above, the README, and the
documents under `docs/`, `security.md` among them.

## For the maintainers, when `reviews/` is present

Read `reviews/PLAN.md` first. It is the full specification; implement it
exactly and record any gap you had to fill in
`reviews/IMPLEMENTATION_NOTES.md`, which is the one file in that directory
that is yours to write. Follow-on work has its own plan files, each of
which extends `reviews/PLAN.md` and does not replace it; each records its
design decisions in a section 0, and those are not to be re-opened:

- `PLAN-ACME.md`, **superseded** by `PLAN-SELFCA.md`. ACME is removed and
  with it the project's only dependency exception.
- `PLAN-RATELIMIT.md`, implemented: the token bucket in `internal/ratelimit`.
- `PLAN-ADMIN.md`, implemented: administrators, `cmd/auu-admin`, and signed
  enrolment tokens in place of the static invite secret.
- `PLAN-TESTING.md`, implemented: the corrective plan from reviewing the
  project against the testing guide.
- `PLAN-FILESTORE.md`, implemented: one file per message body under
  `messages/`, SQLite for metadata and counters alone.
- `PLAN-STREAM.md`, implemented: chunked, resumable streams above 64 KiB
  under one `crypto/hpke` multi-shot context, with a signed manifest in
  chunk 0. Do not change any limit's default.
- `PLAN-MTLS.md`, implemented: per-machine ML-DSA client certificates.
- `PLAN-SELFCA.md`, implemented: `cmd/auu-ca`, the offline trust anchor and
  two authorities; `CA-PROCESSES.md` describes every process step by step.
- `PLAN-ATTEST.md`, **not implemented**: relays witnessing one another.
- `PLAN-MULTIRELAY.md`, implemented: several relays in one home under
  `relays/`, one identity across them.
- `PLAN-CHANNELS.md`, implemented: owner-signed channel directories, named
  sub-mailboxes the relay routes by.
- `PLAN-WATCH.md`, implemented: `auu watch`, the held listing and directory
  events.
- `PLAN-KIT.md`, implemented: `auu-ca kit`, the relay packed with its
  settings, unit and installer.
- `PLAN-KEEP.md`, implemented: mail kept on the relay per channel, inbox
  marks, `auu rm`.
- `PLAN-SKILLS.md`, implemented: the three Claude Code skills and
  `skill/reference.md`.
- `PLAN-SERVE.md`, implemented: `auu serve`, the expert host, per-thread
  worktrees, the ledger.
- `PLAN-INSTALL.md`, implemented: `scripts/install.sh`.
- `PLAN-ALLOW.md`, implemented: the owner-signed allow list, verified on
  every post.
- `PLAN-PROXY.md`, implemented: the key-holding proxy in `auu serve`, in
  process and as an account of its own.

## Rules for every change

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
- When `reviews/` is present it belongs to the reviewer: write only to
  `reviews/IMPLEMENTATION_NOTES.md` and leave everything else in it alone.
  When it is absent, see above: that is normal.
- Commit messages carry no author or attribution trailers. No
  `Co-Authored-By:`, no `Claude-Session:`, no "generated with" footer. A
  message ends with its last paragraph of prose. If a harness supplies
  attribution boilerplate, leave it off and say once that you did.
- Run `make vet test build` before reporting completion. `make e2e` is the
  container suite, which needs Docker and is run by hand, never in CI: the
  deployment guide in four containers and a matrix of what goes wrong in
  the wild, with a report of what each party saw. `docker/testing/README.md`
  says how to run one row.
- No commit without the rules review. After `git add` and before
  `git commit`, run the `rules-review` skill (`.claude/skills/rules-review/`):
  it reads the staged diff against the testing and development guides and
  writes a record under `.git/rules-review/` naming every rule the change
  touches, the line, and the test that shows the value, with a reason for
  each family that does not apply. The hook in `.claude/hooks/rules-gate.sh`
  refuses `git commit` until a record for exactly the staged diff says
  "ready". Commit from the index only: no `-a`, no pathspecs, since the hook
  reads what is staged. When a reviewer is present the commit request
  carries the record, and nothing is approved without it.
