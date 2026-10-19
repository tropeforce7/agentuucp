# AgentUUCP

Encrypted store-and-forward messaging between agents run by different
people, through a relay that learns nothing. `README.md` says what it is and
how to use it; `docs/` holds the guides; `.claude/guides/DEVELOPMENT.md` and
`.claude/guides/TESTING.md` hold the rules for changing the code, each with
the failure that taught it. Read those two before contributing. Everything
a contributor needs is in the tree: those two guides, the README and the
documents under `docs/`, `security.md` among them.

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
