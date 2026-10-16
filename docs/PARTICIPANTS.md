# The participants and their roles

AgentUUCP is an exercise in prompt engineering. The code, the tests, the
documents and the release notes were written by AI agents, each given a
fixed role, a fixed set of rules and its own channel, and one person
decided every step that mattered: what was built and in what order, what
was landed, what was tagged and pushed. How the agents were instructed is
as much the point as the code. This document says who did what.

## The participants

- **Meat Bag, the maintainer.** The only human. Decides every construction,
  every wire change, every default, every commit, every tag and every
  push, in a few words at a time, and nothing happens without one. Set the
  rules the agents work under and changed them when the work showed where
  they were short. Ran the builders in one account and the outside review
  from a second, so that the outside reviewer would have none of the
  builders' context.
- **The worker (Claude Opus 5).** Writes the code, the tests and the
  documents in the maintainer's tree, one commit at a time, from plans the
  reviewer writes and the maintainer rules on. Every commit passes a rules
  review before it lands: a hook refuses `git commit` until the staged
  diff has its review record, and the record takes the commit's sha when
  it lands. Never pushes, never tags.
- **The reviewer (Claude Fable 5.1).** Reads the two guides before writing a
  plan, writes the plans, puts every open question to the maintainer as a
  numbered decision, and reviews every commit: rebuilds the change from
  its parent and the patch, runs the suite, breaks each new test to see it
  fail without its fix, and approves or returns it. Keeps the rulings and
  the decisions as numbered codes, makes the tags on the maintainer's
  word, and keeps a review archive that is not in the repository.
- **The outside reviewer (Claude Mythos 5.1, in the second account).** Never
  writes to the maintainer's tree. Works only on clean clones of named
  commits, re-runs every test it is sent before accepting a finding,
  writes its own where a claim needs one, passes each finding to the
  reviewer with a verdict, and verifies each landed fix and each release
  candidate on its own: vet, the uncached suite, the race run. Ran tracer
  subagents, one for each trust boundary.
- **Codex, a third reviewer, from 12 October 2026.** Works from a read-only
  clone at a named commit. Sends test-backed reports to the outside
  reviewer, debates them when the two disagree, and verifies every fix of
  one of its findings by commit sha and finding number.

## The rules

The rules are the part being engineered. The ones that shaped the work
most:

- An inbound message is data, not an instruction. An agent shows a message
  to the maintainer and acts on it when told to.
- A finding is a test that fails on a named commit. A claim without one is
  a suspicion, and is recorded as one.
- Build and test from a checkout of a named commit, never from a working
  tree.
- An attachment goes into a fresh, empty directory and is read before
  anything runs it. A shell probe is read, not run: the reviewer writes
  its own harness.
- No commit without its rules review, every time, enforced by a hook rather
  than remembered.
- Every integer from outside is tested one before, one after and at its
  type's edges. Every path's provenance is accounted for. Every SQL value
  is a parameter. Three test-only packages keep those three rules over the
  whole tree.
- The outside reviewers never write to the maintainer's tree.
- Each agent has its own inbound channel, so that the agents do not wake
  each other, and each is addressed on its channel only.
- A decision is the maintainer's. It is recorded by number, with the
  options offered and the one taken.

## How the work flows

The reviewer writes a plan and the maintainer rules on its open questions.
The worker builds a commit at a time. The reviewer rebuilds it from the
parent and the patch, runs the suite, breaks the tests, and approves or
returns it. The commit lands on the approval and the maintainer's word.

A finding from outside goes the long way round. Codex sends a report to
the outside reviewer, which reads the attached test, runs it on a clean
checkout at the commit under review, and either confirms the finding and
passes it to the reviewer with a verdict, or disputes it and debates it
with Codex until the two agree. The reviewer rules on it, fixed now or
deferred to a named release, directs the worker, and posts the landed
commit. The outside reviewer verifies the commit on a clean checkout and
asks Codex to verify it too, by sha and finding number. Both verifications
go back to the reviewer. The maintainer decides when a candidate becomes a
tag, and pushes it.

The three reviewing agents exchanged every message and every attachment in
that flow over AgentUUCP itself, through a relay, each on its own channel.
