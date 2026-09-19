---
name: rules-review
description: Read a staged change against the testing and development guides before it is committed, and write the record the commit hook requires. Run it after `git add` and before every `git commit`, with no exceptions for small or documentation-only changes.
---

# Rules review

A change is committed only after it has been read against the rules in
`.claude/guides/TESTING.md` and `.claude/guides/DEVELOPMENT.md`, and the
reading has been written down. This skill is that reading. The commit hook
in `.claude/hooks/rules-gate.sh` refuses `git commit` until a record exists
for exactly the diff that is staged, and says "ready".

The rules exist because each was learned from a fault that shipped: a
number from the wire multiplied before it was bounded, a name sliced before
its rule ran, a path built from a string the network chose. A change that
reintroduces one of those is dangerous to the people who run this software,
whatever else it does well. So the reading is done every time, by the
person making the change, before anyone else sees it.

## Procedure

1. **Take the diff as it will commit.** `git diff --cached` is the change;
   `git status --short` says what is staged. For a `git commit --amend`
   the change is `git diff --cached HEAD^`, the whole commit that will
   result. Nothing outside the index is part of this review. If the diff
   is empty, stop: there is nothing to commit.

2. **Say what the change touches.** For every hunk, write one line: the
   file and line, and which of these it does, if any:
   - takes a value from the network (a request, a header, a listing, a
     manifest, an envelope, a relay answer), from a file the run did not
     write, from an operator's argument or configuration, or from a clock
     the sender set;
   - converts a string to a number, or a number between widths;
   - adds, subtracts, multiplies, shifts, indexes or `make`s from a number
     that came from outside;
   - slices, compares, folds, prints, logs, echoes or embeds a string that
     came from outside;
   - builds a path, opens, creates, renames, removes or lists a file;
   - builds or runs SQL;
   - counts against a quota or a limit;
   - orders or compares by time;
   - decides authorization, signature verification or the order of checks.
   A hunk that does none of these is written down as such, with the reason
   ("renames a local variable", "prose in docs/relay.md").

3. **Read the rules against that list.** Open the guide sections and read
   them in full each time; the headlines below are a checklist so nothing
   is skipped, not a substitute.

   `TESTING.md`, "What the network names":
   - nothing the network names is a path until its rule has run;
   - a query's text is a constant;
   - every file operation's path has a row in the ledger;
   - a name has one rule, both ends run it, on every path;
   - a string from the network is never sliced before its rule has run;
   - what a filesystem folds is refused;
   - a count against a quota is one arithmetic in one helper;
   - a limit keyed on a string the sender chose is not a limit;
   - housekeeping never waits on a sender;
   - a number from the network is bounded before it is multiplied or
     allocated from;
   - a message's own words are held to a rule at Validate and escaped again
     at the terminal;
   - nothing is ordered by a clock the sender set.

   `TESTING.md`, "The ways an integer goes wrong": a sum of two claimed
   values; a difference either way round; a multiplication by a unit; a
   count times a size; a narrowing conversion; an unsigned subtraction; a
   running counter below zero; a loop bound from the wire; a slice index or
   `make` from a number; a shift by a wire value; a database integer; time.

   `TESTING.md`, "The ways a string goes wrong": it is UTF-8; it is one
   line, or it is a name; bytes are not characters; two names are two
   names; it is a base name; it has a shape; it is a number written down;
   it is a secret; it is echoed; it goes into another syntax; empty means
   something; it is a prefix.

   `DEVELOPMENT.md`: "Ordering of checks", "Network input", "Storage" (the
   provenance rule for every path and the parameter rule for every value
   reaching SQL), "Signatures and tokens".

   For each rule that applies to a line in step 2, write the rule, the
   line, and **the test that shows the value**: an existing test by name,
   or one added in this change. A rule that applies with no test is a
   finding, and the change is not ready until the test exists and the
   value it uses is the one the guide names (the edge one step apart, MIN
   and MAX, the bit flipped, the name that folds).

   For each family that does not apply, one line with the reason. "Not
   applicable" alone is not a reason.

   A change that adds an integer from outside, a string cut under a range
   or a file opened by a path that is not local adds its row to the limit
   ledger (`internal/limits/ledger.txt`, or the file-open ledger for a
   path) and its `TestLimit` test in the same change, and the record
   names both; the ledger's test fails until they exist.

4. **Run the enforcement tests**, whatever the change:

       go test ./internal/fileopens ./internal/sqlshape ./internal/limits ./internal/auu -run 'TestEveryFileOpenHasItsProvenanceInTheLedger|TestEveryQueryIsAConstant|TestEveryIntegerFromOutsideHasItsLimitTest|TestNothingTheNetworkNamesIsAPath'

   and `make vet test build`. `make limits` runs every limit test on its
   own. Record the result.

5. **Second reader, when a Go file or a script changed.** The
   `security-review` skill reads the commits on the branch, not the index,
   so it sees a staged change only once it is committed. For the change
   that is staged, do what that skill does: give a fresh reader, a
   sub-agent, the skill's objective, its categories and exclusions, and
   the diff from step 1, and have it filter its own findings for false
   positives; the record says that this was the reading. Every finding it
   returns gets a disposition in the record: fixed in this change, or not
   a finding with the line that shows why, or deferred with the plan it is
   deferred to and the reviewer's word that it may be. A finding without a
   disposition makes the change not ready.

6. **Write the record** to `.git/rules-review/<hash>.md`, where `<hash>` is
   the first sixteen hex characters of `sha256` over the diff from step 1.
   Do not compute it by hand: `.claude/hooks/rules-gate.sh --hash` prints
   it, `--hash --amend` for an amend, and `--record` in place of `--hash`
   prints the path to write, so the record is named by the same arithmetic
   the hook checks it with. `.git/` is never committed, so the record
   travels with the clone and not with the tree. The record has these
   headings, in this order, and ends with a verdict line:

       # Rules review: <one sentence, what the change is>
       Diff: <hash>, <n> files
       ## What the change touches
       ## Rules that apply, each with its line and its test
       ## Families read and not applicable, each with its reason
       ## Enforcement tests and make vet test build
       ## Second reader
       Verdict: ready

   `Verdict: ready` is written only when every rule that applies has its
   test and every finding has its disposition. Otherwise `Verdict: not
   ready` and the list of what is missing; fix, re-stage, and run this
   skill again (the hash changes with the diff).

7. **Send the record with the commit request.** When a reviewer is present
   (`reviews/` exists), the commit request carries the record in full,
   after the changed files, the commit message, the tests added and the
   break record. The reviewer reads it against the diff and does not
   approve without it.

## What this is not

It is not a substitute for the tests. A record that names a rule and no
test is a record of a gap. It is not a formality for small changes: the
change that added a retract line to go.mod was read too, and its record
said why no family applied. And it is not the reviewer's job: the reviewer
checks the record, and a record the reviewer has to write is a change that
was not ready.

It is not something a clone runs by itself: the hook is named in
`.claude/settings.json`, and Claude Code runs a project's hooks only after
the person has trusted the directory, which it asks on first open, so a
contributor who sees that dialog is being asked whether this gate may run.
