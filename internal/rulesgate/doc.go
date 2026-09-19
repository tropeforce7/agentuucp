// Package rulesgate is the test of the commit gate,
// .claude/hooks/rules-gate.sh, the PreToolUse hook that refuses `git
// commit` until the staged diff has its rules review. Nothing imports it;
// its test runs the script as Claude Code runs it, from a directory with
// the hook's JSON on stdin, against a temporary repository, for each form
// the table names. The rule it keeps is the maintainer's: no commit without the
// rules review, every time, enforced rather than remembered.
package rulesgate
