#!/bin/sh
# install-check.sh: prove scripts/install.sh on a machine that has nothing.
#
# The CI job runs this, and so can anybody with docker. It checks the floor
# against go.mod, parses the script, runs shellcheck where there is one, and
# then does the whole of it inside ubuntu:24.04 — a machine with no curl, no
# git and no Go — five times over: an install from a checkout, the same
# again to prove it changes nothing, --relay to add the fourth binary, an
# unprivileged install that has to find the Go the first one put there and
# ends with the Claude Code skills under that user's home, and the same
# with --no-skills, which writes none.
#
# It writes nothing outside the container and its own temporary directory.
set -eu

here=$(cd "$(dirname "$0")/.." && pwd)
cd "$here"

say() { printf '%s\n' "$*"; }
fail() {
	echo "install-check.sh: $*" >&2
	exit 1
}

# 1. The floor in the script is go.mod's, exactly.
floor=$(sed -n 's/^go \([0-9]*\.[0-9]*\).*/\1/p' go.mod)
[ -n "$floor" ] || fail "no go directive in go.mod"
grep -q "^GO_MIN=$floor\$" scripts/install.sh ||
	fail "scripts/install.sh does not say GO_MIN=$floor, which is go.mod's floor"
say "ok: GO_MIN is $floor, as go.mod says"

# 2. It parses, and passes shellcheck where there is one.
sh -n scripts/install.sh || fail "scripts/install.sh does not parse"
say "ok: sh -n"
if command -v shellcheck >/dev/null 2>&1; then
	shellcheck -s sh scripts/install.sh || fail "shellcheck found the above"
	say "ok: shellcheck"
else
	say "no shellcheck here; the CI runner has one"
fi

# 3. The whole of it, on a machine with nothing.
command -v docker >/dev/null 2>&1 || fail "docker is not here, and the rest of this needs a machine with nothing on it"
say "running the five installs in ubuntu:24.04; the first downloads Go"

docker run -i --rm -v "$here:/src:ro" ubuntu:24.04 sh -s <<'CONTAINER'
set -eu
fail() { echo "FAILED: $*" >&2; exit 1; }
has() { grep -q -- "$2" "$1" || fail "$3"; }
hasnot() { grep -q -- "$2" "$1" && fail "$3" || true; }

# Only what the script's own refusal names. ubuntu:24.04 has tar and
# sha256sum and neither curl nor git.
apt-get update -qq >/dev/null
apt-get install -y -qq curl git ca-certificates >/dev/null
cp -a /src /work
cd /work

echo "--- 1. the refusal, before anything is installed ----------------------"
mv /usr/bin/git /usr/bin/git.hidden
if sh scripts/install.sh --from /work >/tmp/nogit 2>&1; then
	fail "it installed with no git"
fi
has /tmp/nogit "this host has no git" "the refusal does not name git"
has /tmp/nogit "apt-get install -y git" "the refusal does not give the apt line"
mv /usr/bin/git.hidden /usr/bin/git

echo "--- 2. the install, from a checkout -----------------------------------"
sh scripts/install.sh --from /work >/tmp/first 2>&1 || { cat /tmp/first; fail "the first install"; }
cat /tmp/first
has /tmp/first "downloading https://dl.google.com/go/" "Go was not downloaded"
has /tmp/first "sha256 ok" "the archive was not checked"
[ -x /usr/local/go/bin/go ] || fail "no go at /usr/local/go"
for t in auu auu-admin auu-ca; do
	[ -x "/usr/local/bin/$t" ] || fail "$t was not installed"
done
[ ! -e /usr/local/bin/auu-relay ] || fail "auu-relay was installed without --relay"
version=$(/usr/local/bin/auu version | awk '{print $2}')
case $version in
v*) ;;
*) fail "auu version says '$version', and a checkout with .git stamps a version" ;;
esac
[ "$(/usr/local/bin/auu-admin version | awk '{print $2}')" = "$version" ] ||
	fail "auu-admin is a different version from auu"
[ "$(/usr/local/bin/auu-ca version | awk '{print $2}')" = "$version" ] ||
	fail "auu-ca is a different version from auu"
# A fixed string, never a pattern: a pseudo-version carries a '+', which is
# repetition to grep -E.
grep -qF "auu: $version" /tmp/first || fail "the report does not say what auu is now"
# Root is told about the skills and given none: they are each person's.
has /tmp/first "the Claude Code skills are in the binary; each person runs 'auu skill install --target claude' once to have them" "root was not told about the skills"
[ ! -e /root/.claude/skills ] || fail "the root install wrote skills under /root"

echo "--- 3. the same again, which changes nothing --------------------------"
sh scripts/install.sh --from /work >/tmp/second 2>&1 || { cat /tmp/second; fail "the second install"; }
cat /tmp/second
hasnot /tmp/second "downloading https://dl.google.com/go/" "Go was downloaded a second time"
has /tmp/second "is new enough" "the second run did not say the Go it found was new enough"
for t in auu auu-admin auu-ca; do
	grep -qF "$t: already at $version" /tmp/second || fail "$t did not say it was already at $version"
done

echo "--- 4. --relay adds the fourth binary ---------------------------------"
sh scripts/install.sh --from /work --relay >/tmp/relay 2>&1 || { cat /tmp/relay; fail "the --relay install"; }
cat /tmp/relay
[ -x /usr/local/bin/auu-relay ] || fail "auu-relay was not installed with --relay"
/usr/local/bin/auu-relay --version | grep -q "schema" || fail "auu-relay --version does not say its schema"
grep -qF "auu-relay: $version (new)" /tmp/relay || fail "the report does not say auu-relay is new"

echo "--- 5. an unprivileged install, which finds the machine's Go ----------"
useradd -m tester
su tester -c 'sh /work/scripts/install.sh --from /work' >/tmp/tester 2>&1 || { cat /tmp/tester; fail "the unprivileged install"; }
cat /tmp/tester
hasnot /tmp/tester "downloading https://dl.google.com/go/" "it downloaded Go again for the unprivileged user"
has /tmp/tester "/usr/local/go/bin/go is new enough" "it did not find the machine's Go"
[ -x /home/tester/.local/bin/auu ] || fail "auu is not in the tester's ~/.local/bin"
[ -x /home/tester/.local/bin/auu-relay ] && fail "the tester got auu-relay without asking" || true
has /tmp/tester "is not on your PATH" "it did not say the PATH line"
has /tmp/tester "export PATH=\"/home/tester/.local/bin:\$PATH\"" "the PATH line is not the one to paste"
# And the skills, for that user, from the binary just installed.
has /tmp/tester "installed auu-connect, auu-setup and auu-relay in /home/tester/.claude/skills for Claude Code (auu $version)" "the skills were not installed for the tester"
has /tmp/tester "  auu-connect/SKILL.md: written" "the install did not say each file"
has /tmp/tester "for Codex, or another agent that reads ~/.agents, run 'auu skill install --target agents'" "the closing line does not name the agents command"
[ ! -e /home/tester/.agents ] || fail "the Claude Code install wrote under ~/.agents"
has /tmp/tester "the Claude Code skills are installed for tester under the directory above" "the closing line does not say whose skills they are"
for s in auu-connect auu-setup auu-relay; do
	[ -s "/home/tester/.claude/skills/$s/SKILL.md" ] || fail "no SKILL.md for $s under the tester's home"
	[ -s "/home/tester/.claude/skills/$s/reference.md" ] || fail "no reference.md for $s under the tester's home"
	cmp -s "/home/tester/.claude/skills/$s/SKILL.md" "/work/skill/$s/SKILL.md" || fail "$s's SKILL.md is not the tree's"
done
[ "$(stat -c %U /home/tester/.claude/skills/auu-connect/SKILL.md)" = tester ] || fail "the skills are not the tester's own"

echo "--- 6. --no-skills, which writes none ------------------------------------"
useradd -m nobody2
su nobody2 -c 'sh /work/scripts/install.sh --from /work --no-skills' >/tmp/noskills 2>&1 || { cat /tmp/noskills; fail "the --no-skills install"; }
cat /tmp/noskills
hasnot /tmp/noskills "skill" "--no-skills said something about skills"
[ ! -e /home/nobody2/.claude ] || fail "--no-skills wrote under the user's .claude"

echo "ALL OK"
CONTAINER

say "ok: the five installs"
