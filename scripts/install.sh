#!/bin/sh
# install.sh: install or update the AgentUUCP tools on a Linux host, with Go
# if the host has none new enough to build them.
#
# Read it before you run it:
#
#   curl -fsSL -o install.sh https://raw.githubusercontent.com/tropeforce7/agentuucp/main/scripts/install.sh
#   less install.sh
#   sudo sh install.sh
#
# or, once you trust it, in one line:
#
#   curl -fsSL https://raw.githubusercontent.com/tropeforce7/agentuucp/main/scripts/install.sh | sudo sh
#
# From a checkout, building what is there rather than fetching a release:
#
#   sh scripts/install.sh --from .
#
# Run as root it installs for the machine, in /usr/local; run as anybody
# else it installs for them, in ~/.local. --prefix DIR puts both somewhere
# else. It installs auu, auu-admin and auu-ca; --relay adds auu-relay, which
# a relay's own host does not need — the kit carries that binary — but a
# host that builds kits does.
#
# The Claude Code skills are in the binary. Run as yourself, it ends by
# writing them under your ~/.claude/skills with 'auu skill install --target
# claude', and names the command for Codex's ~/.agents/skills; run as root
# it says that each person runs that once, since the skills belong to
# whoever runs Claude Code. --no-skills skips that either way.
#
# Running it again is how you update: it says what each tool was and what it
# is now, and leaves a Go that is already new enough alone.
set -eu

# GO_MIN is go.mod's floor. The install CI job holds this line equal to it.
GO_MIN=1.27
MODULE=github.com/tropeforce7/agentuucp

say() { printf '%s\n' "$*"; }
fail() {
	echo "install.sh: $*" >&2
	exit 1
}

# --- what was asked for -----------------------------------------------------

from=""
version=latest
prefix=""
relay=""
skills=yes
while [ $# -gt 0 ]; do
	case $1 in
	--from)
		[ $# -ge 2 ] || fail "--from wants a directory"
		from=$2
		shift 2
		;;
	--version)
		[ $# -ge 2 ] || fail "--version wants a tag, like v0.18.0"
		version=$2
		shift 2
		;;
	--prefix)
		[ $# -ge 2 ] || fail "--prefix wants a directory"
		prefix=$2
		shift 2
		;;
	--no-skills)
		skills=""
		shift
		;;
	--relay)
		relay=yes
		shift
		;;
	-h | --help)
		sed -n '2,31p' "$0" | sed 's/^# \{0,1\}//'
		exit 0
		;;
	*) fail "unknown option $1; run with --help" ;;
	esac
done

# --- the machine ------------------------------------------------------------

[ "$(uname -s)" = Linux ] || fail "this installs on Linux; on $(uname -s) use go.dev or Homebrew for Go and 'go install $MODULE/cmd/...@latest' for the tools"

case "$(uname -m)" in
x86_64) goarch=amd64 ;;
aarch64 | arm64) goarch=arm64 ;;
armv7l | armv6l) goarch=armv6l ;;
*) fail "unknown architecture $(uname -m): Go is published for x86_64, aarch64 and armv7l; install Go yourself from go.dev and run this again" ;;
esac

missing=""
for tool in tar sha256sum git; do
	command -v "$tool" >/dev/null 2>&1 || missing="$missing $tool"
done
if command -v curl >/dev/null 2>&1; then
	get() { curl -fsSL "$1"; }
	getto() { curl -fsSL -o "$2" "$1"; }
elif command -v wget >/dev/null 2>&1; then
	get() { wget -qO- "$1"; }
	getto() { wget -qO "$2" "$1"; }
else
	missing="$missing curl"
fi
# git is what 'go install' fetches a module with, sha256sum what checks the
# Go archive, tar what unpacks it; ca-certificates is why an https fetch can
# be trusted at all, and a container without it fails in curl rather than
# here.
[ -z "$missing" ] || fail "this host has no$missing; install them first:  apt-get install -y$missing ca-certificates"

# go install keeps its module cache and its build cache under HOME, so a run
# that arrives without one — a stripped environment, an odd sudoers — stops
# here rather than half way through a build.
[ -n "${HOME:-}" ] || fail "HOME is not set, and 'go install' needs it for its caches; run this with a HOME, or as root through 'sudo env HOME=/root sh'"
[ -w "$HOME" ] || fail "HOME ($HOME) is not writable, and 'go install' needs to write its caches there"

if [ -z "$prefix" ]; then
	if [ "$(id -u)" = 0 ]; then
		prefix=/usr/local
	else
		prefix=$HOME/.local
	fi
fi
godir=$prefix/go
bindir=$prefix/bin
mkdir -p "$bindir" || fail "cannot make $bindir; run as root, or pass --prefix DIR somewhere you can write"

# --- Go ---------------------------------------------------------------------

# goversion PATH: the x.y of a go binary, empty if it is not one.
goversion() {
	[ -x "$1" ] || return 0
	"$1" version 2>/dev/null | sed -n 's/^go version go\([0-9]*\.[0-9]*\).*/\1/p'
}
# atleast HAVE WANT: both x.y, compared as numbers rather than as text, so
# that 1.9 is not taken for more than 1.27.
atleast() {
	have_major=${1%%.*}
	have_minor=${1#*.}
	want_major=${2%%.*}
	want_minor=${2#*.}
	[ "$have_major" -gt "$want_major" ] ||
		{ [ "$have_major" -eq "$want_major" ] && [ "$have_minor" -ge "$want_minor" ]; }
}

go=""
for candidate in "$(command -v go 2>/dev/null || true)" "$godir/bin/go" /usr/local/go/bin/go; do
	[ -n "$candidate" ] || continue
	have=$(goversion "$candidate")
	[ -n "$have" ] || continue
	if atleast "$have" "$GO_MIN"; then
		go=$candidate
		say "go $have at $candidate is new enough (the floor is $GO_MIN)"
		break
	fi
	say "go $have at $candidate is below the floor of $GO_MIN"
done

if [ -z "$go" ]; then
	# Go would install a newer toolchain by itself when go.mod asks for one
	# it does not have, and do it inside the module cache where nobody can
	# see it. This is the same download made once, in a place the operator
	# can look at and update.
	latest=$(get 'https://go.dev/VERSION?m=text' | head -1) || fail "cannot reach go.dev to find the latest Go; install Go $GO_MIN or later yourself and run this again"
	case $latest in
	go[0-9]*) ;;
	*) fail "go.dev answered ${latest:-nothing} where a version was wanted; install Go $GO_MIN or later yourself and run this again" ;;
	esac
	number=${latest#go}
	short=$(printf '%s' "$number" | sed -n 's/^\([0-9]*\.[0-9]*\).*/\1/p')
	atleast "$short" "$GO_MIN" || fail "the latest Go is $latest and this needs $GO_MIN or later; nothing to do until Go catches up with go.mod"

	archive=$latest.linux-$goarch.tar.gz
	# dl.google.com, not go.dev/dl: the sidecar is a redirect there and
	# answers with a web page, which sha256sum cannot use.
	base=https://dl.google.com/go
	tmp=$(mktemp -d)
	trap 'rm -rf "$tmp"' EXIT INT TERM
	say "downloading $base/$archive"
	getto "$base/$archive" "$tmp/$archive" || fail "cannot download $base/$archive"
	want=$(get "$base/$archive.sha256") || fail "cannot download $base/$archive.sha256, so the archive cannot be checked"
	# The sidecar is the hash alone, with no file name in it, so the line
	# sha256sum checks is made here.
	printf '%s  %s\n' "$want" "$tmp/$archive" | sha256sum -c --quiet - || fail "$archive is not what dl.google.com says it is; nothing was installed"
	say "sha256 ok; unpacking into $godir"
	rm -rf "$godir"
	mkdir -p "$prefix"
	tar -C "$prefix" -xzf "$tmp/$archive" || fail "cannot unpack $archive into $prefix"
	rm -rf "$tmp"
	trap - EXIT INT TERM
	go=$godir/bin/go
	have=$(goversion "$go")
	[ -n "$have" ] || fail "$go does not run after unpacking; $prefix may be on a filesystem mounted noexec"
	say "go $have installed at $godir"
fi

# --- the tools --------------------------------------------------------------

# toolversion NAME: what the installed binary says it is, or nothing.
toolversion() {
	[ -x "$bindir/$1" ] || return 0
	case $1 in
	auu-relay) "$bindir/$1" --version 2>/dev/null | awk '{print $2}' ;;
	*) "$bindir/$1" version 2>/dev/null | awk '{print $2}' ;;
	esac
}

tools="auu auu-admin auu-ca"
[ -z "$relay" ] || tools="$tools auu-relay"

# What is there now, before anything is built: four names, taken one at a
# time rather than through eval, since there are four of them and always
# will be.
was_auu=$(toolversion auu)
was_auu_admin=$(toolversion auu-admin)
was_auu_ca=$(toolversion auu-ca)
was_auu_relay=$(toolversion auu-relay)

set --
if [ -n "$from" ]; then
	[ -f "$from/go.mod" ] || fail "$from is not the agentuucp checkout: no go.mod in it"
	cd "$from"
	for tool in $tools; do set -- "$@" "./cmd/$tool"; done
	say "building $tools from $from"
else
	for tool in $tools; do set -- "$@" "$MODULE/cmd/$tool@$version"; done
	say "installing $tools from $MODULE at $version"
fi

# Whatever git has to be told is told to it for this one command and no
# further: nothing is written to a config file, and nothing of it is left in
# the environment afterwards.
if [ -n "$from" ]; then
	# A checkout somebody else owns — root building in a user's tree, a
	# user building in one root unpacked — is what git calls dubious
	# ownership, and it refuses to read it. 'go install' then cannot stamp
	# the version and stops with "error obtaining VCS status". Naming this
	# one directory safe, for this one command, is narrower than the
	# 'git config --global safe.directory' the message suggests and leaves
	# nothing behind.
	GOBIN=$bindir CGO_ENABLED=0 \
		GIT_CONFIG_COUNT=1 \
		GIT_CONFIG_KEY_0=safe.directory \
		GIT_CONFIG_VALUE_0="$PWD" \
		"$go" install -trimpath "$@" || fail "the build failed; the sentence above says why"
else
	GOBIN=$bindir CGO_ENABLED=0 \
		"$go" install -trimpath "$@" || fail "the build failed; the sentence above says why"
fi

# --- what changed -----------------------------------------------------------

dirty=""
for tool in $tools; do
	case $tool in
	auu) before=$was_auu ;;
	auu-admin) before=$was_auu_admin ;;
	auu-ca) before=$was_auu_ca ;;
	auu-relay) before=$was_auu_relay ;;
	*) before="" ;;
	esac
	now=$(toolversion "$tool")
	case $now in *+dirty) dirty=yes ;; esac
	case "$before:$now" in
	:*) say "$tool: $now (new)" ;;
	*) if [ "$before" = "$now" ]; then
		say "$tool: already at $now"
	else
		say "$tool: $now (was $before)"
	fi ;;
	esac
done

say ""
say "installed in $bindir"
if [ -n "$dirty" ]; then
	say "the version ends in +dirty: the copy they were built from had local changes."
fi
case ":$PATH:" in
*":$bindir:"*) ;;
*) say "$bindir is not on your PATH. Add it:  export PATH=\"$bindir:\$PATH\"" ;;
esac

# --- the skills ---------------------------------------------------------------

# The Claude Code skills are in the binary, and belong to whoever runs
# Claude Code: written out for the person running this, and not for root,
# whose home is nobody's. A file that person has edited is kept and named
# by auu itself, which is not a failed install.
if [ -z "$skills" ]; then
	:
elif [ "$(id -u)" = 0 ]; then
	say ""
	say "the Claude Code skills are in the binary; each person runs 'auu skill install --target claude' once to have them"
else
	say ""
	# The target is given: this is the Claude Code install, and it runs
	# from curl | sh with no terminal to ask at.
	if "$bindir/auu" skill install --target claude; then
		say "the Claude Code skills are installed for $(id -un) under the directory above"
		say "for Codex, or another agent that reads ~/.agents, run 'auu skill install --target agents'"
	else
		say "the Claude Code skills were not all installed; the lines above say which file and why"
	fi
fi
