#!/bin/sh
# rules-gate.sh refuses `git commit` until the staged diff has its rules
# review. It is the PreToolUse hook on the Bash tool that
# .claude/settings.json names, and it can be run by hand:
#
#     .claude/hooks/rules-gate.sh --hash [--amend]      the hash of the diff
#     .claude/hooks/rules-gate.sh --record [--amend]    the path of its record
#
# As a hook it reads Claude Code's JSON from stdin and looks at two fields,
# tool_name and tool_input.command. A tool that is not Bash passes. The
# command is read the way sh reads it, not searched as text: words are
# split on blanks; single quotes, double quotes and backslashes quote;
# `;`, `&&`, `||`, `|`, `&`, a newline, `(` and `)` end a simple command;
# a `$( )` or a backtick substitution is read as commands of its own,
# inside double quotes too, and stands in its word as a mark the gate
# cannot read past; `#` starts a comment; a here-document's body is
# skipped up to its delimiter; a redirection is not a word. So
# `echo "git commit"` is not a commit, a commit message that mentions -a
# is not -a, and `git add x && git commit` is two commands. A string
# handed to `sh -c`, `bash -c` or `eval` is read the same way, in place.
# Variables, globs and `~` are not expanded: a directory named by one
# cannot be entered, and the gate refuses rather than guess.
#
# A simple command is a commit when, after leading assignments and any of
# command, exec, env, nice, nohup, time, sudo and doas, its first word is
# git by base name and git's own options (-C, -c, --git-dir, ...) are
# followed by the word commit. Then:
#
#   - -a, --all, --include, --only, --interactive, --patch, a pathspec (a
#     word that is not an option, or anything after --) and
#     --pathspec-from-file are refused: the gate reads the index, so the
#     commit must be the index.
#   - Nothing but cd may run before the commit in the same call: the gate
#     reads the index when the call starts, and the commit reads it later.
#     A GIT_ variable in front of git is refused for the same reason.
#   - The command word of a simple command, and git's subcommand, must be
#     literal words: one that carries a $ or a backtick, or that a $( )
#     or a backtick substitution is part of, or a git subcommand absent
#     after git's options, or a -C, --git-dir or --work-tree whose value
#     is not literal, is refused, since the gate does not expand and the
#     shell does. `x=commit; git $x`, `git $(echo commit)`, `g=git; $g
#     commit`, `$(echo git) commit` and `git -C $(pwd) commit` each ran a
#     commit past the gate as "not a commit" before this, and
#     `echo "$(git commit -m x)"` ran one the gate never read.
#   - The command does not choose how the gate runs git: of git's own
#     options only -C, --git-dir and --work-tree reach the gate's calls,
#     and those calls turn off core.fsmonitor, external diff and textconv,
#     the config keys that name a command for git to run, which a -c or a
#     repository's own config could otherwise set. The gate runs before
#     the person is asked about the command, so nothing in it may run.
#   - An empty diff passes, and git says "nothing to commit".
#   - Otherwise the record <git-dir>/rules-review/<hash>.md must exist and
#     its last non-blank line must be exactly "Verdict: ready", where
#     <hash> is the first sixteen hex characters of SHA-256 over
#     `git diff --cached`, which --hash prints.
#   - --amend is gated over the commit that will result: its diff is
#     `git diff --cached HEAD^`, which --hash --amend prints. A message-only
#     amend so hashes to the record the commit was gated on; an amend that
#     adds work needs a record over the whole. An amend of a commit with
#     no parent is refused.
#
# A refusal is exit 2 with its sentence on stderr, which is what the hook
# contract reads (code.claude.com/docs/en/hooks). A pass is exit 0 and no
# output. If stdin cannot be read as the hook's JSON, the gate does not
# fail open: input whose text has the word "commit" in it, in any case,
# is refused with a sentence saying it could not be read, and any other
# is let through with a line on stderr saying so, since a gate that
# misread its input would otherwise stop every command; internal/rulesgate
# proves the reading on the documented shape and both answers on input
# off it.

say() { printf '%s\n' "$*" >&2; }
refuse() { say "$*"; exit 2; }
# printable is a value the gate repeats in a sentence, a directory from
# the command or a line from the record, with any control byte made a
# question mark, so that what reaches a terminal is text.
printable() { printf '%s' "$1" | LC_ALL=C tr '\000-\037\177' '?'; }

# hash_of_diff prints the hash of the diff the commit will make: the
# index against HEAD, or against HEAD^ when $base says so for an amend.
# $@ are git's own options from the command, -C and the like, so the gate
# reads the index the commit would.
base=''
hash_of_diff() {
	if command -v sha256sum >/dev/null 2>&1; then
		safegit "$@" -c core.pager=cat diff --cached --no-color --no-ext-diff --no-textconv ${base:+"$base"} | sha256sum | cut -c1-16
	else
		safegit "$@" -c core.pager=cat diff --cached --no-color --no-ext-diff --no-textconv ${base:+"$base"} | shasum -a 256 | cut -c1-16
	fi
}

# safegit is git as the gate runs it: core.fsmonitor off, since that key
# names a command git runs whenever it reads the index and a repository's
# own config could set it (a -c on the command line wins over the config
# files, and the command's own -c no longer reaches the gate); then the
# command's -C, --git-dir and --work-tree, then the gate's subcommand. The
# diffs above add --no-ext-diff and --no-textconv for the other two keys
# that name a command.
safegit() {
	git -c core.fsmonitor=false "$@"
}

usage() {
	say "usage: rules-gate.sh [--hash | --record] [--amend]; with no argument it is the PreToolUse hook and reads JSON on stdin"
	exit 64
}

case ${1-} in
--hash|--record)
	case ${2-} in
	--amend) base='HEAD^' ;;
	'') ;;
	*) usage ;;
	esac
	[ $# -le 2 ] || usage
	gitdir=$(safegit rev-parse --absolute-git-dir) || exit 1
	if [ -n "$base" ]; then
		safegit rev-parse --verify -q "$base" >/dev/null || { say "HEAD has no parent to amend against"; exit 1; }
	fi
	hash=$(hash_of_diff)
	if [ "$1" = --hash ]; then
		printf '%s\n' "$hash"
	else
		printf '%s\n' "$gitdir/rules-review/$hash.md"
	fi
	exit 0
	;;
'') ;;
*) usage ;;
esac

# The reading is one awk program: the JSON, then the command as sh reads
# it, then each simple command. It prints one decision line, PASS,
# NOINPUT, "REFUSE <sentence>" or "COMMIT <0|1 for --amend>", and after
# COMMIT a line "G <option>" for each of git's own options in the command
# and "D <dir>" for the last cd before it. Single quotes are written \047
# because the program sits in one.
program='
function hex4(h,    i, v, c) {
	v = 0
	for (i = 1; i <= 4; i++) {
		c = index("0123456789abcdef", tolower(substr(h, i, 1)))
		if (c == 0) { jbad = 1; return 0 }
		v = v * 16 + c - 1
	}
	return v
}
function utf8(c) {
	if (c == 0) return ""
	if (c < 128) return sprintf("%c", c)
	if (c < 2048) return sprintf("%c%c", 192 + int(c / 64), 128 + c % 64)
	if (c < 65536) return sprintf("%c%c%c", 224 + int(c / 4096), 128 + int(c / 64) % 64, 128 + c % 64)
	return sprintf("%c%c%c%c", 240 + int(c / 262144), 128 + int(c / 4096) % 64, 128 + int(c / 64) % 64, 128 + c % 64)
}
function ws() {
	while (p <= n) {
		c = substr(S, p, 1)
		if (c == " " || c == "\t" || c == "\n" || c == "\r") p++
		else break
	}
}
# jstring reads the JSON string whose opening quote is at p and returns
# its value with every escape decoded.
function jstring(    out, c, code, lo) {
	p++
	out = ""
	while (p <= n) {
		c = substr(S, p, 1)
		if (c == "\"") { p++; return out }
		if (c == "\\") {
			p++
			c = substr(S, p, 1)
			if (c == "n") out = out "\n"
			else if (c == "t") out = out "\t"
			else if (c == "r") out = out "\r"
			else if (c == "b") out = out "\b"
			else if (c == "f") out = out "\f"
			else if (c == "u") {
				code = hex4(substr(S, p + 1, 4)); p += 4
				if (code >= 55296 && code <= 56319 && substr(S, p + 1, 2) == "\\u") {
					lo = hex4(substr(S, p + 3, 4)); p += 6
					code = 65536 + (code - 55296) * 1024 + (lo - 56320)
				}
				out = out utf8(code)
			}
			else out = out c
			p++
			continue
		}
		out = out c
		p++
	}
	jbad = 1
	return out
}
# jvalue reads one JSON value at p and keeps the two strings the gate
# wants, by their path.
function jvalue(path,    c, key, v) {
	ws()
	c = substr(S, p, 1)
	if (c == "{") {
		p++; ws()
		if (substr(S, p, 1) == "}") { p++; return }
		while (p <= n) {
			ws()
			if (substr(S, p, 1) != "\"") { jbad = 1; return }
			key = jstring()
			ws()
			if (substr(S, p, 1) != ":") { jbad = 1; return }
			p++
			jvalue((path == "") ? key : (path "." key))
			if (jbad) return
			ws()
			c = substr(S, p, 1)
			if (c == ",") { p++; continue }
			if (c == "}") { p++; return }
			jbad = 1; return
		}
		jbad = 1; return
	}
	if (c == "[") {
		p++; ws()
		if (substr(S, p, 1) == "]") { p++; return }
		while (p <= n) {
			jvalue(path "[]")
			if (jbad) return
			ws()
			c = substr(S, p, 1)
			if (c == ",") { p++; continue }
			if (c == "]") { p++; return }
			jbad = 1; return
		}
		jbad = 1; return
	}
	if (c == "\"") {
		v = jstring()
		if (path == "tool_name") tool = v
		else if (path == "tool_input.command") { cmd = v; havecmd = 1 }
		return
	}
	if (c == "") { jbad = 1; return }
	while (p <= n) {
		c = substr(S, p, 1)
		if (c == "," || c == "}" || c == "]" || c == " " || c == "\t" || c == "\n" || c == "\r") break
		p++
	}
}

function base(w) { sub(/.*\//, "", w); return w }
function isreserved(w) {
	return w == "if" || w == "then" || w == "else" || w == "elif" || w == "fi" || w == "while" || w == "until" || w == "do" || w == "done" || w == "esac" || w == "{" || w == "}" || w == "!"
}
function isredir(w) { return w ~ /^[0-9]*[<>]/ || w ~ /^&>/ }
function refuse(s) { if (verdict != "REFUSE") { verdict = "REFUSE"; reason = s } }
# addword records a word and whether it is literal: one carrying a $ or a
# backtick is not, a substitution having left its mark in it or a
# variable standing in it, and the gate does not expand either.
function addword(w) { NWORD++; WORD[NWORD] = w; CUT[NWORD] = (w ~ /[$`]/) }
function flush(    A, C, k, i) {
	k = NWORD
	for (i = 1; i <= k; i++) { A[i] = WORD[i]; C[i] = CUT[i] }
	NWORD = 0
	if (k > 0) analyse(A, C, k)
}

# closeparen is the index of the ) that closes the $( at i, read as sh
# reads it: quotes and backslashes skipped over, ( and ) nested; L + 1
# when the text ends first, so an unclosed substitution runs to the end.
function closeparen(s, i, L,    d, c, q, j) {
	d = 1; q = ""; j = i + 2
	while (j <= L) {
		c = substr(s, j, 1)
		if (q == "\047") { if (c == "\047") q = ""; j++; continue }
		if (q == "\"") {
			if (c == "\\") { j += 2; continue }
			if (c == "\"") q = ""
			j++; continue
		}
		if (c == "\\") { j += 2; continue }
		if (c == "\047" || c == "\"") { q = c; j++; continue }
		if (c == "(") d++
		else if (c == ")") { d--; if (d == 0) return j }
		j++
	}
	return L + 1
}

# closetick is the index of the backtick that closes the one at i, a
# backslash escaping the next character; L + 1 when the text ends first.
function closetick(s, i, L,    c, j) {
	j = i + 1
	while (j <= L) {
		c = substr(s, j, 1)
		if (c == "\\") { j += 2; continue }
		if (c == "`") return j
		j++
	}
	return L + 1
}

# inner reads the text of a substitution as commands of its own, in their
# place in the sequence, with the words of the command around it put
# aside and restored: a commit inside $( ) is the commit the shell runs.
function inner(s,    SW, SC, sn, i) {
	sn = NWORD
	for (i = 1; i <= sn; i++) { SW[i] = WORD[i]; SC[i] = CUT[i] }
	NWORD = 0
	scan(s)
	for (i = 1; i <= sn; i++) { WORD[i] = SW[i]; CUT[i] = SC[i] }
	NWORD = sn
}

# scan reads s as sh would, handing each simple command to analyse as it
# ends, in order. A string given to sh -c or eval is scanned from inside
# analyse, so its commands take their place in the sequence.
function scan(s,    i, L, c, d, q, w, inw, nh, hd, hs, k, t, line, j) {
	L = length(s); i = 1; q = ""; w = ""; inw = 0; nh = 0
	while (i <= L) {
		c = substr(s, i, 1)
		if (q == "\047") {
			if (c == "\047") q = ""; else w = w c
			i++; continue
		}
		if (q == "\"") {
			if (c == "$" && substr(s, i + 1, 1) == "(") {
				j = closeparen(s, i, L)
				inner(substr(s, i + 2, j - i - 2))
				w = w "$("; i = j + 1; continue
			}
			if (c == "`") {
				j = closetick(s, i, L)
				inner(substr(s, i + 1, j - i - 1))
				w = w "`"; i = j + 1; continue
			}
			if (c == "\"") q = ""
			else if (c == "\\") {
				d = substr(s, i + 1, 1)
				if (d == "\"" || d == "\\" || d == "$" || d == "`") { w = w d; i++ }
				else if (d == "\n") i++
				else w = w c
			}
			else w = w c
			i++; continue
		}
		if (c == "\047" || c == "\"") { q = c; inw = 1; i++; continue }
		if (c == "\\") {
			d = substr(s, i + 1, 1)
			if (d != "\n") { w = w d; inw = 1 }
			i += 2; continue
		}
		if (c == " " || c == "\t") {
			if (inw) { addword(w); w = ""; inw = 0 }
			i++; continue
		}
		if (c == "#" && !inw) {
			while (i <= L && substr(s, i, 1) != "\n") i++
			continue
		}
		if (c == "\n") {
			if (inw) { addword(w); w = ""; inw = 0 }
			i++
			for (k = 1; k <= nh; k++) {
				while (i <= L) {
					t = index(substr(s, i), "\n")
					if (t == 0) { line = substr(s, i); i = L + 1 }
					else { line = substr(s, i, t - 1); i += t }
					if (HS[k]) sub(/^\t+/, "", line)
					if (line == HD[k]) break
				}
			}
			nh = 0
			flush()
			continue
		}
		if (c == "<" && substr(s, i + 1, 2) == "<<") {
			if (inw && w !~ /^[0-9]+$/) { addword(w) }
			w = ""; inw = 0
			i += 3
			while (substr(s, i, 1) == " " || substr(s, i, 1) == "\t") i++
			while (i <= L && substr(s, i, 1) !~ /[ \t\n;&|()]/) i++
			continue
		}
		if (c == "<" && substr(s, i + 1, 1) == "<") {
			if (inw && w !~ /^[0-9]+$/) { addword(w) }
			w = ""; inw = 0
			i += 2; hs = 0
			if (substr(s, i, 1) == "-") { hs = 1; i++ }
			while (substr(s, i, 1) == " " || substr(s, i, 1) == "\t") i++
			hd = ""
			while (i <= L) {
				c = substr(s, i, 1)
				if (c == "\047" || c == "\"") {
					t = index(substr(s, i + 1), c)
					if (t == 0) { hd = hd substr(s, i + 1); i = L + 1 }
					else { hd = hd substr(s, i + 1, t - 1); i += t + 1 }
					continue
				}
				if (c == "\\") { hd = hd substr(s, i + 1, 1); i += 2; continue }
				if (c ~ /[ \t\n;&|<>()]/) break
				hd = hd c; i++
			}
			nh++; HD[nh] = hd; HS[nh] = hs
			continue
		}
		if (c == "&" && substr(s, i + 1, 1) == ">") { w = w c; inw = 1; i++; continue }
		if (c == "&" && w ~ /[<>]$/) { w = w c; inw = 1; i++; continue }
		if (c == ";" || c == "|" || c == "&" || c == "(" || c == ")") {
			if (inw) { addword(w); w = ""; inw = 0 }
			flush()
			if ((c == "&" || c == "|") && substr(s, i + 1, 1) == c) i++
			i++; continue
		}
		# A substitution: its text is read as commands of its own, and it
		# leaves its mark in the word it is part of, which is then not a
		# word the gate can read as a command or a subcommand.
		if (c == "$" && substr(s, i + 1, 1) == "(") {
			j = closeparen(s, i, L)
			inner(substr(s, i + 2, j - i - 2))
			w = w "$("; inw = 1; i = j + 1; continue
		}
		if (c == "`") {
			j = closetick(s, i, L)
			inner(substr(s, i + 1, j - i - 1))
			w = w "`"; inw = 1; i = j + 1; continue
		}
		w = w c; inw = 1; i++
	}
	if (inw) addword(w)
	flush()
}

# analyse is one simple command, A[1..k], with C[1..k] saying which of
# its words are not literal.
function analyse(A, C, k,    i, j, name, str, gitvar) {
	i = 1
	gitvar = 0
	while (i <= k && (isreserved(A[i]) || A[i] ~ /^[A-Za-z_][A-Za-z0-9_]*=/)) {
		if (A[i] ~ /^GIT_/) gitvar = 1
		i++
	}
	while (i <= k) {
		name = base(A[i])
		if (name == "command" || name == "exec" || name == "env" || name == "nice" || name == "nohup" || name == "time" || name == "sudo" || name == "doas") {
			i++
			while (i <= k && (A[i] ~ /^-/ || A[i] ~ /^[A-Za-z_][A-Za-z0-9_]*=/)) {
				if (A[i] ~ /^GIT_/) gitvar = 1
				if (A[i] == "-u" || A[i] == "-C" || A[i] == "-S" || A[i] == "-g" || A[i] == "-n") i++
				i++
			}
			continue
		}
		break
	}
	if (i > k) return
	if (C[i]) { refuse(LITERAL); return }
	name = base(A[i])
	if (name == "cd") {
		if (verdict != "COMMIT") dir = (i + 1 <= k) ? A[i + 1] : ""
		return
	}
	if (name == "sh" || name == "bash" || name == "zsh" || name == "dash" || name == "ksh" || name == "mksh") {
		for (j = i + 1; j <= k; j++) {
			if (A[j] ~ /^-[A-Za-z]*c$/ && j + 1 <= k) { scan(A[j + 1]); return }
		}
		others++; return
	}
	if (name == "eval") {
		str = ""
		for (j = i + 1; j <= k; j++) str = str (j > i + 1 ? " " : "") A[j]
		scan(str); return
	}
	if (name != "git") { others++; return }
	if (gitvar) { others++; refuse(GITVAR); return }
	gitcommand(A, C, k, i + 1)
}

# gitcommand is a git command: its own options, then the subcommand. Of
# the options only the ones that say where the repository is, -C,
# --git-dir and --work-tree, are kept for the gate\047s own git calls: a
# -c can name a command for git to run (core.fsmonitor, diff.external),
# and --exec-path another git, and the gate does not let the command
# choose how the gate runs git.
function gitcommand(A, C, k, i,    w, name, j, ch, g, isamend) {
	g = 0
	while (i <= k) {
		w = A[i]
		if (w == "-C" || w == "--git-dir" || w == "--work-tree") {
			if (i + 1 > k || C[i + 1]) { refuse(LITERAL); return }
			GG[++g] = w; GG[++g] = A[i + 1]; i += 2; continue
		}
		if (w ~ /^--(git-dir|work-tree)=/) { if (C[i]) { refuse(LITERAL); return } GG[++g] = w; i++; continue }
		if (w == "-c" || w == "--namespace" || w == "--super-prefix" || w == "--config-env") {
			if (i + 1 > k) { others++; return }
			i += 2; continue
		}
		if (w ~ /^-/) { i++; continue }
		break
	}
	if (i > k || C[i]) { refuse(LITERAL); return }
	if (A[i] != "commit") { others++; return }
	if (others > 0) { refuse(ALONE); return }
	others++
	isamend = 0
	for (i++; i <= k; i++) {
		w = A[i]
		if (w == "--") {
			if (i < k) { refuse(INDEX); return }
			break
		}
		if (isredir(w)) {
			if (w ~ /[<>|&]$/) i++
			continue
		}
		if (w ~ /^--/) {
			name = w; sub(/=.*/, "", name)
			if (name == "--all" || name == "--include" || name == "--only" || name == "--interactive" || name == "--patch" || name == "--pathspec-from-file" || name == "--pathspec-file-nul") { refuse(INDEX); return }
			if (name == "--amend") isamend = 1
			if (index(w, "=") == 0 && (name == "--message" || name == "--file" || name == "--reuse-message" || name == "--reedit-message" || name == "--template" || name == "--author" || name == "--date" || name == "--fixup" || name == "--squash" || name == "--cleanup" || name == "--trailer")) i++
			continue
		}
		if (w ~ /^-./) {
			for (j = 2; j <= length(w); j++) {
				ch = substr(w, j, 1)
				if (ch == "a" || ch == "i" || ch == "o" || ch == "p") { refuse(INDEX); return }
				if (ch == "m" || ch == "F" || ch == "C" || ch == "c" || ch == "t") {
					if (j == length(w)) i++
					break
				}
				if (ch == "S" || ch == "u") break
			}
			continue
		}
		refuse(INDEX); return
	}
	if (verdict != "REFUSE") {
		verdict = "COMMIT"; amend = isamend
		ng = g
		for (j = 1; j <= g; j++) G[j] = GG[j]
	}
}

{ S = S $0 "\n" }
END {
	INDEX = "commit from the index: stage with git add, run /rules-review, then git commit with no -a and no paths"
	ALONE = "run git commit on its own: the gate reads the index when the call starts and the commit would read it later, so nothing but cd may come before it"
	GITVAR = "a GIT_ variable in front of git commit is refused: the gate reads the repository the command names with cd or -C, not one a variable points at"
	LITERAL = "the command, or git\047s subcommand, is not a literal word; the gate cannot read it"
	n = length(S); p = 1; jbad = 0; tool = ""; cmd = ""; havecmd = 0
	jvalue("")
	if (jbad || tool == "") { print "NOINPUT"; exit }
	if (tool != "Bash") { print "PASS"; exit }
	if (!havecmd) { print "NOINPUT"; exit }
	verdict = "PASS"; reason = ""; amend = 0; ng = 0; dir = ""; others = 0; NWORD = 0
	scan(cmd)
	if (verdict == "REFUSE") { print "REFUSE " reason; exit }
	if (verdict == "COMMIT") {
		print "COMMIT " amend
		for (i = 1; i <= ng; i++) print "G " G[i]
		if (dir != "") print "D " dir
		exit
	}
	print "PASS"
}
'

# unread is the answer when the input could not be read: a refusal if
# its text mentions a commit, since the gate will not let one through
# unread; otherwise the command goes on, with a line saying why.
input=$(cat)
unread() {
	if printf '%s' "$input" | LC_ALL=C grep -qi commit; then
		refuse "the gate could not read the hook's input ($1) and will not let a commit through unread"
	fi
	say "rules-gate: could not read the hook's input ($1); letting the command through"
	exit 0
}

out=$(printf '%s' "$input" | LC_ALL=C awk "$program") || unread "awk failed"

decision=''
dir=''
set --
while IFS= read -r line; do
	case $line in
	G\ *) set -- "$@" "${line#G }" ;;
	D\ *) dir=${line#D } ;;
	*) [ -n "$decision" ] || decision=$line ;;
	esac
done <<EOF
$out
EOF

case $decision in
PASS)
	exit 0
	;;
NOINPUT)
	unread "not the hook's JSON, or no tool_input.command in it"
	;;
REFUSE\ *)
	refuse "${decision#REFUSE }"
	;;
COMMIT\ *)
	;;
*)
	unread "unexpected decision '$(printable "$decision")'"
	;;
esac

if [ -n "$dir" ]; then
	cd -- "$dir" 2>/dev/null || refuse "the gate could not enter $(printable "$dir") to read the index this commit would use: run git commit from the repository, naming any directory literally"
fi
gitdir=$(safegit "$@" rev-parse --absolute-git-dir 2>/dev/null) || refuse "the gate found no repository for this commit: run git commit from the repository, naming any directory literally"

# An amend is the whole commit that results, the index against HEAD^.
if [ "${decision#COMMIT }" = 1 ]; then
	safegit "$@" rev-parse --verify -q 'HEAD^' >/dev/null 2>&1 || refuse "git commit --amend on a commit with no parent is refused: the gate reads the whole resulting commit as git diff --cached HEAD^, and there is no HEAD^"
	base='HEAD^'
fi

# An empty diff: nothing to review, and git says "nothing to commit".
if safegit "$@" diff --cached --quiet --no-ext-diff --no-textconv ${base:+"$base"} 2>/dev/null; then
	exit 0
fi

hash=$(hash_of_diff "$@")
record="$gitdir/rules-review/$hash.md"
if [ ! -f "$record" ]; then
	if [ -n "$base" ]; then
		refuse "no rules review for the whole amended commit, git diff --cached HEAD^ ($hash): run /rules-review"
	fi
	refuse "no rules review for the staged diff ($hash): run /rules-review"
fi
last=$(awk 'NF { last = $0 } END { print last }' "$record")
[ "$last" = "Verdict: ready" ] || refuse "the rules review for $hash says: $(printable "$last"); fix and run /rules-review again"
exit 0
