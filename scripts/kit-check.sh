#!/usr/bin/env bash
# The relay kit, run under a real systemd.
#
# This is auu-ca kit and its install.sh on the machine it runs on, as root:
# a kit made from a test authority with one administrator, installed on a
# host with no relay, the relay up from the credential the script sealed, a
# token issued, a machine enrolled and sending; then what the script refuses
# (a second install, a kit whose binary was changed) and what it does with a
# kit that carries no bundle; then update, on the installed relay: a
# rotation, a kit that names no administrator, settings and administrators
# edited on the host and kept, a unit deleted and put back; and the two
# refusals at the end. It installs a relay and removes it again, so it
# refuses a machine that already has one. CI runs it on the ubuntu runner,
# whose systemd is PID 1; by hand it wants a throwaway Debian or Ubuntu
# host, or a container booted with /sbin/init.
#
# AUU_BIN names the directory holding auu, auu-admin, auu-ca and auu-relay,
# built for this machine; make build puts them in bin/. The relay the kit
# carries has to be a static build, and a default Linux build with a C
# compiler present is dynamically linked, which the kit refuses — its check
# doing its job. AUU_BIN's auu-relay is used when it is static (CGO_ENABLED=0
# make build), and otherwise a static one is built here when go is on the
# path.
set -euo pipefail

here=$(cd "$(dirname "$0")/.." && pwd)
bin=${AUU_BIN:-$here/bin}
unit=/etc/systemd/system/auu-relay.service
cred=/etc/auu/relay-bundle.cred
url=https://127.0.0.1:9443

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok: $*"; }
# expect TEXT WHAT COMMAND...: run the command, and fail showing its output
# when that output does not contain TEXT.
expect() {
	local text=$1 what=$2 out
	shift 2
	out=$("$@" 2>&1) || true
	if ! grep -qF -- "$text" <<<"$out"; then
		echo "--- $*"; echo "$out"
		fail "$what"
	fi
}

[ "$(id -u)" = 0 ] || fail "run as root: this installs a unit and seals a credential"
for b in auu auu-admin auu-ca; do
	[ -x "$bin/$b" ] || fail "$bin/$b is not there; run make build, or set AUU_BIN"
done
command -v unzip >/dev/null || fail "unzip is not here; apt install unzip"
version=$(systemctl --version | head -1 | awk '{print $2}')
[ "$version" -ge 250 ] || fail "systemd $version: LoadCredentialEncrypted= needs 250 or later"
[ "$(systemctl is-system-running || true)" != offline ] || fail "systemd is not running as PID 1 here"
for existing in /etc/auu /var/lib/auu "$unit" /usr/local/bin/auu-relay; do
	[ ! -e "$existing" ] || fail "$existing exists: this machine already has a relay, and this script removes one"
done
! id auu >/dev/null 2>&1 || fail "user auu exists: this machine already has a relay"

work=$(mktemp -d)
# remove takes the relay off the host, as the guide's last section does,
# backups and all; it is the cleanup, and the way to a host with no relay
# between cases.
remove() {
	set +e
	systemctl stop auu-relay 2>/dev/null
	systemctl disable auu-relay 2>/dev/null
	rm -rf "$unit" "$unit.d"
	systemctl daemon-reload
	systemctl reset-failed auu-relay 2>/dev/null
	userdel auu 2>/dev/null
	rm -rf /etc/auu /var/lib/auu /usr/local/bin/auu-relay
	set -e
}
cleanup() {
	remove
	rm -rf "$work"
}
trap cleanup EXIT

# The journal for one invocation of the unit, so a line from an earlier
# start cannot satisfy a check about a later one.
journal() {
	journalctl _SYSTEMD_INVOCATION_ID="$(systemctl show -p InvocationID --value auu-relay)" --no-pager -o cat
}
# waitfor TEXT [SECONDS]: poll the journal for a line containing TEXT.
waitfor() {
	local tries
	for ((tries = 0; tries < ${2:-30}; tries++)); do
		if journal | grep -qF -- "$1"; then return 0; fi
		sleep 1
	done
	echo "--- journal:"; journal
	fail "the journal never said '$1'"
}
# install_kit DIR [update]: run the kit's script from DIR, its output kept
# in DIR/install.out and shown, and fail if it did not exit 0.
install_kit() {
	local dir=$1 status
	shift
	set +e
	sh "$dir/auu-relay-kit/install.sh" "$@" > "$dir/install.out" 2>&1
	status=$?
	set -e
	sed 's/^/    | /' "$dir/install.out"
	[ $status -eq 0 ] || { echo "--- journal:"; journalctl -u auu-relay --since '-2 minutes' --no-pager -o short-precise | tail -60; fail "install.sh $* exited $status"; }
}
# refuse DIR TEXT [update]: run the kit's script from DIR expecting it to
# exit 1 with TEXT in its output.
refuse() {
	local dir=$1 text=$2 status
	shift 2
	set +e
	sh "$dir/auu-relay-kit/install.sh" "$@" > "$dir/refuse.out" 2>&1
	status=$?
	set -e
	[ $status -eq 1 ] || { cat "$dir/refuse.out"; fail "install.sh $* exited $status, want 1"; }
	grep -qF -- "$text" "$dir/refuse.out" || { cat "$dir/refuse.out"; fail "install.sh $* did not say '$text'"; }
}
# make_kit OUT ARGS...: auu-ca kit for this host, with the relay built here.
make_kit() {
	local out=$1
	shift
	"$bin/auu-ca" kit --host 127.0.0.1 --relay-binary "$work/auu-relay" --out "$out" "$@" > "$out.log" 2>&1 ||
		{ cat "$out.log"; fail "auu-ca kit did not write $out"; }
}
# unpack ZIP DIR: the kit into a directory of its own, as the recipe does
# in the login user's home, with the recipe's -o: a kit already unpacked
# there is replaced without unzip asking.
unpack() {
	mkdir -p "$2"
	(cd "$2" && unzip -oq "$1")
}
# names FILE: whether an administrator file names anybody.
names() { grep -qv '^[[:space:]]*\(#\|$\)' "$1"; }

# shellcheck disable=SC1091
echo "systemd $version on $(. /etc/os-release && echo "$PRETTY_NAME")"

# The operator's side: the authority, an administrator, and the relay built
# static for this host.
export AUU_CA_HOME="$work/ca"
printf 'ci passphrase\n' > "$work/pass"
"$bin/auu-ca" init --name "CI" --passphrase-file "$work/pass" >/dev/null
anchor=$("$bin/auu-ca" show --json | sed -n 's/^  "anchor": "\(.*\)",$/\1/p')
[ -n "$anchor" ] || fail "auu-ca show gave no anchor"
export AUU_HOME="$work/admin"
"$bin/auu" init --name boss >/dev/null
"$bin/auu" id export > "$work/admins"
if [ -x "$bin/auu-relay" ] && ! ldd "$bin/auu-relay" >/dev/null 2>&1; then
	cp "$bin/auu-relay" "$work/auu-relay"
elif command -v go >/dev/null; then
	(cd "$here" && CGO_ENABLED=0 GOOS=linux go build -o "$work/auu-relay" ./cmd/auu-relay)
else
	fail "$bin/auu-relay is dynamically linked and go is not on the path to build a static one; run CGO_ENABLED=0 make build"
fi
pass "the authority, the administrator's line and a static relay binary are ready"

# The kit, and what auu-ca says about it. The wrote line ends with the
# relay's own version when the binary carries one, which a build from a
# checkout does and a binary built from a copied tree does not; the binary
# is asked, and its answer decides what the line must say.
make_kit "$work/kit.zip" --admin "@$work/admins" --passphrase-file "$work/pass"
relayVersion=$("$work/auu-relay" --version 2>/dev/null | sed -n 's/^auu-relay \([^ ]*\).*/\1/p')
grep -qE "^wrote $work/kit.zip \(.*, (amd64|arm64)" "$work/kit.zip.log" ||
	{ cat "$work/kit.zip.log"; fail "auu-ca kit did not report what it wrote"; }
# The version as a fixed string, not a pattern: a pseudo-version holds a +
# and dots, which an expression would read as repetition and any character.
if [ -n "$relayVersion" ] && [ "$relayVersion" != unknown ]; then
	grep -qF ", relay $relayVersion)" "$work/kit.zip.log" ||
		{ cat "$work/kit.zip.log"; fail "the wrote line does not name the relay version $relayVersion"; }
fi
grep -qF "sudo sh auu-relay-kit/install.sh'" "$work/kit.zip.log" || fail "the recipe for a first kit does not run the script's fresh form"
[ "$(stat -c %a "$work/kit.zip")" = 600 ] || fail "the archive is mode $(stat -c %a "$work/kit.zip"), want 600"
warned=$("$bin/auu-ca" show 2>&1 >/dev/null || true)
grep -qF "is still at $work/kit.zip" <<<"$warned" || fail "auu-ca show does not nag about the kit: $warned"
pass "auu-ca kit wrote the archive at 0600, printed the recipe, and show nags about it"

# Installed on a host with no relay: steps 2 to 7 by the script.
unpack "$work/kit.zip" "$work/one"
[ "$(stat -c %a "$work/one/auu-relay-kit/relay-bundle.json")" = 600 ] || fail "unzip did not restore the bundle's mode"
install_kit "$work/one"
waitfor 'bundle_source=credential'
journal | grep -q 'cert=/run/credentials/auu-relay.service/relay-bundle' || fail "the bundle was not read from the credentials directory"
waitfor 'serving from an auu-ca bundle'
[ ! -e "$work/one/auu-relay-kit/relay-bundle.json" ] || fail "the plaintext bundle is still in the kit directory"
[ -s "$cred" ] || fail "systemd-creds wrote nothing"
! grep -q '"server_int_key"' "$cred" || fail "the sealed credential holds the bundle in the clear"
cmp -s "$work/one/auu-relay-kit/MANIFEST" /etc/auu/kit.manifest || fail "/etc/auu/kit.manifest is not the kit's MANIFEST"
if [ -n "$relayVersion" ] && [ "$relayVersion" != unknown ]; then
	grep -qF "  relay version  $relayVersion" "$work/one/auu-relay-kit/README" ||
		fail "the kit's README does not name the relay version $relayVersion"
fi
grep -qF "the relay is up" "$work/one/install.out" || fail "install.sh did not say the relay is up"
grep -qF "curl $url/v1/health" "$work/one/install.out" || fail "install.sh did not print the health URL"
grep -qF "auu relay add $url --name NAME --anchor $anchor" "$work/one/install.out" || fail "install.sh did not print the administrator's line with the anchor"
grep -qF "delete this directory and the archive it came from" "$work/one/install.out" || fail "install.sh did not say what to delete"
pass "install.sh installed the relay, sealed the bundle, removed the plaintext and started the unit from the credential"

# The administrator's machine, a token, a machine, a message.
expect 'pinned its trust anchor' "auu relay add could not pin the anchor over the relay's TLS" \
	"$bin/auu" relay add "$url" --name kit --anchor "$anchor"
expect 'administrators: 1' "auu-admin status does not see the administrator" "$bin/auu-admin" status
token=$("$bin/auu-admin" token issue --note ci --expires 1h | tail -1)
export AUU_HOME="$work/user"
expect 'registered' "auu enrol failed" "$bin/auu" enrol --name bunty --yes "$token"
expect 'sent to bunty' "auu send failed" "$bin/auu" send --to self --subject "from the kit" "hello"
expect 'from the kit' "the message did not come back" "$bin/auu" inbox
pass "a machine enrolled over the kit's relay and exchanged mail"

# What the script refuses. A second fresh run, on a host that has a relay;
# and a kit whose binary was changed by a byte, which fails at the
# manifest before anything is looked at.
refuse "$work/one" "/etc/auu exists: this machine has a relay, or part of one; run 'sh install.sh update' to bring it to this kit"
pass "a second install refuses, naming the path and the update form"
unpack "$work/kit.zip" "$work/bad"
# Unpacked over itself, as an update lands on a kit still there from last
# time: the recipe's -o replaces it without unzip asking, which with no
# terminal here would be a failure and on the operator's would have been
# a prompt on the terminal sudo was about to use.
unpack "$work/kit.zip" "$work/bad"
pass "unzip -o replaces a kit already unpacked there without asking"
printf 'x' | dd of="$work/bad/auu-relay-kit/auu-relay" bs=1 seek=100 conv=notrunc 2>/dev/null
refuse "$work/bad" "auu-relay: FAILED"
grep -qF "is not what auu-ca kit wrote" "$work/bad/refuse.out" || fail "the manifest failure did not say the kit is damaged"
pass "a kit with a byte changed in auu-relay fails at the manifest, naming the file"
refuse "$work/one" "usage: sh install.sh [update]" upgrade
pass "a word other than update is a usage error"

# A kit without its bundle, on a host with no relay: everything installed,
# the relay not started, the two lines printed; then the two lines.
remove
make_kit "$work/nobundle.zip" --admin "@$work/admins" --without-bundle
grep -qF "bundle        none" "$work/nobundle.zip.log" || fail "auu-ca kit --without-bundle did not say the kit has no bundle"
unpack "$work/nobundle.zip" "$work/nb"
[ ! -e "$work/nb/auu-relay-kit/relay-bundle.json" ] || fail "a --without-bundle kit carries a bundle"
install_kit "$work/nb"
grep -qF "systemd-creds encrypt --name=relay-bundle relay-bundle.json $cred" "$work/nb/install.out" || fail "the two lines were not printed"
grep -qF "systemctl enable --now auu-relay" "$work/nb/install.out" || fail "the two lines were not printed"
[ "$(systemctl is-active auu-relay || true)" != active ] || fail "a kit without a bundle started the relay"
[ ! -e "$cred" ] || fail "a kit without a bundle left a credential"
for f in "$unit" /usr/local/bin/auu-relay /etc/auu/relay.json /etc/auu/admins /etc/auu/kit.manifest; do
	[ -e "$f" ] || fail "a kit without a bundle did not install $f"
done
"$bin/auu-ca" relay --host 127.0.0.1 --out "$work/relay-bundle.json" --passphrase-file "$work/pass" >/dev/null 2>&1
(cd "$work" && systemd-creds encrypt --name=relay-bundle relay-bundle.json "$cred" && rm relay-bundle.json && systemctl enable --now auu-relay)
waitfor 'bundle_source=credential'
pass "a kit without its bundle stopped before starting the relay, printed the two lines, and the two lines started it"
# A machine on this relay, for the updates below to keep working for.
export AUU_HOME="$work/admin"
token=$("$bin/auu-admin" token issue --note ci --expires 1h | tail -1)
export AUU_HOME="$work/user2"
expect 'registered' "auu enrol failed on the second relay" "$bin/auu" enrol --name bunty --yes "$token"
expect 'sent to bunty' "auu send failed on the second relay" "$bin/auu" send --to self --subject "before update" "hello"

# Update: a second kit for the host, a rotation, with registration open.
make_kit "$work/kit2.zip" --admin "@$work/admins" --registration open --passphrase-file "$work/pass"
grep -qF "rotation      " "$work/kit2.zip.log" || fail "the second kit was not reported as a rotation"
grep -qF "sudo sh auu-relay-kit/install.sh update'" "$work/kit2.zip.log" || fail "the recipe for a second kit does not run the script's update form"
unpack "$work/kit2.zip" "$work/two"
install_kit "$work/two" update
waitfor 'bundle_source=credential'
journal | grep -q 'registration=open' || fail "the kit's settings were not installed: the journal does not say registration=open"
expect 'sent to bunty' "the enrolled machine could not send after the update" \
	"$bin/auu" send --to self --subject "after update" "still here"
[ "$(sha256sum /usr/local/bin/auu-relay | cut -d' ' -f1)" = "$(sed -n 's/^\([0-9a-f]*\)  auu-relay$/\1/p' "$work/two/auu-relay-kit/MANIFEST")" ] || fail "the installed binary is not the kit's"
cmp -s "$work/two/auu-relay-kit/relay.json" /etc/auu/relay.json || fail "/etc/auu/relay.json is not the kit's, though it was unedited"
cmp -s "$work/two/auu-relay-kit/MANIFEST" /etc/auu/kit.manifest || fail "/etc/auu/kit.manifest is not the new MANIFEST"
grep -qF "sha256sum /usr/local/bin/auu-relay auu-relay" "$work/two/install.out" || fail "update did not print the old and the new binary's hash"
# And what each binary says it is, which a hash cannot tell an operator.
if [ -n "$relayVersion" ] && [ "$relayVersion" != unknown ]; then
	[ "$(grep -c "^auu-relay $relayVersion (schema " "$work/two/install.out")" = 2 ] ||
		fail "update did not print both binaries' versions: $(grep -c "^auu-relay " "$work/two/install.out") lines"
fi
backups=(/var/lib/auu/backups/*)
[ ${#backups[@]} -eq 1 ] || fail "update made ${#backups[@]} backup directories, want one: ${backups[*]}"
for f in relay.db auu-relay auu-relay.service relay.json admins relay-bundle.cred RESTORE; do
	[ -e "${backups[0]}/$f" ] || fail "the backup lacks $f: $(ls "${backups[0]}")"
done
for f in "${backups[0]}"/*; do
	case "$(basename "$f")" in
		relay.db|relay.db-wal|relay.db-shm|auu-relay|auu-relay.service|relay.json|admins|relay-bundle.cred|RESTORE) ;;
		*) fail "the backup holds $f, which nothing copies" ;;
	esac
done
grep -qF "the backup is in ${backups[0]}" "$work/two/install.out" || fail "update did not name the backup"
[ "$(stat -c %a "${backups[0]}")" = 700 ] || fail "the backup directory is mode $(stat -c %a "${backups[0]}"), want 700"
pass "update rotated the bundle, replaced the binary, the unit and the unedited settings, recorded the new manifest, and backed up the six files with RESTORE"

# A kit that names no administrator, on update, keeps the installed one.
make_kit "$work/kit3.zip" --registration open --passphrase-file "$work/pass"
unpack "$work/kit3.zip" "$work/three"
install_kit "$work/three" update
grep -qF "kept /etc/auu/admins: this kit names no administrator" "$work/three/install.out" || fail "a kit naming nobody replaced the administrators"
names /etc/auu/admins || fail "the administrator file lost its line"
waitfor 'bundle_source=credential'
pass "a kit that names no administrator leaves the installed administrators as they were"

# Settings and administrators edited on the host are kept, the kit's copies
# written beside them, and the relay starts with the edits.
sed -i 's/"access_log": "minimal"/"access_log": "full"/' /etc/auu/relay.json
grep -q '"access_log": "full"' /etc/auu/relay.json || fail "the edit to relay.json did not take"
export AUU_HOME="$work/admin2"
"$bin/auu" init --name second >/dev/null
"$bin/auu" id export >> /etc/auu/admins
make_kit "$work/kit4.zip" --admin "@$work/admins" --registration open --passphrase-file "$work/pass"
unpack "$work/kit4.zip" "$work/four"
install_kit "$work/four" update
grep -qF "kept /etc/auu/relay.json, which was edited since the last kit; the kit's is at /etc/auu/relay.json.kit" "$work/four/install.out" || fail "the edited relay.json was not kept"
grep -qF "kept /etc/auu/admins, which was edited since the last kit; the kit's is at /etc/auu/admins.kit" "$work/four/install.out" || fail "the edited admins was not kept"
grep -q '"access_log": "full"' /etc/auu/relay.json || fail "the edited relay.json was replaced"
[ "$(grep -cv '^[[:space:]]*\(#\|$\)' /etc/auu/admins)" = 2 ] || fail "the edited admins was replaced"
cmp -s "$work/four/auu-relay-kit/relay.json" /etc/auu/relay.json.kit || fail "/etc/auu/relay.json.kit is not the kit's copy"
cmp -s "$work/four/auu-relay-kit/admins" /etc/auu/admins.kit || fail "/etc/auu/admins.kit is not the kit's copy"
[ "$(stat -c %a /etc/auu/relay.json.kit)" = 644 ] || fail "relay.json.kit is mode $(stat -c %a /etc/auu/relay.json.kit)"
waitfor 'bundle_source=credential'
waitfor 'access_log=full'
waitfor 'msg="administrators loaded" count=2'
pass "edited settings and administrators were kept, the kit's copies written beside them, and the relay started with the edits"

# The repair: the relay disabled and its unit gone, and update puts it
# back, enabled.
systemctl disable auu-relay >/dev/null 2>&1
rm -f "$unit"
systemctl daemon-reload
install_kit "$work/four" update
[ -e "$unit" ] || fail "update did not put the unit back"
waitfor 'bundle_source=credential'
[ "$(systemctl is-enabled auu-relay)" = enabled ] || fail "the repaired relay is not enabled"
pass "update put a disabled relay's deleted unit back, and the relay is up and enabled"
# And the same kit run again after its bundle was sealed and removed: the
# manifest ignores the missing bundle, the credential is kept.
[ ! -e "$work/four/auu-relay-kit/relay-bundle.json" ] || fail "the bundle is still in the kit directory after update"
install_kit "$work/four" update
waitfor 'bundle_source=credential'
pass "a kit whose bundle was sealed already can be run again"
# A relay that has hit systemd's start limit — restarted too often in too
# short a time, as one crash-looping does — is failed and will not start
# again until reset; update resets it, since that relay is one an update
# is run to repair.
for _ in 1 2 3 4 5 6; do systemctl restart auu-relay 2>/dev/null || true; done
[ "$(systemctl is-active auu-relay || true)" != active ] || fail "six restarts in a row did not trip the start limit; the case proves nothing"
install_kit "$work/four" update
waitfor 'bundle_source=credential'
[ "$(systemctl is-active auu-relay)" = active ] || fail "update did not bring back a relay that had hit the start limit"
pass "update starts a relay that had hit systemd's start limit"

# The two refusals: the fresh form on a host with a relay, and update on a
# host with none.
refuse "$work/four" "run 'sh install.sh update' to bring it to this kit"
remove
refuse "$work/four" "nothing of a relay is installed here; run 'sh install.sh' without update" update
pass "the fresh form refuses a host with a relay naming update, and update refuses a host with none"

echo "the relay kit holds under systemd $version"
