#!/usr/bin/env bash
# The deployment guide, run under a real systemd.
#
# This is docs/deploy-linux.md steps 2 to 7 on the machine it runs on, as
# root: the user, the directories, the binary, the settings, the unit, the
# bundle sealed with systemd-creds and unsealed by LoadCredentialEncrypted=,
# a machine enrolling and sending mail, a rotation, and then the unit with
# its credential line taken away. It installs a relay and removes it again,
# so it refuses to run on a machine that already has one. CI runs it on the
# ubuntu runner, whose systemd is PID 1; by hand it wants a throwaway Debian
# or Ubuntu host, or a container booted with /sbin/init.
#
# systemd-analyze verify only warns about a directive it does not know, and
# the relay then starts without its credential, so the check here greps for
# that warning and fails on it. That is the whole reason this script exists
# rather than a line in the workflow.
#
# AUU_BIN names the directory holding auu, auu-admin, auu-ca and auu-relay,
# built for this machine; make build puts them in bin/.
set -euo pipefail

here=$(cd "$(dirname "$0")/.." && pwd)
bin=${AUU_BIN:-$here/bin}
unit=/etc/systemd/system/auu-relay.service
cred=/etc/auu/relay-bundle.cred

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
for b in auu auu-admin auu-ca auu-relay; do
	[ -x "$bin/$b" ] || fail "$bin/$b is not there; run make build, or set AUU_BIN"
done
version=$(systemctl --version | head -1 | awk '{print $2}')
[ "$version" -ge 250 ] || fail "systemd $version: LoadCredentialEncrypted= needs 250 or later"
[ "$(systemctl is-system-running || true)" != offline ] || fail "systemd is not running as PID 1 here"
for existing in /etc/auu /var/lib/auu "$unit" /usr/local/bin/auu-relay; do
	[ ! -e "$existing" ] || fail "$existing exists: this machine already has a relay, and this script removes one"
done
! id auu >/dev/null 2>&1 || fail "user auu exists: this machine already has a relay"

work=$(mktemp -d)
cleanup() {
	set +e
	systemctl stop auu-relay 2>/dev/null
	systemctl disable auu-relay 2>/dev/null
	rm -rf "$unit" "$unit.d"
	systemctl daemon-reload
	systemctl reset-failed auu-relay 2>/dev/null
	userdel auu 2>/dev/null
	rm -rf /etc/auu /var/lib/auu /usr/local/bin/auu-relay "$work"
}
trap cleanup EXIT

# The journal for one invocation of the unit, so a line from an earlier
# start cannot satisfy a check about a later one. A unit that failed and is
# waiting to be restarted has no current invocation, so the negative case
# reads everything since a moment instead.
journal() {
	if [ -n "${since:-}" ]; then
		journalctl -u auu-relay --since "@$since" --no-pager -o cat
	else
		journalctl _SYSTEMD_INVOCATION_ID="$(systemctl show -p InvocationID --value auu-relay)" --no-pager -o cat
	fi
}
# waitfor TEXT [SECONDS]: poll the journal for a line containing TEXT.
waitfor() {
	local i
	for i in $(seq 1 "${2:-30}"); do
		if journal | grep -qF -- "$1"; then return 0; fi
		sleep 1
	done
	echo "--- journal:"; journal
	fail "the journal never said '$1'"
}

echo "systemd $version on $(. /etc/os-release && echo "$PRETTY_NAME")"

# 2. The user and the directories, as the guide has them: useradd is the form
# every distribution has.
useradd --system --home-dir /var/lib/auu --no-create-home --shell /usr/sbin/nologin --user-group auu
install -d -m 0700 -o auu -g auu /var/lib/auu
install -d -m 0755 /etc/auu

# 3. The binary.
install -o root -g root -m 0755 "$bin/auu-relay" /usr/local/bin/auu-relay

# 4. The settings, from the shipped template with the host edited, and the
# check the guide says to run as auu, expecting the credential refusal.
sed 's#relay.example.com:9443#127.0.0.1:9443#' "$here/docs/systemd/relay.json" > /etc/auu/relay.json
chmod 0644 /etc/auu/relay.json
install -o root -g root -m 0644 /dev/null /etc/auu/admins
set +e
check=$(runuser -u auu -- /usr/local/bin/auu-relay --config /etc/auu/relay.json --print-config 2>&1)
status=$?
set -e
[ $status -eq 1 ] || fail "--print-config outside the unit exited $status, want 1: $check"
want='tls.bundle_credential is "relay-bundle" but CREDENTIALS_DIRECTORY is not set: the relay is not running under a unit with LoadCredentialEncrypted=relay-bundle:... in it'
[ "$check" = "auu-relay: $want" ] || fail "--print-config outside the unit said: $check"
[ "$(stat -c %U:%a /var/lib/auu/messages)" = "auu:700" ] || fail "the message directory was not made as auu 0700"
pass "step 4's check refuses with the credential message, after making the message directory as auu"

# 6. The unit, verified: a misspelled directive is a warning to systemd and a
# relay with no credential to us, so the warning is a failure here.
install -o root -g root -m 0644 "$here/docs/systemd/auu-relay.service" "$unit"
systemctl daemon-reload
verify=$(systemd-analyze verify "$unit" 2>&1) || { echo "$verify"; fail "systemd-analyze verify refused the shipped unit"; }
if echo "$verify" | grep -qi 'unknown'; then echo "$verify"; fail "the shipped unit has a directive this systemd does not know"; fi
pass "systemd-analyze verify accepts the shipped unit with no unknown directive"

# 3a. The authority on the operator's machine, and the pipeline. Nothing but
# the authority's own directory may appear where the operator ran it.
export AUU_CA_HOME="$work/ca"
printf 'ci passphrase\n' > "$work/pass"
"$bin/auu-ca" init --name "CI" --passphrase-file "$work/pass" >/dev/null
cd "$work"
"$bin/auu-ca" relay --host 127.0.0.1 --out - --passphrase-file "$work/pass" 2>"$work/relay.err" \
	| systemd-creds encrypt --name=relay-bundle - "$cred"
grep -q 'wrote the bundle to standard output' "$work/relay.err" || fail "auu-ca relay did not report the pipe: $(cat "$work/relay.err")"
[ "$(ls "$work" | sort | tr '\n' ' ')" = "ca pass relay.err " ] || fail "the pipeline left a file behind: $(ls "$work")"
[ -s "$cred" ] || fail "systemd-creds wrote nothing"
! grep -q '"server_int_key"' "$cred" || fail "the sealed credential holds the bundle in the clear"
anchor=$("$bin/auu-ca" show --json | sed -n 's/^  "anchor": "\(.*\)",$/\1/p')
[ -n "$anchor" ] || fail "auu-ca show gave no anchor"
pass "the bundle went down the pipe into systemd-creds encrypt and touched no disk on the way"

# 6 and 7. Start it, and read the journal for where the bundle came from.
systemctl enable --now auu-relay >/dev/null 2>&1
waitfor 'bundle_source=credential'
journal | grep -q 'cert=/run/credentials/auu-relay.service/relay-bundle' || fail "the bundle was not read from the credentials directory"
waitfor 'serving from an auu-ca bundle'
pass "the relay started from the credential systemd unsealed"

# 5 and 8. An administrator, a token, a machine, a message: the whole thing
# over the certificate the relay minted from the credential's bundle.
export AUU_HOME="$work/admin"
expect 'pinned the trust anchor' "auu init could not pin the anchor over the relay's TLS" \
	"$bin/auu" init --name boss --relay https://127.0.0.1:9443 --anchor "$anchor"
"$bin/auu" id export > /etc/auu/admins
sleep 1
expect 'administrators: 1' "auu-admin status does not see the administrator" "$bin/auu-admin" status
token=$("$bin/auu-admin" token issue --note ci --expires 1h | tail -1)
export AUU_HOME="$work/user"
expect 'registered' "auu enrol failed" "$bin/auu" enrol --name bunty --yes "$token"
expect 'sent to bunty' "auu send failed" "$bin/auu" send --to self --subject "from the credential" "hello"
expect 'from the credential' "the message did not come back" "$bin/auu" inbox
pass "a machine enrolled and exchanged mail over the credential's certificate"

# Day two: the same pipeline, a restart, and the enrolled machine still works.
"$bin/auu-ca" relay --host 127.0.0.1 --out - --passphrase-file "$work/pass" 2>"$work/rotate.err" \
	| systemd-creds encrypt --name=relay-bundle - "$cred"
grep -q 'rotation      2' "$work/rotate.err" || fail "the second issuance was not reported as a rotation"
systemctl restart auu-relay
waitfor 'bundle_source=credential'
expect 'sent to bunty' "the enrolled machine could not send after the rotation" \
	"$bin/auu" send --to self --subject "after rotation" "still here"
pass "a rotation through the same pipeline and a restart kept the enrolled machine working"

# On the operator's side, nothing is on disk to warn about.
warned=$("$bin/auu-ca" show 2>&1 >/dev/null || true)
[ -z "$warned" ] || fail "auu-ca show warned: $warned"
pass "auu-ca show on the operator's side warns about nothing"

# The unit without its credential line: the relay refuses by name, in the
# journal, rather than starting without a bundle.
mkdir -p "$unit.d"
printf '[Service]\nLoadCredentialEncrypted=\n' > "$unit.d/no-credential.conf"
systemctl daemon-reload
since=$(( $(date +%s) - 1 ))
systemctl restart auu-relay || true
waitfor "$want" 15
systemctl stop auu-relay
rm -rf "$unit.d"
systemctl daemon-reload
pass "without LoadCredentialEncrypted= the relay refuses and names the directive"

echo "the deployment guide holds under systemd $version"
