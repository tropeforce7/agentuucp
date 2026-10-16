#!/bin/sh
# install.sh: put this kit's relay on this host as a system service, or
# bring one already here up to what the kit holds.
#
# This is docs/deploy-linux.md steps 2 to 7, in the guide's order, by a
# script that prints each command before it runs it. With no argument it
# installs on a host that has no relay and refuses one that has. With the
# one word 'update' it stops the relay, backs up what it is about to
# replace into /var/lib/auu/backups/<time>/ with a RESTORE file that says
# how to put it back, replaces the binary and the unit, seals the bundle
# here over the old credential when the kit has one, and replaces the
# settings and the administrators only if they have not been edited since
# the last kit; an edited file is kept, the kit's copy written beside it as
# .kit. Every update step is idempotent, so update is also how a relay
# that is half installed or missing its unit or binary is repaired.
#
# It needs systemd 250 or later as PID 1, root, and the kit's own directory
# beside it; every path below is relative to that directory.
set -eu

unit=/etc/systemd/system/auu-relay.service
cred=/etc/auu/relay-bundle.cred
manifest=/etc/auu/kit.manifest
want='tls.bundle_credential is "relay-bundle" but CREDENTIALS_DIRECTORY is not set: the relay is not running under a unit with LoadCredentialEncrypted=relay-bundle:... in it'
# Set by update at the stop and at the backup, and read by fail, so every
# failure after the old relay was stopped says where its pieces are.
stopped=""
backup=""

say() { printf '%s\n' "$*"; }
fail() {
	echo "install.sh: $*" >&2
	[ -z "$backup" ] || echo "the backup is in $backup; RESTORE there says how to put it back" >&2
	[ -z "$stopped" ] || echo "the relay is stopped; systemctl start auu-relay brings the old one back" >&2
	exit 1
}
# waitfor TEXT: poll the journal of the unit's current invocation for a
# line containing TEXT, for up to thirty seconds. This invocation only, so
# on an update the previous start's line cannot stand in for this one's.
waitfor() {
	tries=0
	while [ "$tries" -lt 30 ]; do
		if journalctl _SYSTEMD_INVOCATION_ID="$(systemctl show -p InvocationID --value auu-relay)" --no-pager -o cat 2>/dev/null | grep -qF -- "$1"; then
			return 0
		fi
		tries=$((tries + 1))
		sleep 1
	done
	return 1
}
# unchanged FILE: the installed /etc/auu/FILE hashes to what the last kit's
# manifest recorded for it. No manifest, or no file, is not unchanged.
unchanged() {
	[ -f "$manifest" ] && [ -f "/etc/auu/$1" ] || return 1
	recorded=$(sed -n "s/^\([0-9a-f]*\)  $1\$/\1/p" "$manifest")
	[ -n "$recorded" ] || return 1
	[ "$(sha256sum "/etc/auu/$1" | cut -d' ' -f1)" = "$recorded" ]
}

case "$#:${1:-}" in
	0:) mode=fresh ;;
	1:update) mode=update ;;
	*) fail "usage: sh install.sh [update]" ;;
esac

# 1. Root, the kit's directory, the bundle's mode, the manifest.
[ "$(id -u)" = 0 ] || fail "run as root: this installs a unit and seals a credential"
cd "$(dirname "$0")"
[ ! -e relay-bundle.json ] || chmod 0600 relay-bundle.json
say "sha256sum -c --quiet --ignore-missing MANIFEST"
sha256sum -c --quiet --ignore-missing MANIFEST || fail "the file named above is not what auu-ca kit wrote; this kit is damaged, make another"

# 2. systemd 250 or later, as PID 1.
version=""
if command -v systemctl >/dev/null 2>&1; then
	version=$(systemctl --version | sed -n '1s/^systemd \([0-9]*\).*/\1/p')
fi
if [ -z "$version" ] || [ "$version" -lt 250 ]; then
	fail "systemd ${version:-is not here}: LoadCredentialEncrypted= needs systemd 250 or later as PID 1; on this host use the plain-file form in docs/deploy-linux.md"
fi
[ "$(systemctl is-system-running 2>/dev/null || true)" != offline ] ||
	fail "systemd $version is not running as PID 1 here; on this host use the plain-file form in docs/deploy-linux.md"
if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce 2>/dev/null || true)" = Enforcing ]; then
	say "SELinux is enforcing; this kit has not been tried under it"
fi

# 3. What is here already. A fresh install wants none of these five; an
# update wants any of them, which makes update the way to finish a fresh
# install that stopped part way.
present=""
for p in /etc/auu /var/lib/auu "$unit" /usr/local/bin/auu-relay; do
	[ -n "$present" ] || [ ! -e "$p" ] || present="$p exists"
done
[ -n "$present" ] || ! id auu >/dev/null 2>&1 || present="user auu exists"
if [ "$mode" = fresh ] && [ -n "$present" ]; then
	fail "$present: this machine has a relay, or part of one; run 'sh install.sh update' to bring it to this kit"
fi
if [ "$mode" = update ] && [ -z "$present" ]; then
	fail "nothing of a relay is installed here; run 'sh install.sh' without update"
fi

# 3a. Update: the kit's binary must run here before anything is stopped;
# then the relay is stopped and what the update will replace is backed up,
# with a RESTORE file that says how to put it back.
if [ "$mode" = update ]; then
	say "./auu-relay --help | head -1"
	usage=$(./auu-relay --help 2>&1) || fail "the kit's auu-relay does not run on this machine: is it built for this architecture?"
	printf '%s\n' "$usage" | head -1
	say "systemctl stop auu-relay"
	systemctl stop auu-relay 2>/dev/null || true
	# The stop's failure is let through for a unit that is not there, an
	# install being finished, and the relay's state is then asked whatever
	# the stop said: the backup and the replacement below are made under a
	# stopped relay or not at all. A unit whose file has gone may still be
	# running, so not-found decides only whether there is a relay to start
	# back, and stopped is set once that is known, so fail's sentence is
	# true. systemd says inactive of a unit it does not know.
	state=$(systemctl is-active auu-relay 2>/dev/null || true)
	case "$state" in
		inactive|failed) ;;
		*) fail "the relay did not stop (systemctl is-active says ${state:-nothing}); systemctl status auu-relay says why. Nothing was changed" ;;
	esac
	[ "$(systemctl show -p LoadState --value auu-relay 2>/dev/null || true)" = not-found ] || stopped=1
	stamp=$(date -u +%Y%m%dT%H%M%SZ)
	say "install -d -m 0700 /var/lib/auu/backups/$stamp"
	install -d -m 0700 "/var/lib/auu/backups/$stamp"
	backup=/var/lib/auu/backups/$stamp
	restore=$backup/RESTORE
	{
		echo "# Written by install.sh update on $stamp. To put the relay back as it was,"
		echo "# as root, from this directory:"
		echo "systemctl stop auu-relay"
	} > "$restore"
	for f in /var/lib/auu/relay.db /var/lib/auu/relay.db-wal /var/lib/auu/relay.db-shm; do
		[ ! -e "$f" ] || { say "cp -p $f $backup/"; cp -p "$f" "$backup/"; }
	done
	if [ -e "$backup/relay.db" ]; then
		echo "rm -f /var/lib/auu/relay.db-wal /var/lib/auu/relay.db-shm" >> "$restore"
		for f in relay.db relay.db-wal relay.db-shm; do
			[ ! -e "$backup/$f" ] || echo "install -o auu -g auu -m 0600 $f /var/lib/auu/$f" >> "$restore"
		done
	fi
	if [ -e /usr/local/bin/auu-relay ]; then
		say "cp -p /usr/local/bin/auu-relay $backup/"
		cp -p /usr/local/bin/auu-relay "$backup/"
		echo "install -o root -g root -m 0755 auu-relay /usr/local/bin/auu-relay" >> "$restore"
	fi
	if [ -e "$unit" ]; then
		say "cp -p $unit $backup/"
		cp -p "$unit" "$backup/"
		echo "install -o root -g root -m 0644 auu-relay.service $unit" >> "$restore"
	fi
	for f in relay.json admins; do
		if [ -e "/etc/auu/$f" ]; then
			say "cp -p /etc/auu/$f $backup/"
			cp -p "/etc/auu/$f" "$backup/"
			echo "install -o root -g root -m 0644 $f /etc/auu/$f" >> "$restore"
		fi
	done
	if [ -e "$cred" ]; then
		say "cp -p $cred $backup/"
		cp -p "$cred" "$backup/"
		echo "install -o root -g root -m 0644 relay-bundle.cred $cred" >> "$restore"
	fi
	echo "systemctl daemon-reload" >> "$restore"
	echo "systemctl restart auu-relay" >> "$restore"
fi

# 4. The user and the directories, as the guide has them: useradd is the
# form every distribution has; install -d makes or corrects.
if ! id auu >/dev/null 2>&1; then
	nologin=$(command -v nologin || echo /usr/sbin/nologin)
	say "useradd --system --home-dir /var/lib/auu --no-create-home --shell $nologin --user-group auu"
	useradd --system --home-dir /var/lib/auu --no-create-home --shell "$nologin" --user-group auu
fi
say "install -d -m 0700 -o auu -g auu /var/lib/auu"
install -d -m 0700 -o auu -g auu /var/lib/auu
say "install -d -m 0755 /etc/auu"
install -d -m 0755 /etc/auu

# 5. The binary: run first, so a kit for the wrong architecture fails with
# nothing replaced; on an update the old and the new hash, since the relay
# has no version to print.
if [ "$mode" = fresh ]; then
	say "./auu-relay --help | head -1"
	usage=$(./auu-relay --help 2>&1) || fail "the kit's auu-relay does not run on this machine: is it built for this architecture?"
	printf '%s\n' "$usage" | head -1
fi
if [ "$mode" = update ] && [ -e /usr/local/bin/auu-relay ]; then
	say "sha256sum /usr/local/bin/auu-relay auu-relay"
	sha256sum /usr/local/bin/auu-relay auu-relay
	# And what each says it is, which a hash cannot tell an operator. A
	# binary from before --version prints its usage to stderr and exits
	# non-zero; the line is printed whatever it says.
	say "/usr/local/bin/auu-relay --version; ./auu-relay --version"
	/usr/local/bin/auu-relay --version 2>&1 | head -1 || true
	./auu-relay --version 2>&1 | head -1 || true
fi
say "install -o root -g root -m 0755 auu-relay /usr/local/bin/auu-relay"
install -o root -g root -m 0755 auu-relay /usr/local/bin/auu-relay

# 6. The settings and the administrators. Fresh: installed. Update: an
# installed file the operator has edited since the last kit is kept, and
# the kit's copy goes beside it as FILE.kit; and an administrator file that
# names somebody is never replaced by one that names nobody.
for f in relay.json admins; do
	keep=""
	if [ "$mode" = update ] && [ -e "/etc/auu/$f" ]; then
		if [ "$f" = admins ] && grep -qv '^[[:space:]]*\(#\|$\)' /etc/auu/admins && ! grep -qv '^[[:space:]]*\(#\|$\)' admins; then
			keep="kept /etc/auu/admins: this kit names no administrator"
		elif ! unchanged "$f"; then
			say "install -o root -g root -m 0644 $f /etc/auu/$f.kit"
			install -o root -g root -m 0644 "$f" "/etc/auu/$f.kit"
			keep="kept /etc/auu/$f, which was edited since the last kit; the kit's is at /etc/auu/$f.kit"
		fi
	fi
	if [ -n "$keep" ]; then
		say "$keep"
	else
		say "install -o root -g root -m 0644 $f /etc/auu/$f"
		install -o root -g root -m 0644 "$f" "/etc/auu/$f"
	fi
done
# The guide's check, as the relay's user: outside the unit the credential
# is not there, and that refusal, word for word, is the right answer; any
# other is a problem with the settings.
say "runuser -u auu -- /usr/local/bin/auu-relay --config /etc/auu/relay.json --print-config"
if check=$(runuser -u auu -- /usr/local/bin/auu-relay --config /etc/auu/relay.json --print-config 2>&1); then
	fail "the settings check printed the settings; /etc/auu/relay.json does not name the credential: $check"
fi
[ "$check" = "auu-relay: $want" ] || fail "the settings check said: $check"
say "install -m 0644 MANIFEST $manifest"
install -m 0644 MANIFEST "$manifest"

# 7. The unit, verified: systemd only warns about a directive it does not
# know, and a relay would then start without its credential, so the
# warning is a failure here.
say "install -o root -g root -m 0644 auu-relay.service $unit"
install -o root -g root -m 0644 auu-relay.service "$unit"
say "systemctl daemon-reload"
systemctl daemon-reload
say "systemd-analyze verify $unit"
verify=$(systemd-analyze verify "$unit" 2>&1) || { echo "$verify"; fail "systemd-analyze verify refused the unit"; }
if echo "$verify" | grep -qi 'unknown'; then echo "$verify"; fail "the unit has a directive this systemd does not know"; fi

# 8. The bundle, sealed to this host and removed; or, with none in the kit,
# the credential already here is kept, and with neither the two lines that
# finish the job are printed and the relay is not started.
if [ -e relay-bundle.json ]; then
	say "systemd-creds encrypt --name=relay-bundle relay-bundle.json $cred"
	systemd-creds encrypt --name=relay-bundle relay-bundle.json "$cred" || fail "systemd-creds could not seal the bundle"
	say "rm -f relay-bundle.json"
	rm -f relay-bundle.json
	! grep -q server_int_key "$cred" || fail "$cred holds the bundle in the clear; systemd-creds did not seal it"
elif [ ! -e "$cred" ]; then
	say "this kit has no bundle and $cred is not here; everything else is installed."
	say "Once relay-bundle.json is on this host, as root, from the directory it is in:"
	say "  systemd-creds encrypt --name=relay-bundle relay-bundle.json $cred"
	say "  systemctl enable --now auu-relay"
	[ -z "$backup" ] || say "the backup is in $backup; RESTORE there says how to put it back"
	exit 0
fi

# 9. Started, or restarted, and the journal read for where the bundle came
# from. enable is idempotent, so a relay whose unit was gone, or that was
# once disabled, survives a reboot again; reset-failed lets a relay that
# had been failing, or restarting too often for systemd's start limit,
# start again, which is what an update that repairs it needs.
if [ "$mode" = fresh ]; then
	say "systemctl enable --now auu-relay"
	systemctl enable --now auu-relay || fail "the relay did not start; journalctl -u auu-relay says why"
else
	say "systemctl enable auu-relay"
	systemctl enable auu-relay || fail "the unit could not be enabled"
	say "systemctl reset-failed auu-relay"
	systemctl reset-failed auu-relay 2>/dev/null || true
	say "systemctl restart auu-relay"
	systemctl restart auu-relay || fail "the relay did not start; journalctl -u auu-relay says why"
fi
if ! waitfor 'bundle_source=credential'; then
	journalctl -u auu-relay --no-pager -o cat --since '-2 minutes' 2>/dev/null | tail -40
	fail "the relay did not start from the credential within 30s; its journal is above"
fi

# 10. What to do next, read from the kit's own files.
url=$(sed -n 's/^  "public_url": "\(.*\)",*$/\1/p' relay.json)
anchor=$(sed -n 's/^  trust anchor   //p' README)
port=${url##*:}
say ""
say "the relay is up. From anywhere:"
say "  curl $url/v1/health"
say "and from an administrator's own machine, pointing it at the relay with the trust anchor, then the check:"
say "  auu relay add $url --name NAME --anchor $anchor"
say "  auu-admin status"
if command -v ufw >/dev/null 2>&1; then
	say "ufw is here and nothing here has touched it; to open the port: ufw allow $port/tcp"
elif command -v firewall-cmd >/dev/null 2>&1; then
	say "firewalld is here and nothing here has touched it; to open the port: firewall-cmd --permanent --add-port=$port/tcp && firewall-cmd --reload"
fi
if [ -n "$backup" ]; then
	say "the backup is in $backup; RESTORE there says how to put it back, and backups are yours to remove"
fi
say "delete this directory and the archive it came from: they hold nothing the relay needs now"
