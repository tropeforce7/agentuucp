#!/bin/sh
# The relay machine's PID 1: the container form of the systemd unit.
#
# The unit unseals the bundle with LoadCredentialEncrypted= into
# $CREDENTIALS_DIRECTORY and runs the relay as auu on the shipped settings.
# Here the bundle arrives the way a person delivers it, as a file copied to
# /etc/auu/delivered/, and is installed as the credential readable by auu
# alone; the relay is then started exactly as the unit starts it. Until a
# bundle has been delivered there is no relay, which is what happens under
# the unit too.
#
# /etc/auu/extra-args, when present, holds flags appended to the command
# line, so a test can restart the relay with a setting changed the way an
# operator would edit ExecStart=.
set -eu

creds=/run/credentials/auu-relay
delivered=/etc/auu/delivered/relay-bundle.json

install -d -m 0700 -o auu -g auu /var/lib/auu
install -d -m 0755 /etc/auu/delivered
install -d -m 0700 -o auu -g auu "$creds"

if [ ! -e "$delivered" ] && [ ! -e "$creds/relay-bundle" ]; then
	echo "waiting for the bundle to be delivered to $delivered"
	i=0
	while [ ! -e "$delivered" ]; do
		sleep 1
		i=$((i + 1))
		if [ "$i" -ge 600 ]; then
			echo "no bundle was delivered in ten minutes"
			exit 1
		fi
	done
fi
if [ -e "$delivered" ]; then
	install -o auu -g auu -m 0400 "$delivered" "$creds/relay-bundle"
	rm -f "$delivered"
	echo "installed the delivered bundle as the credential relay-bundle"
fi

export CREDENTIALS_DIRECTORY="$creds"
extra=""
if [ -f /etc/auu/extra-args ]; then
	extra=$(cat /etc/auu/extra-args)
fi
# shellcheck disable=SC2086
exec runuser -u auu -- /usr/local/bin/auu-relay --config /etc/auu/relay.json $extra
