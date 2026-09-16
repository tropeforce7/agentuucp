#!/bin/sh
# A person's machine: nothing runs on it until the test runs something, as
# a person would, with docker compose exec. The runtime directories are
# where auu's agent keeps its socket on a machine with a login session.
set -eu
install -d -m 0700 -o you -g you /run/user/1000
install -d -m 0700 -o alice -g alice /run/user/1001
install -d -m 0700 -o bob -g bob /run/user/1002
exec sleep infinity
