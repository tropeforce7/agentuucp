#!/usr/bin/env bash
# The container suite, start to finish: build the image, bring the four
# machines up, run the cycle and the matrix, write the report to out/, and
# take everything down again. make e2e runs this.
#
#   AUU_E2E_KEEP=1     leave the stack up afterwards, for a look; the tests
#                      can then be run again with go test -tags e2e in this
#                      directory, and -run 'TestMatrix/K/K13' works once
#                      TestCycle has run.
#   AUU_E2E_RUN=REGEX  run only the tests matching it.
#   AUU_E2E_SLOW=1     include the rows that wait real time to pass.
#   AUU_E2E_NOFAULT=1  every fault helper does nothing; the rows that still
#                      pass are the ones whose assertion does not depend
#                      on the fault, which the notes list. Such a run
#                      writes out/report-nofault.md and out/test-nofault.log,
#                      never the real report's names: it is meant to fail,
#                      and must not overwrite the run that proves the suite
#                      green.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
cd "$here"
mkdir -p out

command -v docker >/dev/null || { echo "docker is not installed" >&2; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "docker compose is not available" >&2; exit 1; }

# prev is the release family O runs as the old party, the old relay and the
# old tools; each release moves it to the one before. It is built from a
# clone of this repository at its tag, made from the local object store and
# fetching nothing, so that Go stamps the binaries with the tag as it stamps
# any tagged build: a tree from git archive carries no version, and the
# family's first assertion is the old binary's version.
prev=v0.15.0
repo=$(git -C "$here" rev-parse --show-toplevel)
if ! git -C "$repo" rev-parse -q --verify "refs/tags/$prev" >/dev/null; then
	echo "this clone has no tag $prev, which family O builds the previous release from; run 'git fetch --tags' and try again" >&2
	exit 1
fi
prevdir=$(mktemp -d)
removeprev() { rm -rf "$prevdir"; }
trap removeprev EXIT
# The clone is a directory under the context's root and not the root, so the
# .dockerignore in the old tree, which leaves out .git, is not the context's.
git -c advice.detachedHead=false clone -q --depth 1 --branch "$prev" "file://$repo" "$prevdir/src"
export AUU_E2E_PREV="$prevdir"

docker compose build
docker compose up -d
cleanup() {
	# First, since a failing command in an EXIT trap under set -e ends it.
	removeprev
	if [ -z "${AUU_E2E_KEEP:-}" ]; then
		docker compose down -v
	else
		echo "the stack is still up; docker compose -f $here/compose.yaml down -v removes it"
	fi
}
trap cleanup EXIT

args=(-tags e2e -count=1 -timeout 90m -v)
if [ -n "${AUU_E2E_RUN:-}" ]; then
	args+=(-run "$AUU_E2E_RUN")
fi
report=report.md
log=test.log
if [ "${AUU_E2E_NOFAULT:-}" = 1 ]; then
	report=report-nofault.md
	log=test-nofault.log
fi
set +e
go test "${args[@]}" . 2>&1 | tee "out/$log" | grep -E '^(ok|FAIL|PASS|--- |    --- |        --- )'
status=${PIPESTATUS[0]}
set -e
echo "the report is $here/out/$report; the full test output is $here/out/$log"
exit "$status"
