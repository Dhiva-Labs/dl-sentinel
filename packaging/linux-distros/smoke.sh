#!/usr/bin/env bash
# Smoke test for an installed DL Sentinel package, run in the Fedora,
# openSUSE and Arch containers by verify.sh and after the AUR build by
# aur.sh. The repository is mounted at /src. Same checks as CI's deb-install
# job: both command names, --help, the rule list, and real scans of the test
# fixtures with their documented exit codes (1 policy violated, 0 clean).
set -euo pipefail

# readlink: on Fedora and Arch /usr/sbin is a symlink to /usr/bin and comes
# first on root's PATH.
test "$(readlink -f "$(command -v dl-sentinel)")" = /usr/bin/dl-sentinel
test "$(readlink -f "$(command -v sentinel)")" = /usr/bin/dl-sentinel
node --version
dl-sentinel --version
sentinel --version
dl-sentinel --help > /dev/null
dl-sentinel rules > /tmp/rules.txt
head -n 5 /tmp/rules.txt

work="$(mktemp -d)"
cp -r /src/tests/fixtures/. "$work/"

code=0
dl-sentinel scan "$work/vulnerable-app" --format json --quiet > /tmp/report.json || code=$?
echo "vulnerable-app exit code: $code"
test "$code" -eq 1
node -e '
  const r = JSON.parse(require("fs").readFileSync("/tmp/report.json", "utf8"));
  console.log(JSON.stringify({ tool: r.tool, stats: r.stats, scannersRun: r.scannersRun }));
  if (!(r.findings.length > 0 && r.scannersRun.length === 6 && r.errors.length === 0)) process.exit(1);
'

code=0
dl-sentinel scan "$work/clean-app" --quiet > /dev/null || code=$?
echo "clean-app exit code: $code"
test "$code" -eq 0
echo "dl-sentinel smoke test passed"
