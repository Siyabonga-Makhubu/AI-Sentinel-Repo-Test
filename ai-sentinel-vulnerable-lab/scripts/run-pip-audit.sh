#!/usr/bin/env sh
set -eu
mkdir -p scan-output
pip-audit -r requirements.txt --format=json > scan-output/pip-audit.json
status=$?
exit "$status"
