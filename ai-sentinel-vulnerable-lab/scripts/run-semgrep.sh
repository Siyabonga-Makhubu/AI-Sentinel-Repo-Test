#!/usr/bin/env sh
set -eu
mkdir -p scan-output
semgrep scan --config semgrep/rules.yml --json app/ > scan-output/semgrep.json
