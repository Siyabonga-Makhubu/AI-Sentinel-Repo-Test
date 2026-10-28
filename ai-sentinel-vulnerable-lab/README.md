# ai-sentinel-vulnerable-lab

An intentionally insecure, self-contained assessment target for authorized AI Sentinel testing. **Never deploy this repository to a public network or use it as a production template.** The source includes deliberately unsafe patterns and pinned vulnerable dependencies. It contains no real credentials, production data, external service calls, or production database.

## Setup and scans

Use Python 3.11 for best compatibility with the intentionally old PyYAML dependency. The test extra includes pinned scanner versions (Semgrep 1.119.0 and pip-audit 2.9.0).

```bash
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements-test.txt
```

Scan the pinned dependency manifest (pip-audit supports `-r` and `--format=json`):

```bash
mkdir -p scan-output
pip-audit -r requirements.txt --format=json > scan-output/pip-audit.json
```

On PowerShell, create the output folder with `New-Item -ItemType Directory -Force scan-output` and use the same pip-audit command. The command may exit nonzero when it finds vulnerabilities; preserve its JSON output and exit status as scanner evidence.

Run the local custom Semgrep rules and optionally the maintained community ruleset:

```bash
semgrep scan --config semgrep/rules.yml --json app/ > scan-output/semgrep.json
semgrep scan --config p/python --json app/ > scan-output/semgrep-community.json
```

The expected rule configuration for reproducible required checks is `semgrep/rules.yml`. Community rule availability and matches may change with Semgrep releases. Validate saved JSON:

```bash
python scripts/validate-results.py --semgrep scan-output/semgrep.json --pip-audit scan-output/pip-audit.json
python -m pytest
```

The validator fails when required findings are missing, output is malformed/missing, or Semgrep reports scan errors. `expected-findings/manifest.json` separates intended targets from confirmed scanner findings; its confirmed list stays empty until actual output has been reviewed and recorded.

## Local app

The primary target is source and manifests; no app startup is needed for either scan. If you want to check the health endpoint:

```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Only `/health` is available by default. Demo routes require `LAB_ENABLE_DEMOS=true`; they use only a synthetic in-memory SQLite database. Risky helpers are not invoked at startup or during ordinary tests. Do not expose this service outside localhost. To use Docker, run `docker compose up --build`; its host binding is explicitly `127.0.0.1:8000`. Stop and remove it with `docker compose down --remove-orphans` (add `--volumes` if you created volumes).

## Vulnerable examples and remediation concepts

All examples carry an `INTENTIONALLY VULNERABLE` marker. The eight local Semgrep IDs cover:

| Case | Pattern and expected rule | Remediation concept |
|---|---|---|
| SQL injection | Concatenated user input in SQL; `lab.python.sql-injection` | Parameterized query |
| Shell injection risk | User input concatenated into `subprocess.run(..., shell=True)`; `lab.python.shell-injection` | Argument array, no shell |
| Unsafe pickle | `pickle.loads`; `lab.python.unsafe-pickle` | Avoid pickle for untrusted data; use constrained formats |
| Unsafe YAML | `yaml.load(..., Loader=yaml.Loader)`; `lab.python.unsafe-yaml` | `yaml.safe_load` |
| Placeholder secret | Fake `FAKE_API_KEY`; `lab.python.hardcoded-placeholder-secret` | Secret manager and configuration; never commit actual secrets |
| Path traversal | Unchecked base/user path join; `lab.python.path-traversal` | Resolve and enforce containment |
| Weak password hash | MD5; `lab.python.weak-hash` | Argon2id, scrypt, or bcrypt with suitable parameters |
| Error disclosure | Returns exception text; `lab.python.information-disclosure` | Generic response; log details privately |

Rule severities are the local rule's Semgrep severity metadata, not a claim about exploit impact. Static matches need context and do not by themselves prove exploitability. The path rule is deliberately broad and may need review; safe controls are in `tests/fixtures/controls.py`.

## Dependency advisories

`requirements.txt` intentionally pins PyYAML 5.1.2 and Requests 2.19.1. The findings manifest records their published advisory identifiers, ranges, references, and advisory severity sources. Public references include [GHSA-3pqx-4fqf-j49f](https://github.com/advisories/GHSA-3pqx-4fqf-j49f), [GHSA-6757-jp84-gxfx](https://github.com/advisories/GHSA-6757-jp84-gxfx), [GHSA-x84v-xcm2-53pg](https://github.com/advisories/GHSA-x84v-xcm2-53pg), and [GHSA-j8r2-6x86-q33q](https://github.com/advisories/GHSA-j8r2-6x86-q33q). Database contents, alias mapping, pip-audit version, and expected scanner output can change over time. These are intended findings until scanner output confirms them; see verification notes in the manifest and this run's report.

## AI Sentinel assessment

Register this repository using AI Sentinel's authorized repository-assessment workflow. Compare its dependency and source findings to `expected-findings/manifest.json`, checking evidence locations, severity mapping, scan errors, and coverage limitations. Do not ask AI Sentinel to automatically fix this lab; the purpose is to evaluate detections. Treat unreported findings and scanner errors as separate outcomes from a clean scan.

## Verification status

Run `python -m pytest`, Semgrep, and pip-audit as described above. Scanner detections are not pre-claimed: use the actual generated output and tool versions to update confirmed results. Advisory versions above are based on the linked published ranges; scanner confirmation depends on available databases and environment compatibility.

Initial local verification (2026-10-28): Python 3.13.14, pytest 8.4.2, and pip 26.2.1; tests reported 8 passed and 1 skipped. The skipped test invokes Semgrep, which is not installed. Semgrep config parsed as YAML and contained eight unique rules. Neither Semgrep nor pip-audit ran in this environment, so all scanner detections remain unconfirmed; see `expected-findings/verification.json`.
