import json
import subprocess
import sys
from pathlib import Path

SCRIPT = Path("scripts/validate-results.py")

def invoke(*args):
    return subprocess.run([sys.executable, str(SCRIPT), *map(str, args)], capture_output=True, text=True)

def test_validator_rejects_missing_and_malformed(tmp_path):
    missing = invoke("--semgrep", tmp_path / "absent.json")
    assert missing.returncode == 2 and "INVALID RESULTS" in missing.stderr
    broken = tmp_path / "broken.json"
    broken.write_text("{", encoding="utf-8")
    result = invoke("--semgrep", broken)
    assert result.returncode == 2

def test_validator_distinguishes_scanner_error(tmp_path):
    out = tmp_path / "error.json"
    out.write_text(json.dumps({"results": [], "errors": [{"message":"scan failed"}]}), encoding="utf-8")
    result = invoke("--semgrep", out)
    assert result.returncode == 2 and "SCANNER ERROR" in result.stderr

def test_validator_empty_valid_output_reports_missing(tmp_path):
    out = tmp_path / "empty.json"
    out.write_text(json.dumps({"results": [], "errors": []}), encoding="utf-8")
    result = invoke("--semgrep", out)
    assert result.returncode == 1 and "missing=" in result.stdout

def test_validator_handles_pip_audit_json_shape(tmp_path):
    out = tmp_path / "audit.json"
    out.write_text(json.dumps({"dependencies": [{"name":"requests", "version":"2.19.1", "vulns":[{"id":"PYSEC-2018-28", "aliases":["CVE-2018-18074"]}]}]}), encoding="utf-8")
    result = invoke("--pip-audit", out)
    assert "CVE-2018-18074" in result.stdout
    assert "missing=" in result.stdout
