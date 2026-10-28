import json
import shutil
import subprocess
import pytest

def test_custom_rules_detect_all_intended_cases_and_ignore_controls():
    if not shutil.which("semgrep"):
        pytest.skip("Semgrep CLI is not installed; install requirements-test.txt")
    run = subprocess.run(["semgrep", "scan", "--config", "semgrep/rules.yml", "--json", "app/"], capture_output=True, text=True)
    assert run.returncode == 0, run.stderr
    data = json.loads(run.stdout)
    assert not data.get("errors"), data.get("errors")
    found = {item["check_id"].split(".")[-1] for item in data["results"]}
    expected = {"sql-injection", "shell-injection", "unsafe-pickle", "unsafe-yaml", "hardcoded-placeholder-secret", "path-traversal", "weak-hash", "information-disclosure"}
    assert expected <= found
    controls = subprocess.run(["semgrep", "scan", "--config", "semgrep/rules.yml", "--json", "tests/fixtures/controls.py"], capture_output=True, text=True)
    assert controls.returncode == 0, controls.stderr
    control_data = json.loads(controls.stdout)
    assert not control_data.get("results"), control_data.get("results")
