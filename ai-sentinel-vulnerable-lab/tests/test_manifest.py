import json
from pathlib import Path

def test_manifest_valid_and_unique():
    data = json.loads(Path("expected-findings/manifest.json").read_text(encoding="utf-8"))
    ids = [item["id"] for item in data["intended_findings"]]
    assert len(ids) == len(set(ids))
    assert all(item["verification_status"] in {"verified", "unverified"} for item in data["intended_findings"])
    for item in data["intended_findings"]:
        if item["scanner"] == "pip-audit":
            assert item["advisory_reference"].startswith("https://")
