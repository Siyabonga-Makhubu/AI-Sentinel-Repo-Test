from pathlib import Path
import yaml

def test_custom_semgrep_rules_are_valid_yaml_with_unique_ids():
    config = yaml.safe_load(Path("semgrep/rules.yml").read_text(encoding="utf-8"))
    rules = config["rules"]
    ids = [rule["id"] for rule in rules]
    assert len(ids) == 8
    assert len(ids) == len(set(ids))
    assert all(rule["languages"] == ["python"] and rule["severity"] in {"ERROR", "WARNING", "INFO"} for rule in rules)
