#!/usr/bin/env python3
"""Compare scanner JSON to ground truth; scanner failures are never clean scans."""
import argparse
import json
import sys
from pathlib import Path

def read_json(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid or missing scanner output {path}: {exc}") from exc

def semgrep_keys(data):
    if not isinstance(data, dict) or "results" not in data or not isinstance(data["results"], list):
        raise ValueError("invalid Semgrep JSON: expected results list")
    if data.get("errors"):
        raise RuntimeError(f"Semgrep reported scanner errors: {data['errors']}")
    return {item.get("check_id", "").split(".")[-1] for item in data["results"]}

def audit_keys(data):
    if not isinstance(data, dict) or not isinstance(data.get("dependencies"), list):
        raise ValueError("invalid pip-audit JSON: expected dependencies list")
    found=set()
    for dep in data["dependencies"]:
        if not isinstance(dep, dict) or not isinstance(dep.get("vulns", []), list):
            raise ValueError("invalid pip-audit dependency entry")
        for vuln in dep.get("vulns", []):
            if not isinstance(vuln, dict): raise ValueError("invalid pip-audit vulnerability entry")
            found.update([vuln.get("id"), *vuln.get("aliases", [])])
    return {item for item in found if item}

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--manifest", default="expected-findings/manifest.json")
    p.add_argument("--semgrep")
    p.add_argument("--pip-audit")
    args=p.parse_args()
    try:
        manifest=read_json(args.manifest)
        any_missing=False
        for scanner, path, keyfn in (("semgrep",args.semgrep,semgrep_keys),("pip-audit",args.pip_audit,audit_keys)):
            if not path: continue
            observed=keyfn(read_json(path))
            expected={(x["rule_id"].split(".")[-1] if scanner=="semgrep" else x["advisory_id"]) for x in manifest["intended_findings"] if x["scanner"]==scanner and x.get("required",True)}
            missing=expected-observed
            print(f"{scanner}: detected={sorted(expected & observed)} missing={sorted(missing)} unexpected={sorted(observed-expected)}")
            any_missing |= bool(missing)
        if not args.semgrep and not args.pip_audit: raise ValueError("provide at least one scanner output")
        return 1 if any_missing else 0
    except RuntimeError as exc:
        print(f"SCANNER ERROR: {exc}",file=sys.stderr); return 2
    except (ValueError, KeyError, TypeError) as exc:
        print(f"INVALID RESULTS: {exc}",file=sys.stderr); return 2

if __name__=="__main__": raise SystemExit(main())
