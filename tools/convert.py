#!/usr/bin/env python3
"""Batch-convert the Sigma rule library to each target SIEM query language.

Drives sigma-cli (pySigma) over every rule in ``rules/`` and writes the
generated queries into ``build/<target>/``. This is the core of the
detection-as-code loop: one vendor-neutral Sigma rule, validated once, compiled
to Splunk SPL and Microsoft Sentinel / Defender KQL.

Conversion is *log-source aware*. Not every SIEM schema carries every data
source (for example, Microsoft Defender XDR has no first-class DNS-query table),
so each target declares which Sigma log-source categories it supports. A rule
whose category a target cannot carry is reported as SKIPPED with a reason -- that
is expected, and honest. A rule that a target *should* be able to compile but
fails on is a hard FAIL and exits non-zero so CI catches it.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = REPO_ROOT / "rules"
BUILD_DIR = REPO_ROOT / "build"

# Log-source categories Microsoft Defender XDR / Sentinel (via the kusto
# backend's microsoft_xdr pipeline) maps to device tables.
XDR_CATEGORIES = {
    "process_creation", "image_load", "network_connection",
    "file_event", "file_access", "file_change", "file_delete", "file_rename",
    "registry_event", "registry_add", "registry_set", "registry_delete",
}

# label, sigma backend, pipeline, extension, supported categories (None = all)
TARGETS = [
    {"label": "splunk", "backend": "splunk", "pipeline": "sysmon",
     "ext": "spl", "categories": None},
    {"label": "sentinel", "backend": "kusto", "pipeline": "microsoft_xdr",
     "ext": "kql", "categories": XDR_CATEGORIES},
]


def find_rules() -> list[Path]:
    return sorted(p for p in RULES_DIR.rglob("*.yml") if p.is_file())


def rule_category(rule: Path) -> str:
    data = yaml.safe_load(rule.read_text(encoding="utf-8"))
    return (data.get("logsource") or {}).get("category", "")


def convert_rule(rule: Path, backend: str, pipeline: str) -> tuple[bool, str]:
    cmd = ["sigma", "convert", "-t", backend, "-p", pipeline, str(rule)]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        return False, proc.stderr.strip() or proc.stdout.strip()
    return True, proc.stdout.strip()


def main() -> int:
    rules = find_rules()
    if not rules:
        print("No Sigma rules found under rules/", file=sys.stderr)
        return 1

    print(f"Converting {len(rules)} rule(s) to {len(TARGETS)} target(s)...\n")
    failures = 0

    for target in TARGETS:
        label, backend = target["label"], target["backend"]
        pipeline, ext = target["pipeline"], target["ext"]
        supported = target["categories"]
        out_dir = BUILD_DIR / label
        out_dir.mkdir(parents=True, exist_ok=True)
        blocks: list[str] = []

        for rule in rules:
            rel = rule.relative_to(REPO_ROOT)
            category = rule_category(rule)
            if supported is not None and category not in supported:
                print(f"  [skip] {label:<8} <- {rel}  (no '{category}' table)")
                continue
            ok, result = convert_rule(rule, backend, pipeline)
            if ok:
                blocks.append(f"// source: {rel}\n{result}\n")
                print(f"  [ok]   {label:<8} <- {rel}")
            else:
                failures += 1
                print(f"  [FAIL] {label:<8} <- {rel}\n         {result}",
                      file=sys.stderr)

        out_file = out_dir / f"detections.{ext}"
        out_file.write_text("\n".join(blocks) + "\n", encoding="utf-8")
        print(f"  -> wrote {out_file.relative_to(REPO_ROOT)}\n")

    if failures:
        print(f"FAILED: {failures} conversion(s) did not compile.", file=sys.stderr)
        return 1
    print("All applicable rules compiled to their target SIEM(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
