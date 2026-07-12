"""Structural and policy tests for the Sigma rule library.

These run without any Sigma backend installed (pure YAML), so they are fast and
always green in CI. They enforce the house style every detection must follow:
required metadata, an ATT&CK technique tag, a valid severity, and a globally
unique rule id. `sigma check` and tools/convert.py cover Sigma-schema validity
and cross-SIEM compilation separately.
"""
from __future__ import annotations

import uuid
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
RULES = sorted((REPO_ROOT / "rules").rglob("*.yml"))

REQUIRED_FIELDS = {
    "title", "id", "status", "description", "references",
    "author", "date", "tags", "logsource", "detection", "level",
}
VALID_LEVELS = {"informational", "low", "medium", "high", "critical"}
VALID_STATUS = {"experimental", "test", "stable", "deprecated", "unsupported"}


def load(rule: Path) -> dict:
    return yaml.safe_load(rule.read_text(encoding="utf-8"))


def test_rules_exist():
    assert RULES, "no Sigma rules found under rules/"


@pytest.mark.parametrize("rule", RULES, ids=lambda p: p.name)
def test_required_fields(rule: Path):
    data = load(rule)
    missing = REQUIRED_FIELDS - data.keys()
    assert not missing, f"{rule.name} missing fields: {sorted(missing)}"


@pytest.mark.parametrize("rule", RULES, ids=lambda p: p.name)
def test_valid_level_and_status(rule: Path):
    data = load(rule)
    assert data["level"] in VALID_LEVELS, f"{rule.name}: bad level {data['level']!r}"
    assert data["status"] in VALID_STATUS, f"{rule.name}: bad status {data['status']!r}"


@pytest.mark.parametrize("rule", RULES, ids=lambda p: p.name)
def test_valid_uuid(rule: Path):
    data = load(rule)
    uuid.UUID(str(data["id"]))  # raises ValueError if malformed


@pytest.mark.parametrize("rule", RULES, ids=lambda p: p.name)
def test_has_attack_technique_tag(rule: Path):
    data = load(rule)
    tags = [str(t) for t in data.get("tags", [])]
    techniques = [t for t in tags if t.startswith("attack.t")]
    assert techniques, f"{rule.name}: no attack.tXXXX technique tag"


@pytest.mark.parametrize("rule", RULES, ids=lambda p: p.name)
def test_detection_has_condition(rule: Path):
    data = load(rule)
    assert "condition" in data["detection"], f"{rule.name}: detection has no condition"


def test_ids_are_unique():
    seen: dict[str, str] = {}
    for rule in RULES:
        rid = str(load(rule)["id"])
        assert rid not in seen, f"duplicate id {rid} in {rule.name} and {seen[rid]}"
        seen[rid] = rule.name
