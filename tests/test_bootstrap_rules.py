"""tests/test_bootstrap_rules.py
------------------------------
Unit tests for src/memory/bootstrap_rules.py.

Verifies:
  - Fails loudly (raises FileNotFoundError) if raw_rules_dir does not exist.
  - Fails loudly (raises FileNotFoundError) if raw_rules_dir is empty (never silently invents rules).
  - Ingests pre-sourced rules into ChromaDB collection.
  - Sourced rule directory data/raw_rules contains >= 50 valid JSON rule files.
"""

from __future__ import annotations

import glob
import json
import os
import sys
from typing import Any, Dict

import pytest

# Ensure repository root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.memory.bootstrap_rules import bootstrap_experience_rules
from src.memory.experience_store import ExperienceStore


def test_bootstrap_nonexistent_dir_fails_loudly() -> None:
    """Verify bootstrap fails loudly when raw_rules directory does not exist."""
    with pytest.raises(FileNotFoundError, match="Raw rules directory not found"):
        bootstrap_experience_rules(raw_rules_dir="/path/does/not/exist/raw_rules")


def test_bootstrap_empty_dir_fails_loudly(tmp_path) -> None:
    """Verify bootstrap fails loudly if raw_rules directory contains no JSON files."""
    empty_dir = tmp_path / "empty_rules"
    empty_dir.mkdir()

    with pytest.raises(FileNotFoundError, match="No JSON rule files found"):
        bootstrap_experience_rules(raw_rules_dir=str(empty_dir))


def test_bootstrap_ingests_valid_rules(tmp_path) -> None:
    """Verify bootstrap reads sourced JSON rule files and ingests into ChromaDB."""
    rules_dir = tmp_path / "test_rules"
    rules_dir.mkdir()
    chroma_dir = tmp_path / "test_chroma"

    sample_rule_1: Dict[str, Any] = {
        "rule_id": "EXP-BOOTSTRAP-001",
        "attack_class": "ARP_POISON_MITM",
        "behavior_summary": "Unsolicited ARP reply claiming server IP",
        "symbolic_conditions": [{"field": "delta_arp", "op": "==", "value": 1}],
        "forbidden_actions": ["drop_victim_ip"],
        "mandated_remediation": "ISOLATE_MAC_THEN_IPSEC",
        "confidence_rating": 0.95,
    }
    sample_rule_2: Dict[str, Any] = {
        "rule_id": "EXP-BOOTSTRAP-002",
        "attack_class": "BENIGN_SPIKE",
        "behavior_summary": "Benign client reconnect small jump",
        "symbolic_conditions": [{"field": "delta_seq", "op": "<", "value": 500}],
        "forbidden_actions": ["drop_victim_ip"],
        "mandated_remediation": "MONITOR_ONLY",
        "confidence_rating": 0.85,
    }

    with open(rules_dir / "rule_1.json", "w", encoding="utf-8") as f:
        json.dump(sample_rule_1, f)
    with open(rules_dir / "rule_2.json", "w", encoding="utf-8") as f:
        json.dump(sample_rule_2, f)

    count = bootstrap_experience_rules(
        raw_rules_dir=str(rules_dir),
        persist_dir=str(chroma_dir),
    )
    assert count == 2

    store = ExperienceStore(persist_dir=str(chroma_dir))
    assert store.count() == 2
    r1 = store.get_rule("EXP-BOOTSTRAP-001")
    assert r1 is not None
    assert r1["attack_class"] == "ARP_POISON_MITM"


def test_presourced_rules_directory_integrity() -> None:
    """Verify pre-sourced data/raw_rules has >= 50 valid rules and no missing files."""
    rule_files = glob.glob("data/raw_rules/*.json")
    assert len(rule_files) >= 50, f"Expected at least 50 sourced rules, found {len(rule_files)}"

    for file_path in rule_files:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            assert "rule_id" in data
            assert "attack_class" in data
            assert "symbolic_conditions" in data
            assert "mandated_remediation" in data
