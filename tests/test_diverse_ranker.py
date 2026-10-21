"""tests/test_diverse_ranker.py
-----------------------------
Unit tests for src/memory/diverse_ranker.py.

Verifies:
  - Deterministic symbolic predicate evaluation V(x, R_k).
  - Metric extraction from both flat and nested alert dictionaries.
  - Partitioning by attack classes (ARP_POISON_MITM, TCP_SESSION_HIJACK, UDP_FLOOD, BENIGN_SPIKE).
  - Class-diverse candidate downsampling (P -> K).
  - Filtering candidates by predicate verification.
"""

from __future__ import annotations

import os
import sys
from typing import Any, Dict, List

import pytest

# Ensure repository root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.memory.diverse_ranker import (
    ALL_ATTACK_CLASSES,
    DiverseRanker,
    evaluate_symbolic_predicate,
    extract_metric_value,
    verify_predicate,
)


def test_extract_metric_value_flat_and_nested() -> None:
    """Verify extraction of sensor metrics from flat and nested alert structures."""
    # Flat structure
    flat_data = {
        "delta_arp": 1,
        "delta_seq": 2048,
        "duplicate_acks": 3,
        "payload_entropy": 7.5,
    }
    assert extract_metric_value(flat_data, "delta_arp") == 1
    assert extract_metric_value(flat_data, "delta_seq") == 2048
    assert extract_metric_value(flat_data, "duplicate_acks") == 3
    assert extract_metric_value(flat_data, "payload_entropy") == 7.5

    # Nested schema structure (AegisNetAnomalyAlert-v1)
    nested_data = {
        "layer2_state": {"delta_arp": 0, "claimed_ip": "172.28.0.20"},
        "layer4_state": {"delta_seq": 5000, "duplicate_acks": 5},
        "entropy_metrics": {"shannon_entropy": 6.8},
    }
    assert extract_metric_value(nested_data, "delta_arp") == 0
    assert extract_metric_value(nested_data, "delta_seq") == 5000
    assert extract_metric_value(nested_data, "duplicate_acks") == 5
    assert extract_metric_value(nested_data, "payload_entropy") == 6.8

    # Missing metrics
    assert extract_metric_value({}, "delta_seq") is None
    assert extract_metric_value("not_a_dict", "delta_seq") is None  # type: ignore


def test_evaluate_symbolic_predicate_operators() -> None:
    """Verify all comparison operators (==, !=, >, >=, <, <=) in symbolic evaluation."""
    alert = {"delta_seq": 1500, "duplicate_acks": 3, "delta_arp": 1}

    # Equality
    assert evaluate_symbolic_predicate(alert, {"symbolic_conditions": [{"field": "delta_arp", "op": "==", "value": 1}]}) is True
    assert evaluate_symbolic_predicate(alert, {"symbolic_conditions": [{"field": "delta_arp", "op": "==", "value": 0}]}) is False

    # Inequality
    assert evaluate_symbolic_predicate(alert, {"symbolic_conditions": [{"field": "delta_arp", "op": "!=", "value": 0}]}) is True

    # Greater than / Greater equal
    assert evaluate_symbolic_predicate(alert, {"symbolic_conditions": [{"field": "delta_seq", "op": ">", "value": 1460}]}) is True
    assert evaluate_symbolic_predicate(alert, {"symbolic_conditions": [{"field": "delta_seq", "op": ">", "value": 2000}]}) is False
    assert evaluate_symbolic_predicate(alert, {"symbolic_conditions": [{"field": "delta_seq", "op": ">=", "value": 1500}]}) is True

    # Less than / Less equal
    assert evaluate_symbolic_predicate(alert, {"symbolic_conditions": [{"field": "duplicate_acks", "op": "<", "value": 5}]}) is True
    assert evaluate_symbolic_predicate(alert, {"symbolic_conditions": [{"field": "duplicate_acks", "op": "<=", "value": 3}]}) is True
    assert evaluate_symbolic_predicate(alert, {"symbolic_conditions": [{"field": "duplicate_acks", "op": "<", "value": 2}]}) is False


def test_evaluate_symbolic_predicate_multiple_conditions() -> None:
    """Verify conjunction (AND) of multiple symbolic conditions."""
    alert = {"delta_seq": 5000, "duplicate_acks": 4, "delta_arp": 0}
    rule = {
        "symbolic_conditions": [
            {"field": "delta_seq", "op": ">", "value": 1460},
            {"field": "duplicate_acks", "op": ">=", "value": 3},
            {"field": "delta_arp", "op": "==", "value": 0},
        ]
    }
    assert evaluate_symbolic_predicate(alert, rule) is True

    # One condition fails
    failing_rule = {
        "symbolic_conditions": [
            {"field": "delta_seq", "op": ">", "value": 1460},
            {"field": "duplicate_acks", "op": ">=", "value": 10},
        ]
    }
    assert evaluate_symbolic_predicate(alert, failing_rule) is False


def test_evaluate_symbolic_predicate_missing_metric_returns_false() -> None:
    """Verify evaluation returns False when an alert is missing a required metric."""
    alert = {"delta_arp": 1}
    rule = {"symbolic_conditions": [{"field": "delta_seq", "op": ">", "value": 1000}]}
    assert evaluate_symbolic_predicate(alert, rule) is False


def test_evaluate_symbolic_predicate_malformed_conditions_returns_false() -> None:
    """Verify malformed condition structures safely return False."""
    alert = {"delta_seq": 100}
    assert evaluate_symbolic_predicate(alert, {"symbolic_conditions": "not_a_list"}) is False
    assert evaluate_symbolic_predicate(alert, {"symbolic_conditions": ["not_a_dict"]}) is False
    assert evaluate_symbolic_predicate(alert, {"symbolic_conditions": [{"field": "delta_seq", "op": "UNKNOWN_OP", "value": 100}]}) is False


def test_partition_by_class() -> None:
    """Verify candidate partitioning across attack classes."""
    candidates = [
        {"rule_id": "R1", "attack_class": "ARP_POISON_MITM"},
        {"rule_id": "R2", "attack_class": "ARP_POISON_MITM"},
        {"rule_id": "R3", "attack_class": "TCP_SESSION_HIJACK"},
        {"rule_id": "R4", "attack_class": "UDP_FLOOD"},
        {"rule_id": "R5", "attack_class": "BENIGN_SPIKE"},
    ]
    partition = DiverseRanker.partition_by_class(candidates)
    assert set(partition.keys()) == set(ALL_ATTACK_CLASSES)
    assert len(partition["ARP_POISON_MITM"]) == 2
    assert len(partition["TCP_SESSION_HIJACK"]) == 1
    assert len(partition["UDP_FLOOD"]) == 1
    assert len(partition["BENIGN_SPIKE"]) == 1


def test_downsample_diverse_round_robin() -> None:
    """Verify downsampling selects class-diverse representatives."""
    candidates: List[Dict[str, Any]] = []
    # 10 ARP rules, 5 TCP rules, 3 UDP rules, 2 Benign rules
    for i in range(10):
        candidates.append({"rule_id": f"ARP-{i}", "attack_class": "ARP_POISON_MITM"})
    for i in range(5):
        candidates.append({"rule_id": f"TCP-{i}", "attack_class": "TCP_SESSION_HIJACK"})
    for i in range(3):
        candidates.append({"rule_id": f"UDP-{i}", "attack_class": "UDP_FLOOD"})
    for i in range(2):
        candidates.append({"rule_id": f"BENIGN-{i}", "attack_class": "BENIGN_SPIKE"})

    # Ephemeral ranker instance without connecting to storage
    ranker = DiverseRanker.__new__(DiverseRanker)
    selected = ranker.downsample_diverse(candidates, k=5)

    assert len(selected) == 5
    selected_classes = {r["attack_class"] for r in selected}
    # All 4 classes should be represented in the top 5!
    assert len(selected_classes) == 4
    assert set(ALL_ATTACK_CLASSES).issubset(selected_classes)


def test_filter_by_predicate() -> None:
    """Verify filtering a candidate list with predicate verification."""
    alert = {"delta_arp": 1, "delta_seq": 0}
    candidates = [
        {"rule_id": "R1", "symbolic_conditions": [{"field": "delta_arp", "op": "==", "value": 1}]},
        {"rule_id": "R2", "symbolic_conditions": [{"field": "delta_arp", "op": "==", "value": 0}]},
        {"rule_id": "R3", "symbolic_conditions": [{"field": "delta_seq", "op": ">", "value": 1000}]},
    ]
    ranker = DiverseRanker.__new__(DiverseRanker)
    filtered = ranker.filter_by_predicate(alert, candidates)
    assert len(filtered) == 1
    assert filtered[0]["rule_id"] == "R1"
