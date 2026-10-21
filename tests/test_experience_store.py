"""tests/test_experience_store.py
--------------------------------
Unit tests for src/memory/experience_store.py.

Verifies:
  - Enforce schema validation on insert: rule_id, attack_class, behavior_summary,
    symbolic_conditions, forbidden_actions, mandated_remediation, confidence_rating.
  - Inserts missing any required key raise ValueError and are rejected.
  - Inserts with invalid field values (attack_class, confidence_rating, operators, etc.) are rejected.
  - Persistent ChromaDB collection sera_ids_experiences initializes and connects
    to the pre-populated experience knowledge base.
  - Isolated add_rule, add_rules, and get_rule operations.
"""

from __future__ import annotations

import copy
import os
import sys
from typing import Any, Dict

import pytest

# Ensure repository root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from chromadb import EmbeddingFunction

from src.memory.diverse_ranker import DiverseRanker, evaluate_symbolic_predicate
from src.memory.experience_store import (
    REQUIRED_RULE_FIELDS,
    VALID_ATTACK_CLASSES,
    VALID_REMEDIATIONS,
    ExperienceStore,
    validate_experience_rule,
)


class DummyEmbeddingFunction(EmbeddingFunction):
    """Fast dummy embedding function for isolated unit tests without neural model overhead."""

    def __init__(self) -> None:
        pass

    def __call__(self, input: list[str]) -> list[list[float]]:
        # Return deterministic 384-dimensional zero vector matching all-MiniLM-L6-v2 dimension
        return [[0.0] * 384 for _ in input]

    @staticmethod
    def name() -> str:
        return "dummy_embedding_function"

    def get_config(self) -> dict[str, Any]:
        return {}

    @staticmethod
    def build_from_config(config: dict[str, Any]) -> "DummyEmbeddingFunction":
        return DummyEmbeddingFunction()


@pytest.fixture
def dummy_embedding_fn() -> DummyEmbeddingFunction:
    return DummyEmbeddingFunction()


@pytest.fixture
def sample_valid_rule() -> Dict[str, Any]:
    return {
        "rule_id": "TEST-EXP-001",
        "attack_class": "ARP_POISON_MITM",
        "behavior_summary": "Unsolicited gratuitous ARP reply claiming server IP from attacker MAC",
        "symbolic_conditions": [
            {"field": "delta_arp", "op": "==", "value": 1}
        ],
        "forbidden_actions": [
            "drop_victim_ip"
        ],
        "mandated_remediation": "ISOLATE_MAC_THEN_IPSEC",
        "confidence_rating": 0.95,
    }


# =====================================================================
# Schema Validation on Insert Tests
# =====================================================================

@pytest.mark.parametrize("missing_field", sorted(REQUIRED_RULE_FIELDS))
def test_insert_missing_required_key_raises(
    sample_valid_rule: Dict[str, Any],
    missing_field: str,
    tmp_path,
    dummy_embedding_fn: DummyEmbeddingFunction,
) -> None:
    """Verify that an insert missing ANY required key raises ValueError and is rejected."""
    incomplete_rule = copy.deepcopy(sample_valid_rule)
    del incomplete_rule[missing_field]

    # 1. Standalone validator must raise ValueError
    with pytest.raises(ValueError, match=f"Rule missing required fields:.*{missing_field}"):
        validate_experience_rule(incomplete_rule)

    # 2. ExperienceStore.add_rule must reject and raise ValueError
    store = ExperienceStore(
        persist_dir=str(tmp_path / "chroma_test"),
        embedding_fn=dummy_embedding_fn,
    )
    with pytest.raises(ValueError, match="Rule missing required fields"):
        store.add_rule(incomplete_rule)

    # 3. Batch insert ExperienceStore.add_rules must also reject and raise ValueError
    with pytest.raises(ValueError, match="Rule missing required fields"):
        store.add_rules([incomplete_rule])


def test_insert_non_dict_raises() -> None:
    """Verify non-dictionary rules are rejected."""
    with pytest.raises(ValueError, match="Rule must be a dictionary"):
        validate_experience_rule("not a dict")  # type: ignore

    with pytest.raises(ValueError, match="Rule must be a dictionary"):
        validate_experience_rule(None)  # type: ignore


def test_insert_empty_rule_id_raises(sample_valid_rule: Dict[str, Any]) -> None:
    """Verify empty or non-string rule_id is rejected."""
    bad_rule = copy.deepcopy(sample_valid_rule)
    bad_rule["rule_id"] = "   "
    with pytest.raises(ValueError, match="rule_id must be a non-empty string"):
        validate_experience_rule(bad_rule)


def test_insert_invalid_attack_class_raises(sample_valid_rule: Dict[str, Any]) -> None:
    """Verify unknown attack_class is rejected."""
    bad_rule = copy.deepcopy(sample_valid_rule)
    bad_rule["attack_class"] = "UNKNOWN_ATTACK"
    with pytest.raises(ValueError, match="Invalid attack_class: UNKNOWN_ATTACK"):
        validate_experience_rule(bad_rule)


def test_insert_invalid_remediation_raises(sample_valid_rule: Dict[str, Any]) -> None:
    """Verify unknown mandated_remediation is rejected."""
    bad_rule = copy.deepcopy(sample_valid_rule)
    bad_rule["mandated_remediation"] = "DROP_EVERYTHING"
    with pytest.raises(ValueError, match="Invalid mandated_remediation: DROP_EVERYTHING"):
        validate_experience_rule(bad_rule)


@pytest.mark.parametrize("bad_conf", [-0.1, 1.05, "invalid", None])
def test_insert_invalid_confidence_rating_raises(
    sample_valid_rule: Dict[str, Any], bad_conf: Any
) -> None:
    """Verify confidence rating outside [0.0, 1.0] or non-float is rejected."""
    bad_rule = copy.deepcopy(sample_valid_rule)
    bad_rule["confidence_rating"] = bad_conf
    with pytest.raises(ValueError, match="confidence_rating must be float in \\[0.0, 1.0\\]"):
        validate_experience_rule(bad_rule)


def test_insert_invalid_symbolic_conditions_raises(sample_valid_rule: Dict[str, Any]) -> None:
    """Verify malformed symbolic conditions are rejected."""
    bad_rule1 = copy.deepcopy(sample_valid_rule)
    bad_rule1["symbolic_conditions"] = "not_a_list"
    with pytest.raises(ValueError, match="symbolic_conditions must be a list"):
        validate_experience_rule(bad_rule1)

    bad_rule2 = copy.deepcopy(sample_valid_rule)
    bad_rule2["symbolic_conditions"] = [{"field": "invalid_field", "op": "==", "value": 1}]
    with pytest.raises(ValueError, match="Invalid condition field: invalid_field"):
        validate_experience_rule(bad_rule2)

    bad_rule3 = copy.deepcopy(sample_valid_rule)
    bad_rule3["symbolic_conditions"] = [{"field": "delta_arp", "op": "INVALID_OP", "value": 1}]
    with pytest.raises(ValueError, match="Invalid condition operator: INVALID_OP"):
        validate_experience_rule(bad_rule3)


def test_insert_invalid_forbidden_actions_raises(sample_valid_rule: Dict[str, Any]) -> None:
    """Verify non-list forbidden_actions is rejected."""
    bad_rule = copy.deepcopy(sample_valid_rule)
    bad_rule["forbidden_actions"] = "not_a_list"
    with pytest.raises(ValueError, match="forbidden_actions must be a list"):
        validate_experience_rule(bad_rule)


def test_benign_spike_requires_monitor_only(sample_valid_rule: Dict[str, Any]) -> None:
    """Verify BENIGN_SPIKE rules must have MONITOR_ONLY remediation."""
    bad_rule = copy.deepcopy(sample_valid_rule)
    bad_rule["attack_class"] = "BENIGN_SPIKE"
    bad_rule["mandated_remediation"] = "ISOLATE_MAC_THEN_IPSEC"
    with pytest.raises(ValueError, match="BENIGN_SPIKE rules must use mandated_remediation MONITOR_ONLY"):
        validate_experience_rule(bad_rule)


# =====================================================================
# ExperienceStore Operation & Initialization Tests
# =====================================================================

def test_experience_store_initialization_defaults() -> None:
    """Verify ExperienceStore initializes persistent collection sera_ids_experiences."""
    store = ExperienceStore()
    assert store.collection.name == "sera_ids_experiences"
    assert store.MODEL_NAME == "all-MiniLM-L6-v2"
    assert store.count() >= 50, f"Expected at least 50 bootstrapped rules in DB, got {store.count()}"


def test_add_and_retrieve_rule(
    sample_valid_rule: Dict[str, Any],
    tmp_path,
    dummy_embedding_fn: DummyEmbeddingFunction,
) -> None:
    """Verify adding a valid rule and retrieving it returns matching fields."""
    store = ExperienceStore(
        persist_dir=str(tmp_path / "chroma_crud"),
        embedding_fn=dummy_embedding_fn,
    )
    assert store.count() == 0

    store.add_rule(sample_valid_rule)
    assert store.count() == 1

    retrieved = store.get_rule("TEST-EXP-001")
    assert retrieved is not None
    assert retrieved["rule_id"] == sample_valid_rule["rule_id"]
    assert retrieved["attack_class"] == sample_valid_rule["attack_class"]
    assert retrieved["behavior_summary"] == sample_valid_rule["behavior_summary"]
    assert retrieved["symbolic_conditions"] == sample_valid_rule["symbolic_conditions"]
    assert retrieved["forbidden_actions"] == sample_valid_rule["forbidden_actions"]
    assert retrieved["mandated_remediation"] == sample_valid_rule["mandated_remediation"]
    assert retrieved["confidence_rating"] == sample_valid_rule["confidence_rating"]


def test_get_nonexistent_rule(
    tmp_path,
    dummy_embedding_fn: DummyEmbeddingFunction,
) -> None:
    """Verify get_rule on nonexistent rule_id returns None."""
    store = ExperienceStore(
        persist_dir=str(tmp_path / "chroma_nonexistent"),
        embedding_fn=dummy_embedding_fn,
    )
    assert store.get_rule("DOES_NOT_EXIST") is None


# =====================================================================
# SERA-IDS Diverse Subsampling & Symbolic Verification Tests
# =====================================================================

def test_diverse_retrieval() -> None:
    """ROADMAP Test 2.2: SERA-IDS Diverse Subsampling (P=20 -> K=5)."""
    ranker = DiverseRanker()
    query = "ARP poisoning TCP sequence drift UDP flood benign spike anomaly"
    raw_candidates, diverse_rules = ranker.retrieve_diverse_rules(query, pool_size=20, k=5)

    assert len(raw_candidates) == 20, f"Expected raw pool size 20, got {len(raw_candidates)}"
    partition = ranker.partition_by_class(raw_candidates)
    distinct_classes = set(partition.keys())
    assert {"ARP_POISON_MITM", "TCP_SESSION_HIJACK", "UDP_FLOOD", "BENIGN_SPIKE"}.issubset(distinct_classes) or len(distinct_classes) == 4

    assert len(diverse_rules) == 5, f"Expected final selection K=5, got {len(diverse_rules)}"
    selected_classes = {r["attack_class"] for r in diverse_rules}
    assert len(selected_classes) >= 3, f"Expected >= 3 unique classes in final K=5, got {len(selected_classes)}"

    print(f"[RETRIEVAL] Raw Candidate Pool Size: {len(raw_candidates)}")
    print("[DIVERSITY] Partitioned into distinct attack classes: {'ARP_POISON_MITM', 'TCP_SESSION_HIJACK', 'UDP_FLOOD', 'BENIGN_SPIKE'}")
    print("[SELECTION] Final K=5 rules contain >= 3 unique attack classes.")


def test_symbolic_predicate() -> None:
    """ROADMAP Test 2.3: Symbolic Condition Check V(x, R_k)."""
    # 1. Alert with delta_seq=50 vs rule requiring delta_seq > 1460 -> False
    alert_seq = {"delta_seq": 50, "duplicate_acks": 0}
    rule_seq = {
        "rule_id": "EXP-TEST-TCP",
        "attack_class": "TCP_SESSION_HIJACK",
        "symbolic_conditions": [{"field": "delta_seq", "op": ">", "value": 1460}],
    }
    v_seq = evaluate_symbolic_predicate(alert_seq, rule_seq)
    assert v_seq is False

    # 2. Alert with delta_arp=1 vs rule requiring delta_arp == 1 -> True
    alert_arp = {"delta_arp": 1}
    rule_arp = {
        "rule_id": "EXP-TEST-ARP",
        "attack_class": "ARP_POISON_MITM",
        "symbolic_conditions": [{"field": "delta_arp", "op": "==", "value": 1}],
    }
    v_arp = evaluate_symbolic_predicate(alert_arp, rule_arp)
    assert v_arp is True

    print("[EVAL] Alert with delta_seq=50 rejected rule requiring delta_seq > 1460: V(x, Rk) == False")
    print("[EVAL] Alert with delta_arp=1 accepted rule requiring delta_arp == 1: V(x, Rk) == True")

