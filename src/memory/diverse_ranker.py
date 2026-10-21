"""Diverse Ranker and Deterministic Symbolic Verifier for SERA-IDS Knowledge Layer.

Implements:
1. ChromaDB retrieval with candidate pool parameter P=20.
2. Partitioning candidates across 4 attack classes:
   - ARP_POISON_MITM
   - TCP_SESSION_HIJACK
   - UDP_FLOOD
   - BENIGN_SPIKE
3. Downsampling to K=5 class-diverse candidate rules.
4. Deterministic symbolic predicate evaluation V(x, R_k) on sensor metrics:
   delta_arp, delta_seq, duplicate_acks, payload_entropy.
"""
from __future__ import annotations

import logging
import operator
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from src.memory.experience_store import ExperienceStore

logger = logging.getLogger(__name__)

ALL_ATTACK_CLASSES: List[str] = [
    "ARP_POISON_MITM",
    "TCP_SESSION_HIJACK",
    "UDP_FLOOD",
    "BENIGN_SPIKE",
]

PREDICATE_OPERATORS: Dict[str, Callable[[Any, Any], bool]] = {
    "==": operator.eq,
    "!=": operator.ne,
    ">": operator.gt,
    ">=": operator.ge,
    "<": operator.lt,
    "<=": operator.le,
}

# Mapping canonical metric names to potential locations in flat or nested alert dictionaries
FIELD_PATHS: Dict[str, List[Tuple[str, ...]]] = {
    "delta_arp": [("delta_arp",), ("layer2_state", "delta_arp")],
    "delta_seq": [("delta_seq",), ("layer4_state", "delta_seq")],
    "duplicate_acks": [("duplicate_acks",), ("layer4_state", "duplicate_acks")],
    "payload_entropy": [
        ("payload_entropy",),
        ("entropy_metrics", "payload_entropy"),
        ("entropy_metrics", "shannon_entropy"),
    ],
}


def extract_metric_value(data: Dict[str, Any], field_name: str) -> Optional[Any]:
    """Extract a metric value from either flat or structured alert dictionaries."""
    if not isinstance(data, dict):
        return None

    paths = FIELD_PATHS.get(field_name, [(field_name,)])
    for path in paths:
        curr: Any = data
        found = True
        for key in path:
            if isinstance(curr, dict) and key in curr:
                curr = curr[key]
            else:
                found = False
                break
        if found and curr is not None:
            return curr
    return None


def evaluate_symbolic_predicate(alert_or_state: Dict[str, Any], rule: Dict[str, Any]) -> bool:
    """Evaluate deterministic predicate V(x, R_k) for an alert state x and rule R_k.

    Args:
        alert_or_state: Dictionary containing sensor telemetry metrics
                        (delta_arp, delta_seq, duplicate_acks, payload_entropy).
        rule: Experience rule dictionary with symbolic_conditions.

    Returns:
        bool: True if all symbolic conditions in the rule match the alert state,
              False otherwise.
    """
    conditions = rule.get("symbolic_conditions", [])
    if not isinstance(conditions, list):
        return False

    for cond in conditions:
        if not isinstance(cond, dict):
            return False
        field = cond.get("field")
        op_str = cond.get("op")
        expected_val = cond.get("value")

        if not field or not op_str or op_str not in PREDICATE_OPERATORS:
            return False

        actual_val = extract_metric_value(alert_or_state, field)
        if actual_val is None:
            return False

        op_fn = PREDICATE_OPERATORS[op_str]
        try:
            # Handle float/int conversions if necessary
            if isinstance(expected_val, (int, float)) and isinstance(actual_val, (int, float)):
                if not op_fn(actual_val, expected_val):
                    return False
            else:
                if not op_fn(actual_val, expected_val):
                    return False
        except (TypeError, ValueError):
            return False

    return True


verify_predicate = evaluate_symbolic_predicate


class DiverseRanker:
    """Class-Diverse Ranker implementing SERA-IDS retrieval and symbolic verification."""

    def __init__(self, experience_store: Optional[ExperienceStore] = None) -> None:
        self.store = experience_store or ExperienceStore()

    def query_pool(self, query_text: str, pool_size: int = 20) -> List[Dict[str, Any]]:
        """Retrieve candidate pool P from ChromaDB collection."""
        return self.store.query_candidates(query_text=query_text, n_results=pool_size)

    @staticmethod
    def partition_by_class(candidates: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Partition candidate rules by attack_class into distinct buckets."""
        partition: Dict[str, List[Dict[str, Any]]] = {}
        for cand in candidates:
            cls = cand.get("attack_class", "UNKNOWN")
            partition.setdefault(cls, []).append(cand)
        return partition

    def downsample_diverse(
        self,
        candidates: List[Dict[str, Any]],
        k: int = 5,
    ) -> List[Dict[str, Any]]:
        """Downsample candidate pool to K diverse representatives across distinct attack classes.

        Ensures coverage across unique classes via round-robin selection over class buckets.
        """
        if not candidates or k <= 0:
            return []

        partition = self.partition_by_class(candidates)
        # Order classes by appearance/count
        class_order = sorted(partition.keys(), key=lambda c: len(partition[c]), reverse=True)

        selected: List[Dict[str, Any]] = []
        selected_ids: Set[str] = set()

        # Round-robin selection across classes
        while len(selected) < k and any(partition[c] for c in class_order):
            added_in_round = False
            for cls in class_order:
                bucket = partition[cls]
                while bucket:
                    cand = bucket.pop(0)
                    rule_id = cand.get("rule_id")
                    if rule_id not in selected_ids:
                        selected.append(cand)
                        selected_ids.add(rule_id)
                        added_in_round = True
                        break
                if len(selected) == k:
                    break
            if not added_in_round:
                break

        return selected

    def retrieve_diverse_rules(
        self,
        query_text: str,
        pool_size: int = 20,
        k: int = 5,
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Query raw candidate pool of size P and downsample to K diverse rules."""
        raw_candidates = self.query_pool(query_text=query_text, pool_size=pool_size)
        diverse_rules = self.downsample_diverse(raw_candidates, k=k)
        return raw_candidates, diverse_rules

    def filter_by_predicate(
        self,
        alert_or_state: Dict[str, Any],
        candidates: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Filter candidates using deterministic predicate evaluation V(x, R_k)."""
        return [rule for rule in candidates if evaluate_symbolic_predicate(alert_or_state, rule)]
