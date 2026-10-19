"""Episodic Experience Store for AegisNet-AI SERA-IDS architecture.

Stores historical rule-based knowledge in ChromaDB with Sentence-BERT embeddings.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List, Optional

import chromadb
from chromadb.utils import embedding_functions

logger = logging.getLogger(__name__)

REQUIRED_RULE_FIELDS = {
    "rule_id",
    "attack_class",
    "behavior_summary",
    "symbolic_conditions",
    "forbidden_actions",
    "mandated_remediation",
    "confidence_rating",
}

VALID_ATTACK_CLASSES = {
    "ARP_POISON_MITM",
    "TCP_SESSION_HIJACK",
    "UDP_FLOOD",
    "BENIGN_SPIKE",
}

VALID_REMEDIATIONS = {
    "ISOLATE_MAC_THEN_IPSEC",
    "MONITOR_ONLY",
    "RATE_LIMIT",
}

VALID_CONDITION_FIELDS = {
    "delta_arp",
    "delta_seq",
    "duplicate_acks",
    "payload_entropy",
}

VALID_OPS = {"==", "!=", ">", ">=", "<", "<="}


def validate_experience_rule(rule: Dict[str, Any]) -> None:
    """Validate experience rule structure and field constraints.

    Raises:
        ValueError: If any validation rule fails.
    """
    missing = REQUIRED_RULE_FIELDS - set(rule.keys())
    if missing:
        raise ValueError(f"Rule missing required fields: {sorted(missing)}")

    if rule["attack_class"] not in VALID_ATTACK_CLASSES:
        raise ValueError(f"Invalid attack_class: {rule['attack_class']}")

    if rule["mandated_remediation"] not in VALID_REMEDIATIONS:
        raise ValueError(f"Invalid mandated_remediation: {rule['mandated_remediation']}")

    try:
        conf = float(rule["confidence_rating"])
        if not (0.0 <= conf <= 1.0):
            raise ValueError()
    except (ValueError, TypeError):
        raise ValueError(f"confidence_rating must be float in [0.0, 1.0], got {rule.get('confidence_rating')}")

    if not isinstance(rule["symbolic_conditions"], list):
        raise ValueError("symbolic_conditions must be a list")

    for cond in rule["symbolic_conditions"]:
        if cond.get("field") not in VALID_CONDITION_FIELDS:
            raise ValueError(f"Invalid condition field: {cond.get('field')}")
        if cond.get("op") not in VALID_OPS:
            raise ValueError(f"Invalid condition operator: {cond.get('op')}")

    if rule["attack_class"] == "BENIGN_SPIKE" and rule["mandated_remediation"] != "MONITOR_ONLY":
        raise ValueError("BENIGN_SPIKE rules must use mandated_remediation MONITOR_ONLY")


class ExperienceStore:
    """ChromaDB episodic memory store implementing SERA-IDS experiences."""

    COLLECTION_NAME = "sera_ids_experiences"
    MODEL_NAME = "all-MiniLM-L6-v2"

    def __init__(self, persist_dir: Optional[str] = None, client: Optional[Any] = None) -> None:
        self.persist_dir = persist_dir or os.getenv("CHROMA_PERSIST_DIR", "./data/chromadb")
        os.makedirs(self.persist_dir, exist_ok=True)

        self.embedding_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
            model_name=self.MODEL_NAME
        )
        self.client = client or chromadb.PersistentClient(path=self.persist_dir)
        self.collection = self.client.get_or_create_collection(
            name=self.COLLECTION_NAME,
            embedding_function=self.embedding_fn,
        )

    def add_rule(self, rule: Dict[str, Any]) -> None:
        """Validate and upsert a single experience rule."""
        validate_experience_rule(rule)

        metadata = {
            "rule_id": rule["rule_id"],
            "attack_class": rule["attack_class"],
            "mandated_remediation": rule["mandated_remediation"],
            "confidence_rating": float(rule["confidence_rating"]),
            "symbolic_conditions": json.dumps(rule["symbolic_conditions"]),
            "forbidden_actions": json.dumps(rule["forbidden_actions"]),
        }

        self.collection.upsert(
            ids=[rule["rule_id"]],
            documents=[rule["behavior_summary"]],
            metadatas=[metadata],
        )

    def add_rules(self, rules: List[Dict[str, Any]]) -> int:
        """Validate and upsert multiple experience rules in batch."""
        if not rules:
            return 0

        ids = []
        documents = []
        metadatas = []

        for rule in rules:
            validate_experience_rule(rule)
            ids.append(rule["rule_id"])
            documents.append(rule["behavior_summary"])
            metadatas.append({
                "rule_id": rule["rule_id"],
                "attack_class": rule["attack_class"],
                "mandated_remediation": rule["mandated_remediation"],
                "confidence_rating": float(rule["confidence_rating"]),
                "symbolic_conditions": json.dumps(rule["symbolic_conditions"]),
                "forbidden_actions": json.dumps(rule["forbidden_actions"]),
            })

        self.collection.upsert(
            ids=ids,
            documents=documents,
            metadatas=metadatas,
        )
        return len(rules)

    def get_rule(self, rule_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a stored rule by its ID."""
        result = self.collection.get(ids=[rule_id], include=["documents", "metadatas"])
        if not result["ids"]:
            return None

        doc = result["documents"][0]
        meta = result["metadatas"][0]
        return {
            "rule_id": meta["rule_id"],
            "attack_class": meta["attack_class"],
            "behavior_summary": doc,
            "symbolic_conditions": json.loads(meta["symbolic_conditions"]),
            "forbidden_actions": json.loads(meta["forbidden_actions"]),
            "mandated_remediation": meta["mandated_remediation"],
            "confidence_rating": float(meta["confidence_rating"]),
        }

    def query_candidates(self, query_text: str, n_results: int = 20) -> List[Dict[str, Any]]:
        """Query experience collection for nearest semantic candidate rules."""
        total = self.count()
        if total == 0:
            return []

        fetch_k = min(n_results, total)
        results = self.collection.query(
            query_texts=[query_text],
            n_results=fetch_k,
            include=["documents", "metadatas", "distances"],
        )

        candidates: List[Dict[str, Any]] = []
        if not results["ids"] or not results["ids"][0]:
            return candidates

        for doc, meta in zip(results["documents"][0], results["metadatas"][0]):
            candidates.append({
                "rule_id": meta["rule_id"],
                "attack_class": meta["attack_class"],
                "behavior_summary": doc,
                "symbolic_conditions": json.loads(meta["symbolic_conditions"]),
                "forbidden_actions": json.loads(meta["forbidden_actions"]),
                "mandated_remediation": meta["mandated_remediation"],
                "confidence_rating": float(meta["confidence_rating"]),
            })

        return candidates

    def count(self) -> int:
        """Return the number of stored rules in the collection."""
        return self.collection.count()
