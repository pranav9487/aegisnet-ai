"""Bootstrap offline experience rules into ChromaDB sera_ids_experiences collection."""
from __future__ import annotations

import glob
import json
import logging
import os
import sys
from typing import Optional

# Ensure project root is in sys.path for direct execution
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from src.memory.experience_store import ExperienceStore

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("bootstrap_rules")


def bootstrap_experience_rules(
    raw_rules_dir: str = "data/raw_rules",
    persist_dir: Optional[str] = None,
) -> int:
    """Load all JSON experience rules and populate ChromaDB collection."""
    rule_files = sorted(glob.glob(os.path.join(raw_rules_dir, "*.json")))
    if not rule_files:
        logger.error("No JSON rule files found in %s", raw_rules_dir)
        return 0

    store = ExperienceStore(persist_dir=persist_dir)
    loaded_rules = []
    for filepath in rule_files:
        with open(filepath, "r", encoding="utf-8") as f:
            rule_data = json.load(f)
            loaded_rules.append(rule_data)

    inserted = store.add_rules(loaded_rules)
    total_in_db = store.count()
    logger.info("Successfully ingested %d rules into sera_ids_experiences (total in DB: %d)", inserted, total_in_db)
    return total_in_db


if __name__ == "__main__":
    count = bootstrap_experience_rules()
    if count < 50:
        logger.error("Expected at least 50 rules, got %d", count)
        sys.exit(1)
    print(f"sera_ids_experiences count: {count}")
    sys.exit(0)
