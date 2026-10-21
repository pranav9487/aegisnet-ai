"""src/agents/validator.py
------------------------
JSON Schema Validation for AegisNet Defense Policies.

Validates LLM-generated policy output against AegisNetDefensePolicy-v1 schema
before any policy reaches the kernel enforcer.

This module is a dependency of orchestrator.py (not a standalone step),
but is created here so the orchestrator import chain is complete for Step 1 testing.
Full retry/fallback routing is implemented per v0.8 Step 2.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, Optional

import jsonschema

logger = logging.getLogger("aegisnet.validator")

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
POLICY_SCHEMA_PATH = _REPO_ROOT / "schemas" / "AegisNetDefensePolicy-v1.json"

# Compiled MAC regex for fast validation
_MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")


def load_schema(schema_path: Optional[Path] = None) -> Dict[str, Any]:
    """Load and return the AegisNetDefensePolicy-v1 JSON Schema."""
    path = schema_path or POLICY_SCHEMA_PATH
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def validate_policy(
    policy: Dict[str, Any],
    schema: Optional[Dict[str, Any]] = None,
) -> None:
    """Validate a policy dict against AegisNetDefensePolicy-v1 JSON Schema.

    Additional semantic checks beyond the schema:
    - target_attacker_mac must match MAC regex.
    - ipsec_configuration.key_material_hex must be exactly 72 lowercase hex chars.
    - confidence must be in [0.0, 1.0].

    Raises:
        jsonschema.ValidationError: On schema violation.
        ValueError: On additional semantic constraint violation.
    """
    if schema is None:
        schema = load_schema()

    # JSON Schema structural validation
    jsonschema.validate(instance=policy, schema=schema)

    # Semantic: MAC format
    mac = policy.get("target_attacker_mac", "")
    if not _MAC_RE.match(mac):
        raise ValueError(
            f"[SCHEMA VALID] target_attacker_mac {mac!r} does not match MAC regex"
        )

    # Semantic: key_material_hex length and format
    ipsec = policy.get("ipsec_configuration", {})
    key_hex = ipsec.get("key_material_hex", "")
    if len(key_hex) != 72:
        raise ValueError(
            f"[SCHEMA VALID] ipsec_configuration.key_material_hex length "
            f"{len(key_hex)} != 72"
        )
    if not re.fullmatch(r"[0-9a-f]{72}", key_hex):
        raise ValueError(
            f"[SCHEMA VALID] ipsec_configuration.key_material_hex contains "
            f"non-lowercase-hex characters"
        )

    # Semantic: confidence range
    confidence = policy.get("confidence", 0.0)
    if not (0.0 <= float(confidence) <= 1.0):
        raise ValueError(
            f"[SCHEMA VALID] confidence {confidence!r} out of range [0.0, 1.0]"
        )

    logger.info(
        "[SCHEMA VALID] Key 'policy_id' present: %s",
        policy.get("policy_id"),
    )
    logger.info(
        "[SCHEMA VALID] Key 'target_attacker_mac' matches MAC regex: %s",
        mac,
    )
    logger.info(
        "[SCHEMA VALID] 'ipsec_configuration.key_material_hex' length == 72 characters"
    )
