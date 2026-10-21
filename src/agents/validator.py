"""src/agents/validator.py
------------------------
Schema Validation & Fallback Router for AegisNet-AI (v0.8 Step 2).

Responsibilities:
  1. JSON Schema validation of LLM-generated policies against
     AegisNetDefensePolicy-v1.json (with correct field names:
     static_arp_fixes / ipsec_configuration / key_material_hex).
  2. Semantic constraint checks beyond the schema (MAC regex, 72-char key,
     confidence range, forbidden-command absence).
  3. Retry router: up to MAX_ATTEMPTS=2 LLM calls per agent node, with the
     prior schema error injected into the next prompt for self-correction.
  4. Multi-provider fallback: Groq free-tier → Gemini Flash free-tier.

Security invariant: LLM output is UNTRUSTED. Every policy MUST pass
validate_policy() before any field is forwarded to the kernel enforcer.
"""

from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import jsonschema

logger = logging.getLogger("aegisnet.validator")

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
POLICY_SCHEMA_PATH = _REPO_ROOT / "schemas" / "AegisNetDefensePolicy-v1.json"

MAX_ATTEMPTS: int = 2  # retry ceiling for schema-validation failures

# Compiled MAC regex (lowercase colon-separated)
_MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")

# Forbidden shell patterns that must never appear in any validated policy field
_FORBIDDEN_PATTERNS: List[re.Pattern] = [
    re.compile(r"iptables\s+-[FP]"),        # chain flush / default DROP
    re.compile(r"ebtables\s+-F"),            # ebtables flush (outside rollback)
    re.compile(r"ip\s+xfrm\s+(?:state|policy)\s+flush"),  # xfrm flush (outside rollback)
    re.compile(r"rm\s+-rf"),                 # filesystem destruction
    re.compile(r"curl\s+.*\|\s*sh"),         # piped shell execution
]


# ---------------------------------------------------------------------------
# Schema loading
# ---------------------------------------------------------------------------

def load_schema(schema_path: Optional[Path] = None) -> Dict[str, Any]:
    """Load and return the AegisNetDefensePolicy-v1 JSON Schema."""
    path = schema_path or POLICY_SCHEMA_PATH
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Core validation
# ---------------------------------------------------------------------------

def validate_policy(
    policy: Dict[str, Any],
    schema: Optional[Dict[str, Any]] = None,
) -> None:
    """Validate a policy dict against AegisNetDefensePolicy-v1 JSON Schema.

    Performs three layers of checks in order:
      1. JSON Schema structural validation (jsonschema library).
      2. Semantic constraint checks (MAC regex, key length/format, confidence).
      3. Forbidden-command scan across all string fields.

    Logs [SCHEMA VALID] lines consumed by Test 3.1.

    Raises:
        jsonschema.ValidationError: On JSON Schema violation.
        ValueError: On semantic or forbidden-command violation.
    """
    if schema is None:
        schema = load_schema()

    # ---- Layer 1: structural ----
    jsonschema.validate(instance=policy, schema=schema)

    # ---- Layer 2: semantic ----

    # policy_id present (schema guarantees this, but log it explicitly for Test 3.1)
    policy_id = policy.get("policy_id", "")
    if not policy_id:
        raise ValueError("policy_id must be present and non-empty")

    # target_attacker_mac MAC regex
    mac = policy.get("target_attacker_mac", "")
    if not _MAC_RE.match(mac):
        raise ValueError(
            f"target_attacker_mac {mac!r} does not match MAC regex"
        )

    # ipsec_configuration.key_material_hex: 72 lowercase hex chars
    ipsec = policy.get("ipsec_configuration", {})
    key_hex = ipsec.get("key_material_hex", "")
    if len(key_hex) != 72:
        raise ValueError(
            f"ipsec_configuration.key_material_hex length {len(key_hex)} != 72"
        )
    if not re.fullmatch(r"[0-9a-f]{72}", key_hex):
        raise ValueError(
            "ipsec_configuration.key_material_hex must be 72 lowercase hex characters"
        )

    # confidence in [0.0, 1.0]
    confidence = policy.get("confidence", 0.0)
    if not (0.0 <= float(confidence) <= 1.0):
        raise ValueError(
            f"confidence {confidence!r} out of range [0.0, 1.0]"
        )

    # ---- Layer 3: forbidden-command scan ----
    _check_forbidden_commands(policy)

    # ---- Log validation success ----
    logger.info("[SCHEMA VALID] Key 'policy_id' present: %s", policy_id)
    logger.info("[SCHEMA VALID] Key 'target_attacker_mac' matches MAC regex: %s", mac)
    logger.info("[SCHEMA VALID] 'ipsec_configuration.key_material_hex' length == 72 characters")


def _check_forbidden_commands(policy: Dict[str, Any]) -> None:
    """Recursively scan all string values in a policy for forbidden shell patterns.

    Raises:
        ValueError: If any forbidden pattern is found.
    """
    _scan_value(policy)


def _scan_value(value: Any) -> None:
    """Recursively scan JSON value for forbidden command patterns."""
    if isinstance(value, str):
        for pattern in _FORBIDDEN_PATTERNS:
            if pattern.search(value):
                raise ValueError(
                    f"Forbidden command pattern detected in policy field: "
                    f"{pattern.pattern!r} matched in {value[:100]!r}"
                )
    elif isinstance(value, dict):
        for v in value.values():
            _scan_value(v)
    elif isinstance(value, list):
        for item in value:
            _scan_value(item)


# ---------------------------------------------------------------------------
# Provider fallback router
# ---------------------------------------------------------------------------

# Type alias for an LLM provider callable: (prompt, system) -> str
LLMProvider = Callable[[str, str], str]


def _make_groq_provider(model: str = "llama-3.1-8b-instant") -> LLMProvider:
    """Return a Groq provider callable."""
    def _call(prompt: str, system: str) -> str:
        from groq import Groq  # type: ignore

        api_key = os.getenv("GROQ_API_KEY")
        if not api_key:
            raise EnvironmentError("GROQ_API_KEY not set")
        client = Groq(api_key=api_key)
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
            temperature=0,
            max_tokens=1024,
        )
        return response.choices[0].message.content or ""
    return _call


def _make_gemini_provider() -> LLMProvider:
    """Return a Gemini Flash provider callable."""
    def _call(prompt: str, system: str) -> str:
        import google.generativeai as genai  # type: ignore

        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            raise EnvironmentError("GEMINI_API_KEY not set")
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel(
            "gemini-1.5-flash",
            system_instruction=system,
        )
        response = model.generate_content(
            prompt,
            generation_config={"temperature": 0, "max_output_tokens": 1024},
        )
        return response.text or ""
    return _call


# Default provider chain (Groq first, Gemini fallback)
_DEFAULT_PROVIDERS: List[Tuple[str, LLMProvider]] = [
    ("groq", _make_groq_provider()),
    ("gemini", _make_gemini_provider()),
]


def llm_call_with_fallback(
    prompt: str,
    system: str,
    providers: Optional[List[Tuple[str, LLMProvider]]] = None,
) -> Tuple[str, str]:
    """Try each provider in order; return (response_text, provider_name).

    Provider chain default: Groq → Gemini Flash.

    Args:
        prompt: User-facing prompt content.
        system: System instruction for the LLM.
        providers: Optional override for the provider list (for testing).

    Returns:
        Tuple of (response text, provider name used).

    Raises:
        RuntimeError: If all providers fail.
    """
    chain = providers if providers is not None else _DEFAULT_PROVIDERS
    errors: List[str] = []

    for name, provider_fn in chain:
        try:
            text = provider_fn(prompt, system)
            logger.info("[PROVIDER] %s responded (len=%d)", name, len(text))
            return text, name
        except Exception as exc:
            logger.warning("[PROVIDER] %s failed: %s", name, exc)
            errors.append(f"{name}: {exc}")

    raise RuntimeError(
        f"All LLM providers exhausted. Errors: {'; '.join(errors)}"
    )


# ---------------------------------------------------------------------------
# Retry router
# ---------------------------------------------------------------------------

def validate_with_retry(
    policy_generator: Callable[[Optional[str]], Dict[str, Any]],
    schema: Optional[Dict[str, Any]] = None,
    max_attempts: int = MAX_ATTEMPTS,
) -> Dict[str, Any]:
    """Run policy_generator up to max_attempts times, validating each result.

    On schema-validation failure, passes the error message string to the
    next call of policy_generator so the agent can self-correct.

    Args:
        policy_generator: Callable that takes an optional prior-error string
                          and returns a policy dict. Called up to max_attempts times.
        schema: Pre-loaded JSON Schema dict (loaded from disk if None).
        max_attempts: Maximum number of generation+validation attempts (default 2).

    Returns:
        The first validated policy dict that passes all checks.

    Raises:
        ValueError: If no valid policy is produced within max_attempts attempts.
    """
    if schema is None:
        schema = load_schema()

    last_error: Optional[str] = None

    for attempt in range(1, max_attempts + 1):
        logger.info("[RETRY] Attempt %d/%d", attempt, max_attempts)

        policy = policy_generator(last_error)

        try:
            validate_policy(policy, schema)
            logger.info("[RETRY] Validation passed on attempt %d", attempt)
            return policy
        except (jsonschema.ValidationError, ValueError) as exc:
            last_error = str(exc)
            logger.warning(
                "[RETRY] Attempt %d validation failed: %s", attempt, last_error
            )

    raise ValueError(
        f"Policy failed validation after {max_attempts} attempt(s). "
        f"Last error: {last_error}"
    )
