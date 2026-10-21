"""tests/test_orchestrator.py
-----------------------------
Unit tests for the AegisNet Multi-Agent Orchestrator (v0.8 Step 1).

Test 3.1: test_policy_schema_conformance
  - Verifies that the 3-agent pipeline produces a JSON policy conforming to
    AegisNetDefensePolicy-v1 schema.
  - Verifies key_material_hex is exactly 72 hex characters.
  - Does NOT require live LLM API access — uses mocked LLM responses.
  - Does NOT require Docker, root, or kernel access.

Expected Output per ROADMAP.md:
  tests/test_orchestrator.py::test_policy_schema_conformance PASSED
  [SCHEMA VALID] Key 'policy_id' present
  [SCHEMA VALID] Key 'target_attacker_mac' matches MAC regex
  [SCHEMA VALID] 'ipsec_configuration.key_material_hex' length == 72 characters
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest

# Ensure the project root is on sys.path for `src` imports
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from src.agents.orchestrator import (
    AgentSecurityState,
    _build_deterministic_policy,
    _generate_key_material_hex,
    node_command_compiler,
    node_policy_synthesizer,
    node_threat_triage,
)
from src.agents.validator import validate_policy, load_schema


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_TELEMETRY: Dict[str, Any] = {
    "alert_id": "ALERT-ARPINVARIA-95e4102e",
    "timestamp_utc": "2026-10-17T12:57:28.898322+00:00",
    "detection_engine": "ARP_INVARIANT",
    "severity": "CRITICAL",
    "layer2_state": {
        "observed_mac": "02:42:ac:1c:00:42",
        "expected_mac": "02:42:ac:1c:00:14",
        "claimed_ip": "172.28.0.20",
        "delta_arp": 1,
    },
    "layer4_state": {
        "protocol": "ARP",
        "delta_seq": 0,
        "duplicate_acks": 0,
    },
    "entropy_metrics": {
        "shannon_entropy": 0.0,
        "entropy_delta_pct": 0.0,
    },
}

SAMPLE_TOPOLOGY: Dict[str, Any] = {
    "nodes": [
        {"id": "172.28.0.20", "hostname": "target-server", "role": "SERVER",
         "mac": "02:42:ac:1c:00:14", "can_block_ip": False},
        {"id": "172.28.0.66", "hostname": "red-attacker", "role": "UNTRUSTED",
         "mac": "02:42:ac:1c:00:42", "can_block_ip": True},
    ]
}

SAMPLE_EXPERIENCES: list = [
    {
        "rule_id": "RULE-ARP-001",
        "attack_class": "ARP_POISON_MITM",
        "behavior_summary": "Attacker sends unsolicited ARP replies to poison cache",
        "symbolic_conditions": [{"field": "delta_arp", "op": "==", "value": 1}],
        "forbidden_actions": ["block_victim_ip"],
        "mandated_remediation": "ISOLATE_MAC_THEN_IPSEC",
        "confidence_rating": 0.95,
    }
]


# ---------------------------------------------------------------------------
# Helper: build a complete deterministic policy
# ---------------------------------------------------------------------------

def _make_deterministic_policy() -> Dict[str, Any]:
    triage = {
        "attacker_mac": "02:42:ac:1c:00:42",
        "victim_ip": "172.28.0.20",
        "attack_class": "ARP_POISON_MITM",
        "confidence": 0.95,
    }
    strategy = {
        "apply_mac_isolation": True,
        "apply_ipsec": True,
    }
    return _build_deterministic_policy(triage, strategy, SAMPLE_TELEMETRY)


# ---------------------------------------------------------------------------
# Test 3.1: Strict JSON Schema Policy Generation
# ---------------------------------------------------------------------------

def test_policy_schema_conformance(capsys):
    """Test 3.1: Validate that the orchestrator emits a schema-conformant policy.

    Runs node_threat_triage → node_policy_synthesizer → node_command_compiler
    with mocked LLM calls (no real API needed), then validates the output against
    AegisNetDefensePolicy-v1 JSON Schema.

    Expected ROADMAP Output:
        [SCHEMA VALID] Key 'policy_id' present
        [SCHEMA VALID] Key 'target_attacker_mac' matches MAC regex
        [SCHEMA VALID] 'ipsec_configuration.key_material_hex' length == 72 characters
    """
    schema = load_schema()

    # Build initial state
    state: AgentSecurityState = {
        "telemetry": SAMPLE_TELEMETRY,
        "topology": SAMPLE_TOPOLOGY,
        "experiences": SAMPLE_EXPERIENCES,
        "triage_diagnostic": {},
        "strategy": {},
        "final_policy": None,
        "provider_used": "mock",
        "attempt_count": 1,
        "error_log": [],
    }

    # Patch LLM calls so this test runs without API keys
    triage_response = json.dumps({
        "attacker_mac": "02:42:ac:1c:00:42",
        "attacker_ip": "172.28.0.66",
        "victim_ip": "172.28.0.20",
        "attack_class": "ARP_POISON_MITM",
        "confidence": 0.97,
        "blast_radius_ips": ["172.28.0.20"],
        "triage_notes": "ARP cache poisoning detected — attacker MAC isolated",
    })

    strategy_response = json.dumps({
        "apply_mac_isolation": True,
        "apply_ipsec": True,
        "static_arp_fixes_needed": True,
        "ipsec_mode": "transport",
        "ipsec_cipher": "aes-gcm-256",
        "rationale": "ARP MITM requires MAC isolation and IPsec to prevent replay",
        "forbidden_actions_avoided": ["block_victim_ip", "flush_default_chain"],
    })

    with patch("src.agents.orchestrator._call_groq", return_value=triage_response), \
         patch("src.agents.orchestrator._call_gemini", return_value=triage_response):
        state = node_threat_triage(state)

    with patch("src.agents.orchestrator._call_groq", return_value=strategy_response), \
         patch("src.agents.orchestrator._call_gemini", return_value=strategy_response):
        state = node_policy_synthesizer(state)

    # For Agent 3: LLM call raises so deterministic policy is used (guaranteed valid)
    with patch("src.agents.orchestrator._call_groq", side_effect=Exception("mock")), \
         patch("src.agents.orchestrator._call_gemini", side_effect=Exception("mock")):
        state = node_command_compiler(state)

    policy = state["final_policy"]
    assert policy is not None, "Pipeline must produce a final_policy"

    # ---- Schema validation (this also emits the [SCHEMA VALID] lines) ----
    validate_policy(policy, schema)

    # ---- Assertions that drive the [SCHEMA VALID] print lines ----

    # (1) policy_id
    policy_id = policy.get("policy_id", "")
    assert policy_id, "policy_id must be present and non-empty"
    print(f"[SCHEMA VALID] Key 'policy_id' present")

    # (2) target_attacker_mac matches MAC regex
    mac = policy.get("target_attacker_mac", "")
    mac_re = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
    assert mac_re.match(mac), f"target_attacker_mac {mac!r} must match MAC regex"
    print(f"[SCHEMA VALID] Key 'target_attacker_mac' matches MAC regex")

    # (3) key_material_hex length == 72
    ipsec = policy.get("ipsec_configuration", {})
    key_hex = ipsec.get("key_material_hex", "")
    assert len(key_hex) == 72, (
        f"ipsec_configuration.key_material_hex length {len(key_hex)} != 72"
    )
    assert re.fullmatch(r"[0-9a-f]{72}", key_hex), (
        "key_material_hex must be 72 lowercase hex characters"
    )
    print(f"[SCHEMA VALID] 'ipsec_configuration.key_material_hex' length == 72 characters")

    # Additional safety assertions
    assert policy.get("target_attacker_mac") == "02:42:ac:1c:00:42", (
        "target_attacker_mac must be the attacker's hardware MAC (not victim IP)"
    )
    assert 0.0 <= policy["confidence"] <= 1.0


# ---------------------------------------------------------------------------
# Supporting unit tests
# ---------------------------------------------------------------------------

def test_key_material_hex_length():
    """key_material_hex must always be exactly 72 lowercase hex chars."""
    for _ in range(10):
        key = _generate_key_material_hex()
        assert len(key) == 72, f"Expected 72, got {len(key)}"
        assert re.fullmatch(r"[0-9a-f]{72}", key), "Must be lowercase hex"


def test_deterministic_policy_schema_valid():
    """Deterministic policy builder must always produce schema-valid output."""
    schema = load_schema()
    policy = _make_deterministic_policy()
    validate_policy(policy, schema)  # must not raise


def test_attacker_mac_never_overwritten_by_llm():
    """Agent 3 must not allow the LLM to replace the attacker MAC with an arbitrary value."""
    state: AgentSecurityState = {
        "telemetry": SAMPLE_TELEMETRY,
        "topology": SAMPLE_TOPOLOGY,
        "experiences": SAMPLE_EXPERIENCES,
        "triage_diagnostic": {
            "attacker_mac": "02:42:ac:1c:00:42",
            "victim_ip": "172.28.0.20",
            "attack_class": "ARP_POISON_MITM",
            "confidence": 0.95,
        },
        "strategy": {"apply_mac_isolation": True, "apply_ipsec": True},
        "final_policy": None,
        "provider_used": "mock",
        "attempt_count": 1,
        "error_log": [],
    }

    # LLM tries to inject a wrong MAC
    bad_policy = json.dumps({
        "policy_id": "POL-ARPITM-deadbeef",
        "alert_ref": "ALERT-ARPINVARIA-95e4102e",
        "target_attacker_mac": "ff:ff:ff:ff:ff:ff",  # WRONG — injected by "malicious" LLM
        "static_arp_fixes": [],
        "mac_isolation": {"drop_attacker_mac": True, "use_ebtables": True},
        "ipsec_configuration": {
            "apply_ipsec": True, "mode": "transport", "cipher": "aes-gcm-256",
            "spi_client_to_server": 4097, "spi_server_to_client": 4098,
            "key_material_hex": "a" * 72,
        },
        "ttl_seconds": 300,
        "confidence": 0.9,
    })

    with patch("src.agents.orchestrator._call_groq", return_value=bad_policy), \
         patch("src.agents.orchestrator._call_gemini", return_value=bad_policy):
        result = node_command_compiler(state)

    # The deterministic base always wins for the attacker MAC
    final_mac = result["final_policy"]["target_attacker_mac"]
    assert final_mac == "02:42:ac:1c:00:42", (
        f"Attacker MAC must not be overridden by LLM; got {final_mac!r}"
    )
