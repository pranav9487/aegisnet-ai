"""src/agents/orchestrator.py
--------------------------
LangGraph Multi-Agent Orchestration Pipeline for AegisNet-AI.

Three-agent pipeline:
  Agent 1 (node_threat_triage):      Resolves true attacker MAC from claimed victim IP.
  Agent 2 (node_policy_synthesizer): Designs Layer-2 isolation + Layer-3 IPsec ESP strategy.
  Agent 3 (node_command_compiler):   Emits strict JSON conforming to AegisNetDefensePolicy-v1.

Provider fallback: Groq (free-tier) → Gemini Flash (free-tier).
LLM output is UNTRUSTED — every policy is validated via JSON Schema before use.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import secrets
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, TypedDict

from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("aegisnet.orchestrator")

# ---------------------------------------------------------------------------
# Schema path
# ---------------------------------------------------------------------------
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
POLICY_SCHEMA_PATH = _REPO_ROOT / "schemas" / "AegisNetDefensePolicy-v1.json"

# ---------------------------------------------------------------------------
# AgentSecurityState — the shared state flowing through all three nodes
# ---------------------------------------------------------------------------

class AgentSecurityState(TypedDict, total=False):
    """Shared mutable state flowing through the LangGraph pipeline."""

    # Input: sensor telemetry (AegisNetAnomalyAlert-v1 dict)
    telemetry: Dict[str, Any]

    # Input: topology snapshot from NetworkGraph
    topology: Dict[str, Any]

    # Input: SERA-IDS experience rules (list of K=5 diverse rules)
    experiences: List[Dict[str, Any]]

    # Agent 1 output: triage diagnostic
    triage_diagnostic: Dict[str, Any]

    # Agent 2 output: strategy summary
    strategy: Dict[str, Any]

    # Agent 3 output: final policy (AegisNetDefensePolicy-v1)
    final_policy: Optional[Dict[str, Any]]

    # Orchestrator metadata
    provider_used: str
    attempt_count: int
    error_log: List[str]


# ---------------------------------------------------------------------------
# LLM provider helpers
# ---------------------------------------------------------------------------

def _call_groq(prompt: str, system: str, model: str = "llama-3.1-8b-instant") -> str:
    """Call Groq API. Returns raw text response. Raises on failure."""
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


def _call_gemini(prompt: str, system: str) -> str:
    """Call Gemini Flash API. Returns raw text response. Raises on failure."""
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


def _llm_call_with_fallback(prompt: str, system: str) -> tuple[str, str]:
    """Try Groq first; fall back to Gemini. Returns (text, provider_name)."""
    try:
        text = _call_groq(prompt, system)
        logger.info("LLM response from Groq (len=%d)", len(text))
        return text, "groq"
    except Exception as exc:
        logger.warning("Groq failed (%s), falling back to Gemini", exc)

    text = _call_gemini(prompt, system)
    logger.info("LLM response from Gemini (len=%d)", len(text))
    return text, "gemini"


def _extract_json_from_response(text: str) -> Dict[str, Any]:
    """Extract the first valid JSON object from an LLM response string."""
    # Try direct parse first
    stripped = text.strip()
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        pass

    # Try extracting from markdown code fence
    fence_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", stripped, re.DOTALL)
    if fence_match:
        try:
            return json.loads(fence_match.group(1))
        except json.JSONDecodeError:
            pass

    # Try extracting the first { ... } block
    brace_match = re.search(r"\{.*\}", stripped, re.DOTALL)
    if brace_match:
        try:
            return json.loads(brace_match.group(0))
        except json.JSONDecodeError:
            pass

    raise ValueError(f"No valid JSON object found in LLM response: {text[:200]!r}")


# ---------------------------------------------------------------------------
# Agent 1 — Threat Triage
# ---------------------------------------------------------------------------

def node_threat_triage(state: AgentSecurityState) -> AgentSecurityState:
    """Agent 1: Resolve true attacker MAC from claimed victim IP via topology + telemetry.

    Reads: state['telemetry'], state['topology'], state['experiences']
    Writes: state['triage_diagnostic']

    Security invariant: The attacker's real MAC is in telemetry.layer2_state.observed_mac.
    The claimed IP is the victim's IP that the attacker is spoofing.
    We NEVER block by spoofed IP — only by attacker MAC.
    """
    telemetry = state.get("telemetry", {})
    topology = state.get("topology", {})
    experiences = state.get("experiences", [])

    layer2 = telemetry.get("layer2_state", {})
    attacker_mac = layer2.get("observed_mac", "")
    claimed_ip = layer2.get("claimed_ip", "")
    expected_mac = layer2.get("expected_mac", "")
    delta_arp = layer2.get("delta_arp", 0)

    layer4 = telemetry.get("layer4_state", {})
    detection_engine = telemetry.get("detection_engine", "")
    severity = telemetry.get("severity", "")

    system_prompt = (
        "You are Agent 1 (Threat Triage) of AegisNet-AI, an autonomous cyber-defense system. "
        "Your job is to analyze a sensor alert and topology context, then produce ONLY a JSON "
        "triage diagnostic. No explanatory text — pure JSON only."
    )

    user_prompt = f"""Analyze this network security alert and topology context:

SENSOR ALERT:
{json.dumps(telemetry, indent=2)}

TOPOLOGY (node attributes relevant to alert):
{json.dumps(topology, indent=2)}

EXPERIENCE RULES (top-K SERA-IDS retrievals):
{json.dumps(experiences[:3], indent=2)}

Produce a JSON triage diagnostic with exactly these fields:
{{
  "attacker_mac": "<the real hardware MAC of the attacker — observed_mac from layer2_state>",
  "attacker_ip": "<IP address the attacker is operating from, if known, else null>",
  "victim_ip": "<the IP being spoofed/targeted — claimed_ip from layer2_state>",
  "attack_class": "<one of: ARP_POISON_MITM, TCP_SESSION_HIJACK, UDP_FLOOD, BENIGN_SPIKE>",
  "confidence": <float 0.0-1.0>,
  "blast_radius_ips": [<list of victim IPs at risk>],
  "triage_notes": "<brief reasoning>"
}}

CRITICAL: attacker_mac MUST be the observed_mac ({attacker_mac!r}), NOT the victim IP or expected_mac.
Output JSON only."""

    try:
        text, provider = _llm_call_with_fallback(user_prompt, system_prompt)
        triage = _extract_json_from_response(text)
    except Exception as exc:
        logger.error("Agent 1 LLM call failed: %s — using deterministic fallback", exc)
        # Deterministic fallback: derive triage directly from telemetry without LLM
        triage = _deterministic_triage(telemetry)
        provider = "deterministic_fallback"

    # Safety override: always use the MAC from the sensor, never trust the LLM
    # on this critical field — enforce it from the ground truth telemetry.
    if attacker_mac:
        triage["attacker_mac"] = attacker_mac
    if claimed_ip:
        triage["victim_ip"] = claimed_ip

    state["triage_diagnostic"] = triage
    state["provider_used"] = provider
    logger.info(
        "Agent 1 triage complete: attack_class=%s, attacker_mac=%s",
        triage.get("attack_class"),
        triage.get("attacker_mac"),
    )
    return state


def _deterministic_triage(telemetry: Dict[str, Any]) -> Dict[str, Any]:
    """Produce a triage result deterministically from telemetry when LLM is unavailable."""
    layer2 = telemetry.get("layer2_state", {})
    layer4 = telemetry.get("layer4_state", {})
    engine = telemetry.get("detection_engine", "")

    attack_class_map = {
        "ARP_INVARIANT": "ARP_POISON_MITM",
        "TCP_SEQUENCE_DRIFT": "TCP_SESSION_HIJACK",
        "DUPLICATE_ACK": "TCP_SESSION_HIJACK",
        "ENTROPY_SPIKE": "UDP_FLOOD",
    }
    attack_class = attack_class_map.get(engine, "ARP_POISON_MITM")

    return {
        "attacker_mac": layer2.get("observed_mac", ""),
        "attacker_ip": None,
        "victim_ip": layer2.get("claimed_ip", ""),
        "attack_class": attack_class,
        "confidence": 0.85,
        "blast_radius_ips": [layer2.get("claimed_ip", "")] if layer2.get("claimed_ip") else [],
        "triage_notes": f"Deterministic fallback triage from {engine}",
    }


# ---------------------------------------------------------------------------
# Agent 2 — Policy Synthesizer
# ---------------------------------------------------------------------------

def node_policy_synthesizer(state: AgentSecurityState) -> AgentSecurityState:
    """Agent 2: Design Layer-2 isolation + Layer-3 IPsec ESP strategy.

    Reads: state['triage_diagnostic'], state['experiences'], state['topology']
    Writes: state['strategy']
    """
    triage = state.get("triage_diagnostic", {})
    experiences = state.get("experiences", [])
    topology = state.get("topology", {})

    attacker_mac = triage.get("attacker_mac", "")
    victim_ip = triage.get("victim_ip", "")
    attack_class = triage.get("attack_class", "ARP_POISON_MITM")

    system_prompt = (
        "You are Agent 2 (Policy Synthesizer) of AegisNet-AI. "
        "Design a defense strategy combining MAC isolation and IPsec. "
        "Output ONLY JSON — no prose, no code blocks, no markdown."
    )

    user_prompt = f"""Design a defense strategy for this triage result:

TRIAGE DIAGNOSTIC:
{json.dumps(triage, indent=2)}

EXPERIENCE RULES (SERA-IDS top-K):
{json.dumps(experiences, indent=2)}

TOPOLOGY CONTEXT:
{json.dumps(topology, indent=2)}

Produce a JSON strategy with exactly these fields:
{{
  "apply_mac_isolation": <true/false — drop attacker MAC via ebtables>,
  "apply_ipsec": <true/false — encrypt traffic with IPsec ESP AES-256-GCM>,
  "static_arp_fixes_needed": <true/false — restore correct ARP bindings>,
  "ipsec_mode": "transport",
  "ipsec_cipher": "aes-gcm-256",
  "rationale": "<brief strategy reasoning>",
  "forbidden_actions_avoided": [<list of forbidden actions that were NOT taken>]
}}

CRITICAL RULES:
- NEVER recommend blocking the victim IP ({victim_ip!r}) — only block attacker MAC ({attacker_mac!r}).
- If attack_class is BENIGN_SPIKE, set apply_mac_isolation=false and apply_ipsec=false.
- For ARP_POISON_MITM or TCP_SESSION_HIJACK: apply_mac_isolation=true, apply_ipsec=true.
Output JSON only."""

    try:
        text, provider = _llm_call_with_fallback(user_prompt, system_prompt)
        strategy = _extract_json_from_response(text)
    except Exception as exc:
        logger.error("Agent 2 LLM call failed: %s — using deterministic fallback", exc)
        strategy = _deterministic_strategy(attack_class)
        provider = state.get("provider_used", "deterministic_fallback")

    state["strategy"] = strategy
    logger.info(
        "Agent 2 strategy: mac_isolation=%s, ipsec=%s",
        strategy.get("apply_mac_isolation"),
        strategy.get("apply_ipsec"),
    )
    return state


def _deterministic_strategy(attack_class: str) -> Dict[str, Any]:
    """Produce a strategy result deterministically when LLM is unavailable."""
    isolate = attack_class in ("ARP_POISON_MITM", "TCP_SESSION_HIJACK")
    return {
        "apply_mac_isolation": isolate,
        "apply_ipsec": isolate,
        "static_arp_fixes_needed": attack_class == "ARP_POISON_MITM",
        "ipsec_mode": "transport",
        "ipsec_cipher": "aes-gcm-256",
        "rationale": f"Deterministic strategy for {attack_class}",
        "forbidden_actions_avoided": ["block_victim_ip", "flush_default_chain"],
    }


# ---------------------------------------------------------------------------
# Agent 3 — Command Compiler
# ---------------------------------------------------------------------------

_MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")


def _generate_policy_id(alert_ref: str) -> str:
    """Generate a unique POL-<TAG>-<8hexchars> policy ID."""
    tag = "ARPITM"  # default tag
    suffix = hashlib.md5(f"{alert_ref}{time.time()}".encode()).hexdigest()[:8]
    return f"POL-{tag}-{suffix}"


def _generate_key_material_hex() -> str:
    """Generate a cryptographically secure AES-256-GCM key+salt (72 hex chars).

    Composition: 64 hex chars (32 bytes = 256-bit key) + 8 hex chars (4 bytes salt).
    """
    key_bytes = secrets.token_bytes(32)   # 32 bytes → 64 hex chars
    salt_bytes = secrets.token_bytes(4)   # 4 bytes  → 8 hex chars
    return (key_bytes + salt_bytes).hex()  # 36 bytes → 72 hex chars


def node_command_compiler(state: AgentSecurityState) -> AgentSecurityState:
    """Agent 3: Compile final policy JSON conforming to AegisNetDefensePolicy-v1.

    Reads: state['triage_diagnostic'], state['strategy'], state['telemetry']
    Writes: state['final_policy']

    Temperature is forced to 0 for determinism.
    LLM output is UNTRUSTED — schema validation is applied before accepting.
    """
    triage = state.get("triage_diagnostic", {})
    strategy = state.get("strategy", {})
    telemetry = state.get("telemetry", {})

    attacker_mac = triage.get("attacker_mac", "")
    victim_ip = triage.get("victim_ip", "")
    alert_ref = telemetry.get("alert_id", "ALERT-UNKNOWN-00000000")

    # Canonical expected MAC for victim IP from triage
    layer2 = telemetry.get("layer2_state", {})
    expected_mac = layer2.get("expected_mac", "")

    system_prompt = (
        "You are Agent 3 (Command Compiler) of AegisNet-AI. "
        "Emit ONLY a single valid JSON object conforming to AegisNetDefensePolicy-v1. "
        "No markdown, no explanation, no code fences. Pure JSON only."
    )

    user_prompt = f"""Compile the final AegisNet defense policy JSON.

TRIAGE DIAGNOSTIC:
{json.dumps(triage, indent=2)}

STRATEGY:
{json.dumps(strategy, indent=2)}

TRIGGERING ALERT ID: {alert_ref}

You MUST output exactly this JSON structure (fill in values accordingly):
{{
  "policy_id": "POL-ARPITM-<8 lowercase hex chars>",
  "alert_ref": "{alert_ref}",
  "target_attacker_mac": "<attacker hardware MAC, lowercase colon-separated>",
  "static_arp_fixes": [
    {{"ip_address": "<victim IP>", "mac_address": "<correct MAC for victim>"}}
  ],
  "mac_isolation": {{
    "drop_attacker_mac": <true/false>,
    "use_ebtables": <true/false>
  }},
  "ipsec_configuration": {{
    "apply_ipsec": <true/false>,
    "mode": "transport",
    "cipher": "aes-gcm-256",
    "spi_client_to_server": 4097,
    "spi_server_to_client": 4098,
    "key_material_hex": "<72 lowercase hex chars: 64 key + 8 salt>"
  }},
  "ttl_seconds": 300,
  "confidence": <float 0.0-1.0>
}}

FILL IN:
- target_attacker_mac = {attacker_mac!r}
- static_arp_fixes victim IP = {victim_ip!r}, correct MAC = {expected_mac!r}
- mac_isolation.drop_attacker_mac = {str(strategy.get("apply_mac_isolation", True)).lower()}
- mac_isolation.use_ebtables = {str(strategy.get("apply_mac_isolation", True)).lower()}
- ipsec_configuration.apply_ipsec = {str(strategy.get("apply_ipsec", True)).lower()}
- key_material_hex must be exactly 72 lowercase hex characters
Output ONLY the JSON object."""

    # Try LLM first, then fall through to deterministic compiler
    llm_policy: Optional[Dict[str, Any]] = None
    try:
        text, provider = _llm_call_with_fallback(user_prompt, system_prompt)
        llm_policy = _extract_json_from_response(text)
        state["provider_used"] = provider
    except Exception as exc:
        logger.warning("Agent 3 LLM call failed: %s — building policy deterministically", exc)

    # Build deterministic policy as authoritative baseline; merge LLM values selectively
    det_policy = _build_deterministic_policy(triage, strategy, telemetry)

    if llm_policy:
        policy = _merge_llm_policy(det_policy, llm_policy, attacker_mac, alert_ref)
    else:
        policy = det_policy

    state["final_policy"] = policy
    logger.info(
        "Agent 3 compiled policy: policy_id=%s, target_mac=%s",
        policy.get("policy_id"),
        policy.get("target_attacker_mac"),
    )
    return state


def _build_deterministic_policy(
    triage: Dict[str, Any],
    strategy: Dict[str, Any],
    telemetry: Dict[str, Any],
) -> Dict[str, Any]:
    """Build a fully valid AegisNetDefensePolicy-v1 from structured inputs without LLM."""
    layer2 = telemetry.get("layer2_state", {})
    attacker_mac = triage.get("attacker_mac", "") or layer2.get("observed_mac", "")
    victim_ip = triage.get("victim_ip", "") or layer2.get("claimed_ip", "")
    expected_mac = layer2.get("expected_mac", "")
    alert_ref = telemetry.get("alert_id", "ALERT-UNKNOWN-00000000")

    apply_mac = bool(strategy.get("apply_mac_isolation", True))
    apply_ipsec = bool(strategy.get("apply_ipsec", True))

    suffix = hashlib.md5(f"{alert_ref}{time.monotonic()}".encode()).hexdigest()[:8]
    policy_id = f"POL-ARPITM-{suffix}"
    key_material_hex = _generate_key_material_hex()

    arp_fixes = []
    if victim_ip and expected_mac:
        arp_fixes.append({"ip_address": victim_ip, "mac_address": expected_mac})

    return {
        "policy_id": policy_id,
        "alert_ref": alert_ref,
        "target_attacker_mac": attacker_mac,
        "static_arp_fixes": arp_fixes,
        "mac_isolation": {
            "drop_attacker_mac": apply_mac,
            "use_ebtables": apply_mac,
        },
        "ipsec_configuration": {
            "apply_ipsec": apply_ipsec,
            "mode": "transport",
            "cipher": "aes-gcm-256",
            "spi_client_to_server": 4097,
            "spi_server_to_client": 4098,
            "key_material_hex": key_material_hex,
        },
        "ttl_seconds": 300,
        "confidence": float(triage.get("confidence", 0.85)),
    }


def _merge_llm_policy(
    base: Dict[str, Any],
    llm: Dict[str, Any],
    expected_attacker_mac: str,
    expected_alert_ref: str,
) -> Dict[str, Any]:
    """Selectively adopt safe LLM field values on top of deterministic base.

    Security-critical fields (attacker MAC, key material) are always sourced
    from the deterministic base; only non-critical narrative/config fields
    from the LLM are accepted.
    """
    merged = dict(base)

    # Non-critical overrideable fields
    if "ttl_seconds" in llm and isinstance(llm["ttl_seconds"], int):
        ttl = llm["ttl_seconds"]
        if 30 <= ttl <= 3600:
            merged["ttl_seconds"] = ttl

    if "confidence" in llm:
        try:
            conf = float(llm["confidence"])
            if 0.0 <= conf <= 1.0:
                merged["confidence"] = conf
        except (ValueError, TypeError):
            pass

    # mac_isolation boolean flags (safe to accept)
    if "mac_isolation" in llm and isinstance(llm["mac_isolation"], dict):
        mi = llm["mac_isolation"]
        if isinstance(mi.get("drop_attacker_mac"), bool):
            merged["mac_isolation"]["drop_attacker_mac"] = mi["drop_attacker_mac"]
        if isinstance(mi.get("use_ebtables"), bool):
            merged["mac_isolation"]["use_ebtables"] = mi["use_ebtables"]

    # ipsec apply_ipsec flag only
    if "ipsec_configuration" in llm and isinstance(llm["ipsec_configuration"], dict):
        ic = llm["ipsec_configuration"]
        if isinstance(ic.get("apply_ipsec"), bool):
            merged["ipsec_configuration"]["apply_ipsec"] = ic["apply_ipsec"]

    return merged


# ---------------------------------------------------------------------------
# Orchestrator — builds and runs the LangGraph state machine
# ---------------------------------------------------------------------------

def _build_graph():
    """Construct the LangGraph StateGraph for the 3-agent pipeline.

    Returns a compiled graph ready for invocation.
    """
    try:
        from langgraph.graph import StateGraph, END  # type: ignore
    except ImportError as exc:
        raise ImportError(
            "langgraph is required: pip install langgraph>=0.2.0"
        ) from exc

    builder = StateGraph(AgentSecurityState)
    builder.add_node("threat_triage", node_threat_triage)
    builder.add_node("policy_synthesizer", node_policy_synthesizer)
    builder.add_node("command_compiler", node_command_compiler)

    builder.set_entry_point("threat_triage")
    builder.add_edge("threat_triage", "policy_synthesizer")
    builder.add_edge("policy_synthesizer", "command_compiler")
    builder.add_edge("command_compiler", END)

    return builder.compile()


class AegisNetOrchestrator:
    """High-level orchestrator: accepts a sensor alert, returns a validated defense policy."""

    def __init__(self) -> None:
        self._graph = _build_graph()
        self._schema = self._load_schema()

    @staticmethod
    def _load_schema() -> Dict[str, Any]:
        with open(POLICY_SCHEMA_PATH, "r", encoding="utf-8") as f:
            return json.load(f)

    def run(
        self,
        telemetry: Dict[str, Any],
        topology: Optional[Dict[str, Any]] = None,
        experiences: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Run the 3-agent pipeline and return a schema-validated defense policy.

        Args:
            telemetry: AegisNetAnomalyAlert-v1 dict from the packet sensor.
            topology: Optional topology context (node attributes, edges).
            experiences: Optional SERA-IDS K=5 diverse experience rules.

        Returns:
            Validated AegisNetDefensePolicy-v1 dict.

        Raises:
            ValueError: If the final policy fails schema validation after 2 attempts.
        """
        from src.agents.validator import validate_policy  # import here to avoid circulars

        initial_state: AgentSecurityState = {
            "telemetry": telemetry,
            "topology": topology or {},
            "experiences": experiences or [],
            "triage_diagnostic": {},
            "strategy": {},
            "final_policy": None,
            "provider_used": "unknown",
            "attempt_count": 0,
            "error_log": [],
        }

        max_attempts = 2
        last_error: Optional[Exception] = None

        for attempt in range(1, max_attempts + 1):
            logger.info("Orchestrator attempt %d/%d", attempt, max_attempts)
            initial_state["attempt_count"] = attempt

            result = self._graph.invoke(initial_state)
            policy = result.get("final_policy")

            if policy is None:
                last_error = ValueError("Pipeline produced no final_policy")
                logger.warning("Attempt %d: no policy produced", attempt)
                continue

            try:
                validate_policy(policy, self._schema)
                logger.info(
                    "Policy validated on attempt %d: %s",
                    attempt,
                    policy.get("policy_id"),
                )
                return policy
            except Exception as exc:
                last_error = exc
                logger.warning("Attempt %d schema validation failed: %s", attempt, exc)
                # Pass error context to next attempt via state
                initial_state["error_log"] = result.get("error_log", []) + [str(exc)]

        raise ValueError(
            f"Policy failed schema validation after {max_attempts} attempts. "
            f"Last error: {last_error}"
        )
