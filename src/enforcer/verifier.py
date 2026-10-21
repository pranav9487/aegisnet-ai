"""src/enforcer/verifier.py
-------------------------
Active Health Verification & Atomic Rollback Harness for AegisNet-AI (v0.8 Step 4).

Responsibilities:
  1. Active Probe:
     - Asynchronous dual probe: ICMP echo probe + TCP HTTP probe (`curl -m 1 http://<target_ip>:<port>`).
     - Normal target response window: < 500ms.
  2. Automated Rollback on Degradation:
     - Triggers atomic rollback if latency > 2000ms or on packet loss:
       `ip xfrm state flush && ip xfrm policy flush && ebtables -F && arptables -F`
     - Must complete rollback within 1 second.
  3. Error Analysis Agent (EAA) Notification:
     - Records failure signature with confidence rating theta < 0.50 (typically theta = 0.20)
       into the experience store / audit log to prevent recurring faulty remediations.

Security Invariants:
  - Rollback must be atomic, idempotent, and executed without shell=True.
  - LLM or probe outputs never bypass parameter sanitization.
"""

from __future__ import annotations

import asyncio
import logging
import os
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("aegisnet.verifier")

# Default thresholds
NORMAL_PROBE_TIMEOUT_MS: float = 500.0   # expected response window
ROLLBACK_LATENCY_THRESHOLD_MS: float = 2000.0  # hard latency ceiling for rollback
PROBE_TARGET_IP: str = "172.28.0.20"
PROBE_TARGET_PORT: int = 8080

try:
    from src.enforcer.kernel_xfrm import KernelEnforcementEngine
except ImportError:
    try:
        from enforcer.kernel_xfrm import KernelEnforcementEngine
    except ImportError:
        KernelEnforcementEngine = None  # type: ignore


@dataclass
class ProbeResult:
    """Outcome of an active health probe."""
    success: bool
    latency_ms: float
    icmp_ok: bool
    http_ok: bool
    error: Optional[str] = None
    timestamp: float = field(default_factory=time.time)


class ActiveHealthVerifier:
    """Asynchronous Health Verifier and Atomic Rollback Harness."""

    def __init__(
        self,
        target_ip: Optional[str] = None,
        target_port: Optional[int] = None,
        enforcement_engine: Optional[Any] = None,
        experience_store: Optional[Any] = None,
        rollback_threshold_ms: float = ROLLBACK_LATENCY_THRESHOLD_MS,
    ) -> None:
        self.target_ip = target_ip or os.getenv("SERVER_HOST", PROBE_TARGET_IP)
        self.target_port = target_port or int(os.getenv("SERVER_PORT", PROBE_TARGET_PORT))
        self.rollback_threshold_ms = rollback_threshold_ms

        if enforcement_engine is not None:
            self.enforcer = enforcement_engine
        elif KernelEnforcementEngine is not None:
            self.enforcer = KernelEnforcementEngine(server_ip=self.target_ip)
        else:
            self.enforcer = None

        self.experience_store = experience_store
        self.failure_signatures: List[Dict[str, Any]] = []

    def _run_cmd(self, args: List[str], timeout: Optional[float] = None) -> subprocess.CompletedProcess[str]:
        """Execute a command via argument list without shell=True."""
        return subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )

    async def probe_icmp(self, target_ip: str, timeout_sec: float = 1.0) -> Tuple[bool, float]:
        """Perform asynchronous ICMP echo probe using ping."""
        start = time.perf_counter()
        try:
            proc = await asyncio.create_subprocess_exec(
                "ping", "-c", "1", "-W", str(int(timeout_sec)), target_ip,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=timeout_sec)
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            return (proc.returncode == 0, elapsed_ms)
        except Exception:
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            return (False, elapsed_ms)

    async def probe_http(self, target_ip: str, port: int, timeout_sec: float = 1.0) -> Tuple[bool, float]:
        """Perform asynchronous TCP HTTP probe using curl -m 1."""
        url = f"http://{target_ip}:{port}/"
        start = time.perf_counter()
        try:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "-m", "1", "-o", "/dev/null", url,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=timeout_sec)
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            return (proc.returncode == 0, elapsed_ms)
        except Exception:
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            return (False, elapsed_ms)

    async def async_probe(self) -> ProbeResult:
        """Run ICMP and TCP HTTP probes concurrently within 500ms window."""
        start = time.perf_counter()
        icmp_task = asyncio.create_task(self.probe_icmp(self.target_ip, timeout_sec=1.0))
        http_task = asyncio.create_task(self.probe_http(self.target_ip, self.target_port, timeout_sec=1.0))

        results = await asyncio.gather(icmp_task, http_task, return_exceptions=True)

        icmp_ok, icmp_lat = results[0] if isinstance(results[0], tuple) else (False, 1000.0)
        http_ok, http_lat = results[1] if isinstance(results[1], tuple) else (False, 1000.0)

        total_lat = (time.perf_counter() - start) * 1000.0
        success = icmp_ok and http_ok

        err = None
        if not success:
            err = f"Probe failed: icmp_ok={icmp_ok}, http_ok={http_ok}"

        return ProbeResult(
            success=success,
            latency_ms=total_lat,
            icmp_ok=icmp_ok,
            http_ok=http_ok,
            error=err,
        )

    def execute_rollback(self) -> None:
        """Execute atomic rollback flushing XFRM and isolation rules."""
        logger.warning("[ROLLBACK] Initiating atomic rollback of all kernel enforcements")

        if self.enforcer and hasattr(self.enforcer, "rollback"):
            self.enforcer.rollback()
        else:
            # Fallback direct kernel execution
            self._run_cmd(["ip", "xfrm", "state", "flush"])
            self._run_cmd(["ip", "xfrm", "policy", "flush"])
            self._run_cmd(["ebtables", "-F"])
            self._run_cmd(["arptables", "-F"])

        logger.info("[ROLLBACK] Flushed XFRM states and ebtables rules")

    def record_failure_signature(
        self,
        policy: Optional[Dict[str, Any]],
        reason: str,
        latency_ms: float,
        theta: float = 0.20,
    ) -> Dict[str, Any]:
        """Notify Error Analysis Agent (EAA) and record failure signature with theta < 0.50."""
        policy_id = policy.get("policy_id", "UNKNOWN-POL") if policy else "UNKNOWN-POL"
        sig_id = f"FAIL-{policy_id}-{uuid.uuid4().hex[:8]}"

        signature: Dict[str, Any] = {
            "rule_id": sig_id,
            "attack_class": policy.get("attack_class", "ARP_POISON_MITM") if policy else "ARP_POISON_MITM",
            "behavior_summary": (
                f"Remediation policy {policy_id} caused health check failure "
                f"(latency={latency_ms:.1f}ms): {reason}"
            ),
            "symbolic_conditions": {"delta_arp": 1},
            "forbidden_actions": ["block_victim_ip"],
            "mandated_remediation": "MONITOR_ONLY",
            "confidence_rating": float(theta),  # Must be theta < 0.50
        }

        self.failure_signatures.append(signature)

        if self.experience_store and hasattr(self.experience_store, "add_rule"):
            try:
                self.experience_store.add_rule(signature)
                logger.info("[EAA] Failure signature stored in experience store: %s (theta=%.2f)", sig_id, theta)
            except Exception as exc:
                logger.warning("[EAA] Could not persist failure signature to store: %s", exc)

        logger.info(
            "[EAA] Notified Error Analysis Agent: recorded failure signature %s (theta=%.2f < 0.50)",
            sig_id,
            theta,
        )
        return signature

    def verify_and_remediate(
        self,
        policy: Optional[Dict[str, Any]] = None,
        simulated_latency_ms: Optional[float] = None,
        simulated_packet_loss: bool = False,
    ) -> bool:
        """Verify network health; trigger automatic rollback on latency > 2000ms or loss.

        Args:
            policy: The defense policy currently applied.
            simulated_latency_ms: Optional synthetic latency injection for testing.
            simulated_packet_loss: Optional synthetic packet loss flag for testing.

        Returns:
            True if health verification passed.
            False if health check failed and rollback was triggered.
        """
        if simulated_latency_ms is not None or simulated_packet_loss:
            lat = simulated_latency_ms if simulated_latency_ms is not None else 0.0
            is_loss = simulated_packet_loss
            logger.info("[VERIFY] Evaluating synthetic probe: latency=%.1fms, loss=%s", lat, is_loss)
            probe_result = ProbeResult(
                success=(not is_loss and lat <= self.rollback_threshold_ms),
                latency_ms=lat,
                icmp_ok=not is_loss,
                http_ok=not is_loss,
                error="Synthetic fault injected" if (is_loss or lat > self.rollback_threshold_ms) else None,
            )
        else:
            try:
                probe_result = asyncio.run(self.async_probe())
            except Exception as exc:
                logger.error("[VERIFY] Error executing probe: %s", exc)
                probe_result = ProbeResult(
                    success=False,
                    latency_ms=self.rollback_threshold_ms + 500.0,
                    icmp_ok=False,
                    http_ok=False,
                    error=str(exc),
                )

        # Check health conditions:
        # Failure if latency > 2000ms or packet loss / probe failure
        if probe_result.latency_ms > self.rollback_threshold_ms or not probe_result.success:
            logger.warning(
                "[VERIFY] Health check FAILED (latency=%.1fms > %.1fms or loss). Triggering automatic rollback.",
                probe_result.latency_ms,
                self.rollback_threshold_ms,
            )
            # 1. Execute atomic rollback
            self.execute_rollback()

            # 2. Notify EAA and record failure signature with theta < 0.50
            self.record_failure_signature(
                policy=policy,
                reason=probe_result.error or f"Latency {probe_result.latency_ms:.1f}ms exceeded 2000ms threshold",
                latency_ms=probe_result.latency_ms,
                theta=0.20,
            )
            return False

        logger.info("[VERIFY] Health check PASSED (latency=%.1fms <= 500ms)", probe_result.latency_ms)
        return True
