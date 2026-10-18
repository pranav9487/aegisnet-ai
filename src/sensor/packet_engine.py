"""
src/sensor/packet_engine.py
---------------------------
AegisNet Stateful Packet Sensor — Version 0.1, Step 5.

Responsibilities (zero LLM tokens consumed):
  1. Bind to eth0 (or AEGIS_INTERFACE) via promiscuous Scapy sniffing.
  2. Maintain an in-memory ARP binding table (IP → MAC).
     Compute Δ_ARP ∈ {0, 1} on every ARP reply.
  3. Track bidirectional TCP streams keyed by (src_ip, dst_ip, src_port, dst_port)
     normalised to the canonical direction.
     Compute:
       Δ_SEQ = |S_observed − S_expected|
       duplicate ACK count
       Shannon entropy H(X) of the payload byte distribution
  4. Emit structured JSON alerts strictly conforming to AegisNetAnomalyAlert-v1.
     Write each alert as a single line to /tmp/sensor_alerts.log.

Entropy alert threshold: 40% increase from the per-stream baseline (AGENTS.md §8.6).

Design rules (AGENTS.md §6):
  - Pure, testable functions for all computation logic.
  - Sniff loop and file I/O isolated so unit tests can mock them.
  - No subprocess calls, no LLM calls, no forbidden commands.
"""

import collections
import hashlib
import json
import logging
import math
import os
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

# ---------------------------------------------------------------------------
# Constants & configuration
# ---------------------------------------------------------------------------

IFACE: str = os.environ.get("AEGIS_INTERFACE", "eth0")
ALERT_LOG_PATH: str = "/tmp/sensor_alerts.log"

# Entropy threshold: a jump >= 40% above the stream's running baseline triggers
# an ENTROPY_SPIKE alert (AGENTS.md §8 discrepancy 6).
ENTROPY_SPIKE_THRESHOLD_PCT: float = 40.0

# TCP Δ_SEQ threshold: drifts above this value trigger TCP_SEQUENCE_DRIFT alert.
# Set to 1460 bytes (one MSS) per design document Section 5.1.
SEQ_DRIFT_THRESHOLD: int = 1460

# Duplicate-ACK count that triggers a DUPLICATE_ACK alert.
DUP_ACK_THRESHOLD: int = 3

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [SENSOR] %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Pure computation helpers (no side effects — unit-testable without root)
# ---------------------------------------------------------------------------


def compute_shannon_entropy(payload: bytes) -> float:
    """
    Compute Shannon entropy H(X) of the payload byte distribution.

    H(X) = -Σ p(x) * log2(p(x))

    Returns a value in [0.0, 8.0] (bits per byte).
    Returns 0.0 for an empty payload.
    """
    if not payload:
        return 0.0
    freq: Dict[int, int] = collections.Counter(payload)
    total = len(payload)
    entropy = 0.0
    for count in freq.values():
        p = count / total
        entropy -= p * math.log2(p)
    return round(entropy, 6)


def compute_entropy_delta_pct(baseline: float, current: float) -> float:
    """
    Compute percentage change in entropy relative to the baseline.

    Returns 0.0 when baseline is 0 (first packet in stream).
    """
    if baseline == 0.0:
        return 0.0
    return round(((current - baseline) / baseline) * 100.0, 2)


def detect_arp_anomaly(
    ip: str,
    observed_mac: str,
    arp_table: Dict[str, str],
) -> Tuple[int, Optional[str]]:
    """
    Check whether an ARP reply introduces a MAC binding change.

    Parameters
    ----------
    ip          : IP address claimed in the ARP reply.
    observed_mac: MAC address claimed in the ARP reply (hwsrc).
    arp_table   : Current in-memory binding table {ip → mac}.

    Returns
    -------
    (delta_arp, expected_mac)
      delta_arp = 1 if the binding changed (anomaly); 0 if stable or new.
      expected_mac = the previously known MAC, or observed_mac if first seen.
    """
    observed_mac = observed_mac.lower()
    if ip not in arp_table:
        # First sighting — record and return stable
        return 0, observed_mac
    expected_mac = arp_table[ip].lower()
    delta_arp = 0 if observed_mac == expected_mac else 1
    return delta_arp, expected_mac


def canonical_flow_key(
    src_ip: str, dst_ip: str, src_port: int, dst_port: int
) -> Tuple[str, str, int, int]:
    """
    Return a normalised 4-tuple so both directions of a stream map to the
    same key.  The tuple is sorted so the lexicographically smaller
    (IP, port) pair always appears first.
    """
    a = (src_ip, src_port)
    b = (dst_ip, dst_port)
    if a <= b:
        return (src_ip, dst_ip, src_port, dst_port)
    return (dst_ip, src_ip, dst_port, src_port)


def make_alert_id(engine: str) -> str:
    """
    Generate a unique alert ID matching the schema pattern:
        ALERT-<ENGINE>-<8 hex chars>
    """
    suffix = uuid.uuid4().hex[:8]
    # Truncate engine to keep the ID compact and schema-valid
    tag = engine.replace("_", "")[:10]
    return f"ALERT-{tag}-{suffix}"


def build_alert(
    engine: str,
    severity: str,
    observed_mac: str,
    expected_mac: str,
    claimed_ip: str,
    delta_arp: int,
    protocol: str,
    delta_seq: int,
    duplicate_acks: int,
    shannon_entropy: float,
    entropy_delta_pct: float,
) -> Dict[str, Any]:
    """
    Build a fully-formed AegisNetAnomalyAlert-v1 dict.

    All fields are typed to exactly match the JSON Schema.
    """
    return {
        "alert_id": make_alert_id(engine),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "detection_engine": engine,
        "severity": severity,
        "layer2_state": {
            "observed_mac": observed_mac.lower(),
            "expected_mac": expected_mac.lower(),
            "claimed_ip": claimed_ip,
            "delta_arp": delta_arp,
        },
        "layer4_state": {
            "protocol": protocol,
            "delta_seq": delta_seq,
            "duplicate_acks": duplicate_acks,
        },
        "entropy_metrics": {
            "shannon_entropy": shannon_entropy,
            "entropy_delta_pct": entropy_delta_pct,
        },
    }


# ---------------------------------------------------------------------------
# Stateful sensor state (lives in PacketEngine instance)
# ---------------------------------------------------------------------------


class PacketEngine:
    """
    Stateful packet processing engine.

    Maintains:
      - arp_table       : {ip → mac}  — last-known good binding
      - tcp_streams     : {flow_key → StreamState}
      - _alert_callback : callable(alert_dict) — injected for testability
    """

    def __init__(
        self,
        alert_callback=None,
        entropy_spike_threshold_pct: float = ENTROPY_SPIKE_THRESHOLD_PCT,
        seq_drift_threshold: int = SEQ_DRIFT_THRESHOLD,
        dup_ack_threshold: int = DUP_ACK_THRESHOLD,
    ) -> None:
        self.arp_table: Dict[str, str] = {}
        self.tcp_streams: Dict[Any, "_StreamState"] = {}
        self.entropy_spike_threshold_pct = entropy_spike_threshold_pct
        self.seq_drift_threshold = seq_drift_threshold
        self.dup_ack_threshold = dup_ack_threshold
        # Default callback: write JSON line to the alert log file
        self._alert_callback = alert_callback or self._default_alert_callback

    # ------------------------------------------------------------------ #
    # Default alert output                                                 #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _default_alert_callback(alert: Dict[str, Any]) -> None:
        """Write formatted JSON alert to ALERT_LOG_PATH and stderr."""
        line = json.dumps(alert, indent=2)
        logger.warning("ALERT:\n%s", line)
        try:
            with open(ALERT_LOG_PATH, "a") as fh:
                fh.write(line + "\n")
        except OSError as exc:
            logger.error("Cannot write alert log %s: %s", ALERT_LOG_PATH, exc)

    # ------------------------------------------------------------------ #
    # Packet dispatch                                                      #
    # ------------------------------------------------------------------ #

    def process_packet(self, pkt: Any) -> None:
        """
        Dispatch a Scapy packet to the correct handler.

        Called once per captured packet.  Must not raise — exceptions are
        caught and logged so the sniff loop stays alive.
        """
        try:
            from scapy.layers.l2 import ARP
            from scapy.layers.inet import IP, TCP

            if pkt.haslayer(ARP):
                self._handle_arp(pkt)
            elif pkt.haslayer(IP) and pkt.haslayer(TCP):
                self._handle_tcp(pkt)
        except Exception as exc:  # pragma: no cover
            logger.error("process_packet error: %s", exc)

    # ------------------------------------------------------------------ #
    # ARP invariant detection                                              #
    # ------------------------------------------------------------------ #

    def _handle_arp(self, pkt: Any) -> None:
        """
        Inspect an ARP packet for binding changes (Δ_ARP).

        ARP op=2 (reply / is-at) is the primary spoofing vector.
        We also record op=1 (request) to seed the table without alarming.
        """
        from scapy.layers.l2 import ARP as ScapyARP

        arp = pkt[ScapyARP]
        ip: str = arp.psrc
        hwsrc: str = arp.hwsrc.lower()
        op: int = arp.op

        if op == 1:
            # ARP request: seed table if we haven't seen this IP yet
            if ip not in self.arp_table:
                self.arp_table[ip] = hwsrc
            return

        if op != 2:
            return  # Ignore non-standard ARP ops

        # ARP reply
        delta_arp, expected_mac = detect_arp_anomaly(ip, hwsrc, self.arp_table)

        # Always update the table to track the current state
        self.arp_table[ip] = hwsrc

        if delta_arp == 1:
            alert = build_alert(
                engine="ARP_INVARIANT",
                severity="CRITICAL",
                observed_mac=hwsrc,
                expected_mac=expected_mac,
                claimed_ip=ip,
                delta_arp=1,
                protocol="ARP",
                delta_seq=0,
                duplicate_acks=0,
                shannon_entropy=0.0,
                entropy_delta_pct=0.0,
            )
            self._alert_callback(alert)

    # ------------------------------------------------------------------ #
    # TCP stream tracking                                                  #
    # ------------------------------------------------------------------ #

    def _handle_tcp(self, pkt: Any) -> None:
        """
        Track TCP stream state and detect anomalies.

        For each bidirectional stream we track:
          - expected next sequence number per direction
          - duplicate ACK count
          - running baseline entropy
        """
        from scapy.layers.inet import IP as ScapyIP, TCP as ScapyTCP
        from scapy.packet import Raw

        ip_layer = pkt[ScapyIP]
        tcp_layer = pkt[ScapyTCP]

        src_ip: str = ip_layer.src
        dst_ip: str = ip_layer.dst
        src_port: int = int(tcp_layer.sport)
        dst_port: int = int(tcp_layer.dport)
        seq: int = int(tcp_layer.seq)
        ack: int = int(tcp_layer.ack)
        flags: int = int(tcp_layer.flags)

        # Extract payload bytes
        payload: bytes = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else b""

        flow_key = canonical_flow_key(src_ip, dst_ip, src_port, dst_port)

        if flow_key not in self.tcp_streams:
            self.tcp_streams[flow_key] = _StreamState()

        stream = self.tcp_streams[flow_key]

        # TCP flag masks
        FLAG_FIN = 0x01
        FLAG_SYN = 0x02
        FLAG_RST = 0x04
        FLAG_ACK = 0x10

        direction_key = (src_ip, src_port)
        syn_offset = 1 if (flags & FLAG_SYN) else 0

        # ── Sequence drift (Δ_SEQ) ────────────────────────────────────────
        if direction_key not in stream.next_seq:
            stream.next_seq[direction_key] = seq + len(payload) + syn_offset
            delta_seq = 0
        else:
            delta_seq = abs(seq - stream.next_seq[direction_key])
            stream.next_seq[direction_key] = seq + len(payload) + syn_offset

        # ── Duplicate ACK detection ───────────────────────────────────────
        is_pure_ack = (
            (flags & FLAG_ACK) != 0
            and (flags & FLAG_SYN) == 0
            and (flags & FLAG_FIN) == 0
            and (flags & FLAG_RST) == 0
            and len(payload) == 0
        )

        if is_pure_ack:
            if ack == stream.last_ack and ack != 0:
                stream.dup_ack_count += 1
            else:
                stream.dup_ack_count = 0
            stream.last_ack = ack
        elif (flags & FLAG_ACK) != 0 and ack > stream.last_ack:
            stream.dup_ack_count = 0
            stream.last_ack = ack

        # ── Entropy ───────────────────────────────────────────────────────
        entropy = compute_shannon_entropy(payload) if payload else stream.baseline_entropy
        delta_pct = compute_entropy_delta_pct(stream.baseline_entropy, entropy)

        # Update baseline with exponential moving average (α=0.1)
        if payload:
            if stream.baseline_entropy == 0.0:
                stream.baseline_entropy = entropy
            else:
                stream.baseline_entropy = round(
                    0.9 * stream.baseline_entropy + 0.1 * entropy, 6
                )

        # ── Alert routing ─────────────────────────────────────────────────
        layer2_placeholder_mac = "00:00:00:00:00:00"

        if (
            delta_seq > self.seq_drift_threshold
            and stream.dup_ack_count >= self.dup_ack_threshold
        ):
            alert = build_alert(
                engine="TCP_SEQUENCE_DRIFT",
                severity="HIGH",
                observed_mac=layer2_placeholder_mac,
                expected_mac=layer2_placeholder_mac,
                claimed_ip=src_ip,
                delta_arp=0,
                protocol="TCP",
                delta_seq=delta_seq,
                duplicate_acks=stream.dup_ack_count,
                shannon_entropy=entropy,
                entropy_delta_pct=delta_pct,
            )
            self._alert_callback(alert)

        elif stream.dup_ack_count >= self.dup_ack_threshold:
            alert = build_alert(
                engine="DUPLICATE_ACK",
                severity="MEDIUM",
                observed_mac=layer2_placeholder_mac,
                expected_mac=layer2_placeholder_mac,
                claimed_ip=src_ip,
                delta_arp=0,
                protocol="TCP",
                delta_seq=delta_seq,
                duplicate_acks=stream.dup_ack_count,
                shannon_entropy=entropy,
                entropy_delta_pct=delta_pct,
            )
            self._alert_callback(alert)

        elif payload and abs(delta_pct) >= self.entropy_spike_threshold_pct:
            alert = build_alert(
                engine="ENTROPY_SPIKE",
                severity="MEDIUM",
                observed_mac=layer2_placeholder_mac,
                expected_mac=layer2_placeholder_mac,
                claimed_ip=src_ip,
                delta_arp=0,
                protocol="TCP",
                delta_seq=0,
                duplicate_acks=stream.dup_ack_count,
                shannon_entropy=entropy,
                entropy_delta_pct=delta_pct,
            )
            self._alert_callback(alert)


class _StreamState:
    """Per-flow mutable state updated on every TCP packet."""

    __slots__ = (
        "next_seq",
        "last_ack",
        "dup_ack_count",
        "baseline_entropy",
    )

    def __init__(self) -> None:
        self.next_seq: Dict[Tuple[str, int], int] = {}
        self.last_ack: int = 0
        self.dup_ack_count: int = 0
        self.baseline_entropy: float = 0.0

    @staticmethod
    def compute_delta_seq(
        observed_seq: int,
        payload: bytes,
        expected_seq: int,
    ) -> Tuple[int, int]:
        """
        Compute Δ_SEQ = |observed − expected|.

        Also returns the updated expected_seq for the next packet in this
        direction (seq + payload_len, or +1 for SYN/FIN).

        If expected_seq == 0 (first packet), Δ_SEQ is 0 and we seed the
        expected sequence from the observed value.
        """
        if expected_seq == 0:
            delta = 0
            next_expected = observed_seq + len(payload) if payload else observed_seq + 1
        else:
            delta = abs(observed_seq - expected_seq)
            next_expected = observed_seq + len(payload) if payload else expected_seq
        return delta, next_expected


# ---------------------------------------------------------------------------
# Sniff loop (side-effect boundary — not called in unit tests)
# ---------------------------------------------------------------------------


def start_sniffing(engine: PacketEngine, iface: str = IFACE) -> None:
    """
    Start the Scapy promiscuous sniff loop.

    This function never returns under normal operation.
    It is the only function that imports scapy.sniff at module level so that
    unit tests that mock scapy don't need root privileges.
    """
    from scapy.all import sniff

    logger.info("AegisNet sensor starting on interface %s", iface)
    logger.info("Alert log: %s", ALERT_LOG_PATH)
    logger.info(
        "Thresholds — Δ_SEQ > %d | dup_ack >= %d | entropy_spike >= %.0f%%",
        engine.seq_drift_threshold,
        engine.dup_ack_threshold,
        engine.entropy_spike_threshold_pct,
    )

    sniff(
        iface=iface,
        prn=engine.process_packet,
        store=False,       # do not accumulate packets in memory
        filter="arp or tcp",
    )


def seed_arp_table(engine: PacketEngine) -> None:
    """
    Seed the initial ARP binding table from topology config and/or /proc/net/arp.
    Ensures that known legitimate hosts on the subnet have their expected MAC
    established before passive sniffing begins.
    """
    # 1. Try topology config file
    config_paths = [
        os.environ.get("TOPOLOGY_CONFIG_PATH"),
        "/data/topology_graph.json",
        "./data/topology_graph.json",
    ]
    for path in config_paths:
        if path and os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                for node in data.get("nodes", []):
                    ip = node.get("id")
                    mac = node.get("mac")
                    if ip and mac:
                        engine.arp_table[ip] = mac.lower()
                logger.info("Seeded %d ARP entries from %s", len(engine.arp_table), path)
                break
            except Exception as exc:
                logger.warning("Failed to load topology from %s: %s", path, exc)

    # 2. Try /proc/net/arp (kernel ARP cache)
    if os.path.exists("/proc/net/arp"):
        try:
            with open("/proc/net/arp", "r", encoding="utf-8") as f:
                lines = f.readlines()
            for line in lines[1:]:
                parts = line.split()
                if len(parts) >= 4:
                    ip = parts[0]
                    flags = parts[2]
                    mac = parts[3].lower()
                    if flags == "0x2" and mac != "00:00:00:00:00:00":
                        if ip not in engine.arp_table:
                            engine.arp_table[ip] = mac
            logger.info("ARP table currently has %d entries after /proc/net/arp inspection", len(engine.arp_table))
        except Exception as exc:
            logger.warning("Failed to read /proc/net/arp: %s", exc)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    engine = PacketEngine()
    seed_arp_table(engine)
    start_sniffing(engine, iface=IFACE)


if __name__ == "__main__":
    main()
