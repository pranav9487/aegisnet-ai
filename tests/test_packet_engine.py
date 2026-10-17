"""
tests/test_packet_engine.py
---------------------------
Unit tests for src/sensor/packet_engine.py.

Rules (AGENTS.md §6):
  - No root, no Docker, no Scapy live capture, no LLM calls.
  - Scapy packet objects are constructed in-memory using Scapy's own classes
    (requires only `scapy` pip package, no privileges).
  - Tests are fully deterministic.

Expected by ROADMAP Test 1.3:
    test_packet_engine.py::test_entropy_calculation PASSED
    test_packet_engine.py::test_arp_invariant_detection PASSED
    test_packet_engine.py::test_tcp_sequence_drift PASSED
"""

import json
import sys
import os

import pytest

# Make sure the src/ tree is importable when running from the repo root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.sensor.packet_engine import (
    PacketEngine,
    compute_shannon_entropy,
    compute_entropy_delta_pct,
    detect_arp_anomaly,
    canonical_flow_key,
    build_alert,
    make_alert_id,
    ENTROPY_SPIKE_THRESHOLD_PCT,
    SEQ_DRIFT_THRESHOLD,
)


# ---------------------------------------------------------------------------
# Test 1: Shannon Entropy Calculation
# ---------------------------------------------------------------------------

class TestEntropyCalculation:
    """test_entropy_calculation — roadmap PASS criterion."""
    __test__ = False

    def test_empty_payload_returns_zero(self):
        assert compute_shannon_entropy(b"") == 0.0

    def test_uniform_single_byte_returns_zero(self):
        # A payload of all identical bytes has zero entropy
        assert compute_shannon_entropy(b"\x00" * 100) == 0.0

    def test_two_equally_probable_bytes_returns_one(self):
        payload = bytes([0x00, 0xFF] * 50)
        h = compute_shannon_entropy(payload)
        assert abs(h - 1.0) < 1e-5, f"Expected H≈1.0, got {h}"

    def test_all_256_bytes_returns_eight(self):
        # Perfect uniform distribution over all 256 byte values → H = 8 bits
        payload = bytes(range(256))
        h = compute_shannon_entropy(payload)
        assert abs(h - 8.0) < 1e-5, f"Expected H≈8.0, got {h}"

    def test_entropy_delta_pct_baseline_zero(self):
        # When baseline is 0, delta should be 0 (no division by zero)
        assert compute_entropy_delta_pct(0.0, 5.0) == 0.0

    def test_entropy_delta_pct_increase(self):
        # 50% increase
        delta = compute_entropy_delta_pct(baseline=4.0, current=6.0)
        assert abs(delta - 50.0) < 1e-3, f"Expected 50.0%, got {delta}"

    def test_entropy_delta_pct_decrease(self):
        # 25% decrease
        delta = compute_entropy_delta_pct(baseline=8.0, current=6.0)
        assert abs(delta - (-25.0)) < 1e-3, f"Expected -25.0%, got {delta}"


# Alias so pytest collects it under the exact name the roadmap expects
def test_entropy_calculation():
    """Roadmap-named entry point for entropy tests."""
    t = TestEntropyCalculation()
    t.test_empty_payload_returns_zero()
    t.test_uniform_single_byte_returns_zero()
    t.test_two_equally_probable_bytes_returns_one()
    t.test_all_256_bytes_returns_eight()
    t.test_entropy_delta_pct_baseline_zero()
    t.test_entropy_delta_pct_increase()
    t.test_entropy_delta_pct_decrease()


# ---------------------------------------------------------------------------
# Test 2: ARP Invariant Detection
# ---------------------------------------------------------------------------

class TestArpInvariantDetection:
    """test_arp_invariant_detection — roadmap PASS criterion."""
    __test__ = False

    def test_first_sighting_returns_stable(self):
        delta, expected = detect_arp_anomaly(
            ip="172.28.0.20",
            observed_mac="02:42:ac:1c:00:14",
            arp_table={},
        )
        assert delta == 0
        assert expected == "02:42:ac:1c:00:14"

    def test_same_mac_returns_stable(self):
        table = {"172.28.0.20": "02:42:ac:1c:00:14"}
        delta, expected = detect_arp_anomaly(
            ip="172.28.0.20",
            observed_mac="02:42:ac:1c:00:14",
            arp_table=table,
        )
        assert delta == 0
        assert expected == "02:42:ac:1c:00:14"

    def test_mac_change_returns_anomaly(self):
        """
        Core invariant: attacker MAC 02:42:ac:1c:00:42 claims server IP
        172.28.0.20 which was previously bound to 02:42:ac:1c:00:14.
        Δ_ARP must be 1.
        """
        table = {"172.28.0.20": "02:42:ac:1c:00:14"}
        delta, expected = detect_arp_anomaly(
            ip="172.28.0.20",
            observed_mac="02:42:ac:1c:00:42",   # attacker MAC
            arp_table=table,
        )
        assert delta == 1, f"Expected Δ_ARP=1, got {delta}"
        assert expected == "02:42:ac:1c:00:14", f"Expected server MAC, got {expected}"

    def test_engine_fires_alert_on_arp_spoof(self):
        """
        PacketEngine.process_packet → _handle_arp must call the alert
        callback with a valid AegisNetAnomalyAlert-v1-shaped dict.
        Uses a synthetic Scapy ARP packet built in memory (no raw socket).
        """
        from scapy.layers.l2 import ARP, Ether

        fired: list = []
        engine = PacketEngine(alert_callback=lambda a: fired.append(a))

        # Seed the table with the legitimate server binding
        engine.arp_table["172.28.0.20"] = "02:42:ac:1c:00:14"

        # Craft a gratuitous ARP reply from the attacker
        pkt = (
            Ether(src="02:42:ac:1c:00:42", dst="ff:ff:ff:ff:ff:ff")
            / ARP(
                op=2,
                hwsrc="02:42:ac:1c:00:42",
                psrc="172.28.0.20",
                hwdst="ff:ff:ff:ff:ff:ff",
                pdst="172.28.0.20",
            )
        )
        engine.process_packet(pkt)

        assert len(fired) == 1, "Expected exactly 1 alert"
        alert = fired[0]

        # Validate schema shape
        assert alert["detection_engine"] == "ARP_INVARIANT"
        assert alert["layer2_state"]["delta_arp"] == 1
        assert alert["layer2_state"]["observed_mac"] == "02:42:ac:1c:00:42"
        assert alert["layer2_state"]["expected_mac"] == "02:42:ac:1c:00:14"
        assert alert["layer2_state"]["claimed_ip"] == "172.28.0.20"
        assert alert["layer4_state"]["protocol"] == "ARP"
        assert alert["layer4_state"]["delta_seq"] == 0
        assert alert["layer4_state"]["duplicate_acks"] == 0

    def test_engine_does_not_fire_on_legitimate_arp(self):
        from scapy.layers.l2 import ARP, Ether

        fired: list = []
        engine = PacketEngine(alert_callback=lambda a: fired.append(a))

        # Seed the table
        engine.arp_table["172.28.0.10"] = "02:42:ac:1c:00:0a"

        # Craft a legitimate ARP reply (same MAC)
        pkt = (
            Ether(src="02:42:ac:1c:00:0a", dst="ff:ff:ff:ff:ff:ff")
            / ARP(
                op=2,
                hwsrc="02:42:ac:1c:00:0a",
                psrc="172.28.0.10",
                hwdst="ff:ff:ff:ff:ff:ff",
                pdst="172.28.0.10",
            )
        )
        engine.process_packet(pkt)

        assert len(fired) == 0, "No alert expected for legitimate ARP"


def test_arp_invariant_detection():
    """Roadmap-named entry point for ARP invariant tests."""
    t = TestArpInvariantDetection()
    t.test_first_sighting_returns_stable()
    t.test_same_mac_returns_stable()
    t.test_mac_change_returns_anomaly()
    t.test_engine_fires_alert_on_arp_spoof()
    t.test_engine_does_not_fire_on_legitimate_arp()


# ---------------------------------------------------------------------------
# Test 3: TCP Sequence Drift
# ---------------------------------------------------------------------------

class TestTcpSequenceDrift:
    """test_tcp_sequence_drift — roadmap PASS criterion."""
    __test__ = False

    def test_first_packet_seeds_with_zero_drift(self):
        from src.sensor.packet_engine import _StreamState
        delta, next_seq = _StreamState.compute_delta_seq(
            observed_seq=1000,
            payload=b"hello",
            expected_seq=0,   # 0 = first packet
        )
        assert delta == 0
        assert next_seq == 1005

    def test_expected_seq_in_window_returns_zero_drift(self):
        from src.sensor.packet_engine import _StreamState
        delta, next_seq = _StreamState.compute_delta_seq(
            observed_seq=1005,
            payload=b"world",
            expected_seq=1005,
        )
        assert delta == 0
        assert next_seq == 1010

    def test_large_seq_drift_detected(self):
        """
        A forged packet with seq far from expected must produce Δ_SEQ > threshold.
        """
        from src.sensor.packet_engine import _StreamState
        forged_seq = 1005 + 50_000   # huge jump
        delta, _ = _StreamState.compute_delta_seq(
            observed_seq=forged_seq,
            payload=b"INJECT",
            expected_seq=1005,
        )
        assert delta > SEQ_DRIFT_THRESHOLD, (
            f"Expected Δ_SEQ > {SEQ_DRIFT_THRESHOLD}, got {delta}"
        )

    def test_engine_fires_alert_on_seq_drift(self):
        """
        PacketEngine must emit a TCP_SEQUENCE_DRIFT alert when Δ_SEQ > threshold.
        Uses in-memory Scapy IP/TCP packets (no raw socket required).
        """
        from scapy.layers.inet import IP, TCP
        from scapy.layers.l2 import Ether
        from scapy.packet import Raw

        fired: list = []
        engine = PacketEngine(alert_callback=lambda a: fired.append(a))

        # Seed the stream with a first packet so expected_seq is set
        seed_pkt = (
            Ether()
            / IP(src="172.28.0.10", dst="172.28.0.20")
            / TCP(sport=54321, dport=8080, flags="PA", seq=1000, ack=1)
            / Raw(load=b"GET / HTTP/1.1\r\n\r\n")
        )
        engine.process_packet(seed_pkt)
        assert len(fired) == 0, "No alert expected for first legitimate packet"

        # Inject a forged packet with a wildly wrong sequence number
        forged_seq = 1000 + 80_000
        forged_pkt = (
            Ether()
            / IP(src="172.28.0.10", dst="172.28.0.20")
            / TCP(sport=54321, dport=8080, flags="PA", seq=forged_seq, ack=1)
            / Raw(load=b"MALICIOUS-INJECTION")
        )
        engine.process_packet(forged_pkt)

        assert len(fired) == 1, f"Expected 1 alert, got {len(fired)}"
        alert = fired[0]
        assert alert["detection_engine"] == "TCP_SEQUENCE_DRIFT"
        assert alert["layer4_state"]["protocol"] == "TCP"
        assert alert["layer4_state"]["delta_seq"] > SEQ_DRIFT_THRESHOLD

    def test_engine_does_not_fire_on_normal_tcp(self):
        """Normal sequential packets must not produce any alert."""
        from scapy.layers.inet import IP, TCP
        from scapy.layers.l2 import Ether
        from scapy.packet import Raw

        fired: list = []
        engine = PacketEngine(alert_callback=lambda a: fired.append(a))

        seq = 2000
        for _ in range(5):
            payload = b"X" * 100
            pkt = (
                Ether()
                / IP(src="172.28.0.10", dst="172.28.0.20")
                / TCP(sport=12345, dport=8080, flags="PA", seq=seq, ack=1)
                / Raw(load=payload)
            )
            engine.process_packet(pkt)
            seq += len(payload)

        assert len(fired) == 0, f"No alerts expected for normal traffic, got {len(fired)}"

    def test_canonical_flow_key_symmetric(self):
        """Both directions of the same flow must map to the same key."""
        k1 = canonical_flow_key("172.28.0.10", "172.28.0.20", 54321, 8080)
        k2 = canonical_flow_key("172.28.0.20", "172.28.0.10", 8080, 54321)
        assert k1 == k2, f"Expected same key, got {k1} vs {k2}"


def test_tcp_sequence_drift():
    """Roadmap-named entry point for TCP sequence drift tests."""
    t = TestTcpSequenceDrift()
    t.test_first_packet_seeds_with_zero_drift()
    t.test_expected_seq_in_window_returns_zero_drift()
    t.test_large_seq_drift_detected()
    t.test_engine_fires_alert_on_seq_drift()
    t.test_engine_does_not_fire_on_normal_tcp()
    t.test_canonical_flow_key_symmetric()
