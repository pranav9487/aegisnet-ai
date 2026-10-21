"""tests/test_network_graph.py
----------------------------
Unit tests for src/memory/network_graph.py.

Verifies:
  - Gateway, Client, and Server protection (can_block_ip == False).
  - MAC-based rejection preventing self-inflicted DoS under IP spoofing.
  - Untrusted attacker node blockability (can_block_ip == True).
  - 1-hop blast radius excluding defender monitor/enforce instrumentation.

Expected by ROADMAP Test 2.1:
  test_network_graph.py::test_gateway_protection PASSED
  [ASSERTION OK] Target 172.28.0.1 (GATEWAY) flagged as immutable: can_block_ip == False
  test_network_graph.py::test_client_protection PASSED
  [ASSERTION OK] Target 172.28.0.10 (CLIENT) flagged as immutable: can_block_ip == False
  test_network_graph.py::test_server_protection PASSED
  [ASSERTION OK] Target 172.28.0.20 (SERVER) flagged as immutable: can_block_ip == False
  test_network_graph.py::test_mac_based_rejection PASSED
  [ASSERTION OK] Protected MACs (02:42:ac:1c:00:0a, 02:42:ac:1c:00:14, 02:42:ac:1c:00:01) rejected even if IP spoofed
  test_network_graph.py::test_attacker_blockable PASSED
  [ASSERTION OK] 172.28.0.66 (UNTRUSTED) can_block_ip == True, block allowed
  test_network_graph.py::test_blast_radius_attacker PASSED
  [ASSERTION OK] calculate_blast_radius("172.28.0.66") == {"172.28.0.20"}
  test_network_graph.py::test_blast_radius_client PASSED
  [ASSERTION OK] calculate_blast_radius("172.28.0.10") == {"172.28.0.20"}
"""

from __future__ import annotations

import os
import sys

import pytest

# Ensure repository root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.memory.network_graph import (
    NetworkGraph,
    calculate_blast_radius,
    check_gateway_protection,
)


@pytest.fixture
def net_graph() -> NetworkGraph:
    """Fixture providing a freshly loaded NetworkGraph instance."""
    return NetworkGraph()


def test_gateway_protection(net_graph: NetworkGraph) -> None:
    """Verify gateway 172.28.0.1 is immutable and cannot be blocked."""
    node = net_graph.get_node("172.28.0.1")
    assert node is not None, "Gateway node 172.28.0.1 must exist in graph"
    assert node["role"] == "GATEWAY"
    assert node["can_block_ip"] is False
    assert net_graph.check_gateway_protection("172.28.0.1") is False
    assert check_gateway_protection("172.28.0.1", graph=net_graph) is False
    print("[ASSERTION OK] Target 172.28.0.1 (GATEWAY) flagged as immutable: can_block_ip == False")


def test_client_protection(net_graph: NetworkGraph) -> None:
    """Verify victim client 172.28.0.10 is immutable against self-inflicted DoS."""
    node = net_graph.get_node("172.28.0.10")
    assert node is not None, "Client node 172.28.0.10 must exist in graph"
    assert node["role"] == "CLIENT"
    assert node["can_block_ip"] is False
    assert net_graph.check_gateway_protection("172.28.0.10") is False
    assert check_gateway_protection("172.28.0.10", graph=net_graph) is False
    print("[ASSERTION OK] Target 172.28.0.10 (CLIENT) flagged as immutable: can_block_ip == False")


def test_server_protection(net_graph: NetworkGraph) -> None:
    """Verify target server 172.28.0.20 is immutable and cannot be blocked."""
    node = net_graph.get_node("172.28.0.20")
    assert node is not None, "Server node 172.28.0.20 must exist in graph"
    assert node["role"] == "SERVER"
    assert node["can_block_ip"] is False
    assert net_graph.check_gateway_protection("172.28.0.20") is False
    assert check_gateway_protection("172.28.0.20", graph=net_graph) is False
    print("[ASSERTION OK] Target 172.28.0.20 (SERVER) flagged as immutable: can_block_ip == False")


def test_mac_based_rejection(net_graph: NetworkGraph) -> None:
    """Verify protected MACs are rejected even when an untrusted/spoofed IP is proposed."""
    protected_macs = ["02:42:ac:1c:00:0a", "02:42:ac:1c:00:14", "02:42:ac:1c:00:01"]
    spoofed_ips = ["172.28.0.99", "172.28.0.66", "10.0.0.1"]

    for mac in protected_macs:
        for spoofed_ip in spoofed_ips:
            # Even if the IP is unknown or normally blockable (attacker IP 172.28.0.66),
            # matching a protected MAC MUST reject the block proposal.
            allowed = net_graph.check_gateway_protection(target_ip=spoofed_ip, target_mac=mac)
            assert allowed is False, f"Block should have been rejected for protected MAC {mac} on IP {spoofed_ip}"

    print(
        "[ASSERTION OK] Protected MACs (02:42:ac:1c:00:0a, 02:42:ac:1c:00:14, 02:42:ac:1c:00:01) "
        "rejected even if IP spoofed"
    )


def test_attacker_blockable(net_graph: NetworkGraph) -> None:
    """Verify attacker 172.28.0.66 is untrusted and can be blocked."""
    node = net_graph.get_node("172.28.0.66")
    assert node is not None, "Attacker node 172.28.0.66 must exist in graph"
    assert node["role"] == "UNTRUSTED"
    assert node["can_block_ip"] is True
    attacker_mac = "02:42:ac:1c:00:42"
    assert node["mac"] == attacker_mac
    assert net_graph.check_gateway_protection("172.28.0.66", attacker_mac) is True
    assert check_gateway_protection("172.28.0.66", attacker_mac, graph=net_graph) is True
    print("[ASSERTION OK] 172.28.0.66 (UNTRUSTED) can_block_ip == True, block allowed")


def test_blast_radius_attacker(net_graph: NetworkGraph) -> None:
    """Verify blast radius of attacker includes target server but not monitor/enforce edges."""
    radius = net_graph.calculate_blast_radius("172.28.0.66")
    assert radius == {"172.28.0.20"}
    assert calculate_blast_radius("172.28.0.66", graph=net_graph) == {"172.28.0.20"}
    print('[ASSERTION OK] calculate_blast_radius("172.28.0.66") == {"172.28.0.20"}')


def test_blast_radius_client(net_graph: NetworkGraph) -> None:
    """Verify blast radius of client includes target server but not monitor/enforce edges."""
    radius = net_graph.calculate_blast_radius("172.28.0.10")
    assert radius == {"172.28.0.20"}
    assert calculate_blast_radius("172.28.0.10", graph=net_graph) == {"172.28.0.20"}
    print('[ASSERTION OK] calculate_blast_radius("172.28.0.10") == {"172.28.0.20"}')
