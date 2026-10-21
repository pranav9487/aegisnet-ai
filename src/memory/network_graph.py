"""src/memory/network_graph.py
----------------------------
Dual-Memory Knowledge Layer: Topology Graph Engine for AegisNet-AI.

Enforces Gateway and Protected Host Immutability Invariant:
  - Rejects any block proposal targeting a host with can_block_ip == False.
  - Rejects any block proposal where target_mac matches a protected host's MAC,
    preventing self-inflicted DoS caused by attacker IP spoofing.
  - Calculates blast radius as 1-hop outgoing reachability excluding defender
    instrumentation edges ('monitor', 'enforce').
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, Optional, Set

import networkx as nx

logger = logging.getLogger("aegisnet.network_graph")

DEFAULT_TOPOLOGY_PATH = "data/topology_graph.json"
EXCLUDED_BLAST_LABELS = frozenset({"monitor", "enforce"})


def _resolve_topology_path(config_path: Optional[str] = None) -> Path:
    """Resolve topology configuration file path safely."""
    path_str = config_path or os.environ.get("TOPOLOGY_CONFIG_PATH", DEFAULT_TOPOLOGY_PATH)
    path = Path(path_str)
    if not path.is_absolute():
        # Check current working directory first
        cwd_path = Path.cwd() / path
        if cwd_path.exists():
            return cwd_path
        # Fall back to repository root relative to this file
        repo_root = Path(__file__).resolve().parent.parent.parent
        repo_path = repo_root / path
        if repo_path.exists():
            return repo_path
    return path


class NetworkGraph:
    """Directed topology graph maintaining immutable protection rules and blast radius."""

    def __init__(self, config_path: Optional[str] = None) -> None:
        self.config_path: Path = _resolve_topology_path(config_path)
        self.graph: nx.MultiDiGraph = nx.MultiDiGraph()
        self.protected_ips: Set[str] = set()
        self.protected_macs: Set[str] = set()
        self.load_topology(self.config_path)

    def load_topology(self, config_path: Path | str) -> None:
        """Load and parse topology JSON as-is into a directed NetworkX graph."""
        path = Path(config_path)
        if not path.exists():
            raise FileNotFoundError(f"Topology configuration not found at {path}")

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.graph.clear()
        self.protected_ips.clear()
        self.protected_macs.clear()

        nodes = data.get("nodes", [])
        edges = data.get("edges", [])

        for node in nodes:
            node_id = str(node["id"])
            attrs: Dict[str, Any] = {
                "hostname": str(node.get("hostname", "")),
                "role": str(node.get("role", "")),
                "mac": str(node.get("mac", "")).lower(),
                "can_block_ip": bool(node.get("can_block_ip", False)),
                "criticality": str(node.get("criticality", "")),
            }
            self.graph.add_node(node_id, **attrs)

            if not attrs["can_block_ip"]:
                self.protected_ips.add(node_id)
                if attrs["mac"]:
                    self.protected_macs.add(attrs["mac"])

        for edge in edges:
            src = str(edge["src"])
            dst = str(edge["dst"])
            label = str(edge.get("label", ""))
            self.graph.add_edge(src, dst, label=label)

        logger.info(
            "Loaded topology graph: %d nodes (%d protected), %d edges",
            self.graph.number_of_nodes(),
            len(self.protected_ips),
            self.graph.number_of_edges(),
        )

    def get_node(self, node_id: str) -> Optional[Dict[str, Any]]:
        """Return attributes for a node, or None if node does not exist."""
        if self.graph.has_node(node_id):
            return dict(self.graph.nodes[node_id])
        return None

    def check_gateway_protection(
        self,
        target_ip: Optional[str] = None,
        target_mac: Optional[str] = None,
    ) -> bool:
        """Evaluate whether a proposed block on target_ip/target_mac is allowed.

        Safety Invariant:
          Rejects the block proposal if either:
            (a) The node at target_ip has can_block_ip == False (e.g. GATEWAY, CLIENT, SERVER, DEFENDER).
            (b) target_mac matches the hardware MAC of any protected node (can_block_ip == False).

        Returns:
            True if block proposal is ALLOWED (target is not protected, safe to isolate).
            False if block proposal is REJECTED (target IP or MAC is immutable/protected).
        """
        # Condition (a): Target IP check
        if target_ip is not None:
            if target_ip in self.protected_ips:
                logger.warning(
                    "Block rejected: target IP %s is protected (can_block_ip == False)",
                    target_ip,
                )
                return False
            node_data = self.get_node(target_ip)
            if node_data and not node_data.get("can_block_ip", False):
                logger.warning(
                    "Block rejected: node %s has can_block_ip == False",
                    target_ip,
                )
                return False

        # Condition (b): Hardware MAC check (prevents DoS when attacker spoofs IP)
        if target_mac is not None:
            norm_mac = target_mac.strip().lower()
            if norm_mac in self.protected_macs:
                logger.warning(
                    "Block rejected: target MAC %s belongs to a protected host",
                    norm_mac,
                )
                return False

        return True

    def is_protected(
        self,
        target_ip: Optional[str] = None,
        target_mac: Optional[str] = None,
    ) -> bool:
        """Convenience query: True if target_ip or target_mac is immutable/protected."""
        return not self.check_gateway_protection(target_ip, target_mac)

    def calculate_blast_radius(self, compromised_ip: str) -> Set[str]:
        """Compute the blast radius of a compromised node.

        Returns:
            Set of node IDs reachable by outgoing edges exactly 1 hop from
            compromised_ip, excluding instrumentation edges ('monitor', 'enforce').
        """
        if not self.graph.has_node(compromised_ip):
            return set()

        reachable: Set[str] = set()
        for _, dst, data in self.graph.out_edges(compromised_ip, data=True):
            edge_label = data.get("label", "")
            if edge_label not in EXCLUDED_BLAST_LABELS:
                reachable.add(dst)

        return reachable


# Module-level convenience singleton / functions
TopologyGraph = NetworkGraph

_DEFAULT_GRAPH: Optional[NetworkGraph] = None


def get_default_graph() -> NetworkGraph:
    """Return or initialize the singleton NetworkGraph."""
    global _DEFAULT_GRAPH
    if _DEFAULT_GRAPH is None:
        _DEFAULT_GRAPH = NetworkGraph()
    return _DEFAULT_GRAPH


def check_gateway_protection(
    target_ip: Optional[str] = None,
    target_mac: Optional[str] = None,
    graph: Optional[NetworkGraph] = None,
) -> bool:
    """Module-level helper to evaluate block proposal against protected topology."""
    g = graph or get_default_graph()
    return g.check_gateway_protection(target_ip=target_ip, target_mac=target_mac)


def calculate_blast_radius(
    compromised_ip: str,
    graph: Optional[NetworkGraph] = None,
) -> Set[str]:
    """Module-level helper to compute 1-hop blast radius."""
    g = graph or get_default_graph()
    return g.calculate_blast_radius(compromised_ip=compromised_ip)
