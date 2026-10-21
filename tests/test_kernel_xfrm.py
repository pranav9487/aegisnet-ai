"""tests/test_kernel_xfrm.py
--------------------------
Unit tests for Linux Netlink XFRM Enforcer (v0.8 Step 3).

Verifies:
  1. Parameter validation & safety invariants (reject protected MACs, reject bad keys/IPs/SPIs).
  2. Construction of correct ebtables/arptables/iptables MAC isolation commands.
  3. Construction of static ARP fix commands.
  4. Construction of IPsec ESP Transport SAs and SPs via `ip xfrm`.
  5. Rollback flush command execution.

Does NOT require root, Docker, or real kernel execution — uses mocks for subprocess calls.
"""

import sys
from pathlib import Path
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from src.enforcer.kernel_xfrm import KernelEnforcementEngine


@pytest.fixture
def sample_policy() -> Dict[str, Any]:
    return {
        "policy_id": "TEST-POL-01",
        "target_attacker_mac": "02:42:ac:1c:00:42",
        "static_arp_fixes": [
            {"ip_address": "172.28.0.10", "mac_address": "02:42:ac:1c:00:0a"}
        ],
        "ipsec_configuration": {
            "apply_ipsec": True,
            "mode": "transport",
            "cipher": "aes-gcm-256",
            "spi_client_to_server": 4097,
            "spi_server_to_client": 4098,
            "key_material_hex": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef12345678",
        },
    }


def test_safety_rejects_protected_macs():
    """Engine must refuse to block protected MACs (gateway, victim client, server)."""
    eng = KernelEnforcementEngine()
    for protected_mac in ["02:42:ac:1c:00:01", "02:42:ac:1c:00:0a", "02:42:ac:1c:00:14"]:
        policy = {
            "policy_id": "BAD-POL",
            "target_attacker_mac": protected_mac,
        }
        with pytest.raises(ValueError, match="SAFETY INVARIANT VIOLATION"):
            eng.enforce_defense_policy(policy)


def test_validation_rejects_bad_mac():
    """Engine must reject malformed MAC address."""
    eng = KernelEnforcementEngine()
    with pytest.raises(ValueError, match="Invalid target_attacker_mac"):
        eng.enforce_defense_policy({"target_attacker_mac": "not-a-mac"})


def test_validation_rejects_bad_key_length(sample_policy):
    """Engine must reject key_material_hex whose length is not 72 chars."""
    eng = KernelEnforcementEngine()
    sample_policy["ipsec_configuration"]["key_material_hex"] = "a" * 64  # only 64, missing 8 salt
    with patch.object(eng, "_run_cmd"):
        with pytest.raises(ValueError, match="Invalid key_material_hex"):
            eng.enforce_defense_policy(sample_policy)


def test_validation_rejects_bad_spi(sample_policy):
    """Engine must reject SPI out of 32-bit range."""
    eng = KernelEnforcementEngine()
    sample_policy["ipsec_configuration"]["spi_client_to_server"] = 0
    with patch.object(eng, "_run_cmd"):
        with pytest.raises(ValueError, match="SPIs must be in range"):
            eng.enforce_defense_policy(sample_policy)


def test_enforce_defense_policy_commands(sample_policy):
    """Engine issues the exact required kernel commands for isolation, ARP, and IPsec."""
    eng = KernelEnforcementEngine(server_ip="172.28.0.20")
    executed_cmds = []

    def mock_run(args, **kwargs):
        executed_cmds.append(list(args))
        m = MagicMock()
        m.returncode = 0
        return m

    with patch.object(eng, "_run_cmd", side_effect=mock_run):
        eng.enforce_defense_policy(sample_policy)

    # 1. Check MAC isolation commands
    has_ebtables = any(cmd[:4] == ["ebtables", "-A", "INPUT", "-s"] for cmd in executed_cmds)
    has_arptables = any(cmd[:4] == ["arptables", "-A", "INPUT", "--src-mac"] for cmd in executed_cmds)
    has_iptables = any(cmd[:4] == ["iptables", "-A", "INPUT", "-m"] for cmd in executed_cmds)
    assert has_ebtables, "Must issue ebtables MAC drop"
    assert has_arptables, "Must issue arptables MAC drop"
    assert has_iptables, "Must issue iptables MAC drop"

    # 2. Check static ARP commands
    has_arp = any(cmd == ["arp", "-s", "172.28.0.10", "02:42:ac:1c:00:0a"] for cmd in executed_cmds)
    assert has_arp, "Must issue arp -s"

    # 3. Check XFRM state add commands
    # Inbound SA: 172.28.0.10 -> 172.28.0.20, spi 0x1001
    inbound_sa = [
        cmd for cmd in executed_cmds
        if cmd[:4] == ["ip", "xfrm", "state", "add"] and "src" in cmd and cmd[cmd.index("src") + 1] == "172.28.0.10"
    ]
    assert len(inbound_sa) == 1, "Must add inbound SA for 172.28.0.10 -> 172.28.0.20"
    assert "0x1001" in inbound_sa[0] or "4097" in inbound_sa[0]
    assert "rfc4106(gcm(aes))" in inbound_sa[0]
    assert "128" in inbound_sa[0]

    # Outbound SA: 172.28.0.20 -> 172.28.0.10, spi 0x1002
    outbound_sa = [
        cmd for cmd in executed_cmds
        if cmd[:4] == ["ip", "xfrm", "state", "add"] and "src" in cmd and cmd[cmd.index("src") + 1] == "172.28.0.20"
    ]
    assert len(outbound_sa) == 1, "Must add outbound SA for 172.28.0.20 -> 172.28.0.10"
    assert "0x1002" in outbound_sa[0] or "4098" in outbound_sa[0]

    # 4. Check XFRM policy add commands
    inbound_sp = [
        cmd for cmd in executed_cmds
        if cmd[:4] == ["ip", "xfrm", "policy", "add"] and "in" in cmd
    ]
    assert len(inbound_sp) == 1, "Must add inbound XFRM policy"

    outbound_sp = [
        cmd for cmd in executed_cmds
        if cmd[:4] == ["ip", "xfrm", "policy", "add"] and "out" in cmd
    ]
    assert len(outbound_sp) == 1, "Must add outbound XFRM policy"


def test_rollback_commands(sample_policy):
    """Rollback flushes XFRM state, policy, ebtables, and arptables."""
    eng = KernelEnforcementEngine(server_ip="172.28.0.20")
    executed_cmds = []

    def mock_run(args, **kwargs):
        executed_cmds.append(list(args))
        m = MagicMock()
        m.returncode = 0
        return m

    with patch.object(eng, "_run_cmd", side_effect=mock_run):
        eng.rollback()

    assert ["ip", "xfrm", "state", "flush"] in executed_cmds
    assert ["ip", "xfrm", "policy", "flush"] in executed_cmds
    assert ["ebtables", "-F"] in executed_cmds
    assert ["arptables", "-F"] in executed_cmds
