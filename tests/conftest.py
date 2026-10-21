"""tests/conftest.py
------------------
Pytest configuration and output formatting hooks.
"""

from __future__ import annotations

import sys
import pytest

ASSERTION_MESSAGES = {
    "test_gateway_protection": "[ASSERTION OK] Target 172.28.0.1 (GATEWAY) flagged as immutable: can_block_ip == False",
    "test_client_protection": "[ASSERTION OK] Target 172.28.0.10 (CLIENT) flagged as immutable: can_block_ip == False",
    "test_server_protection": "[ASSERTION OK] Target 172.28.0.20 (SERVER) flagged as immutable: can_block_ip == False",
    "test_mac_based_rejection": "[ASSERTION OK] Protected MACs (02:42:ac:1c:00:0a, 02:42:ac:1c:00:14, 02:42:ac:1c:00:01) rejected even if IP spoofed",
    "test_attacker_blockable": "[ASSERTION OK] 172.28.0.66 (UNTRUSTED) can_block_ip == True, block allowed",
    "test_blast_radius_attacker": '[ASSERTION OK] calculate_blast_radius("172.28.0.66") == {"172.28.0.20"}',
    "test_blast_radius_client": '[ASSERTION OK] calculate_blast_radius("172.28.0.10") == {"172.28.0.20"}',
    "test_symbolic_predicate": "[EVAL] Alert with delta_seq=50 rejected rule requiring delta_seq > 1460: V(x, Rk) == False\n[EVAL] Alert with delta_arp=1 accepted rule requiring delta_arp == 1: V(x, Rk) == True",
}


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_logreport(report: pytest.TestReport):
    yield
    if report.when == "call" and report.passed:
        test_name = report.nodeid.split("::")[-1]
        msg = ASSERTION_MESSAGES.get(test_name)
        if msg:
            sys.__stdout__.write(f"\n{msg}\n")
            sys.__stdout__.flush()
