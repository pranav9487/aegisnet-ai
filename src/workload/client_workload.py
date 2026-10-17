"""
src/workload/client_workload.py
--------------------------------
Continuous legitimate client that sends:
  - HTTP GET heartbeats to the target-server every 1.5 seconds.
  - HTTP POST payloads (simulated application data) every 3 seconds.
  - UDP heartbeat datagrams every 1.5 seconds on port 9000.

Runs inside the victim-client container (172.28.0.10).
"""

import logging
import os
import socket
import time
import threading
from typing import NoReturn

import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [CLIENT] %(message)s",
)
logger = logging.getLogger(__name__)

SERVER_HOST = os.environ.get("SERVER_HOST", "172.28.0.20")
SERVER_PORT = int(os.environ.get("SERVER_PORT", 8080))
INTERVAL_SECONDS = 1.5
UDP_PORT = 9000

BASE_URL = f"http://{SERVER_HOST}:{SERVER_PORT}"


def send_http_heartbeat() -> None:
    """Send a GET request to the server and log the result."""
    try:
        resp = requests.get(BASE_URL, timeout=2)
        logger.info("GET %s → HTTP %d", BASE_URL, resp.status_code)
    except requests.RequestException as exc:
        logger.warning("GET failed: %s", exc)


def send_http_post() -> None:
    """Send a POST payload simulating application data."""
    payload = {"timestamp": time.time(), "data": "aegisnet-workload-packet"}
    try:
        resp = requests.post(BASE_URL, json=payload, timeout=2)
        logger.info("POST %s → HTTP %d", BASE_URL, resp.status_code)
    except requests.RequestException as exc:
        logger.warning("POST failed: %s", exc)


def udp_heartbeat_loop() -> NoReturn:
    """Send UDP heartbeat datagrams every INTERVAL_SECONDS seconds."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    seq = 0
    while True:
        message = f"AEGIS-HB seq={seq} ts={time.time():.3f}".encode()
        try:
            sock.sendto(message, (SERVER_HOST, UDP_PORT))
            logger.debug("UDP heartbeat seq=%d sent", seq)
        except OSError as exc:
            logger.warning("UDP send failed: %s", exc)
        seq += 1
        time.sleep(INTERVAL_SECONDS)


def main() -> NoReturn:
    logger.info(
        "AegisNet client starting — target %s:%d", SERVER_HOST, SERVER_PORT
    )

    # Start UDP heartbeat in a daemon thread
    udp_thread = threading.Thread(target=udp_heartbeat_loop, daemon=True)
    udp_thread.start()

    # Give the server a moment to be ready on first boot
    time.sleep(2)

    post_counter = 0
    while True:
        send_http_heartbeat()

        post_counter += 1
        if post_counter % 2 == 0:
            send_http_post()

        time.sleep(INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
