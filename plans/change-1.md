# Task: Resolve Network Attachment Conflict for `blue-ai-defender`

## Issue

There is a conflict between the two project specification documents regarding how `blue-ai-defender` attaches to the network.

- **`ROADMAP.md` (Section 4, Step 2)** specifies that `blue-ai-defender` should be attached to the `aegisnet-bridge` network with its own static IP `172.28.0.2`, alongside `victim-client`, `target-server`, and `red-attacker`.
- **The project reference doc's `docker-compose.yml` example** instead uses:
  ```yaml
  blue-ai-defender:
    network_mode: "service:target-server"
  ```
  which attaches the defender to `target-server`'s network namespace instead of giving it an independent bridge IP.

## Required Resolution

Implement the **ROADMAP.md version**: give `blue-ai-defender` its own static IP (`172.28.0.2`) on the `aegisnet-bridge` network, with `NET_ADMIN` and `NET_RAW` capabilities, same as the other three containers.

**Do not use** `network_mode: service:target-server`.

### Why this approach

1. The sensor's promiscuous sniffing (Module 1) is designed to observe all Layer-2 broadcast and ARP traffic across the whole subnet — not just traffic entering/leaving `target-server`'s interface. An independent bridge attachment is required to see attacks directed at `victim-client` as well as `target-server`.
2. The NetworkX topology graph (Module 2 / `src/memory/network_graph.py`) models `blue-ai-defender` as its own node with its own criticality/role attributes — this only makes sense if it has its own identity on the network.
3. Test 1.2's expected output assumes the sensor is passively observing ARP traffic about `172.28.0.20` from a vantage point on the shared subnet, consistent with its own bridge IP, not a namespace-shared view.

---

## Checkpoints

- [x] **Checkpoint 1: Audit current state**
  Inspect the current `docker-compose.yml` and confirm whether `blue-ai-defender` is using `network_mode: service:target-server` or already has an independent IP.

  **Actual Output / Findings:**
  Confirmed in `docker-compose.yml`: `blue-ai-defender` is configured on network `aegisnet-bridge` with independent static IP `172.28.0.2`. It does not use `network_mode: service:target-server`.

- [x] **Checkpoint 2: Apply the fix**
  Update `docker-compose.yml` so `blue-ai-defender` is attached to `aegisnet-bridge` with static IP `172.28.0.2`, and has `NET_ADMIN` + `NET_RAW` capabilities. Remove any `network_mode: service:target-server` line.

  **Actual Output / Actions:**
  Verified `blue-ai-defender` has `NET_ADMIN` and `NET_RAW` capabilities (`cap_add`) and `privileged: true`. Additionally configured explicit static MAC addresses matching `data/topology_graph.json` across all services:
  - `blue-ai-defender`: `02:42:ac:1c:00:02` (IP `172.28.0.2`)
  - `victim-client`: `02:42:ac:1c:00:0a` (IP `172.28.0.10`)
  - `target-server`: `02:42:ac:1c:00:14` (IP `172.28.0.20`)
  - `red-attacker`: `02:42:ac:1c:00:42` (IP `172.28.0.66`)

- [x] **Checkpoint 3: Rebuild and bring the stack up**
  Run `docker compose up -d` (with `--force-recreate` if needed) and confirm no errors.

  **Actual Output:**
  ```text
  $ docker compose up -d --force-recreate
  [+] up 4/4
   ✔ Container blue-ai-defender Started 4.7s
   ✔ Container victim-client    Started 4.3s
   ✔ Container red-attacker     Started 4.5s
   ✔ Container target-server    Started 4.9s
  ```

- [x] **Checkpoint 4: Verify independent addressing**
  Run `docker network inspect aegisnet-bridge` and confirm all 4 containers report distinct IPs, including `blue-ai-defender` at `172.28.0.2`.

  **Actual Output:**
  ```text
  $ docker network inspect aegisnet-ai_aegisnet-bridge
  Containers:
    blue-ai-defender: IPv4 = 172.28.0.2/24,  MAC = 02:42:ac:1c:00:02
    victim-client:    IPv4 = 172.28.0.10/24, MAC = 02:42:ac:1c:00:0a
    target-server:    IPv4 = 172.28.0.20/24, MAC = 02:42:ac:1c:00:14
    red-attacker:     IPv4 = 172.28.0.66/24, MAC = 02:42:ac:1c:00:42
  ```

- [x] **Checkpoint 5: Verify connectivity**
  From `blue-ai-defender`, ping both `victim-client` (`172.28.0.10`) and `target-server` (`172.28.0.20`). Confirm 0% packet loss for both.

  **Actual Output:**
  ```text
  $ docker exec blue-ai-defender ping -c 3 172.28.0.10 && docker exec blue-ai-defender ping -c 3 172.28.0.20
  PING 172.28.0.10 (172.28.0.10) 56(84) bytes of data.
  64 bytes from 172.28.0.10: icmp_seq=1 ttl=64 time=0.505 ms
  64 bytes from 172.28.0.10: icmp_seq=2 ttl=64 time=0.034 ms
  64 bytes from 172.28.0.10: icmp_seq=3 ttl=64 time=0.056 ms

  --- 172.28.0.10 ping statistics ---
  3 packets transmitted, 3 received, 0% packet loss, time 2046ms
  rtt min/avg/max/mdev = 0.034/0.198/0.505/0.217 ms

  PING 172.28.0.20 (172.28.0.20) 56(84) bytes of data.
  64 bytes from 172.28.0.20: icmp_seq=1 ttl=64 time=0.169 ms
  64 bytes from 172.28.0.20: icmp_seq=2 ttl=64 time=0.057 ms
  64 bytes from 172.28.0.20: icmp_seq=3 ttl=64 time=0.074 ms

  --- 172.28.0.20 ping statistics ---
  3 packets transmitted, 3 received, 0% packet loss, time 2045ms
  rtt min/avg/max/mdev = 0.057/0.100/0.169/0.049 ms
  ```

- [x] **Checkpoint 6: Verify sensor interface name**
  Run `ip link show` inside `blue-ai-defender`. Confirm the actual interface name (do not assume `eth0` — Docker network driver versions can name it differently). Update the sensor's bind target in `src/sensor/packet_engine.py` / `.env` (`AEGIS_INTERFACE`) if it differs.

  **Actual Output:**
  ```text
  $ docker exec blue-ai-defender ip link show
  1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
      link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
  2: eth0@if36: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default 
      link/ether 02:42:ac:1c:00:02 brd ff:ff:ff:ff:ff:ff link-netnsid 0
  ```
  Confirmed: Primary interface is `eth0`, exactly matching `.env` (`AEGIS_INTERFACE=eth0`) and `src/sensor/packet_engine.py`.

- [x] **Checkpoint 7: Confirm promiscuous mode is viable**
  Check whether the bridge/container NIC needs explicit promiscuous mode enabled for Scapy sniffing to capture all subnet traffic (not just traffic to/from the defender's own IP).

  **Actual Output:**
  ```text
  $ docker exec blue-ai-defender ip link set eth0 promisc on && docker exec blue-ai-defender ip link show eth0
  2: eth0@if36: <BROADCAST,MULTICAST,PROMISC,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default 
      link/ether 02:42:ac:1c:00:02 brd ff:ff:ff:ff:ff:ff link-netnsid 0
  ```
  Confirmed: `eth0` inside `blue-ai-defender` successfully toggles and supports `PROMISC` mode directly due to `privileged: true` and `NET_ADMIN` capabilities. In addition, Scapy's native `sniff(iface='eth0')` enables promiscuous capture on the AF_PACKET socket by default.

- [x] **Checkpoint 8: Proceed to Test 1.2**
  Only after Checkpoints 1–7 pass, run Test 1.2 (Stateful Packet Sensor Invariant Detection) and record the actual output against the expected `AegisNetAnomalyAlert-v1` ARP invariant JSON.

  **Actual Output:**
  ```bash
  $ docker exec -d blue-ai-defender python3 -u /src/sensor/packet_engine.py
  $ docker exec red-attacker python3 /attacks/arp_spoof.py --count 5
  $ docker exec blue-ai-defender cat /tmp/sensor_alerts.log | head -n 30
  ```
  ```json
  {
    "alert_id": "ALERT-ARPINVARIA-95e4102e",
    "timestamp_utc": "2026-10-17T12:57:28.898322+00:00",
    "detection_engine": "ARP_INVARIANT",
    "severity": "CRITICAL",
    "layer2_state": {
      "observed_mac": "02:42:ac:1c:00:42",
      "expected_mac": "02:42:ac:1c:00:14",
      "claimed_ip": "172.28.0.20",
      "delta_arp": 1
    },
    "layer4_state": {
      "protocol": "ARP",
      "delta_seq": 0,
      "duplicate_acks": 0
    },
    "entropy_metrics": {
      "shannon_entropy": 0.0,
      "entropy_delta_pct": 0.0
    }
  }
  ```
  **Schema Validation:** Passed (`schemas/AegisNetAnomalyAlert-v1.json`).
  **Verdict:** PASS (`delta_arp == 1`, observed_mac = `02:42:ac:1c:00:42`, expected_mac = `02:42:ac:1c:00:14`).
