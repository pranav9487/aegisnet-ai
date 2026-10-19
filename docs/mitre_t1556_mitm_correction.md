# Correction: MITM Technique ID in Project Documentation

The project's `details_for_this_project` document lists "T1556" as the MITRE ATT&CK technique for MITM. **This is incorrect and should not be embedded into the RAG store as-is.** Verified against attack.mitre.org:

| Cited in project doc | Actual MITRE assignment |
|---|---|
| T1556 = "MITM" | **T1556 is actually "Modify Authentication Process"** (credential-access/persistence technique involving tampering with PAM, auth DLLs, etc. — unrelated to network MITM) |
| (correct ID) | **T1557 = "Adversary-in-the-Middle"** — this is the correct parent technique for MITM. T1557.002 (ARP Cache Poisoning) is its relevant sub-technique for this project, already covered in `mitre_t1557_002_arp.md`. |

## T1557 — Adversary-in-the-Middle (correct reference)
ID: T1557. Tactics: Credential Access, Collection. Platforms: Linux, Network Devices, Windows, macOS.

Adversaries position themselves between two or more networked devices to support follow-on behaviors such as network sniffing, transmitted data manipulation, or credential replay. They abuse protocols that influence traffic flow (ARP, DNS, LLMNR) to force devices to route through an adversary-controlled system. Sub-techniques: T1557.001 (Name Resolution Poisoning/SMB Relay), T1557.002 (ARP Cache Poisoning — this project's primary attack class), T1557.003 (DHCP Spoofing), T1557.004 (Evil Twin).

## Also worth correcting: T1563.002 mapping
The project doc also cites "T1563.002 (RDP/TCP Hijacking)" for the blind TCP session hijack attack. This is also imprecise: **T1563.002 is specifically "RDP Hijacking"** (a sub-technique of T1563, Remote Service Session Hijacking), which covers hijacking an existing Windows RDP session — not blind TCP sequence-number prediction/injection against an arbitrary TCP stream. MITRE ATT&CK does not have a dedicated sub-technique for classic blind TCP sequence-prediction hijacking (a textbook network-security attack predating ATT&CK's scope, which focuses on post-compromise adversary behavior rather than low-level protocol attacks). For this project's TCP desync/hijack attack class, the more defensible mapping is:
- Parent technique **T1557 (Adversary-in-the-Middle)** generally, since the attacker is positioned to observe and inject into the stream, OR
- Citing it as a classical protocol-level attack (Mitnick/Morris-style blind spoofing) without forcing an exact ATT&CK ID, since none fits precisely.

## Recommended action
When Agent 1/2's prompts reference technique IDs for citation purposes, use **T1557 / T1557.002** for ARP poisoning and avoid citing T1563.002 for the generic TCP hijack class — or relabel that attack internally as `TCP_SESSION_HIJACK_BLIND_INJECTION` (as already used in the SERA-IDS experience rule schema) without an ATT&CK sub-technique ID, rather than attaching an incorrect one.
