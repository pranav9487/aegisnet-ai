# MITRE ATT&CK T1557.002 — ARP Cache Poisoning (Summary)

Source: attack.mitre.org, technique T1557.002. Sub-technique of **T1557, Adversary-in-the-Middle** (tactics: Credential Access, Collection). Platforms: Linux, Windows, macOS.

## Technique description
Adversaries poison ARP caches to position themselves between two or more networked devices. When a device makes an ARP request, it stores the resulting IP-to-MAC mapping in its cache; an adversary can passively wait for that request and race the legitimate owner to reply first, or — the method this project's `arp_poison.py` implements — send unsolicited **gratuitous ARP replies** that announce false ownership of an IP address to every device on the local segment without waiting for a request at all. ARP is stateless and unauthenticated, so devices accept and overwrite cache entries from these replies with no verification.

## MITRE-documented mitigations
| ID | Mitigation | Relevance to AegisNet-AI |
|---|---|---|
| M1042 | Disable or Remove Feature or Program | Consider disabling cache updates triggered by gratuitous ARP replies at the OS/NIC level. |
| M1037 | Filter Network Traffic | Enable DHCP Snooping and Dynamic ARP Inspection (DAI) on switches to validate IP-MAC bindings against DHCP lease records. |
| M1035 | Limit Access to Resource Over Network | **Create static ARP entries for networked devices** — this is the mitigation AegisNet-AI implements directly via `arp -s <ip> <mac>`, pinning the victim's correct binding so the attacker's gratuitous replies cannot override it. |

## Why this matters for the project's defense logic
MITRE explicitly notes static ARP entries are the standard mitigation but calls them "infeasible for large networks" — which is precisely the gap AegisNet-AI's *dynamic* approach closes: rather than statically pre-configuring every binding network-wide, the system detects the live poisoning attempt (Δ_ARP invariant breach) and reactively injects a static binding only for the specific IP under active attack, combined with isolating the attacker's MAC via ebtables/arptables. This is the justification Agent 2 (Policy Synthesizer) should cite when selecting the `ISOLATE_MAC_THEN_IPSEC` remediation path for ARP-class incidents.

## Correction to project documentation
The project's `details_for_this_project` document is accurate for this technique ID (T1557.002). No correction needed here — see `mitre_t1556_mitm_correction.md` for an ID error found elsewhere in the same document.
