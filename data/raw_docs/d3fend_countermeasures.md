# MITRE D3FEND — Network Isolation Countermeasures (Summary)

Source: d3fend.mitre.org, "Isolate" tactic → "Network Isolation" (D3-NI) technique category. D3FEND is MITRE's defensive counterpart to ATT&CK, funded by NSA, mapping countermeasures to the ATT&CK techniques and digital artifacts they address.

## Network Isolation (D3-NI) — parent technique
Network Isolation techniques prevent network hosts from accessing non-essential network resources, typically by disconnecting or restricting a compromised or malicious host's reach. Relevant subclasses for this project:

| D3FEND ID | Technique | Definition | Relevance to AegisNet-AI |
|---|---|---|---|
| D3-NTF | Network Traffic Filtering | Restricting network traffic originating from any location based on defined criteria. | Parent category covering both the ebtables (Layer-2) and arptables (ARP-layer) drop rules the enforcer issues against the attacker's MAC. |
| D3-ITF | Inbound Traffic Filtering | Restricting traffic originating from untrusted networks/hosts destined toward a protected host. | Maps to `ebtables -A INPUT -s <attacker_mac> -j DROP` — this project filters inbound frames at the bridge by source MAC. |
| D3-BDI | Broadcast Domain Isolation | Restricts how many hosts a device can contact on its local broadcast domain (also referenced as Network Segmentation). | Conceptually what gratuitous-ARP-based MITM abuses (shared broadcast domain); the project's MAC quarantine is a reactive, per-incident form of this rather than static segmentation. |
| D3-ET | Encrypted Tunnels | Encrypted encapsulation of routable network traffic. | This is the D3FEND category the project's IPsec ESP transport-mode enforcement falls under — once the attacker's MAC is isolated, the remaining Layer-3 defense is to encrypt the session so that any future on-path observation yields only ciphertext. |

## Mapping to the project's two-stage remediation (`ISOLATE_MAC_THEN_IPSEC`)
The `mandated_remediation` value used throughout the SERA-IDS experience rules (e.g. `ISOLATE_MAC_THEN_IPSEC`) corresponds to exactly two D3FEND technique categories applied in sequence:
1. **D3-ITF (Inbound Traffic Filtering)** — drop frames from the confirmed rogue MAC at Layer 2 (ebtables/arptables). This stops the active poisoning/injection but does not retroactively protect confidentiality of any traffic the attacker already observed.
2. **D3-ET (Encrypted Tunnels)** — establish an authenticated IPsec ESP transport-mode SA between the legitimate endpoints. This is what prevents a *future* on-path position (e.g. from a different compromised host) from yielding readable traffic, independent of whether MAC filtering alone is bypassed.

This two-stage structure is also why Agent 2 (Policy Synthesizer)'s directive in the project design explicitly requires deciding both "(1) Can this be neutralized at Layer 2?" and "(2) Does the session require IPsec?" — these map directly to D3-ITF and D3-ET as distinct, composable D3FEND countermeasures rather than a single monolithic action.
