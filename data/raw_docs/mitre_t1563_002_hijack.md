# MITRE ATT&CK T1563 / T1563.002 — Remote Service Session Hijacking (Summary)

Source: attack.mitre.org, technique T1563 and sub-technique T1563.002. Tactic: Lateral Movement. Platforms: Linux, macOS (T1563.001 SSH Hijacking), Windows (T1563.002 RDP Hijacking).

## Scope note (read first)
As flagged in `mitre_t1556_mitm_correction.md`, this technique family covers hijacking an **already-authenticated remote administration session** (SSH or RDP) to move laterally using the victim's existing trust relationship — it does not describe blind TCP sequence-number prediction against an arbitrary application-layer TCP stream, which is what this project's `tcp_hijack.py` / `attacks/tcp_desync.py` actually implements. Included here for completeness and because the broader technique description (session takeover without needing credentials) is conceptually adjacent, but do not cite T1563.002 specifically as the ATT&CK ID for this project's TCP desync attack class.

## T1563 — Remote Service Session Hijacking (parent technique)
Adversaries may take control of a pre-existing session with a remote service to move laterally, rather than creating a new authenticated session themselves. This requires obtaining elevated privileges first (root access, or access to the target's session-hijacking vector).

## T1563.001 — SSH Hijacking
Adversaries hijack an existing SSH session rather than initiating a new one — e.g. by attaching to another user's `screen`/`tmux` session, or by hijacking the SSH agent socket (setting `$SSH_AUTH_SOCK` to the victim's socket), which grants access to every system the original user had key-based access to. Requires root access or access to the target user's agent socket on Linux.

## T1563.002 — RDP Hijacking
The Windows analog: hijacking an active Remote Desktop session to inherit its authenticated state without needing the password.

## Mitigations (apply loosely by analogy, not directly)
- Restrict SSH key-store technologies (`ssh-agent`) unless properly protected; enforce strong key-pair passwords.
- Disallow remote access via SSH/RDP as root or other privileged accounts.
- Monitor for anomalous session reuse (agent socket access by a different process/user, lateral pivoting without a corresponding new authentication event).

## Relevance to this project
Limited. The genuinely relevant defensive principle — **detecting activity on an existing session that didn't originate from a fresh, legitimate authentication** — is analogous to this project's TCP sequence-drift detection (Δ_SEQ invariant), which flags packets injected into an already-established TCP stream whose sequence number diverges from the tracked state machine. But the ATT&CK citation itself should not be T1563.002 for this attack class; see the correction file for the recommended handling.
