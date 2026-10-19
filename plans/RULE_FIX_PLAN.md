# AegisNet-AI: Rule Fix Plan (Book 2 — SERA-IDS Experience Rules)

## 1. Objective

Fix the experience rule files in `data/raw_rules/` so that `tools/check_rules.py` passes with no ERROR lines and no dead-rule WARN lines.

## 2. Context

The current checker run loaded 50 rules with correct class counts (ARP_POISON_MITM 14, TCP_SESSION_HIJACK 14, UDP_FLOOD 10, BENIGN_SPIKE 12). It reported:

- **ERRORS (11):** BENIGN_SPIKE rules EXP-039, 040, 041, 042, 043, 044, 045, 046, 048, 049, 050 fire on sample states where attack rules also fire.
- **WARNINGS (6):** Dead attack rules EXP-018, 019, 020, 025, 026, 028 never match any sample state.

Sensor fields available: `delta_arp` (0 or 1), `delta_seq`, `duplicate_acks`, `payload_entropy`.
Allowed ops: `==`, `!=`, `>`, `>=`, `<`, `<=`.
Baseline normal traffic: entropy 3.2 to 4.5, delta_seq 0, delta_arp 0.

## 3. Constraints (do not violate)

- Edit ONLY the `symbolic_conditions` field (and `mandated_remediation` on BENIGN rules if wrong). Do not change `rule_id`, `attack_class`, `behavior_summary`, `forbidden_actions`, or `confidence_rating`.
- Do NOT edit `tools/check_rules.py`, EXACT thresholds in the checker, or the GRID to make tests pass. The checker is the source of truth.
- Do NOT change rules that are not listed in Section 2 unless a fix requires it; report any such change.
- BENIGN_SPIKE rules must keep `mandated_remediation: MONITOR_ONLY`.
- No rule may drop a victim IP.
- Do not run commands other than the ones listed in Section 6. Do not install packages.

## 4. Fix Rules

| Rule type | Required fix |
|---|---|
| BENIGN_SPIKE | Include `payload_entropy <= 4.5`, `duplicate_acks < 3`, `delta_seq <= 1460`. Benign bursts must stay under attack thresholds. |
| ARP_POISON_MITM | Require `delta_arp == 1`. |
| TCP_SESSION_HIJACK | Use `delta_seq > 1460` and `duplicate_acks >= 3`. Optional: `payload_entropy >= 7.6` for injected-payload variants. |
| UDP_FLOOD | Use a condition the sensor computes (entropy jump or volume). Do not use `delta_seq`. |
| Dead rules | Make the threshold reachable by the sensor grid, or lower it to a value the sensor can produce. |

## 5. Expected Output vs Actual Output

**Expected Output (target):**
```
Rules loaded: 50
Counts: {'ARP_POISON_MITM': 14, 'TCP_SESSION_HIJACK': 14, 'UDP_FLOOD': 10, 'BENIGN_SPIKE': 12}
PASS
```
- Zero `ERROR` lines.
- Zero `WARN` lines about dead rules.

**Actual Output:** (agent fills this in after each run)
```
Rules loaded: 50
Counts: {'ARP_POISON_MITM': 14, 'TCP_SESSION_HIJACK': 14, 'UDP_FLOOD': 10, 'BENIGN_SPIKE': 12}
PASS
```

**Verdict:** [x] MATCH / [ ] DIVERGE

## 6. Commands the Agent May Run

```bash
python3 ~/aegisnet-ai/tools/check_rules.py
cat ~/aegisnet-ai/data/raw_rules/EXP-XXX.json
python3 -m json.tool ~/aegisnet-ai/data/raw_rules/EXP-XXX.json
```

## 7. Loop Protocol (MANDATORY)

Repeat until Actual Output matches Expected Output:

1. **RUN** `python3 ~/aegisnet-ai/tools/check_rules.py`.
2. **CAPTURE** the full output into Section 5 "Actual Output".
3. **COMPARE** against Expected Output (Section 5).
4. **IF DIVERGENT:** read each ERROR/WARN line, open the named file, fix its `symbolic_conditions` per Section 4, and return to step 1.
5. **IF MATCH:** mark the verdict MATCH and stop.

Rules for the loop:
- Change the rule files, not the checker or the expected output.
- Fix one class of problem per iteration, then re-run.
- Stop and report to the user after 10 iterations without reaching MATCH. Include the last Actual Output and the files still failing.
- Each iteration, log one line: `Iteration N: <number of ERRORs> errors, <number of WARNs> warns, files changed: <list>`.

## 8. Completion Criteria

- [x] `check_rules.py` exits with code 0.
- [x] Actual Output matches Expected Output.
- [x] Only rule files under `data/raw_rules/` were modified.
- [x] Iteration log is included in the final report.
- [x] Final report lists every changed file with its old and new `symbolic_conditions`.

## 9. Final Report Format

```
Iterations: N
Final verdict: MATCH / DIVERGE
Files changed: [list]
Unresolved issues: [list or none]
```

Note for the user (not for the agent): the checker only confirms the rules do not contradict each other on the sample grid. Review each rule against real sensor output before relying on it.
