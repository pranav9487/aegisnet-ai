#!/usr/bin/env python3
"""Validate data/raw_rules/*.json for AegisNet-AI SERA-IDS experience rules."""
import glob, itertools, json, operator, os, sys
from collections import Counter

RULE_DIR = os.path.expanduser("~/aegisnet-ai/data/raw_rules")
REQUIRED = {"rule_id", "attack_class", "behavior_summary", "symbolic_conditions",
            "forbidden_actions", "mandated_remediation", "confidence_rating"}
FIELDS = {"delta_arp": (0, 1), "delta_seq": (0, 100000),
          "duplicate_acks": (0, 20), "payload_entropy": (0.0, 8.0)}
OPS = {"==": operator.eq, "!=": operator.ne, ">": operator.gt,
       ">=": operator.ge, "<": operator.lt, "<=": operator.le}
REMEDIATIONS = {"ISOLATE_MAC_THEN_IPSEC", "MONITOR_ONLY", "RATE_LIMIT"}
CLASS_RANGES = {"ARP_POISON_MITM": (12, 15), "TCP_SESSION_HIJACK": (12, 15),
                "UDP_FLOOD": (8, 10), "BENIGN_SPIKE": (10, 12)}

# Sample grid of possible sensor states (covers the thresholds used in the roadmap)
GRID = [dict(delta_arp=a, delta_seq=s, duplicate_acks=d, payload_entropy=h)
        for a, s, d, h in itertools.product(
            [0, 1], [0, 500, 1460, 2000, 50000], [0, 2, 3, 5], [3.5, 5.0, 7.0, 7.8])]

errors, warnings = [], []

def matches(rule, state):
    for c in rule["symbolic_conditions"]:
        if c["field"] not in state or not OPS[c["op"]](state[c["field"]], c["value"]):
            return False
    return True

rules = {}
for path in sorted(glob.glob(os.path.join(RULE_DIR, "*.json"))):
    name = os.path.basename(path)
    try:
        r = json.load(open(path))
    except json.JSONDecodeError as e:
        errors.append(f"{name}: invalid JSON ({e})"); continue

    missing = REQUIRED - r.keys()
    if missing:
        errors.append(f"{name}: missing keys {sorted(missing)}"); continue

    if r["attack_class"] not in CLASS_RANGES:
        errors.append(f"{name}: unknown attack_class {r['attack_class']}")
    if r["mandated_remediation"] not in REMEDIATIONS:
        errors.append(f"{name}: bad mandated_remediation {r['mandated_remediation']}")
    if not (0.0 <= float(r["confidence_rating"]) <= 1.0):
        errors.append(f"{name}: confidence_rating out of [0,1]")
    if any("victim" in a for a in r["forbidden_actions"]) is False:
        warnings.append(f"{name}: forbidden_actions does not block victim IP drops")

    for c in r["symbolic_conditions"]:
        if c.get("field") not in FIELDS:
            errors.append(f"{name}: unknown field {c.get('field')}")
        if c.get("op") not in OPS:
            errors.append(f"{name}: unknown op {c.get('op')}")
        if c.get("field") == "delta_arp" and c.get("value") not in (0, 1):
            errors.append(f"{name}: delta_arp value must be 0 or 1")

    if r["attack_class"] == "BENIGN_SPIKE" and r["mandated_remediation"] != "MONITOR_ONLY":
        errors.append(f"{name}: BENIGN_SPIKE must use MONITOR_ONLY")
    if any("drop_victim" in a for a in r["mandated_remediation"].lower().split()):
        errors.append(f"{name}: remediation drops victim")

    rules[name] = r

# Counts per class
counts = Counter(r["attack_class"] for r in rules.values())
for cls, (lo, hi) in CLASS_RANGES.items():
    n = counts.get(cls, 0)
    if not lo <= n <= hi:
        errors.append(f"class {cls}: {n} rules, expected {lo}-{hi}")
total = len(rules)
if total < 50:
    errors.append(f"only {total} rules, need >= 50")

# Overlap: BENIGN rules must not fire on a state where an attack rule fires
attack_hits = {n for n, r in rules.items() if r["attack_class"] != "BENIGN_SPIKE"
               for s in GRID if matches(r, s)}
for n, r in rules.items():
    if r["attack_class"] != "BENIGN_SPIKE":
        if not any(matches(r, s) for s in GRID):
            warnings.append(f"{n}: attack rule matches no sample state (dead rule?)")
        continue
    for s in GRID:
        if matches(r, s):
            attacks = [m for m, ar in rules.items()
                       if ar["attack_class"] != "BENIGN_SPIKE" and matches(ar, s)]
            if attacks:
                errors.append(f"{n}: BENIGN rule fires on state {s} "
                              f"where attack rules {attacks[:3]} also fire")
                break

print(f"Rules loaded: {total}")
print("Counts:", dict(counts))
for w in warnings: print("WARN ", w)
for e in errors:   print("ERROR", e)
print("PASS" if not errors else f"FAIL: {len(errors)} error(s)")
sys.exit(1 if errors else 0)
