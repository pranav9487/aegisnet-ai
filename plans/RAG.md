# AegisNet-AI: RAG Content Sourcing Roadmap (Pre-v0.5 Prerequisite)

---

## 0. Purpose & Placement

This roadmap fills a gap in `ROADMAP.md`: Version 0.5 assumes the "books" (Book 1 static docs, Book 2 experience rules) already exist as raw content, but no step actually sources them. **Execute everything in this document before running `ROADMAP.md` → Version 0.5 → Step 2 (`experience_store.py`) and Step 4 (`bootstrap_rules.py`).**

```
v0.1 (Cyber-Range + Sensor)
      │
      ▼
[THIS ROADMAP: RAG Content Sourcing]   ← you are here
      │
      ▼
v0.5 Step 1 (Topology Graph Engine) — independent, can run in parallel with this
v0.5 Step 2 (Experience Store)       ← blocked until Section 2 below is done
v0.5 Step 3 (Diverse Ranker)         ← blocked until Section 2 below is done
v0.5 Step 4 (Bootstrap Script)       ← blocked until Sections 2 & 3 below are done
```

Nothing in v0.1 touches the RAG, so this work can happen in parallel with v0.1 testing.

---

## 1. Directory Scaffold

```bash
mkdir -p data/raw_rules data/raw_docs
```

- `data/raw_rules/` → Book 2 source material (experience rules, as individual JSON files)
- `data/raw_docs/` → Book 1 source material (static reference text, as markdown/text files)

These are staging directories. Nothing here is a ChromaDB collection yet — `bootstrap_rules.py` and a new `bootstrap_static_docs.py` (Section 4) read from here and embed into Chroma.

---

## 2. Book 2: Experience Rules (`sera_ids_experiences`)

**Who sources this: you, with optional agent drafting + your review.** There is no public dataset of "SERA rules" — they encode your own system's ground-truth attack logic, so correctness here matters more than speed.

### 2.1 Rule Schema

Each file in `data/raw_rules/` is one JSON object:

```json
{
  "rule_id": "EXP-004",
  "attack_class": "ARP_POISON_MITM",
  "behavior_summary": "Gratuitous ARP reply binds server IP to a foreign MAC address.",
  "symbolic_conditions": [
    {"field": "delta_arp", "op": "==", "value": 1}
  ],
  "forbidden_actions": ["drop_victim_ip"],
  "mandated_remediation": "ISOLATE_MAC_THEN_IPSEC",
  "confidence_rating": 0.9
}
```

### 2.2 Coverage Target

Minimum 50 rules (per `ROADMAP.md` v0.5 Step 4), spread across at least these classes so the diverse ranker's `K=5` downsample has something to diversify over:

| Attack class | Target count | Source |
|---|---|---|
| `ARP_POISON_MITM` | 12–15 | Derived from `attacks/arp_spoof.py` variants you build in v0.1 |
| `TCP_SESSION_HIJACK` | 12–15 | Derived from `attacks/tcp_desync.py` variants |
| `UDP_FLOOD` | 8–10 | New attack pattern, not yet scripted in v0.1 — write rules first, script later if needed |
| `BENIGN_SPIKE` | 10–12 | Legitimate traffic bursts (client reconnects, retries) that must NOT trigger remediation — critical for your false-positive metric in v1.0 benchmarking |

### 2.3 Execution Steps

- [x] **Step 2.3.1:** For each attack class, list every distinct parameter variant you can produce from your own attack scripts (e.g. ARP: slow drip vs. burst flood; TCP: near-window vs. far-window seq prediction).
- [x] **Step 2.3.2:** Draft rule JSON for each variant. You may have the agentic IDE generate a first-pass draft from the attack taxonomy already in `details_for_this_project` — but review every `symbolic_conditions` block yourself, since an incorrect condition silently breaks retrieval later with no visible error.
- [x] **Step 2.3.3:** Write 10–12 `BENIGN_SPIKE` rules describing traffic that looks anomalous but isn't (e.g. `delta_seq` small jump from a reconnect). These are what keep your Self-Inflicted DoS metric at 0% in the v1.0 benchmark.
- [x] **Step 2.3.4:** Validate every file is syntactically valid JSON and matches the schema:
  ```bash
  python3 -c "
  import json, glob, sys
  required = {'rule_id','attack_class','behavior_summary','symbolic_conditions','forbidden_actions','mandated_remediation','confidence_rating'}
  for f in glob.glob('data/raw_rules/*.json'):
      obj = json.load(open(f))
      missing = required - obj.keys()
      if missing:
          print(f'{f}: MISSING {missing}'); sys.exit(1)
  print('All rule files valid.')
  "
  ```
  Actual Output:
  ```
  All rule files valid.
  ```
- [x] **Step 2.3.5:** Confirm count ≥ 50:
  ```bash
  ls data/raw_rules/*.json | wc -l
  ```
  Actual Output:
  ```
  50
  ```

**Comparison Verdict:** [x] PASS / [ ] FAIL (loop back if count < 50 or any file fails schema validation)

---

## 3. Book 1: Static Reference Docs (`static_security_docs`)

**Who sources this: you, directly — not agent-generated.** This store exists to ground Agent 3's command syntax and Agent 1/2's technique references in real standards text. Hallucinated or paraphrased RFC/MITRE content here defeats the purpose of having a static ground-truth store at all.

### 3.1 Required Content & Sources

| Content | Where to get it | Save as |
|---|---|---|
| RFC 4301 (IPsec Security Architecture) | https://www.rfc-editor.org/rfc/rfc4301 — public domain, copy relevant sections | `data/raw_docs/rfc4301_ipsec_architecture.md` |
| RFC 4303 (ESP) | https://www.rfc-editor.org/rfc/rfc4303 | `data/raw_docs/rfc4303_esp.md` |
| MITRE ATT&CK T1557.002 (ARP Poisoning) | https://attack.mitre.org/techniques/T1557/002/ | `data/raw_docs/mitre_t1557_002_arp.md` |
| MITRE ATT&CK Blind TCP session hijacking (no exact ATT&CK sub-technique; see T1557 for the parent AiTM technique)| https://attack.mitre.org/techniques/T1563/002/ | `data/raw_docs/mitre_t1563_002_hijack.md` |
| MITRE ATT&CK T1557 Adversary-in-the-Middle | https://attack.mitre.org/techniques/T1556/ | `data/raw_docs/mitre_t1556_mitm.md` |
| MITRE D3FEND countermeasures (network isolation, traffic filtering) | https://d3fend.mitre.org/ | `data/raw_docs/d3fend_countermeasures.md` |
| `ip xfrm` command syntax | `man ip-xfrm` locally, or `man` page copy | `data/raw_docs/ip_xfrm_syntax.md` |
| `ebtables`/`arptables` syntax | `man ebtables`, `man arptables` | `data/raw_docs/ebtables_arptables_syntax.md` |

### 3.2 Execution Steps

- [x] **Step 3.2.1:** Pull each RFC/MITRE page above and extract only the sections relevant to this project (don't dump entire RFCs — focus on SA/SP parameters for 4301, ESP header/trailer format for 4303).
- [x] **Step 3.2.2:** Save `man` page output for `ip-xfrm`, `ebtables`, `arptables` verbatim — these need to be exactly correct since Agent 3 compiles commands from retrieved syntax:
  ```bash
  man ip-xfrm > data/raw_docs/ip_xfrm_syntax.md
  man ebtables > data/raw_docs/ebtables_syntax.md
  man arptables > data/raw_docs/arptables_syntax.md
  ```
- [x] **Step 3.2.3:** Chunk any file longer than ~1500 words into logical sub-sections (one file per sub-topic) — large monolithic files hurt retrieval precision in the `static_security_docs` query step.
- [x] **Step 3.2.4:** Confirm all 8 required files (or their chunked equivalents) are present:
  ```bash
  ls data/raw_docs/
  ```
  Actual Output:
  ```
  arptables_syntax.md
  d3fend_countermeasures.md
  ebtables_syntax.md
  ip_xfrm_syntax.md
  mitre_t1557_002_arp.md
  mitre_t1563_002_hijack.md
  rfc4301_ipsec_architecture.md
  rfc4303_esp.md
  ```

**Comparison Verdict:** [x] PASS / [ ] FAIL (loop back if any required source is missing)

---

## 4. Hand-Off to the Agentic IDE

Once Sections 2 and 3 both show PASS, give the coding agent this instruction (it covers the gap `ROADMAP.md` leaves open):

> "Read every JSON file in `data/raw_rules/` and insert each as a document into the ChromaDB `sera_ids_experiences` collection (per `src/memory/experience_store.py`'s schema), using `all-MiniLM-L6-v2` embeddings. Then create `src/memory/bootstrap_static_docs.py`: read every file in `data/raw_docs/`, chunk if needed, and embed into a new `static_security_docs` collection using the same embedding function. Run both and report collection counts via `collection.count()`."

### 4.1 Verification

```bash
python3 -c "
import chromadb
from chromadb.utils import embedding_functions
ef = embedding_functions.SentenceTransformerEmbeddingFunction(model_name='all-MiniLM-L6-v2')
client = chromadb.PersistentClient(path='./data/chromadb')
exp = client.get_collection('sera_ids_experiences', embedding_function=ef)
docs = client.get_collection('static_security_docs', embedding_function=ef)
print('sera_ids_experiences count:', exp.count())
print('static_security_docs count:', docs.count())
"
```

Expected: `sera_ids_experiences count: 50` (or more), `static_security_docs count: 8` (or more, if chunked).

Actual Output:
```
sera_ids_experiences count: 50
static_security_docs count: 42
```

**Comparison Verdict:** [x] PASS / [ ] FAIL (loop back to Section 2 or 3 if either count is 0 or implausibly low)

---

## 5. Only After This: Resume `ROADMAP.md`

Once Section 4's verification passes, proceed to `ROADMAP.md` → Version 0.5 → Step 2 (`experience_store.py`) through Step 4 (`bootstrap_rules.py` — note: at this point it's reading pre-sourced content, not inventing it), then continue into Test 2.1–2.3 as written.
