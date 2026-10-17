# AGENTS.md: Instructions for Coding Agents Working on AegisNet-AI

This file tells coding agents (Claude Code, Copilot, Cursor, or similar) how to work in this repository. Read it fully before making any change. For the phased build plan, see `ROADMAP.md`. For the research background and architecture, see the project details document.

---

## 1. Project Summary

AegisNet-AI is an autonomous, containerized cyber-range for detecting and remediating Layer-2 and Layer-4 Man-in-the-Middle attacks. It has four parts:

1. **Deterministic packet sensor** (`src/sensor/`): Scapy-based sniffer that computes ARP binding deviation (Δ_ARP), TCP sequence drift (Δ_SEQ), duplicate ACK counts, and Shannon entropy. It uses zero LLM tokens.
2. **Dual-memory knowledge layer** (`src/memory/`): NetworkX topology graph with gateway protection rules, plus a ChromaDB experience store implementing SERA-IDS class-diverse retrieval (P=20 → K=5) and symbolic condition checks V(x, R_k).
3. **Multi-agent reasoning** (`src/agents/`): LangGraph pipeline with three agents (Threat Triage → Policy Synthesizer → Command Compiler). It outputs strict JSON only. Provider fallback order is Groq → Gemini, both free-tier cloud APIs.
4. **Verified enforcement** (`src/enforcer/`): Applies ebtables and arptables MAC isolation, static ARP entries, and Linux XFRM IPsec ESP (AES-256-GCM) transport SAs and policies. A 500 ms health probe rolls back on failure.

A SOC dashboard (`src/ui/`) and a benchmark harness (`tests/benchmark_suite.py`) complete the project.

---

## 2. Non-Negotiable Safety Rules

These rules apply everywhere in the code, tests, and configs. Do not relax them, even if a task seems to require it.

- **Never execute offensive scripts outside the lab.** Scripts in `attacks/` may only target the containers defined in `docker-compose.yml` (172.28.0.0/24). Never add targets, interfaces, or IP ranges outside that subnet.
- **Never block a gateway or protected host.** Any remediation that drops traffic must pass `check_gateway_protection()`. Hosts with `can_block_ip == False` (gateway and server) must never receive an IP-level drop rule.
- **Never block the victim's IP.** Isolation must target the attacker's hardware (MAC) address, not the spoofed IP. Blocking by IP causes a self-inflicted DoS, which is the main failure mode this project exists to prevent.
- **Never emit or execute forbidden commands.** Blacklist at minimum: `iptables -F`, `iptables -P ... DROP` on the default chain, `ebtables -F` outside the rollback path, `ip xfrm` flushes outside the rollback path, and any `rm -rf`, `curl | sh`, or shell metacharacter injection from LLM output.
- **LLM output is untrusted.** Every policy from Agent 3 must pass JSON Schema validation (`AegisNetDefensePolicy-v1`) before reaching the enforcer. Build shell commands from validated fields only. Never pass raw LLM strings to a shell.
- **Validate key material.** AES-256-GCM keys must be exactly 32 bytes (64 hex characters), plus a 4-byte salt where the schema requires it. Reject anything else.
- **Rollback must be atomic and tested.** Any enforcement path must have a matching rollback. The rollback must complete within 1 second of a health-check failure.
- **No secrets in the repository.** API keys live in `.env`, which is git-ignored. Never hardcode `GROQ_API_KEY`, `GEMINI_API_KEY`, or any token. Provide `.env.example` with placeholder values only.

---

## 3. Execution Protocol (Mandatory)

Follow this loop for every task and every roadmap step:

1. **Implement** the smallest change that satisfies the step.
2. **Execute** the verification command given in the roadmap for that step.
3. **Capture** stdout, stderr, and the exit code.
4. **Compare** the result against the roadmap's Expected Output.
5. **Record** the actual output in the roadmap's Actual Output block.
6. **Evaluate:**
   - On a match, mark the checkbox `[x]` and move on.
   - On a divergence, do not advance. Inspect logs, fix the implementation, and return to step 2.

Rules that follow from this protocol:

- Never mark a task complete without running its verification command.
- Never fabricate Actual Output. If a command cannot run, record the real error and stop.
- Never modify an Expected Output to make a test pass. If the expectation itself looks wrong, flag it to the user and explain why.
- Never mark a version complete until every test in that version passes.

---

## 4. Repository Layout

```
aegisnet-ai/
├── AGENTS.md
├── ROADMAP.md
├── README.md
├── .env.example
├── .gitignore
├── docker-compose.yml
├── docker/
│   ├── client/Dockerfile
│   ├── server/Dockerfile
│   ├── attacker/Dockerfile
│   └── defender/Dockerfile
├── attacks/
│   ├── arp_spoof.py
│   └── tcp_desync.py
├── src/
│   ├── workload/          # server_app.py, client_workload.py
│   ├── sensor/            # packet_engine.py
│   ├── memory/            # network_graph.py, experience_store.py, diverse_ranker.py, bootstrap_rules.py
│   ├── agents/            # orchestrator.py, validator.py
│   ├── enforcer/          # kernel_xfrm.py, verifier.py
│   └── ui/                # dashboard.py
├── schemas/
│   ├── AegisNetAnomalyAlert-v1.json
│   └── AegisNetDefensePolicy-v1.json
├── tests/
│   ├── test_packet_engine.py
│   ├── test_network_graph.py
│   ├── test_experience_store.py
│   ├── test_orchestrator.py
│   ├── test_verifier.py
│   ├── test_integration_e2e.py
│   └── benchmark_suite.py
├── docs/
│   └── VIVA_DEMO_SCRIPT.md
└── data/
    ├── chromadb/          # git-ignored
    └── topology_graph.json
```

Create the tree with: `mkdir -p src/{sensor,memory,agents,enforcer,workload,ui} attacks data/chromadb tests`

Place new code only in the directories above. Do not create new top-level directories without asking.

---

## 5. Environment and Runtime

- **Host:** Windows 10/11 with WSL2 (Ubuntu 24.04, kernel 5.15+ or 6.6+).
- **Containers:** Docker Desktop with the WSL2 backend.
- **Python:** 3.11.x. Use a virtual environment for local work.
- **Kernel features:** Netlink XFRM, `ebtables`, `arptables`, `iptables`, `iproute2`. Packet capture and kernel changes need `NET_ADMIN` and `NET_RAW`, which the defender and attacker containers receive through `cap_add`.
- **Sniffing interface:** `eth0`, configurable through `AEGIS_INTERFACE`.
- **Dependencies:** pinned minimum versions in `requirements.txt` (scapy, pyroute2, networkx, chromadb, sentence-transformers, langgraph, groq, jsonschema, streamlit, pytest, and others). Install with `pip install -r requirements.txt`.

Environment variables (see `.env.example`):

```bash
GROQ_API_KEY=
GEMINI_API_KEY=
CHROMA_PERSIST_DIR=./data/chromadb
TOPOLOGY_CONFIG_PATH=./data/topology_graph.json
AEGIS_INTERFACE=eth0
```

---

## 6. Coding Standards

- **Language:** Python 3.11+. Use type hints on all public functions and `TypedDict` or Pydantic models for structured data.
- **Packet and kernel code:** Keep parsing and state logic pure and testable. Isolate side effects (netlink calls, subprocess calls, sniffing loops) behind small functions so unit tests can mock them.
- **Subprocess calls:** Use argument lists, never `shell=True` with interpolated strings. Validate every IP, MAC, SPI, and key before use.
- **Schemas first:** Define or update the JSON Schema before writing code that produces or consumes the data.
- **Logging:** Use the `logging` module. Log alerts and enforcement actions to `./logs/`. Never log API keys or key material. Redact `key_hex` in every log line.
- **Tests:** Each module gets a matching test file. Unit tests must not require root, Docker, or an LLM API. Mark kernel and container tests with `@pytest.mark.integration` so they can be run separately.
- **Token discipline:** The sensor must never call an LLM. LLM calls happen only after a validated anomaly. Keep prompts under roughly 350 tokens of structured JSON input.
- **Determinism:** Set `temperature=0` for the command compiler. Agents must return JSON only, with no conversational text.

---

## 7. Common Commands

```bash
# Bring up the cyber-range
docker compose up -d

# Connectivity baseline
docker exec victim-client ping -c 3 172.28.0.20

# Unit tests (no root, no Docker, no API calls)
pytest tests/ -v -m "not integration"

# Integration tests (requires running containers and root in the defender)
pytest tests/test_integration_e2e.py -s

# Benchmark (small run)
python3 tests/benchmark_suite.py --trials 20

# Dashboard
streamlit run src/ui/dashboard.py   # http://localhost:8501

# Tear down
docker compose down
```

---

## 8. Known Discrepancies to Resolve

The source documents disagree in a few places. Do not guess. Raise each one with the user before implementing the affected code, and record the agreed resolution here.

1. **Defender networking:** The project details specify `network_mode: "service:target-server"` for `blue-ai-defender`. The roadmap specifies its own bridge address (172.28.0.2). Choose one and update both documents.
2. **Policy schema field names:** The project details use `static_arp_bindings` and `ipsec_enforcement.key_hex`. The roadmap's Test 3.1 and Test 3.2 use `static_arp_fixes`, `ip_address`, `mac_address`, `ipsec_configuration`, and `key_material_hex`. The schema file is the source of truth, so align the tests to it.
3. **Attacker MAC in the roadmap:** Test 1.2 expects the attacker MAC as `02:42:ac:1c:00:42`, and the expected server MAC as `02:42:ac:1c:00:14`. Confirm these match the MACs assigned in `docker-compose.yml`.
4. **Benchmark trial counts:** The roadmap runs 100 trials per attack class (300 total). Test 4.2 uses `--trials 20` as a quick run. Confirm which count is used for the final evaluation tables.
5. **SPI values:** The project details use `0x1001` and `0x1002` in the `ip xfrm` examples. The roadmap test config uses decimal `4097` and `4098`, which are the same values. Keep one format in the code and document it.
6. **Entropy alert threshold:** The project details use a 40% jump for UDP entropy. The roadmap does not state a threshold. Define it in `src/sensor/packet_engine.py` and document it here.

---

## 9. Definition of Done

A task is done only when all of the following are true:

- The code implements the roadmap step.
- The step's verification command ran, and its output matches the Expected Output.
- Actual Output is recorded in `ROADMAP.md`.
- No forbidden command or unvalidated LLM output reaches the kernel path.
- Unit tests pass without root or API access.
- No secrets are committed.

A version is done only when every test in that version passes and its checkbox in `ROADMAP.md` is ticked.

---

## 10. What Not to Do

- Do not replace the deterministic sensor with LLM-based packet inspection.
- Do not let an LLM write to the shell, the kernel, or any file outside `./logs/` and `./data/`.
- Do not add a new dependency without checking that it is open source and free to run locally.
- Do not expand scope beyond the roadmap without asking.
- Do not silently change tests, schemas, or expected outputs to make failures disappear.
