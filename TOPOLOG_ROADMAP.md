# AegisNet-AI: Topology Demo Page — Addendum Roadmap

---

## 0. Context & Scope

- This roadmap covers **one additive feature only**: a standalone Streamlit page (`pages/1_Topology.py`) that visualizes the 4 containers (`victim-client`, `target-server`, `red-attacker`, `blue-ai-defender`) with live state-change simulation, for use in the upcoming project presentation.
- The main `ROADMAP.md` (v0.1 → v1.0) is treated as **already complete** per current project status. This addendum does not re-verify or re-run any of that work.
- **Non-negotiable constraint:** this feature must not alter, import from, or share state with any existing backend module, sensor, agent pipeline, or dashboard page. It is a net-new file with its own isolated `st.session_state` namespace.
- This addendum maps to, and partially fulfills ahead of schedule, the **v1.0 "Interactive SOC Dashboard → Topology Canvas"** deliverable already defined in `ROADMAP.md`.
- **Rule of Execution (inherited from `ROADMAP.md` §3):** the agent must not skip steps, assume implicit success, or check a box without running the verification command, capturing real output, and comparing it against Expected Output.

---

## 1. Pre-Flight: Non-Interference Check

- [ ] **Step 1.1:** Confirm the location of the existing Streamlit entrypoint and `pages/` directory (or confirm one needs to be created).

Command:
```bash
find . -iname "*.py" -path "*streamlit*" -o -iname "dashboard.py" 2>/dev/null
ls pages/ 2>/dev/null || echo "no pages/ directory yet"
```

Expected Output:
```
<path to existing dashboard entrypoint found>
<existing pages/ directory listed, OR "no pages/ directory yet">
```

Actual Output:
```
[Agent must run command and paste raw terminal output here]
```

Comparison Verdict: [ ] PASS / [ ] FAIL (Loop back if entrypoint cannot be located — confirm with user before proceeding)

- [ ] **Step 1.2:** Confirm the new file does not import, read, or write anything from existing backend modules (`src/sensor`, `src/memory`, `src/agents`, `src/enforcer`).

Command:
```bash
grep -E "^(from src|import src)" pages/1_Topology.py || echo "CLEAN: no backend imports"
```

Expected Output:
```
CLEAN: no backend imports
```

Actual Output:
```
[Agent must run command and paste raw terminal output here]
```

Comparison Verdict: [ ] PASS / [ ] FAIL (Loop back if any backend import is found — remove it, this page must stay standalone)

---

## 2. Placement & Launch

- [ ] **Step 2.1:** Copy `1_Topology.py` into the `pages/` directory alongside the existing dashboard page(s).

Command:
```bash
cp 1_Topology.py pages/1_Topology.py
ls pages/
```

Expected Output:
```
1_Topology.py
<any pre-existing page files, unchanged>
```

Actual Output:
```
[Agent must run command and paste raw terminal output here]
```

Comparison Verdict: [ ] PASS / [ ] FAIL (Loop back if any existing page file is missing or overwritten)

- [ ] **Step 2.2:** Launch the Streamlit app and confirm it starts without error.

Command:
```bash
streamlit run <your_main_entrypoint>.py --server.headless true &
sleep 3
curl -s -o /dev/null -w "%{http_code}" http://localhost:8501
```

Expected Output:
```
200
```

Actual Output:
```
[Agent must run command and paste raw terminal output here]
```

Comparison Verdict: [ ] PASS / [ ] FAIL (Loop back if non-200 or startup error is thrown)

- [ ] **Step 2.3:** Confirm the new page appears in the sidebar navigation alongside existing pages (manual visual check, screenshot or description required).

Expected Output:
```
Sidebar lists: [existing page(s)] + "Topology"
```

Actual Output:
```
[Agent must describe/paste what the sidebar shows here]
```

Comparison Verdict: [ ] PASS / [ ] FAIL (Loop back if the new page does not appear, or if any existing page disappears)

---

## 3. Diagram Rendering

- [ ] **Step 3.1:** Open the Topology page and confirm all 4 nodes render with correct labels and IPs.

Expected Output:
```
Nodes visible: victim-client (172.28.0.10), target-server (172.28.0.20),
red-attacker, blue-ai-defender (172.28.0.2)
Default state: "🟢 Normal Operation"
```

Actual Output:
```
[Agent must paste/describe what rendered here]
```

Comparison Verdict: [ ] PASS / [ ] FAIL (Loop back if any node/label is missing or mislabeled)

---

## 4. Demo Controls — State Transitions

- [ ] **Step 4.1:** Click "Simulate ARP Attack" and confirm diagram + status text update.

Expected Output:
```
Status: "🔴 ARP Spoofing Detected"
Client/server/attacker nodes and link turn red
MTTD metric populates (e.g. 180 ms)
```

Actual Output:
```
[Agent must paste/describe what changed here]
```

Comparison Verdict: [ ] PASS / [ ] FAIL (Loop back if state does not visibly change)

- [ ] **Step 4.2:** Click "Simulate TCP Hijack" and confirm diagram + status text update.

Expected Output:
```
Status: "🔴 TCP Session Hijack Detected"
Same red-state visual treatment as ARP attack
MTTD metric populates (e.g. 190 ms)
```

Actual Output:
```
[Agent must paste/describe what changed here]
```

Comparison Verdict: [ ] PASS / [ ] FAIL (Loop back if state does not visibly change)

- [ ] **Step 4.3:** Click "Trigger Defense (IPsec)" and confirm diagram + status text + metrics update.

Expected Output:
```
Brief spinner ("Synthesizing policy → enforcing kernel rules → verifying health...")
Status: "🔵 IPsec ESP Tunnel Active"
Client/server nodes and link turn blue, attacker node greys out
MTTR metric populates (e.g. 1.42 s)
"Attacker Packets Post-Defense" shows 0
```

Actual Output:
```
[Agent must paste/describe what changed here]
```

Comparison Verdict: [ ] PASS / [ ] FAIL (Loop back if any metric fails to populate or diagram doesn't reflect defended state)

- [ ] **Step 4.4:** Click "Reset to Normal" and confirm full return to baseline state.

Expected Output:
```
Status: "🟢 Normal Operation"
All nodes/links green, MTTD/MTTR metrics clear back to "—"
```

Actual Output:
```
[Agent must paste/describe what changed here]
```

Comparison Verdict: [ ] PASS / [ ] FAIL (Loop back if any value persists from the prior state)

---

## 5. Regression Check — Existing App Untouched

- [ ] **Step 5.1:** Navigate back to the pre-existing dashboard page(s) and confirm they render exactly as they did before this addendum.

Expected Output:
```
Existing dashboard page loads identically to pre-addendum behavior
No shared session_state keys collide (no unexpected values bleeding across pages)
```

Actual Output:
```
[Agent must paste/describe what rendered here]
```

Comparison Verdict: [ ] PASS / [ ] FAIL (Loop back if any existing page's behavior changed)

- [ ] **Step 5.2:** Confirm no backend process (sensor, agent orchestrator, enforcer) was started, stopped, or modified by adding this page.

Command:
```bash
git status --porcelain | grep -v "pages/1_Topology.py"
```

Expected Output:
```
<empty — no other files modified>
```

Actual Output:
```
[Agent must run command and paste raw terminal output here]
```

Comparison Verdict: [ ] PASS / [ ] FAIL (Loop back if any file outside this addendum shows as modified)

---

## 6. Presentation Readiness

- [ ] **Step 6.1:** Full dry-run of the live demo sequence to be used in the presentation.

Sequence:
```
Reset to Normal → Simulate ARP Attack → Trigger Defense (IPsec) → Reset to Normal
```

Expected Output:
```
Full sequence completes in under ~20 seconds with no errors, console warnings,
or visual glitches at any transition
```

Actual Output:
```
[Agent must paste/describe the dry-run result here]
```

Comparison Verdict: [ ] PASS / [ ] FAIL (Loop back if any transition errors or lags noticeably)

---

## 7. Master Checklist (Addendum Complete When All Checked)

- [ ] Pre-flight non-interference confirmed (no backend imports, existing files untouched).
- [ ] Page placed in `pages/` and app launches cleanly (HTTP 200).
- [ ] New page appears in sidebar nav without disrupting existing pages.
- [ ] All 4 nodes render correctly with correct labels/IPs in default state.
- [ ] ARP attack simulation visually and numerically correct.
- [ ] TCP hijack simulation visually and numerically correct.
- [ ] Defense trigger (IPsec) simulation visually and numerically correct.
- [ ] Reset returns to clean baseline state.
- [ ] Existing dashboard page(s) confirmed unaffected (regression pass).
- [ ] Full presentation dry-run sequence completes cleanly.

---

## 8. Explicitly Out of Scope (Do Not Attempt Before Presentation)

- Wiring this page to real sensor/agent output (see `HOOK POINT` comment in the file itself) — this is future work, not required for the current deadline.
- Any modification to `src/sensor`, `src/memory`, `src/agents`, `src/enforcer`, or the main `ROADMAP.md` test suite.
- Any change to existing dashboard pages beyond their presence in the sidebar nav list.
