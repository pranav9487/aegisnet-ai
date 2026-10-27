"""src/ui/dashboard.py
--------------------
AegisNet-AI Real-Time SOC Dashboard (Version 1.0, Step 1).

Components:
  1. Topology Canvas      - interactive Plotly graph of the 5-node cyber-range.
  2. delta_SEQ Stream     - live Plotly dual-axis chart (TCP drift + Shannon entropy).
  3. Agent Thought Stream - scrolling log of LangGraph agent trace events.
  4. MTTD/MTTR/Cost Scorecard - KPI tiles updated on each detected attack.

Run with:
    streamlit run src/ui/dashboard.py   # http://localhost:8501

All data is read from live log files / shared state; no LLM calls originate here.
"""

from __future__ import annotations

import json
import os
import random
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import networkx as nx
import pandas as pd
import plotly.graph_objects as go
import streamlit as st

# ---------------------------------------------------------------------------
# Page configuration (MUST be first Streamlit call)
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="AegisNet-AI - SOC Dashboard",
    page_icon="shield",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Constants / paths
# ---------------------------------------------------------------------------
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
TOPOLOGY_PATH = _REPO_ROOT / "data" / "topology_graph.json"
ALERT_LOG_PATH = Path("/tmp/sensor_alerts.log")

# ---------------------------------------------------------------------------
# CSS - dark premium theme
# ---------------------------------------------------------------------------
CUSTOM_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

:root {
    --bg-primary:    #0a0e1a;
    --bg-card:       #111827;
    --bg-card2:      #1a2235;
    --accent-blue:   #3b82f6;
    --accent-cyan:   #06b6d4;
    --accent-green:  #10b981;
    --accent-red:    #ef4444;
    --accent-amber:  #f59e0b;
    --accent-purple: #8b5cf6;
    --text-primary:  #f1f5f9;
    --text-muted:    #64748b;
    --border:        #1e293b;
}

html, body, [data-testid="stAppViewContainer"] {
    background-color: var(--bg-primary) !important;
    font-family: 'Inter', sans-serif;
    color: var(--text-primary);
}

[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #0f172a 0%, #1e1b4b 100%) !important;
    border-right: 1px solid var(--border);
}

[data-testid="stSidebar"] * { color: var(--text-primary) !important; }

.block-container { padding: 1rem 2rem !important; max-width: 100% !important; }

.kpi-card {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 1.25rem 1.5rem;
    text-align: center;
    transition: transform 0.2s ease, box-shadow 0.2s ease;
    position: relative;
    overflow: hidden;
}
.kpi-card::before {
    content: '';
    position: absolute;
    inset: 0;
    border-radius: 12px;
    opacity: 0.08;
    background: linear-gradient(135deg, var(--accent-blue), transparent);
}
.kpi-card:hover { transform: translateY(-2px); box-shadow: 0 0 20px rgba(59,130,246,0.3); }

.kpi-value {
    font-size: 2rem;
    font-weight: 700;
    letter-spacing: -0.02em;
    line-height: 1;
    margin-bottom: 0.25rem;
}
.kpi-label {
    font-size: 0.75rem;
    font-weight: 500;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--text-muted);
}
.kpi-green  { color: var(--accent-green); }
.kpi-blue   { color: var(--accent-blue); }
.kpi-amber  { color: var(--accent-amber); }
.kpi-red    { color: var(--accent-red); }
.kpi-purple { color: var(--accent-purple); }

.section-header {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.85rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    color: var(--text-muted);
    margin-bottom: 0.75rem;
    border-bottom: 1px solid var(--border);
    padding-bottom: 0.5rem;
}

.thought-log {
    background: #050810;
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 0.75rem 1rem;
    height: 280px;
    overflow-y: auto;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.72rem;
    line-height: 1.6;
}
.log-agent1   { color: var(--accent-cyan); }
.log-agent2   { color: var(--accent-purple); }
.log-agent3   { color: var(--accent-blue); }
.log-enforcer { color: var(--accent-green); }
.log-sensor   { color: var(--accent-amber); }
.log-alert    { color: var(--accent-red); font-weight: 600; }
.log-ts       { color: var(--text-muted); }

.status-badge {
    display: inline-block;
    padding: 0.15rem 0.55rem;
    border-radius: 9999px;
    font-size: 0.65rem;
    font-weight: 700;
    letter-spacing: 0.06em;
    text-transform: uppercase;
}
.badge-green { background: rgba(16,185,129,0.15); color: var(--accent-green); border: 1px solid rgba(16,185,129,0.3); }
.badge-red   { background: rgba(239,68,68,0.15);  color: var(--accent-red);   border: 1px solid rgba(239,68,68,0.3); }
.badge-amber { background: rgba(245,158,11,0.15); color: var(--accent-amber); border: 1px solid rgba(245,158,11,0.3); }

#MainMenu, footer, header { visibility: hidden; }
</style>
"""

st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Session-state init
# ---------------------------------------------------------------------------
def _init_state() -> None:
    defaults: Dict[str, Any] = {
        "seq_times":          deque(maxlen=120),
        "seq_values":         deque(maxlen=120),
        "entropy_values":     deque(maxlen=120),
        "alerts":             [],
        "agent_log":          deque(maxlen=200),
        "mttd_ms":            None,
        "mttr_ms":            None,
        "total_alerts":       0,
        "total_remediations": 0,
        "last_attack_class":  "—",
        "defense_status":     "MONITORING",
        "api_calls_used":     0,
        "_last_alert_pos":    0,
        "_tick":              0,
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v

_init_state()

# ---------------------------------------------------------------------------
# Topology loading
# ---------------------------------------------------------------------------
@st.cache_data(ttl=60)
def load_topology() -> Dict[str, Any]:
    if TOPOLOGY_PATH.exists():
        with open(TOPOLOGY_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    return {
        "nodes": [
            {"id": "172.28.0.1",  "hostname": "aegisnet-gateway", "role": "GATEWAY",   "mac": "02:42:ac:1c:00:01", "can_block_ip": False},
            {"id": "172.28.0.10", "hostname": "victim-client",    "role": "CLIENT",    "mac": "02:42:ac:1c:00:0a", "can_block_ip": False},
            {"id": "172.28.0.20", "hostname": "target-server",    "role": "SERVER",    "mac": "02:42:ac:1c:00:14", "can_block_ip": False},
            {"id": "172.28.0.2",  "hostname": "blue-ai-defender", "role": "DEFENDER",  "mac": "02:42:ac:1c:00:02", "can_block_ip": False},
            {"id": "172.28.0.66", "hostname": "red-attacker",     "role": "UNTRUSTED", "mac": "02:42:ac:1c:00:42", "can_block_ip": True},
        ],
        "edges": [
            {"src": "172.28.0.10", "dst": "172.28.0.20", "label": "http-workload"},
            {"src": "172.28.0.10", "dst": "172.28.0.20", "label": "udp-heartbeat"},
            {"src": "172.28.0.66", "dst": "172.28.0.20", "label": "attack-path"},
            {"src": "172.28.0.2",  "dst": "172.28.0.10", "label": "monitor"},
            {"src": "172.28.0.2",  "dst": "172.28.0.20", "label": "monitor"},
            {"src": "172.28.0.2",  "dst": "172.28.0.66", "label": "enforce"},
        ],
    }

# ---------------------------------------------------------------------------
# Topology figure builder
# ---------------------------------------------------------------------------
_ROLE_COLOR = {"GATEWAY": "#f59e0b", "CLIENT": "#3b82f6", "SERVER": "#10b981",
               "DEFENDER": "#8b5cf6", "UNTRUSTED": "#ef4444"}
_ROLE_SYMBOL = {"GATEWAY": "diamond", "CLIENT": "circle", "SERVER": "square",
                "DEFENDER": "star", "UNTRUSTED": "x"}
_EDGE_COLOR = {"http-workload": "#3b82f6", "udp-heartbeat": "#06b6d4",
               "attack-path": "#ef4444", "monitor": "#8b5cf6", "enforce": "#10b981"}

_POS: Dict[str, tuple] = {
    "172.28.0.1":  (0.5,  1.0),
    "172.28.0.10": (0.0,  0.5),
    "172.28.0.20": (1.0,  0.5),
    "172.28.0.2":  (0.5,  0.0),
    "172.28.0.66": (0.85, 0.15),
}


def build_topology_figure(topo: Dict[str, Any], active_alert: Optional[Dict[str, Any]] = None) -> go.Figure:
    nodes_data = topo.get("nodes", [])
    edges_data = topo.get("edges", [])

    edge_traces = []
    for e in edges_data:
        src, dst, label = e["src"], e["dst"], e.get("label", "")
        x0, y0 = _POS.get(src, (0.5, 0.5))
        x1, y1 = _POS.get(dst, (0.5, 0.5))
        color = _EDGE_COLOR.get(label, "#334155")
        width = 3 if label == "attack-path" else 1.5
        dash  = "dot" if label in ("monitor", "enforce") else "solid"
        edge_traces.append(go.Scatter(
            x=[x0, x1, None], y=[y0, y1, None],
            mode="lines",
            line=dict(width=width, color=color, dash=dash),
            hoverinfo="skip", showlegend=False,
        ))

    node_x, node_y, node_text, node_hover = [], [], [], []
    node_colors, node_sizes, node_symbols = [], [], []
    node_line_widths, node_line_colors = [], []
    attacker_ip = "172.28.0.66"
    for n in nodes_data:
        nid  = n["id"]
        x, y = _POS.get(nid, (0.5, 0.5))
        role = n.get("role", "")
        color = _ROLE_COLOR.get(role, "#64748b")
        is_att = nid == attacker_ip
        if is_att and active_alert:
            color = "#ff2020"
        node_x.append(x); node_y.append(y)
        node_colors.append(color)
        node_sizes.append(28 if is_att and active_alert else 22)
        node_symbols.append(_ROLE_SYMBOL.get(role, "circle"))
        node_line_widths.append(3 if is_att and active_alert else 1.5)
        node_line_colors.append("#ffffff")
        node_text.append(f"<b>{n.get('hostname', nid)}</b><br>{nid}<br>{n.get('mac','')}")
        node_hover.append(f"{n.get('hostname',nid)} [{role}]<br>IP: {nid}<br>MAC: {n.get('mac','')}")

    node_trace = go.Scatter(
        x=node_x, y=node_y, mode="markers+text",
        marker=dict(
            size=node_sizes,
            color=node_colors,
            symbol=node_symbols,
            line=dict(width=node_line_widths, color=node_line_colors),
            opacity=0.95,
        ),
        text=node_text,
        textposition="top center",
        textfont=dict(size=9, color="#cbd5e1", family="Inter"),
        hovertext=node_hover, hoverinfo="text", showlegend=False,
    )

    legend_traces = [
        go.Scatter(x=[None], y=[None], mode="markers",
                   marker=dict(size=10, color=_ROLE_COLOR[r], symbol=_ROLE_SYMBOL[r]),
                   name=r, showlegend=True)
        for r in ["GATEWAY", "CLIENT", "SERVER", "DEFENDER", "UNTRUSTED"]
    ]

    fig = go.Figure(data=edge_traces + [node_trace] + legend_traces)
    fig.update_layout(
        paper_bgcolor="#0a0e1a", plot_bgcolor="#0a0e1a",
        margin=dict(l=10, r=10, t=10, b=10), height=300,
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False, range=[-0.15, 1.15]),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False, range=[-0.15, 1.15]),
        legend=dict(font=dict(size=10, color="#cbd5e1"), bgcolor="rgba(10,14,26,0.8)",
                    bordercolor="#1e293b", borderwidth=1, x=1.01, y=1),
        hoverlabel=dict(bgcolor="#1a2235", bordercolor="#334155", font_size=11, font_family="Inter"),
    )
    return fig

# ---------------------------------------------------------------------------
# Alert log reader
# ---------------------------------------------------------------------------
def read_new_alerts() -> List[Dict[str, Any]]:
    new_alerts: List[Dict[str, Any]] = []
    if not ALERT_LOG_PATH.exists():
        return new_alerts
    try:
        with open(ALERT_LOG_PATH, "rb") as f:
            f.seek(st.session_state["_last_alert_pos"])
            raw = f.read()
            st.session_state["_last_alert_pos"] = f.tell()
        for line in raw.decode("utf-8", errors="replace").splitlines():
            line = line.strip()
            if line:
                try:
                    new_alerts.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    except OSError:
        pass
    return new_alerts

# ---------------------------------------------------------------------------
# Demo / synthetic data
# ---------------------------------------------------------------------------
_DEMO_EVENTS = [
    ("sensor",   "delta_ARP binding deviation detected on eth0"),
    ("alert",    "ALERT-ARP triggered | Δ_ARP=1 | observed_mac=02:42:ac:1c:00:42"),
    ("agent1",   "[Threat Triage] Resolved attacker MAC: 02:42:ac:1c:00:42 | confidence=0.96"),
    ("agent2",   "[Policy Synthesizer] Strategy: MAC isolation + IPsec ESP AES-256-GCM"),
    ("agent3",   "[Command Compiler] POL-ARPITM-a3f7c901 compiled — schema VALID"),
    ("enforcer", "ebtables MAC drop rule applied for 02:42:ac:1c:00:42"),
    ("enforcer", "ip xfrm SA established SPI 0x1001 / 0x1002 (AES-GCM-256)"),
    ("enforcer", "500ms health probe: HTTP 200 OK from victim-client to target-server"),
]
_ATTACK_CLASSES = ["ARP_POISON_MITM", "TCP_SESSION_HIJACK", "BENIGN_SPIKE"]


def _inject_demo_tick() -> None:
    tick = st.session_state["_tick"]
    st.session_state["_tick"] = tick + 1
    ts = datetime.now(tz=timezone.utc).strftime("%H:%M:%S.%f")[:-3]
    st.session_state["seq_times"].append(ts)

    period = tick % 35
    if period in range(8, 13):
        val = random.uniform(3500, 10000)
        st.session_state["defense_status"] = "ACTIVE"
    elif period in (13, 14):
        val = random.uniform(100, 500)
        st.session_state["defense_status"] = "REMEDIATED"
        if period == 13:
            mttd = round(random.uniform(140, 195), 1)
            mttr = round(random.uniform(950, 2100), 1)
            st.session_state["mttd_ms"] = mttd
            st.session_state["mttr_ms"] = mttr
            st.session_state["total_alerts"] += 1
            st.session_state["total_remediations"] += 1
            st.session_state["last_attack_class"] = random.choice(_ATTACK_CLASSES)
            st.session_state["api_calls_used"] += random.randint(2, 4)
    elif period > 16:
        val = max(0, 120 + random.gauss(0, 30))
        st.session_state["defense_status"] = "MONITORING"
        st.session_state["mttd_ms"] = None
        st.session_state["mttr_ms"] = None
    else:
        val = max(0, 120 + random.gauss(0, 30))

    st.session_state["seq_values"].append(val)
    ent = round(random.uniform(1.8, 7.2) if val > 1000 else random.uniform(3.2, 4.8), 2)
    st.session_state["entropy_values"].append(ent)

    if tick % 6 == 0 and st.session_state["defense_status"] != "MONITORING":
        idx = (tick // 6) % len(_DEMO_EVENTS)
        kind, msg = _DEMO_EVENTS[idx]
        st.session_state["agent_log"].append((ts, kind, msg))
    elif tick % 20 == 0:
        st.session_state["agent_log"].append((ts, "sensor", f"Normal traffic — samples={len(st.session_state['seq_values'])}"))

# ---------------------------------------------------------------------------
# delta_SEQ chart
# ---------------------------------------------------------------------------
def build_seq_chart() -> go.Figure:
    times  = list(st.session_state["seq_times"])
    values = list(st.session_state["seq_values"])
    entrop = list(st.session_state["entropy_values"])
    if not times:
        times, values, entrop = ["—"], [0], [0]

    fig = go.Figure()
    peak = max(max(values) * 1.05, 2000)
    fig.add_hrect(y0=1460, y1=peak, fillcolor="rgba(239,68,68,0.06)", line_width=0)
    fig.add_hline(y=1460, line=dict(color="#ef4444", width=1, dash="dash"),
                  annotation_text="SEQ threshold (1460 B)",
                  annotation_font=dict(size=9, color="#ef4444"),
                  annotation_position="top left")
    fig.add_trace(go.Scatter(
        x=times, y=values, mode="lines", name="delta_SEQ (bytes)",
        line=dict(color="#3b82f6", width=2),
        fill="tozeroy", fillcolor="rgba(59,130,246,0.08)",
    ))
    fig.add_trace(go.Scatter(
        x=times, y=entrop, mode="lines", name="Shannon H(X) bits",
        line=dict(color="#8b5cf6", width=1.5, dash="dot"),
        yaxis="y2",
    ))
    fig.update_layout(
        paper_bgcolor="#0a0e1a", plot_bgcolor="#111827",
        margin=dict(l=50, r=50, t=15, b=30), height=220,
        xaxis=dict(showgrid=False, zeroline=False, tickfont=dict(size=9, color="#64748b"), nticks=10),
        yaxis=dict(title=dict(text="delta_SEQ (bytes)", font=dict(size=10, color="#3b82f6")),
                   showgrid=True, gridcolor="#1e293b", zeroline=False,
                   tickfont=dict(size=9, color="#64748b")),
        yaxis2=dict(title=dict(text="H(X) bits", font=dict(size=10, color="#8b5cf6")),
                    overlaying="y", side="right", showgrid=False, zeroline=False,
                    range=[0, 8], tickfont=dict(size=9, color="#8b5cf6")),
        legend=dict(font=dict(size=10, color="#cbd5e1"), bgcolor="rgba(10,14,26,0.8)",
                    bordercolor="#1e293b", borderwidth=1, x=0.01, y=0.99),
        hoverlabel=dict(bgcolor="#1a2235", bordercolor="#334155", font_size=11),
    )
    return fig

# ---------------------------------------------------------------------------
# Agent thought-stream
# ---------------------------------------------------------------------------
_LOG_CLASS  = {"agent1": "log-agent1", "agent2": "log-agent2", "agent3": "log-agent3",
               "enforcer": "log-enforcer", "sensor": "log-sensor", "alert": "log-alert"}
_LOG_PREFIX = {"agent1": "[Threat Triage]", "agent2": "[Policy Synth]",
               "agent3": "[Cmd Compiler]", "enforcer": "[Enforcer]",
               "sensor": "[Sensor]", "alert": "[ALERT]"}


def render_agent_thought_stream() -> None:
    log_items = list(st.session_state["agent_log"])
    if not log_items:
        html = "<div class='thought-log'><span style='color:#475569'>No events yet — waiting for sensor activity...</span></div>"
    else:
        lines = []
        for ts, kind, msg in reversed(log_items[-60:]):
            cls    = _LOG_CLASS.get(kind, "log-sensor")
            prefix = _LOG_PREFIX.get(kind, f"[{kind}]")
            lines.append(f"<span class='log-ts'>{ts}</span> <span class='{cls}'>{prefix} {msg}</span>")
        html = "<div class='thought-log'>" + "<br>".join(lines) + "</div>"
    st.markdown(html, unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# KPI tile helper
# ---------------------------------------------------------------------------
def _kpi(label: str, value: str, color_class: str, col) -> None:
    col.markdown(
        f"<div class='kpi-card'>"
        f"<div class='kpi-value {color_class}'>{value}</div>"
        f"<div class='kpi-label'>{label}</div>"
        f"</div>",
        unsafe_allow_html=True,
    )

# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------
with st.sidebar:
    st.markdown("### AegisNet-AI")
    st.markdown("<small style='color:#64748b'>Real-Time SOC Dashboard v1.0</small>", unsafe_allow_html=True)
    st.divider()

    demo_mode        = st.toggle("Demo Simulation", value=True,
                                 help="Inject synthetic data when no live sensor is running.")
    refresh_interval = st.slider("Refresh interval (s)", 1, 10, 2)

    st.divider()
    st.markdown("**Sensor**")
    sensor_status = "Live" if ALERT_LOG_PATH.exists() else "Demo"
    st.markdown(f"Alert log: `{ALERT_LOG_PATH.name}` — {sensor_status}")

    st.divider()
    topo = load_topology()
    node_count = len(topo.get("nodes", []))
    protected  = sum(1 for n in topo.get("nodes", []) if not n.get("can_block_ip", True))
    st.markdown(f"**Network** — Nodes: **{node_count}** | Protected: **{protected}**")

    st.divider()
    st.markdown("**Thresholds**")
    st.markdown("delta_SEQ alert: **1 460 B** (1 MSS)")
    st.markdown("Entropy spike: **+40%** baseline")
    st.markdown("MTTR limit: **2 500 ms**")

    if st.button("Force refresh", use_container_width=True):
        st.cache_data.clear()
        st.rerun()

# ---------------------------------------------------------------------------
# Main layout
# ---------------------------------------------------------------------------
title_col, status_col = st.columns([4, 1])
with title_col:
    st.markdown("## AegisNet-AI — Security Operations Centre")
    st.markdown("<small style='color:#64748b'>Autonomous MitM Detection & Remediation - Layer-2/4 Cyber Range</small>",
                unsafe_allow_html=True)
with status_col:
    status    = st.session_state["defense_status"]
    badge_map = {"MONITORING": "badge-green", "ACTIVE": "badge-red", "REMEDIATED": "badge-amber"}
    badge_cls = badge_map.get(status, "badge-green")
    st.markdown(f"<br><div class='status-badge {badge_cls}'>{status}</div>", unsafe_allow_html=True)

st.divider()

# --- KPI scorecard ---
st.markdown("<div class='section-header'>KPI Scorecard</div>", unsafe_allow_html=True)
k1, k2, k3, k4, k5 = st.columns(5)
mttd = st.session_state.get("mttd_ms")
mttr = st.session_state.get("mttr_ms")
_kpi("MTTD",          f"{mttd} ms" if mttd else "—",                        "kpi-blue",   k1)
_kpi("MTTR",          f"{mttr} ms" if mttr else "—",                        "kpi-green",  k2)
_kpi("Total Alerts",  str(st.session_state["total_alerts"]),                 "kpi-amber",  k3)
_kpi("Remediations",  str(st.session_state["total_remediations"]),           "kpi-purple", k4)
_kpi("API Calls",     str(st.session_state["api_calls_used"]),               "kpi-red",    k5)

st.markdown("<br>", unsafe_allow_html=True)

# --- Topology + delta_SEQ stream ---
topo_col, seq_col = st.columns([5, 7], gap="medium")
with topo_col:
    st.markdown("<div class='section-header'>Network Topology Canvas</div>", unsafe_allow_html=True)
    active_alert = st.session_state["alerts"][-1] if st.session_state["alerts"] else None
    topo_fig     = build_topology_figure(topo, active_alert)
    st.plotly_chart(topo_fig, use_container_width=True, config={"displayModeBar": False})
    lac = st.session_state["last_attack_class"]
    st.markdown(f"<small style='color:#64748b'>Last attack: <b style='color:#f59e0b'>{lac}</b></small>",
                unsafe_allow_html=True)

with seq_col:
    st.markdown("<div class='section-header'>delta_SEQ Stream and Shannon Entropy</div>", unsafe_allow_html=True)
    seq_fig = build_seq_chart()
    st.plotly_chart(seq_fig, use_container_width=True, config={"displayModeBar": False})
    sv = list(st.session_state["seq_values"])
    ev = list(st.session_state["entropy_values"])
    if sv:
        c1, c2, c3 = st.columns(3)
        c1.metric("Latest delta_SEQ", f"{sv[-1]:.0f} B",    delta=f"{sv[-1]-sv[-2]:.0f} B" if len(sv) > 1 else None)
        c2.metric("Shannon H(X)",     f"{ev[-1]:.2f} bits",  delta=f"{ev[-1]-ev[-2]:.2f}"   if len(ev) > 1 else None)
        c3.metric("Window samples",   str(len(sv)))

# --- Agent thought stream ---
st.markdown("<div class='section-header'>Agent Thought Stream</div>", unsafe_allow_html=True)
render_agent_thought_stream()

# --- Live alert table ---
if st.session_state["alerts"]:
    st.markdown("<br><div class='section-header'>Recent Alerts</div>", unsafe_allow_html=True)
    rows = [{
        "Alert ID":     a.get("alert_id", "—"),
        "Engine":       a.get("detection_engine", "—"),
        "Severity":     a.get("severity", "—"),
        "Attacker MAC": a.get("layer2_state", {}).get("observed_mac", "—"),
        "Victim IP":    a.get("layer2_state", {}).get("claimed_ip", "—"),
        "Timestamp":    a.get("timestamp", "—"),
    } for a in reversed(st.session_state["alerts"][-10:])]
    st.dataframe(pd.DataFrame(rows), use_container_width=True, height=200)

# ---------------------------------------------------------------------------
# Per-tick data ingestion
# ---------------------------------------------------------------------------
new_alerts = read_new_alerts()
for alert in new_alerts:
    st.session_state["alerts"].append(alert)
    st.session_state["total_alerts"] += 1
    ts     = datetime.now(tz=timezone.utc).strftime("%H:%M:%S.%f")[:-3]
    engine = alert.get("detection_engine", "SENSOR")
    sev    = alert.get("severity", "")
    mac    = alert.get("layer2_state", {}).get("observed_mac", "")
    st.session_state["agent_log"].append((ts, "alert", f"{engine} [{sev}] attacker={mac}"))
    st.session_state["seq_times"].append(ts)
    st.session_state["seq_values"].append(alert.get("layer4_state", {}).get("delta_seq", 0))
    st.session_state["entropy_values"].append(alert.get("layer4_state", {}).get("shannon_entropy", 0))

if demo_mode and not new_alerts:
    _inject_demo_tick()

# Auto-refresh
time.sleep(refresh_interval)
st.rerun()
