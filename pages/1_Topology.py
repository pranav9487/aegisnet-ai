"""
AegisNet-AI — Live Topology & Threat Status (Demo Page)
--------------------------------------------------------
Standalone Streamlit page. Drop this file into your existing `pages/`
folder (next to your current dashboard script) and Streamlit will add
it to the sidebar automatically — no changes needed to anything else.

This file does NOT import from your existing modules, so it cannot
break your current backend/dashboard. It runs entirely on its own
session_state, with buttons that simulate attack/defense transitions
and a live-looking packet/log console for the presentation. If you
later want to wire it to real sensor output, see the "HOOK POINT"
comment near the bottom.
"""

import streamlit as st
import time
from datetime import datetime

st.set_page_config(page_title="AegisNet-AI | Topology", layout="wide")

# ----------------------------------------------------------------------
# STATE
# ----------------------------------------------------------------------
if "net_state" not in st.session_state:
    st.session_state.net_state = "normal"          # normal | arp_attack | tcp_attack | defended
if "mttd_ms" not in st.session_state:
    st.session_state.mttd_ms = None
if "mttr_s" not in st.session_state:
    st.session_state.mttr_s = None
if "packets_blocked" not in st.session_state:
    st.session_state.packets_blocked = 0
if "logs" not in st.session_state:
    st.session_state.logs = []   # list of (level, text) tuples

STATE = st.session_state.net_state

def ts() -> str:
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]

# Color scheme per state
PALETTE = {
    "normal":      {"client": "#4ADE80", "server": "#4ADE80", "attacker": "#9CA3AF", "defender": "#60A5FA", "link": "#4ADE80", "attack_link": "#374151"},
    "arp_attack":  {"client": "#F87171", "server": "#F87171", "attacker": "#EF4444", "defender": "#60A5FA", "link": "#F87171", "attack_link": "#EF4444"},
    "tcp_attack":  {"client": "#F87171", "server": "#F87171", "attacker": "#EF4444", "defender": "#60A5FA", "link": "#F87171", "attack_link": "#EF4444"},
    "defended":    {"client": "#4ADE80", "server": "#4ADE80", "attacker": "#6B7280", "defender": "#3B82F6", "link": "#3B82F6", "attack_link": "#1F2937"},
}
C = PALETTE.get(STATE, PALETTE["normal"])

STATUS_LABEL = {
    "normal":     ("🟢 Normal Operation", "All traffic flowing, no anomalies detected."),
    "arp_attack": ("🔴 ARP Spoofing Detected", "Gratuitous ARP reply binding server IP to attacker MAC."),
    "tcp_attack": ("🔴 TCP Session Hijack Detected", "Sequence number desynchronization / blind injection in progress."),
    "defended":   ("🔵 IPsec ESP Tunnel Active", "Attacker MAC isolated. AES-256-GCM encrypted channel established."),
}

# ----------------------------------------------------------------------
# HEADER
# ----------------------------------------------------------------------
st.title("🛡️ AegisNet-AI — Live Network Topology")
label, desc = STATUS_LABEL.get(STATE, STATUS_LABEL["normal"])
st.subheader(label)
st.caption(desc)

# ----------------------------------------------------------------------
# SVG TOPOLOGY DIAGRAM BUILDER
# ----------------------------------------------------------------------
def node_icon(kind: str, color: str, cx: int, cy: int) -> str:
    """Return an inline SVG snippet for a node icon at (cx, cy)."""
    if kind == "client":
        return (
            f'<g transform="translate({cx-30},{cy-22})">'
            f'<rect x="0" y="0" width="60" height="38" rx="6" fill="{color}" opacity="0.15" stroke="{color}" stroke-width="2.5"/>'
            f'<rect x="8" y="8" width="44" height="22" rx="3" fill="{color}" opacity="0.35"/>'
            f'<rect x="18" y="38" width="24" height="4" rx="1" fill="{color}"/>'
            f'</g>'
        )
    if kind == "server":
        return (
            f'<g transform="translate({cx-26},{cy-30})">'
            f'<rect x="0" y="0" width="52" height="16" rx="3" fill="{color}" opacity="0.3" stroke="{color}" stroke-width="2"/>'
            f'<rect x="0" y="20" width="52" height="16" rx="3" fill="{color}" opacity="0.3" stroke="{color}" stroke-width="2"/>'
            f'<rect x="0" y="40" width="52" height="16" rx="3" fill="{color}" opacity="0.3" stroke="{color}" stroke-width="2"/>'
            f'<circle cx="44" cy="8" r="2.5" fill="{color}"/>'
            f'<circle cx="44" cy="28" r="2.5" fill="{color}"/>'
            f'<circle cx="44" cy="48" r="2.5" fill="{color}"/>'
            f'</g>'
        )
    if kind == "attacker":
        return (
            f'<g transform="translate({cx-24},{cy-24})">'
            f'<circle cx="24" cy="18" r="16" fill="{color}" opacity="0.25" stroke="{color}" stroke-width="2.5"/>'
            f'<circle cx="17" cy="15" r="2.5" fill="{color}"/>'
            f'<circle cx="31" cy="15" r="2.5" fill="{color}"/>'
            f'<path d="M14 26 Q24 18 34 26" stroke="{color}" stroke-width="2.5" fill="none"/>'
            f'<path d="M8 10 Q24 -6 40 10" stroke="{color}" stroke-width="2.5" fill="none"/>'
            f'</g>'
        )
    if kind == "defender":
        return (
            f'<g transform="translate({cx-22},{cy-26})">'
            f'<path d="M22 0 L44 8 L44 26 Q44 44 22 52 Q0 44 0 26 L0 8 Z" fill="{color}" opacity="0.2" stroke="{color}" stroke-width="2.5"/>'
            f'<path d="M14 26 L20 32 L32 18" stroke="{color}" stroke-width="3" fill="none" stroke-linecap="round" stroke-linejoin="round"/>'
            f'</g>'
        )
    return ""

def link(x1: int, y1: int, x2: int, y2: int, color: str, dashed: bool = False, pulse: bool = False) -> str:
    dash = 'stroke-dasharray="6,4"' if dashed else ""
    anim = '<animate attributeName="stroke-opacity" values="1;0.2;1" dur="1s" repeatCount="indefinite"/>' if pulse else ""
    return f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{color}" stroke-width="3" {dash}>{anim}</line>'

attack_pulse = STATE in ("arp_attack", "tcp_attack")
defended_mode = STATE == "defended"

raw_svg = (
    f'<svg viewBox="0 0 760 320" width="100%" height="320" xmlns="http://www.w3.org/2000/svg" style="width:100%;height:320px;max-width:900px;display:block;">'
    f'{link(130, 80, 380, 140, C["link"], dashed=defended_mode, pulse=False)}'
    f'{link(380, 140, 630, 80, C["link"], dashed=defended_mode, pulse=False)}'
    f'{link(130, 80, 630, 80, C["attack_link"], dashed=True, pulse=attack_pulse)}'
    f'{node_icon("client", C["client"], 130, 80)}'
    f'{node_icon("defender", C["defender"], 380, 140)}'
    f'{node_icon("server", C["server"], 630, 80)}'
    f'{node_icon("attacker", C["attacker"], 380, 245)}'
    f'<text x="130" y="135" text-anchor="middle" fill="#F3F4F6" font-size="13" font-weight="600" font-family="system-ui, -apple-system, sans-serif">victim-client</text>'
    f'<text x="130" y="152" text-anchor="middle" fill="#9CA3AF" font-size="11" font-family="ui-monospace, monospace">172.28.0.10</text>'
    f'<text x="630" y="135" text-anchor="middle" fill="#F3F4F6" font-size="13" font-weight="600" font-family="system-ui, -apple-system, sans-serif">target-server</text>'
    f'<text x="630" y="152" text-anchor="middle" fill="#9CA3AF" font-size="11" font-family="ui-monospace, monospace">172.28.0.20</text>'
    f'<text x="380" y="195" text-anchor="middle" fill="#F3F4F6" font-size="13" font-weight="600" font-family="system-ui, -apple-system, sans-serif">blue-ai-defender</text>'
    f'<text x="380" y="212" text-anchor="middle" fill="#9CA3AF" font-size="11" font-family="ui-monospace, monospace">172.28.0.2</text>'
    f'<text x="380" y="295" text-anchor="middle" fill="#F3F4F6" font-size="13" font-weight="600" font-family="system-ui, -apple-system, sans-serif">red-attacker</text>'
    f'</svg>'
)

# ----------------------------------------------------------------------
# LOG CONSOLE RENDERER
# ----------------------------------------------------------------------
LEVEL_COLOR = {
    "info": "#9CA3AF",
    "attack": "#F87171",
    "detect": "#FBBF24",
    "defense": "#60A5FA",
    "success": "#4ADE80",
}

def render_console() -> str:
    rows = "".join(
        f'<div style="color:{LEVEL_COLOR.get(lvl, "#E5E7EB")};white-space:pre-wrap;margin-bottom:3px;line-height:1.4;">{text}</div>'
        for lvl, text in st.session_state.logs[-200:]
    )
    return (
        f'<div style="background:#0B0F19;border:1px solid #1F2937;border-radius:10px;'
        f'padding:14px;height:368px;overflow-y:auto;font-family:ui-monospace,Menlo,Consolas,monospace;'
        f'font-size:12px;display:flex;flex-direction:column;">'
        f'{rows if rows else "<span style=\'color:#4B5563\'>-- console idle --</span>"}'
        f'</div>'
    )

def log(level: str, text: str, placeholder=None, render_fn=None, delay: float = 0.0) -> None:
    """Append a log line and optionally re-render a live placeholder for a typewriter effect."""
    st.session_state.logs.append((level, f"[{ts()}] {text}"))
    if placeholder is not None and render_fn is not None:
        placeholder.markdown(render_fn(), unsafe_allow_html=True)
        if delay > 0:
            time.sleep(delay)

# ----------------------------------------------------------------------
# 2-COLUMN VIEW: TOPOLOGY CARD (LEFT) & LIVE CONSOLE (RIGHT)
# ----------------------------------------------------------------------
left, right = st.columns([3, 2])

with left:
    container_html = (
        f'<div style="background:linear-gradient(135deg, #0B0F17 0%, #111827 50%, #172033 100%);'
        f'border:1px solid #1F2937;border-radius:14px;padding:24px 16px;min-height:368px;display:flex;'
        f'justify-content:center;align-items:center;box-shadow:0 8px 30px rgba(0,0,0,0.4);">{raw_svg}</div>'
    )
    st.markdown(container_html, unsafe_allow_html=True)

with right:
    st.markdown("**Live Packet / Agent Console**")
    console_placeholder = st.empty()
    console_placeholder.markdown(render_console(), unsafe_allow_html=True)

# ----------------------------------------------------------------------
# DEMO CONTROLS
# ----------------------------------------------------------------------
st.write("")
st.markdown("#### Demo Controls")
c1, c2, c3, c4 = st.columns(4)

if c1.button("🟢 Reset to Normal", use_container_width=True):
    st.session_state.net_state = "normal"
    st.session_state.mttd_ms = None
    st.session_state.mttr_s = None
    st.session_state.packets_blocked = 0
    st.session_state.logs = []
    log("info", "Console reset. Baseline traffic nominal.", console_placeholder, render_console)
    st.rerun()

if c2.button("⚠️ Simulate ARP Attack", use_container_width=True):
    st.session_state.net_state = "arp_attack"
    sequence = [
        ("attack", "ARP: gratuitous reply RX on eth0 (unsolicited)"),
        ("attack", "  src_mac=02:42:ac:1c:00:42  claims ip=172.28.0.20"),
        ("attack", "  src_mac=02:42:ac:1c:00:42  claims ip=172.28.0.10"),
        ("detect", "ARP-TABLE: binding mismatch — expected 02:42:ac:1c:00:14, got 02:42:ac:1c:00:42"),
        ("detect", "delta_ARP = 1  (invariant breach)"),
        ("detect", "ALERT INC-2026-8812 generated -> dispatched to Module 2 (GraphRAG)"),
    ]
    for lvl, text in sequence:
        log(lvl, text, console_placeholder, render_console, delay=0.18)
    st.session_state.mttd_ms = 180
    st.rerun()

if c3.button("⚠️ Simulate TCP Hijack", use_container_width=True):
    st.session_state.net_state = "tcp_attack"
    sequence = [
        ("attack", "TCP: forged packet injected  172.28.0.10:49152 -> 172.28.0.20:8080"),
        ("attack", "  flags=PSH,ACK  seq=3892104500  ack=1024"),
        ("detect", "  expected_seq=3892056300 -> delta_SEQ = 48200 bytes (> theta=1460)"),
        ("detect", "  duplicate_ACK burst: 5 in 80ms (>=3 within 100ms window)"),
        ("detect", "  payload_entropy=7.82 (binary/obfuscated, baseline H~3.5-4.8)"),
        ("detect", "ALERT: TCP_SESSION_DESYNC flagged -> dispatched to Module 2 (GraphRAG)"),
    ]
    for lvl, text in sequence:
        log(lvl, text, console_placeholder, render_console, delay=0.18)
    st.session_state.mttd_ms = 190
    st.rerun()

if c4.button("🔵 Trigger Defense (IPsec)", use_container_width=True):
    sequence = [
        ("defense", "AGENT 1 (Triage): attacker_mac=02:42:ac:1c:00:42, victim_ip=172.28.0.10 confirmed"),
        ("defense", "AGENT 2 (Policy): strategy=ISOLATE_MAC_THEN_IPSEC - gateway protection respected"),
        ("defense", "AGENT 3 (Compiler): policy JSON validated against AegisNetDefensePolicy-v1 schema"),
        ("defense", "ENFORCER: ebtables -A INPUT -s 02:42:ac:1c:00:42 -j DROP"),
        ("defense", "ENFORCER: ip xfrm state add ... aead rfc4106(gcm(aes)) spi=0x1001 mode transport"),
        ("defense", "PROBE: HTTP GET 172.28.0.20:8080 -> 200 OK in 12ms"),
        ("success", "STATUS: attacker packet interception = 0 -> NEUTRALIZED"),
    ]
    for lvl, text in sequence:
        log(lvl, text, console_placeholder, render_console, delay=0.2)
    st.session_state.net_state = "defended"
    st.session_state.mttr_s = 1.42
    st.session_state.packets_blocked = st.session_state.get("packets_blocked", 0) + 1
    st.rerun()

# ----------------------------------------------------------------------
# STATUS STRIP
# ----------------------------------------------------------------------
st.write("")
m1, m2, m3, m4 = st.columns(4)
m1.metric("Mean Time to Detect", f"{st.session_state.mttd_ms} ms" if st.session_state.mttd_ms else "—")
m2.metric("Mean Time to Remediate", f"{st.session_state.mttr_s} s" if st.session_state.mttr_s else "—")
m3.metric("Attacker Packets Post-Defense", 0 if defended_mode else "—")
m4.metric("API Token Cost (demo)", "$0.00")

st.caption(
    "This page is self-contained for demo purposes and does not read or write any state used "
    "by the rest of the application. Button clicks only change local session_state."
)

# ----------------------------------------------------------------------
# HOOK POINT (optional, for later — not needed for this presentation)
# ----------------------------------------------------------------------
# To wire this to real sensor output later, replace the `sequence` lists
# above with lines built from your sensor's actual alert JSON fields
# (delta_arp, delta_seq, duplicate_acks, payload_entropy, etc.) instead
# of the hardcoded demo values, and drive st.session_state.net_state
# based on its "anomaly_type" field instead of a manual click.
