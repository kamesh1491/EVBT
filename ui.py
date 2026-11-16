"""
ui.py
Shared dashboard helpers: theme CSS, cards, badges, chart styling and the
glue that runs one simulated reading through BMS -> detection -> database.
"""
import html
from datetime import datetime, timedelta

import pandas as pd
import streamlit as st

from modules import authentication, attack_detector, bms_monitor, database
from modules.battery_simulator import BatterySimulator

COLORS = {"bg": "#0A1428", "surface": "#0F1D3A", "border": "#1E3A66", "blue": "#2F80FF",
          "cyan": "#22D3EE", "green": "#22C55E", "yellow": "#FACC15", "orange": "#F97316",
          "red": "#EF4444", "text": "#FFFFFF", "muted": "#8FA6C9"}
LEVEL_COLOR = {"ok": COLORS["green"], "warn": COLORS["yellow"], "crit": COLORS["red"], "info": COLORS["cyan"]}
SEVERITY_COLOR = {"LOW": COLORS["cyan"], "MEDIUM": COLORS["yellow"], "HIGH": COLORS["orange"], "CRITICAL": COLORS["red"]}
STATUS_COLOR = {"Detected": COLORS["red"], "Blocked": COLORS["green"], "Resolved": COLORS["cyan"]}

LOGO_SVG = ('<svg width="34" height="34" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">'
            '<path d="M12 2 4 5v6c0 5 3.4 9.2 8 11 4.6-1.8 8-6 8-11V5l-8-3Z" stroke="#22D3EE" stroke-width="1.6"/>'
            '<path d="M13 6.5 8.5 13h3l-1 4.5L15.5 11h-3L13 6.5Z" fill="#2F80FF"/></svg>')

CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Manrope:wght@400;500;600;700;800&display=swap');
html, body, .stApp, [class*="st-"] { font-family: 'Manrope', 'Segoe UI', system-ui, sans-serif; }
.stApp { background: #0A1428; }
header[data-testid="stHeader"] { background: transparent; }
.block-container { padding-top: 2.2rem; padding-bottom: 3rem; max-width: 1400px; }
[data-testid="stSidebar"] { background: #0C1A33; border-right: 1px solid #1B3158; }
h1, h2, h3 { letter-spacing: -0.01em; }
.vs-brand { display:flex; gap:12px; align-items:center; padding: 6px 4px 18px 4px; }
.vs-name { font-weight:800; font-size:1.15rem; letter-spacing:.14em; color:#fff; line-height:1.1; }
.vs-tag { font-size:.62rem; letter-spacing:.12em; color:#22D3EE; margin-top:3px; }
.vs-user { background:#0F1D3A; border:1px solid #1E3A66; border-radius:12px; padding:10px 12px; margin:10px 0 8px 0; }
.vs-user b { color:#fff; } .vs-user span { color:#8FA6C9; font-size:.8rem; }
.vs-title { font-size:1.9rem; font-weight:800; margin:0; color:#fff; }
.vs-sub { color:#8FA6C9; margin:.2rem 0 1.4rem 0; font-size:.95rem; }
.vs-card { background:#0F1D3A; border:1px solid #1E3A66; border-radius:16px; padding:16px 18px;
           border-left:4px solid var(--accent); min-height:128px; margin-bottom:14px; }
.vs-label { color:#8FA6C9; font-size:.85rem; font-weight:600; }
.vs-value { font-size:2rem; font-weight:800; color:#fff; line-height:1.15; margin:6px 0 8px 0; }
.vs-unit { font-size:1rem; font-weight:600; color:#8FA6C9; margin-left:4px; }
.vs-badge { display:inline-block; padding:3px 10px; border-radius:999px; font-size:.75rem; font-weight:700;
            color:var(--c); background:color-mix(in srgb, var(--c) 16%, transparent);
            border:1px solid color-mix(in srgb, var(--c) 55%, transparent); }
.vs-panel { background:#0F1D3A; border:1px solid #1E3A66; border-radius:16px; padding:16px 18px; margin-bottom:14px; }
.vs-panel h4 { margin:0 0 6px 0; color:#fff; font-size:1.05rem; }
.vs-panel p { color:#8FA6C9; font-size:.9rem; margin:0 0 6px 0; }
.vs-table-wrap { overflow-x:auto; border:1px solid #1E3A66; border-radius:14px; background:#0F1D3A; }
table.vs-table { width:100%; border-collapse:collapse; font-size:.88rem; }
table.vs-table th { text-align:left; color:#8FA6C9; font-weight:600; padding:10px 14px; border-bottom:1px solid #1E3A66; background:#0C1A33; }
table.vs-table td { padding:10px 14px; border-bottom:1px solid #162B50; color:#E6EEFF; vertical-align:top; }
table.vs-table tr:last-child td { border-bottom:none; }
.vs-step { display:flex; gap:10px; align-items:flex-start; padding:7px 0; color:#E6EEFF; font-size:.9rem; }
.vs-dot { width:9px; height:9px; border-radius:50%; margin-top:6px; flex:none; background:var(--c); }
.vs-warn { border-radius:12px; padding:10px 14px; margin-bottom:8px; font-size:.9rem; color:#fff;
           background:color-mix(in srgb, var(--c) 14%, #0F1D3A); border:1px solid color-mix(in srgb, var(--c) 60%, transparent); }
.stButton > button, .stDownloadButton > button { border-radius:10px; font-weight:700; border:1px solid #2F80FF; }
.stButton > button:focus-visible, .stDownloadButton > button:focus-visible { outline:2px solid #22D3EE; }
[data-testid="stPlotlyChart"] { background:#0F1D3A; border:1px solid #1E3A66; border-radius:16px; padding:6px; }
</style>
"""


def inject_css():
    st.markdown(CSS, unsafe_allow_html=True)


def page_header(title: str, subtitle: str = ""):
    st.markdown(f'<div class="vs-title">{html.escape(title)}</div><div class="vs-sub">{html.escape(subtitle)}</div>',
                unsafe_allow_html=True)


def badge(text: str, color: str) -> str:
    return f'<span class="vs-badge" style="--c:{color}">{html.escape(str(text))}</span>'


def metric_card(label: str, value, unit: str = "", level: str = "info", status: str = ""):
    """Dashboard card: label, big value, optional unit and status chip."""
    color = LEVEL_COLOR[level]
    unit_html = f'<span class="vs-unit">{html.escape(unit)}</span>' if unit else ""
    chip = badge(status, color) if status else ""
    st.markdown(f'<div class="vs-card" style="--accent:{color}"><div class="vs-label">{html.escape(label)}</div>'
                f'<div class="vs-value">{html.escape(str(value))}{unit_html}</div>{chip}</div>',
                unsafe_allow_html=True)


def severity_badge(sev: str) -> str:
    return badge(sev, SEVERITY_COLOR.get(sev, COLORS["muted"]))


def alerts_table(df: pd.DataFrame, empty_text: str = "No security alerts recorded yet.") -> str:
    """HTML table with colored severity/status indicators."""
    if df.empty:
        return f'<div class="vs-panel"><p>{html.escape(empty_text)}</p></div>'
    rows = ""
    for r in df.itertuples():
        rows += (f"<tr><td>#{r.id}</td><td>{html.escape(r.attack_type)}</td><td>{html.escape(r.description)}</td>"
                 f"<td>{severity_badge(r.severity)}</td><td>{html.escape(r.timestamp)}</td>"
                 f"<td>{badge(r.status, STATUS_COLOR.get(r.status, COLORS['muted']))}</td></tr>")
    return ('<div class="vs-table-wrap"><table class="vs-table"><thead><tr><th>Alert ID</th><th>Attack type</th>'
            '<th>Description</th><th>Severity</th><th>Timestamp</th><th>Detection status</th></tr></thead>'
            f'<tbody>{rows}</tbody></table></div>')


def steps_html(steps: list) -> str:
    """List of (text, level) detection-log lines."""
    return "".join(f'<div class="vs-step"><span class="vs-dot" style="--c:{LEVEL_COLOR[lv]}"></span>'
                   f'<span>{html.escape(t)}</span></div>' for t, lv in steps)


def style_fig(fig, height: int = 300, title: str = ""):
    fig.update_layout(
        title=dict(text=title, font=dict(size=15, color="#FFFFFF")) if title else None,
        height=height, margin=dict(l=10, r=10, t=44 if title else 14, b=10),
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#C7D6F0", family="Manrope, Segoe UI, sans-serif"),
        hovermode="x unified", legend=dict(orientation="h", y=-0.2))
    fig.update_xaxes(gridcolor="#1E3A66", zeroline=False)
    fig.update_yaxes(gridcolor="#1E3A66", zeroline=False)
    return fig


def show_chart(fig, key: str):
    """Render a Plotly chart (works with old and new Streamlit width APIs)."""
    try:
        st.plotly_chart(fig, width="stretch", key=key)
    except TypeError:
        st.plotly_chart(fig, use_container_width=True, key=key)


# ------------------------------------------------------------ session state
def current_user():
    return st.session_state.get("auth")


def current_role():
    user = current_user()
    return user["role"] if user else None


def require_login():
    if not current_user():
        st.warning("Please sign in from the main page (run `streamlit run app.py`).")
        st.stop()


def get_limits() -> dict:
    if "limits" not in st.session_state:
        st.session_state["limits"] = dict(bms_monitor.DEFAULT_LIMITS)
    return st.session_state["limits"]


def get_simulator() -> BatterySimulator:
    """One simulator per browser session; continues from the last stored reading."""
    if "sim" not in st.session_state:
        last = database.get_latest_reading()
        st.session_state["sim"] = BatterySimulator.from_reading(last) if last else BatterySimulator()
    return st.session_state["sim"]


def step_and_store(dt_s: float = 60.0, load_factor: float = 1.0, ambient: float = None, timestamp=None):
    """Simulator -> BMS -> detection -> database (with SHA-256 hash)."""
    sim = get_simulator()
    if ambient is not None:
        sim.ambient = ambient
    reading = sim.step(dt_s, load_factor)
    stored = database.insert_reading(timestamp=timestamp, **reading)
    issues = bms_monitor.check_reading(stored, get_limits())
    anomalies = attack_detector.detect_abnormal_values(stored)  # physical-plausibility check
    if anomalies:
        database.insert_alert(attack_detector.ATTACK_TAMPERING,
                              f"Reading #{stored['id']} failed plausibility checks: " + "; ".join(anomalies),
                              "HIGH", "Detected")
    return stored, issues, anomalies


def backfill(n: int = 60, dt_s: float = 60.0):
    """Generate n readings quickly, time-stamped one second apart ending now."""
    now = datetime.now()
    for k in range(n):
        ts = (now - timedelta(seconds=n - k)).strftime(database.TIME_FMT)
        step_and_store(dt_s=dt_s, timestamp=ts)


def security_status():
    """(text, level) from the real alert table."""
    alerts = database.get_alerts(limit=200)
    if alerts.empty:
        return "SECURE", "ok"
    if (alerts["status"] == "Detected").any():
        return "ACTION REQUIRED", "crit"
    recent = pd.to_datetime(alerts["timestamp"]) > datetime.now() - timedelta(minutes=15)
    if recent.any():
        return "THREATS BLOCKED", "warn"
    return "SECURE", "ok"


def health_status(reading, limits):
    """(label, level) for the Battery health card."""
    if reading is None:
        return "No data", "info"
    status = bms_monitor.overall_status(bms_monitor.check_reading(reading, limits))
    return {"NORMAL": ("Healthy", "ok"), "WARNING": ("Warning", "warn"), "CRITICAL": ("Critical", "crit")}[status]
