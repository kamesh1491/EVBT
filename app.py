"""
VoltShield - Secure EV Battery Monitoring and Cyberattack Detection System
Entry point: login, sidebar navigation and the Home dashboard.
Run with:  streamlit run app.py
"""
import time

import plotly.graph_objects as go
import streamlit as st

from modules import attack_detector, authentication, database, ui

st.set_page_config(page_title="VoltShield | EV Battery Security Monitor", page_icon="⚡",
                   layout="wide", initial_sidebar_state="expanded")


@st.cache_resource
def init_backend() -> bool:
    """Create the database and demo users once per server run."""
    database.init_db()
    authentication.ensure_default_users()
    return True


init_backend()
ui.inject_css()
st.session_state.setdefault("auth", None)
st.session_state.setdefault("login_failures", 0)
st.session_state.setdefault("locked_until", 0.0)

MAX_LOGIN_FAILURES = 5
LOCK_SECONDS = 30


def login_view():
    """Sign-in screen. Real failed logins are recorded as security alerts."""
    _, mid, _ = st.columns([1, 1.2, 1])
    with mid:
        st.markdown(f'<div class="vs-brand" style="justify-content:center;padding-top:60px">{ui.LOGO_SVG}'
                    '<div><div class="vs-name">VOLTSHIELD</div>'
                    '<div class="vs-tag">EV BATTERY SECURITY MONITOR</div></div></div>', unsafe_allow_html=True)
        remaining = st.session_state["locked_until"] - time.time()
        if remaining > 0:
            st.error(f"Too many failed attempts. Sign-in is locked for {int(remaining) + 1} more seconds.")
            return
        with st.form("login_form"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            submitted = st.form_submit_button("Sign in", type="primary")
        if submitted:
            user = authentication.authenticate(username, password)
            if user:
                st.session_state["auth"] = user
                st.session_state["login_failures"] = 0
                st.rerun()
            st.session_state["login_failures"] += 1
            n = st.session_state["login_failures"]
            sev = attack_detector.login_failure_severity(n, username.strip().lower() == "admin")
            extra = " Repeated failures suggest a brute-force attempt." if n >= 3 else ""
            database.insert_alert(attack_detector.ATTACK_UNAUTHORIZED,
                                  f"Failed sign-in for username '{username.strip()[:40]}' "
                                  f"(attempt {n} in this session).{extra}", sev, "Blocked")
            if n >= MAX_LOGIN_FAILURES:
                st.session_state["locked_until"] = time.time() + LOCK_SECONDS
                st.session_state["login_failures"] = 0
                st.rerun()
            st.error("Incorrect username or password. Access denied.")
        with st.expander("Demo accounts (academic project)"):
            st.markdown("Administrator: `admin` / `Admin@123`  \nViewer: `viewer` / `Viewer@123`")


def home():
    """Page 1: Home dashboard."""
    ui.page_header("Home dashboard", "Live overview of the simulated battery pack and its security state.")
    limits = ui.get_limits()

    @st.fragment(run_every=3)
    def body():
        latest = database.get_latest_reading()
        total = database.count_readings()
        alerts_total = database.count_alerts()
        health, health_level = ui.health_status(latest, limits)
        sec_text, sec_level = ui.security_status()

        c1, c2, c3, c4 = st.columns(4)
        with c1:
            ui.metric_card("Total battery readings", f"{total:,}", level="info", status="Simulated data")
        with c2:
            ui.metric_card("Pack voltage", f"{latest['voltage']:.1f}" if latest else "—", "V", "info")
        with c3:
            t = latest["temperature"] if latest else None
            lvl = "info" if t is None else "crit" if t > limits["temp_max"] else "warn" if t > limits["temp_warn"] else "ok"
            ui.metric_card("Temperature", f"{t:.1f}" if t is not None else "—", "°C", lvl)
        with c4:
            s = latest["soc"] if latest else None
            lvl = "info" if s is None else "crit" if s < limits["soc_low_critical"] else "warn" if s < limits["soc_low_warn"] else "ok"
            ui.metric_card("State of charge", f"{s:.1f}" if s is not None else "—", "%", lvl)

        c5, c6, c7, c8 = st.columns(4)
        with c5:
            ui.metric_card("Current flow", f"{latest['current']:.1f}" if latest else "—", "A",
                           "info", latest["charging_status"] if latest else "")
        with c6:
            ui.metric_card("Battery health", health, level=health_level, status="BMS limits check")
        with c7:
            ui.metric_card("Security status", sec_text, level=sec_level, status="From alert log")
        with c8:
            ui.metric_card("Total detected attacks", alerts_total, level="crit" if alerts_total else "ok",
                           status="All time")

        if latest is None:
            st.info("No readings yet. Open Battery monitoring and press Start, or generate sample history below.")
            if st.button("Generate 60 sample readings", type="primary"):
                ui.backfill(60)
                st.rerun()

        left, right = st.columns([2, 3])
        with left:
            soc = latest["soc"] if latest else 0
            fig = go.Figure(go.Indicator(
                mode="gauge+number", value=soc, number=dict(suffix=" %", font=dict(color="#FFFFFF")),
                gauge=dict(axis=dict(range=[0, 100], tickcolor="#8FA6C9"), bar=dict(color="#22D3EE"),
                           bgcolor="#0A1428", borderwidth=0,
                           steps=[dict(range=[0, limits["soc_low_critical"]], color="#5B1F27"),
                                  dict(range=[limits["soc_low_critical"], limits["soc_low_warn"]], color="#5A4A12"),
                                  dict(range=[limits["soc_low_warn"], 100], color="#12305A")])))
            ui.style_fig(fig, height=300, title="State of charge")
            ui.show_chart(fig, "home_soc_gauge")
        with right:
            st.markdown("##### Recent security alerts")
            st.markdown(ui.alerts_table(database.get_alerts(limit=5), "No alerts yet. Run an attack simulation to see detections here."),
                        unsafe_allow_html=True)

    body()


# ----------------------------------------------------------------- routing
if not st.session_state["auth"]:
    login_view()
    st.stop()

pages = [
    st.Page(home, title="Home dashboard", icon=":material/dashboard:", default=True),
    st.Page("pages/1_Battery_Monitoring.py", title="Battery monitoring", icon=":material/battery_charging_full:"),
    st.Page("pages/2_Attack_Simulation.py", title="Attack simulation", icon=":material/bug_report:"),
    st.Page("pages/3_Security_Alerts.py", title="Security alerts", icon=":material/notifications_active:"),
    st.Page("pages/4_Reports.py", title="Reports", icon=":material/analytics:"),
]
nav = st.navigation(pages, position="hidden")

with st.sidebar:
    st.markdown(f'<div class="vs-brand">{ui.LOGO_SVG}<div><div class="vs-name">VOLTSHIELD</div>'
                '<div class="vs-tag">EV BATTERY SECURITY MONITOR</div></div></div>', unsafe_allow_html=True)
    for p in pages:
        st.page_link(p)
    user = st.session_state["auth"]
    st.markdown(f'<div class="vs-user"><b>{user["username"]}</b><br><span>{authentication.role_label(user["role"])}</span></div>',
                unsafe_allow_html=True)
    if st.button("Sign out"):
        for key in ("auth", "sim", "sim_running", "attack_results"):
            st.session_state.pop(key, None)
        st.rerun()

nav.run()
