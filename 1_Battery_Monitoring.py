"""Page 2 (file 1): Battery monitoring with live-looking simulated readings."""
import plotly.graph_objects as go
import streamlit as st

from modules import authentication, bms_monitor, database, ui

ui.require_login()
ui.page_header("Battery monitoring",
               "Simulated 96S Li-ion pack (about 355 V, 150 Ah). All readings are simulated, not from real hardware.")

limits = ui.get_limits()
is_admin = authentication.has_permission(ui.current_role(), "configure")
st.session_state.setdefault("sim_running", False)

# ---------------------------------------------------------------- controls
c1, c2, c3, c4 = st.columns([1, 1, 1.4, 1.4])
with c1:
    if st.button("Start simulation", type="primary", disabled=st.session_state["sim_running"]):
        st.session_state["sim_running"] = True
        st.rerun()
with c2:
    if st.button("Stop simulation", disabled=not st.session_state["sim_running"]):
        st.session_state["sim_running"] = False
        st.rerun()
with c3:
    dt_s = st.select_slider("Simulated seconds per update", options=[10, 30, 60, 120, 300], value=60)
with c4:
    refresh = st.select_slider("Refresh every (s)", options=[1, 2, 3, 5], value=2)

c5, c6, c7 = st.columns([1.4, 1.4, 1])
with c5:
    load = st.slider("Driving load factor", 0.5, 2.0, 1.0, 0.1,
                     help="Scales the discharge current. Raise it to trigger over-current and heating warnings.")
with c6:
    ambient = st.slider("Ambient temperature (°C)", 20, 50, 30)
with c7:
    st.write("")
    if st.button("Generate 60 readings"):
        ui.backfill(60, dt_s=dt_s)
        st.rerun()

with st.expander("BMS limits" + ("" if is_admin else " (read-only for viewers)")):
    a, b, c = st.columns(3)
    with a:
        limits["voltage_min"] = st.number_input("Minimum voltage (V)", 200.0, 400.0, limits["voltage_min"], disabled=not is_admin)
        limits["voltage_max"] = st.number_input("Maximum voltage (V)", 300.0, 450.0, limits["voltage_max"], disabled=not is_admin)
    with b:
        limits["temp_warn"] = st.number_input("Temperature warning (°C)", 20.0, 80.0, limits["temp_warn"], disabled=not is_admin)
        limits["temp_max"] = st.number_input("Temperature critical (°C)", 30.0, 90.0, limits["temp_max"], disabled=not is_admin)
    with c:
        limits["current_discharge_max"] = st.number_input("Max discharge current (A)", 50.0, 400.0, limits["current_discharge_max"], disabled=not is_admin)
        limits["current_charge_max"] = st.number_input("Max charge current (A)", 20.0, 300.0, limits["current_charge_max"], disabled=not is_admin)

running = st.session_state["sim_running"]
st.markdown(ui.badge("SIMULATION RUNNING" if running else "SIMULATION STOPPED",
                     ui.COLORS["green"] if running else ui.COLORS["muted"]), unsafe_allow_html=True)


def live_view():
    """Add one reading when running, then draw status, warnings and charts."""
    if st.session_state["sim_running"]:
        try:
            ui.step_and_store(dt_s=dt_s, load_factor=load, ambient=ambient)
        except Exception as exc:  # keep the dashboard alive if the DB is busy
            st.error(f"Could not store reading: {exc}")

    df = database.get_readings(limit=120)
    if df.empty:
        st.info("No readings yet. Press Start simulation or Generate 60 readings.")
        return
    last = df.iloc[-1].to_dict()
    issues = bms_monitor.check_reading(last, limits)
    state = bms_monitor.charging_state(last["current"])
    state_color = {"Charging": ui.COLORS["green"], "Discharging": ui.COLORS["cyan"], "Idle": ui.COLORS["muted"]}[state]

    m1, m2, m3, m4 = st.columns(4)
    with m1:
        ui.metric_card("Battery voltage", f"{last['voltage']:.1f}", "V", "info")
    with m2:
        ui.metric_card("Battery current", f"{last['current']:.1f}", "A", "info", state)
    with m3:
        lvl = "crit" if last["temperature"] > limits["temp_max"] else "warn" if last["temperature"] > limits["temp_warn"] else "ok"
        ui.metric_card("Temperature", f"{last['temperature']:.1f}", "°C", lvl)
    with m4:
        ui.metric_card("State of charge", f"{last['soc']:.1f}", "%", "info", f"Reading #{last['id']}")

    st.markdown(f"**Power flow:** {ui.badge(state, state_color)}", unsafe_allow_html=True)
    if issues:
        for item in issues:
            color = ui.COLORS["red"] if item["level"] == "critical" else ui.COLORS["yellow"]
            st.markdown(f'<div class="vs-warn" style="--c:{color}"><b>{item["parameter"]}</b> · {item["message"]}</div>',
                        unsafe_allow_html=True)
    else:
        st.markdown(f'<div class="vs-warn" style="--c:{ui.COLORS["green"]}">All parameters are inside the configured limits.</div>',
                    unsafe_allow_html=True)

    def line(y, title, color, unit, hlines, key):
        fig = go.Figure(go.Scatter(x=df["time"], y=df[y], mode="lines", line=dict(color=color, width=2.4), name=title))
        for value, label, col in hlines:
            fig.add_hline(y=value, line=dict(color=col, dash="dash", width=1), annotation_text=label,
                          annotation_font_color=col, annotation_position="top left")
        fig.update_yaxes(title_text=unit)
        ui.style_fig(fig, height=290, title=title)
        ui.show_chart(fig, key)

    g1, g2 = st.columns(2)
    with g1:
        line("voltage", "Battery voltage", ui.COLORS["blue"], "V",
             [(limits["voltage_max"], "max", ui.COLORS["red"]), (limits["voltage_min"], "min", ui.COLORS["red"])], "mon_v")
    with g2:
        line("current", "Battery current (+ charging, − discharging)", ui.COLORS["cyan"], "A",
             [(limits["current_charge_max"], "charge limit", ui.COLORS["red"]),
              (-limits["current_discharge_max"], "discharge limit", ui.COLORS["red"])], "mon_i")
    g3, g4 = st.columns(2)
    with g3:
        line("temperature", "Battery temperature", ui.COLORS["orange"], "°C",
             [(limits["temp_warn"], "warning", ui.COLORS["yellow"]), (limits["temp_max"], "critical", ui.COLORS["red"])], "mon_t")
    with g4:
        line("soc", "State of charge", ui.COLORS["green"], "%",
             [(limits["soc_low_warn"], "low", ui.COLORS["yellow"]), (limits["soc_high_warn"], "high", ui.COLORS["yellow"])], "mon_s")


# The fragment re-runs by itself while the simulation is running (live-looking updates)
st.fragment(live_view, run_every=refresh if running else None)()
