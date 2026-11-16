"""Page 5 (file 4): Reports, charts and CSV export."""
import plotly.graph_objects as go
import streamlit as st

from modules import attack_detector, database, ui

ui.require_login()
ui.page_header("Reports", "Battery history, detected attacks and exportable data.")

readings = database.get_readings()
alerts = database.get_alerts()
classified = attack_detector.classify_readings(readings)
suspicious = int(classified["suspicious"].sum()) if not classified.empty else 0
normal = len(classified) - suspicious

m1, m2, m3, m4 = st.columns(4)
with m1:
    ui.metric_card("Total battery readings", f"{len(readings):,}", level="info")
with m2:
    ui.metric_card("Total detected attacks", len(alerts), level="crit" if len(alerts) else "ok")
with m3:
    ui.metric_card("Normal readings", f"{normal:,}", level="ok")
with m4:
    ui.metric_card("Suspicious readings", f"{suspicious:,}", level="crit" if suspicious else "ok")

if readings.empty:
    st.info("No readings yet. Start the simulation on the Battery monitoring page to build a history.")
else:
    a, b = st.columns(2)
    with a:
        fig = go.Figure(go.Pie(labels=["Normal", "Suspicious"], values=[normal, suspicious], hole=0.62,
                               marker=dict(colors=[ui.COLORS["green"], ui.COLORS["red"]]),
                               textinfo="value+percent", sort=False))
        ui.style_fig(fig, height=320, title="Normal vs suspicious readings")
        ui.show_chart(fig, "rep_pie")
    with b:
        types = [attack_detector.ATTACK_TAMPERING, attack_detector.ATTACK_UNAUTHORIZED, attack_detector.ATTACK_CHARGING]
        counts = [int((alerts["attack_type"] == t).sum()) if not alerts.empty else 0 for t in types]
        fig = go.Figure(go.Bar(x=["Sensor tampering", "Unauthorized access", "Charging manipulation"], y=counts,
                               marker_color=[ui.COLORS["orange"], ui.COLORS["blue"], ui.COLORS["cyan"]]))
        fig.update_yaxes(title_text="Alerts", dtick=1)
        ui.style_fig(fig, height=320, title="Attack category distribution")
        ui.show_chart(fig, "rep_bar")

    def history(column, title, color, unit, key):
        fig = go.Figure(go.Scatter(x=classified["time"], y=classified[column], mode="lines",
                                   line=dict(color=color, width=2.2), name=title))
        bad = classified[classified["suspicious"]]
        if not bad.empty:
            fig.add_trace(go.Scatter(x=bad["time"], y=bad[column], mode="markers", name="Suspicious",
                                     marker=dict(color=ui.COLORS["red"], size=11, symbol="x")))
        fig.update_yaxes(title_text=unit)
        ui.style_fig(fig, height=320, title=title)
        ui.show_chart(fig, key)

    history("temperature", "Battery temperature history", ui.COLORS["orange"], "°C", "rep_t")
    history("voltage", "Battery voltage history", ui.COLORS["blue"], "V", "rep_v")

    if suspicious:
        st.markdown("##### Suspicious readings")
        bad = classified[classified["suspicious"]][["id", "timestamp", "voltage", "temperature", "soc", "reason"]]
        st.dataframe(bad, hide_index=True)

st.markdown("##### Export")
e1, e2 = st.columns(2)
with e1:
    if not classified.empty:
        export = classified.drop(columns=["time"])
        st.download_button("Download readings (CSV)", export.to_csv(index=False).encode("utf-8"),
                           "voltshield_readings.csv", "text/csv")
    else:
        st.caption("Readings export becomes available once data exists.")
with e2:
    if not alerts.empty:
        st.download_button("Download alerts (CSV)", alerts.to_csv(index=False).encode("utf-8"),
                           "voltshield_alerts.csv", "text/csv")
    else:
        st.caption("Alerts export becomes available once an alert exists.")
