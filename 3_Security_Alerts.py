"""Page 4 (file 3): Security alerts stored in SQLite."""
import streamlit as st

from modules import attack_detector, database, ui

ui.require_login()
ui.page_header("Security alerts", "Every detection is stored in SQLite with its severity and status.")


@st.fragment(run_every=5)
def alerts_view():
    df = database.get_alerts()
    counts = df["severity"].value_counts() if not df.empty else {}
    cols = st.columns(4)
    for col, sev in zip(cols, attack_detector.SEVERITIES):
        with col:
            n = int(counts.get(sev, 0)) if len(df) else 0
            color = ui.SEVERITY_COLOR[sev]
            st.markdown(f'<div class="vs-card" style="--accent:{color};min-height:96px"><div class="vs-label">{sev.title()} severity</div>'
                        f'<div class="vs-value" style="margin-bottom:0">{n}</div></div>', unsafe_allow_html=True)

    f1, f2, f3 = st.columns(3)
    with f1:
        sev_sel = st.multiselect("Severity", attack_detector.SEVERITIES, key="f_sev")
    with f2:
        types = [attack_detector.ATTACK_TAMPERING, attack_detector.ATTACK_UNAUTHORIZED, attack_detector.ATTACK_CHARGING]
        type_sel = st.multiselect("Attack type", types, key="f_type")
    with f3:
        status_sel = st.multiselect("Detection status", ["Detected", "Blocked", "Resolved"], key="f_status")

    view = df
    if not view.empty:
        if sev_sel:
            view = view[view["severity"].isin(sev_sel)]
        if type_sel:
            view = view[view["attack_type"].isin(type_sel)]
        if status_sel:
            view = view[view["status"].isin(status_sel)]

    st.caption(f"Showing {min(len(view), 200)} of {len(view)} matching alerts (newest first).")
    st.markdown(ui.alerts_table(view.head(200), "No alerts match. Run an attack simulation to generate detections."),
                unsafe_allow_html=True)
    if not df.empty:
        st.download_button("Download alerts (CSV)", df.to_csv(index=False).encode("utf-8"),
                           "voltshield_alerts.csv", "text/csv")


alerts_view()
