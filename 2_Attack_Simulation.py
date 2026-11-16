"""
Page 3 (file 2): Cyberattack simulation.
SAFE LOCAL SIMULATION - every attack targets only this app's own SQLite files and
login system. Nothing touches a real vehicle, charger or external network.
"""
import time

import streamlit as st

from modules import attack_detector as det
from modules import authentication, database, integrity_check, ui

ui.require_login()
ui.page_header("Cyberattack simulation",
               "Safe, local attack scenarios against this app's own database and login. No real EV or network is touched.")

role = ui.current_role()
if not authentication.has_permission(role, "simulate_attack"):
    st.error("Access denied: attack simulations are restricted to administrators. "
             "You are signed in as a viewer.")
    st.stop()

limits = ui.get_limits()
results = st.session_state.setdefault("attack_results", {})
if "flash" in st.session_state:
    st.success(st.session_state.pop("flash"))

st.markdown("Severity levels: " + " ".join(ui.severity_badge(s) for s in det.SEVERITIES), unsafe_allow_html=True)
st.write("")


# ------------------------------------------------------------- attack logic
def run_tampering(target: str) -> dict:
    """Attack 1: overwrite a stored sensor value, then verify SHA-256 integrity."""
    steps = []
    record = database.get_latest_reading()
    if record is None or not integrity_check.verify_reading(record)["ok"]:
        record, _, _ = ui.step_and_store()  # attack a fresh, untouched reading
        steps.append(("No clean reading available, generated reading #%d" % record["id"], "info"))
    before = integrity_check.verify_reading(record)
    steps.append((f"Integrity check before attack on reading #{record['id']}: "
                  f"{'PASS' if before['ok'] else 'FAIL'}", "ok" if before["ok"] else "crit"))

    if target == "Temperature (hide overheating)":
        field, forged = "temperature", round(max(record["temperature"] - 20.0, 5.0), 2)
    elif target == "Voltage (inflate)":
        field, forged = "voltage", round(record["voltage"] * 1.15, 2)
    else:
        field, forged = "voltage", 520.0
    original = record[field]
    database.update_reading_value(record["id"], field, forged)
    steps.append((f"Attacker changed {field} from {original} to {forged} directly in battery.db", "crit"))

    tampered = database.get_reading(record["id"])
    previous = database.get_reading(record["id"] - 1)
    verdict = det.detect_tampering(tampered, previous)
    chk = verdict["integrity"]
    steps.append((f"Integrity check after attack: {'PASS' if chk['ok'] else 'FAIL - hash mismatch'}",
                  "ok" if chk["ok"] else "crit"))
    for a in verdict["anomalies"]:
        steps.append((f"Anomaly detector: {a}", "warn"))

    if verdict["detected"]:
        sev = det.tamper_severity(field, forged)
        trusted = (chk["trusted"] or "none")[:12]
        desc = (f"Reading #{record['id']}: {field} altered from {original} to {forged} in battery.db. "
                f"SHA-256 check failed (protected {trusted}… vs recomputed {chk['computed'][:12]}…)."
                + (" Anomalies: " + "; ".join(verdict["anomalies"]) + "." if verdict["anomalies"] else ""))
        alert_id = database.insert_alert(det.ATTACK_TAMPERING, desc, sev, "Detected")
        steps.append((f"Alert #{alert_id} stored with severity {sev}", "warn"))
        return {"steps": steps, "severity": sev}
    steps.append(("Tampering was NOT detected", "crit"))
    return {"steps": steps, "severity": None}


WORDLIST = ["123456", "password", "admin", "qwerty", "letmein", "Admin123", "welcome1", "12345678", "iloveyou", "root"]


def run_unauthorized(target_user: str, attempts: int) -> dict:
    """Attack 2: guess passwords against the real login function."""
    steps, rows, cracked = [], [], False
    for k in range(attempts):
        guess = WORDLIST[k % len(WORDLIST)]
        user = authentication.authenticate(target_user, guess)
        shown = guess[0] + "•" * (len(guess) - 1)
        if user:
            cracked = True
            rows.append((k + 1, shown, "ACCEPTED"))
            break
        rows.append((k + 1, shown, "REJECTED"))
        time.sleep(0.05)
    failed = sum(1 for r in rows if r[2] == "REJECTED")
    for n, shown, res in rows:
        steps.append((f"Attempt {n} as '{target_user}' with password {shown}: {res}",
                      "ok" if res == "REJECTED" else "crit"))
    if cracked:
        sev = "CRITICAL"
        desc = f"Password guessing against '{target_user}' SUCCEEDED after {failed} failures. Change this password."
        status = "Detected"
    else:
        sev = det.login_failure_severity(failed, target_user == "admin")
        desc = (f"{failed} failed login attempts against '{target_user}' from simulated client 203.0.113.45. "
                "Credentials rejected, access denied.")
        status = "Blocked"
    alert_id = database.insert_alert(det.ATTACK_UNAUTHORIZED, desc, sev, status)
    steps.append((f"Access denied. Alert #{alert_id} stored with severity {sev}", "warn" if not cracked else "crit"))
    return {"steps": steps, "severity": sev}


def apply_command(action: str, current: float):
    """Apply an ACCEPTED command to the simulated charger."""
    sim = ui.get_simulator()
    if action == "SET_CHARGE_CURRENT":
        sim.charge_current_setpoint = current
    elif action == "START_CHARGING":
        sim.charging_allowed = True
        sim.charge_current_setpoint = current
    elif action == "STOP_CHARGING":
        sim.charging_allowed = False


def run_command(actor_role, actor_label: str, action: str, current: float) -> dict:
    """Attack 3 / command console: validate permission and safety, then accept or reject."""
    latest = database.get_latest_reading()
    soc = latest["soc"] if latest else 50.0
    temp = latest["temperature"] if latest else 30.0
    decision = det.validate_charging_command(actor_role, action, current, soc, temp, limits)
    steps = [(f"Command received from {actor_label}: {action}"
              + (f" = {current:.0f} A" if action != "STOP_CHARGING" else ""), "info"),
             (f"Pack context: SOC {soc:.0f} %, temperature {temp:.0f} °C", "info")]
    if decision["allowed"]:
        apply_command(action, current)
        steps.append(("Permission and safety checks passed. Command accepted and applied to the simulated charger.", "ok"))
        return {"steps": steps, "severity": None}
    for v in decision["violations"]:
        steps.append((f"Rejected: {v}", "crit"))
    desc = (f"{actor_label} sent {action}"
            + (f" ({current:.0f} A)" if action != "STOP_CHARGING" else "")
            + ". Command rejected: " + "; ".join(decision["violations"]) + ".")
    alert_id = database.insert_alert(det.ATTACK_CHARGING, desc, decision["severity"], "Blocked")
    steps.append((f"Command blocked. Alert #{alert_id} stored with severity {decision['severity']}", "warn"))
    return {"steps": steps, "severity": decision["severity"]}


def result_panel(key: str):
    res = results.get(key)
    if res:
        sev = ui.severity_badge(res["severity"]) if res["severity"] else ui.badge("NO ALERT", ui.COLORS["green"])
        st.markdown(f'<div class="vs-panel"><b>Detection log</b> {sev}{ui.steps_html(res["steps"])}</div>',
                    unsafe_allow_html=True)


# ---------------------------------------------------------------- the cards
c1, c2, c3 = st.columns(3)
with c1:
    st.markdown('<div class="vs-panel"><h4>Attack 1 · Sensor data tampering</h4>'
                '<p>Changes a stored sensor value, then checks SHA-256 integrity against the protected vault.</p></div>',
                unsafe_allow_html=True)
    target = st.selectbox("Value to forge", ["Temperature (hide overheating)", "Voltage (inflate)",
                                             "Voltage (impossible value)"])
    if st.button("Run tampering attack", type="primary", key="b1"):
        results["tamper"] = run_tampering(target)
with c2:
    st.markdown('<div class="vs-panel"><h4>Attack 2 · Unauthorized access</h4>'
                '<p>Guesses passwords against the real login. Wrong credentials are rejected and recorded.</p></div>',
                unsafe_allow_html=True)
    victim = st.selectbox("Target account", ["admin", "viewer", "root"])
    attempts = st.slider("Login attempts", 1, 10, 5)
    if st.button("Run unauthorized login", type="primary", key="b2"):
        results["login"] = run_unauthorized(victim, attempts)
with c3:
    st.markdown('<div class="vs-panel"><h4>Attack 3 · Charging command manipulation</h4>'
                '<p>An unauthenticated sender tries to force a 350 A charging current.</p></div>',
                unsafe_allow_html=True)
    st.write("")
    if st.button("Run command manipulation", type="primary", key="b3"):
        results["charge"] = run_command(None, "Unknown client (no session)", "SET_CHARGE_CURRENT", 350.0)

r1, r2, r3 = st.columns(3)
with r1:
    result_panel("tamper")
with r2:
    result_panel("login")
with r3:
    result_panel("charge")

with st.expander("Charging command console (try allowed and rejected commands)"):
    st.caption("The same permission and safety checks decide every command. Accepted commands change the simulated charger.")
    k1, k2, k3 = st.columns(3)
    with k1:
        who = st.selectbox("Sender", ["Unauthenticated", "Viewer", "Administrator"], index=2)
    with k2:
        action = st.selectbox("Command", ["SET_CHARGE_CURRENT", "START_CHARGING", "STOP_CHARGING"])
    with k3:
        amps = st.number_input("Charging current (A)", 0.0, 500.0, 60.0, 5.0)
    if st.button("Send command", key="send_cmd"):
        actor = {"Unauthenticated": None, "Viewer": authentication.ROLE_VIEWER, "Administrator": authentication.ROLE_ADMIN}[who]
        results["console"] = run_command(actor, who, action, amps)
    result_panel("console")

# ------------------------------------------------------------------- reset
st.markdown("---")
st.markdown("##### Reset simulation")
st.caption("Restores tampered readings from the protected vault, resolves open tampering alerts and resets charger commands.")
o1, o2 = st.columns(2)
with o1:
    wipe_alerts = st.checkbox("Also clear alert history")
with o2:
    wipe_readings = st.checkbox("Also delete all battery readings")
if st.button("Reset simulation"):
    restored = 0
    if wipe_readings:
        database.clear_readings()
        st.session_state.pop("sim", None)
    else:
        df = database.get_readings()
        ok_map = integrity_check.verify_many(df.to_dict("records"))
        for rid, ok in ok_map.items():
            if not ok:
                backup = integrity_check.get_backup(rid)
                if backup:
                    database.restore_reading(backup)
                    restored += 1
        sim = ui.get_simulator()
        sim.charging_allowed, sim.charge_current_setpoint = True, 60.0
    resolved = database.resolve_alerts(det.ATTACK_TAMPERING, "Resolved")
    if wipe_alerts:
        database.clear_alerts()
    st.session_state["attack_results"] = {}
    st.session_state["flash"] = (f"Simulation reset. Restored {restored} tampered reading(s), "
                                 f"resolved {resolved} tampering alert(s).")
    st.rerun()
