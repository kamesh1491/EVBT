"""
selftest.py - automated checks for the VoltShield backend.
Run:  python selftest.py
Uses a temporary folder, so your real data/ folder is never touched.
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from modules import attack_detector as det, authentication as auth, bms_monitor, database, integrity_check

tmp = tempfile.mkdtemp()
database.DATA_DIR, database.DB_PATH = tmp, os.path.join(tmp, "battery.db")
integrity_check.DATA_DIR = tmp
integrity_check.VAULT_PATH = os.path.join(tmp, "vault.db")
integrity_check.KEY_PATH = os.path.join(tmp, "integrity.key")

passed = failed = 0


def check(name, condition):
    global passed, failed
    if condition:
        passed += 1
        print(f"  PASS  {name}")
    else:
        failed += 1
        print(f"  FAIL  {name}")


from modules.battery_simulator import BatterySimulator

database.init_db()
auth.ensure_default_users()
L = bms_monitor.DEFAULT_LIMITS

print("Simulator and database")
sim = BatterySimulator()
for _ in range(30):
    r = sim.step(60)
    rec = database.insert_reading(**r)
check("30 readings stored", database.count_readings() == 30)
check("readings stay in physical range", not det.classify_readings(database.get_readings())["suspicious"].any())

print("SHA-256 integrity")
latest = database.get_latest_reading()
check("untouched record verifies", integrity_check.verify_reading(latest)["ok"])
database.update_reading_value(latest["id"], "temperature", 15.0)
check("edited value is detected", not integrity_check.verify_reading(database.get_reading(latest["id"]))["ok"])
import sqlite3
con = sqlite3.connect(database.DB_PATH)
forged = database.get_reading(latest["id"])
forged_hash = integrity_check.compute_hash(forged)  # best case for attacker: needs the secret key
con.execute("UPDATE battery_readings SET integrity_hash = ? WHERE id = ?", ("0" * 64, latest["id"]))
con.commit(); con.close()
check("forged hash column does not help attacker", not integrity_check.verify_reading(database.get_reading(latest["id"]))["ok"])
cls = det.classify_readings(database.get_readings())
check("tampered row marked suspicious in reports", bool(cls.iloc[-1]["suspicious"]) and cls["suspicious"].sum() == 1)
database.restore_reading(integrity_check.get_backup(latest["id"]))
check("restore from vault repairs the record", integrity_check.verify_reading(database.get_reading(latest["id"]))["ok"])

print("Authentication")
check("admin logs in", (auth.authenticate("admin", "Admin@123") or {}).get("role") == "admin")
check("viewer logs in", (auth.authenticate("viewer", "Viewer@123") or {}).get("role") == "viewer")
check("wrong password rejected", auth.authenticate("admin", "wrong") is None)
check("unknown user rejected", auth.authenticate("nobody", "x") is None)
check("passwords are salted PBKDF2 hashes", database.get_user("admin")["password_hash"].startswith("pbkdf2_sha256$"))
check("viewer cannot simulate attacks", not auth.has_permission("viewer", "simulate_attack"))
check("admin can simulate attacks", auth.has_permission("admin", "simulate_attack"))

print("BMS and detection")
base = {"voltage": 360, "current": -50, "temperature": 30, "soc": 55}
check("normal reading has no BMS issues", bms_monitor.check_reading(base, L) == [])
check("over-temperature is critical", bms_monitor.overall_status(bms_monitor.check_reading({**base, "temperature": 60}, L)) == "CRITICAL")
check("over-current is critical", bms_monitor.overall_status(bms_monitor.check_reading({**base, "current": -250}, L)) == "CRITICAL")
check("impossible voltage flagged", bool(det.detect_abnormal_values({**base, "voltage": 520})))
check("unauthenticated 350 A command rejected", not det.validate_charging_command(None, "SET_CHARGE_CURRENT", 350, 60, 30, L)["allowed"])
check("viewer command rejected", not det.validate_charging_command("viewer", "STOP_CHARGING", 0, 60, 30, L)["allowed"])
check("admin safe command accepted", det.validate_charging_command("admin", "SET_CHARGE_CURRENT", 60, 60, 30, L)["allowed"])
check("admin unsafe current rejected", not det.validate_charging_command("admin", "SET_CHARGE_CURRENT", 180, 60, 30, L)["allowed"])
check("severity grows with failed logins", det.login_failure_severity(1) == "LOW" and det.login_failure_severity(9) == "CRITICAL")

print("Alerts")
aid = database.insert_alert(det.ATTACK_TAMPERING, "test", "HIGH", "Detected")
check("alert stored", database.count_alerts() == 1)
check("alert resolved", database.resolve_alerts(det.ATTACK_TAMPERING) == 1)
check("SQL injection text is stored harmlessly",
      database.insert_alert("x'; DROP TABLE users;--", "d", "LOW") > aid and database.get_user("admin") is not None)

print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
