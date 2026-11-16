"""
attack_detector.py
Cybersecurity detection engine: abnormal sensor values, sensor tampering,
failed-login analysis and charging-command validation.
"""
import numpy as np
import pandas as pd

from modules import authentication, integrity_check
from modules.battery_simulator import ocv_pack_voltage

ATTACK_TAMPERING = "Sensor Data Tampering"
ATTACK_UNAUTHORIZED = "Unauthorized Access"
ATTACK_CHARGING = "Charging Command Manipulation"
SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

# Physical plausibility ranges and tolerances (simulated pack)
RANGES = {"voltage": (250.0, 450.0), "temperature": (-20.0, 80.0), "soc": (0.0, 100.0), "current": (-400.0, 200.0)}
OCV_TOLERANCE_V = 40.0
SPIKE = {"temperature": 6.0, "voltage": 30.0, "soc": 5.0}  # max jump between neighbouring readings
MAX_GAP_SECONDS = 600


# ------------------------------------------------------- abnormal values
def detect_abnormal_values(reading: dict, previous: dict = None) -> list:
    """Single-reading checks. Returns a list of human-readable problems."""
    problems = []
    for key, (lo, hi) in RANGES.items():
        if not lo <= reading[key] <= hi:
            problems.append(f"{key} {reading[key]} outside physical range {lo} to {hi}")
    expected = float(ocv_pack_voltage(min(max(reading["soc"], 0), 100)))
    if abs(reading["voltage"] - expected) > OCV_TOLERANCE_V:
        problems.append(f"voltage {reading['voltage']} V inconsistent with SOC {reading['soc']} % "
                        f"(expected about {expected:.0f} V)")
    if previous is not None:
        for key, limit in SPIKE.items():
            if abs(reading[key] - previous[key]) > limit:
                problems.append(f"sudden {key} jump of {abs(reading[key] - previous[key]):.1f}")
    return problems


def classify_readings(df: pd.DataFrame) -> pd.DataFrame:
    """
    Add 'suspicious' (bool) and 'reason' (text) columns to a readings DataFrame.
    Suspicious = hash mismatch, impossible value, SOC/voltage mismatch, or an isolated spike.
    """
    out = df.copy()
    if out.empty:
        out["suspicious"], out["reason"] = [], []
        return out

    reasons = pd.Series([[] for _ in range(len(out))], index=out.index)

    def flag(mask, text):
        for idx in out.index[mask.fillna(False).to_numpy()]:
            reasons.at[idx] = reasons.at[idx] + [text]

    # 1. SHA-256 integrity (compared with the separate vault)
    ok_map = integrity_check.verify_many(out.to_dict("records"))
    flag(~out["id"].map(ok_map).astype(bool), "SHA-256 integrity mismatch")

    # 2. Physical plausibility
    for key, (lo, hi) in RANGES.items():
        flag((out[key] < lo) | (out[key] > hi), f"{key} outside physical range")

    # 3. SOC vs voltage consistency
    expected = ocv_pack_voltage(out["soc"].clip(0, 100).to_numpy())
    flag(pd.Series(np.abs(out["voltage"].to_numpy() - expected) > OCV_TOLERANCE_V, index=out.index),
         "voltage inconsistent with SOC")

    # 4. Isolated spikes: far from the previous reading AND far from the next one
    times = pd.to_datetime(out["timestamp"])
    gap_prev = times.diff().dt.total_seconds().abs() <= MAX_GAP_SECONDS
    gap_next = (-times.diff(-1).dt.total_seconds()).abs() <= MAX_GAP_SECONDS
    for key, limit in SPIKE.items():
        d_prev = (out[key] - out[key].shift(1)).abs()
        d_next = (out[key] - out[key].shift(-1)).abs()
        has_prev = (d_prev > limit) & gap_prev
        next_far = (d_next > limit) & gap_next   # next reading is also far away
        spike = has_prev & (next_far | d_next.isna())
        flag(spike, f"{key} spike")

    out["suspicious"] = reasons.apply(len) > 0
    out["reason"] = reasons.apply(lambda r: "; ".join(r))
    return out


# ------------------------------------------------------------ tampering
def tamper_severity(field: str, new_value: float) -> str:
    """CRITICAL when the forged value is physically impossible, otherwise HIGH."""
    lo, hi = RANGES.get(field, (-1e9, 1e9))
    return "CRITICAL" if not lo <= new_value <= hi else "HIGH"


def detect_tampering(record: dict, previous: dict = None) -> dict:
    """Combine SHA-256 verification with anomaly checks on one stored record."""
    check = integrity_check.verify_reading(record)
    anomalies = detect_abnormal_values(record, previous)
    return {"detected": (not check["ok"]) or bool(anomalies),
            "integrity_ok": check["ok"], "integrity": check, "anomalies": anomalies}


# --------------------------------------------------------------- logins
def login_failure_severity(attempts: int, targets_admin: bool = False) -> str:
    """Severity grows with the number of failed attempts; admin targets rank higher."""
    level = 0 if attempts <= 2 else 1 if attempts <= 4 else 2 if attempts <= 7 else 3
    if targets_admin:
        level = min(level + 1, 3)
    return SEVERITIES[level]


# ------------------------------------------------------ charging command
def validate_charging_command(actor_role, action: str, requested_current: float,
                              soc: float, temperature: float, limits: dict) -> dict:
    """
    Check permission and safety of a charging command.
    action: SET_CHARGE_CURRENT | START_CHARGING | STOP_CHARGING
    Returns {allowed, violations, severity}.
    """
    violations, score = [], 0
    if actor_role is None:
        violations.append("Unauthenticated sender (no valid session)")
        score += 2
    elif not authentication.has_permission(actor_role, "send_charge_command"):
        violations.append(f"Role '{actor_role}' has no permission to control charging")
        score += 1

    if action in ("SET_CHARGE_CURRENT", "START_CHARGING"):
        if requested_current > limits["current_charge_max"]:
            violations.append(f"Requested {requested_current:.0f} A exceeds safe charge limit "
                              f"{limits['current_charge_max']:.0f} A")
            score += 2 if requested_current >= 2 * limits["current_charge_max"] else 1
        if soc >= limits["soc_high_warn"] and requested_current > 0:
            violations.append(f"Battery already at {soc:.0f} % SOC - overcharge risk")
            score += 1
        if temperature >= limits["temp_warn"]:
            violations.append(f"Pack temperature {temperature:.0f} °C is too high to start charging")
            score += 1

    if not violations:
        return {"allowed": True, "violations": [], "severity": None}
    severity = "MEDIUM" if score <= 1 else "HIGH" if score == 2 else "CRITICAL"
    return {"allowed": False, "violations": violations, "severity": severity}
