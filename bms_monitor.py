"""
bms_monitor.py
Battery Management System (BMS) limit checking for the simulated pack.
"""

# Configurable limits for a 96S Li-ion pack (all simulated)
DEFAULT_LIMITS = {
    "voltage_min": 300.0,          # V  - critical below (3.13 V/cell)
    "voltage_max": 415.0,          # V  - critical above
    "voltage_warn_margin": 10.0,   # V  - warning when this close to a limit
    "temp_warn": 45.0,             # degC
    "temp_max": 55.0,              # degC - critical above
    "current_discharge_max": 200.0,  # A
    "current_charge_max": 100.0,     # A  - also the maximum allowed charging command
    "current_warn_ratio": 0.8,     # warn at 80 % of a current limit
    "soc_low_warn": 20.0,          # %
    "soc_low_critical": 10.0,      # %
    "soc_high_warn": 95.0,         # %
}


def charging_state(current: float) -> str:
    """Charging / Discharging / Idle from the sign of the current."""
    if current > 1:
        return "Charging"
    if current < -1:
        return "Discharging"
    return "Idle"


def check_reading(reading: dict, limits: dict = None) -> list:
    """
    Compare a reading with the limits.
    Returns a list of {parameter, level ('warning'|'critical'), message}.
    """
    lim = limits or DEFAULT_LIMITS
    issues = []

    def add(param, level, msg):
        issues.append({"parameter": param, "level": level, "message": msg})

    v, i, t, soc = reading["voltage"], reading["current"], reading["temperature"], reading["soc"]

    if v < lim["voltage_min"]:
        add("Voltage", "critical", f"Under-voltage: {v:.1f} V is below {lim['voltage_min']:.0f} V")
    elif v > lim["voltage_max"]:
        add("Voltage", "critical", f"Over-voltage: {v:.1f} V is above {lim['voltage_max']:.0f} V")
    elif v < lim["voltage_min"] + lim["voltage_warn_margin"]:
        add("Voltage", "warning", f"Voltage low: {v:.1f} V is close to the minimum")
    elif v > lim["voltage_max"] - lim["voltage_warn_margin"]:
        add("Voltage", "warning", f"Voltage high: {v:.1f} V is close to the maximum")

    if t > lim["temp_max"]:
        add("Temperature", "critical", f"Over-temperature: {t:.1f} °C is above {lim['temp_max']:.0f} °C")
    elif t > lim["temp_warn"]:
        add("Temperature", "warning", f"Temperature high: {t:.1f} °C is above {lim['temp_warn']:.0f} °C")

    if i < 0:
        limit, name = lim["current_discharge_max"], "discharge"
    else:
        limit, name = lim["current_charge_max"], "charge"
    if abs(i) > limit:
        add("Current", "critical", f"Over-current: {abs(i):.1f} A exceeds the {name} limit of {limit:.0f} A")
    elif abs(i) > limit * lim["current_warn_ratio"]:
        add("Current", "warning", f"High {name} current: {abs(i):.1f} A is near the {limit:.0f} A limit")

    if soc < lim["soc_low_critical"]:
        add("SOC", "critical", f"SOC critically low: {soc:.1f} %")
    elif soc < lim["soc_low_warn"]:
        add("SOC", "warning", f"SOC low: {soc:.1f} %")
    elif soc > lim["soc_high_warn"]:
        add("SOC", "warning", f"SOC very high: {soc:.1f} %")

    return issues


def overall_status(issues: list) -> str:
    """NORMAL / WARNING / CRITICAL for a list returned by check_reading()."""
    if any(x["level"] == "critical" for x in issues):
        return "CRITICAL"
    if issues:
        return "WARNING"
    return "NORMAL"
