"""
battery_simulator.py
Simulated EV battery pack (96S Li-ion, ~355 V nominal, 150 Ah, ~53 kWh).
ALL VALUES ARE SIMULATED - no real hardware or vehicle is involved.

Sign convention: current > 0 = charging, current < 0 = discharging.
"""
import random

import numpy as np

CELLS = 96
# Open-circuit voltage curve of one Li-ion cell: (SOC %, volts)
_SOC_POINTS = [0, 10, 20, 50, 80, 100]
_CELL_V_POINTS = [3.00, 3.45, 3.60, 3.80, 4.05, 4.20]
PACK_RESISTANCE_OHM = 0.08  # internal resistance of the whole pack


def ocv_pack_voltage(soc, cells: int = CELLS):
    """Open-circuit pack voltage for a given SOC (works on scalars and arrays)."""
    return np.interp(soc, _SOC_POINTS, _CELL_V_POINTS) * cells


class BatterySimulator:
    """Physics-inspired battery model that produces one reading per step()."""

    def __init__(self, capacity_ah: float = 150.0, soc: float = 65.0,
                 temperature: float = 32.0, ambient: float = 30.0):
        self.capacity_ah = capacity_ah
        self.soc = soc
        self.temperature = temperature
        self.ambient = ambient
        self.mode = "discharging"          # charging | discharging | idle
        self.charging_allowed = True       # changed by authorised charging commands
        self.charge_current_setpoint = 60.0  # A, changed by authorised commands
        self.charge_start_soc = 20.0       # plug in below this SOC
        self.charge_stop_soc = 95.0        # unplug above this SOC
        self._load = 55.0                  # driving load random walk (A)

    @classmethod
    def from_reading(cls, reading: dict):
        """Continue from the last stored reading so the history stays continuous."""
        sim = cls(soc=float(reading["soc"]), temperature=float(reading["temperature"]))
        sim.mode = "charging" if reading["current"] > 1 else "discharging"
        return sim

    def _update_mode(self):
        if self.mode == "discharging" and self.soc <= self.charge_start_soc:
            self.mode = "charging"
        elif self.mode == "charging" and self.soc >= self.charge_stop_soc:
            self.mode = "discharging"
        if self.mode == "charging" and not self.charging_allowed:
            self.mode = "idle"
        if self.mode == "idle" and self.charging_allowed and self.soc < self.charge_stop_soc:
            self.mode = "charging"

    def step(self, dt_s: float = 60.0, load_factor: float = 1.0) -> dict:
        """Advance the simulation by dt_s simulated seconds and return a reading."""
        self._update_mode()
        if self.mode == "discharging":
            self._load = min(110.0, max(25.0, self._load + random.gauss(0, 6)))
            current = -self._load * load_factor
        elif self.mode == "charging":
            # CC-CV style taper above 85 % SOC
            taper = 1.0 if self.soc <= 85 else max(0.15, (100 - self.soc) / 15)
            current = self.charge_current_setpoint * taper
        else:
            current = 0.0
        current += random.gauss(0, 0.4)

        # Coulomb counting
        self.soc = min(100.0, max(0.0, self.soc + current * dt_s / 3600 / self.capacity_ah * 100))
        # Heat from current, with thermal lag toward a target temperature
        target = self.ambient + 0.12 * abs(current)
        self.temperature += (target - self.temperature) * 0.15 + random.gauss(0, 0.15)
        voltage = float(ocv_pack_voltage(self.soc)) + current * PACK_RESISTANCE_OHM + random.gauss(0, 0.4)

        status = "Charging" if current > 1 else "Discharging" if current < -1 else "Idle"
        return {
            "voltage": round(voltage, 2),
            "current": round(current, 2),
            "temperature": round(self.temperature, 2),
            "soc": round(self.soc, 2),
            "charging_status": status,
        }
