# VoltShield – Secure EV Battery Monitoring and Cyberattack Detection System

A simulation-based academic mini-project for **Electric and Battery Technology (EVBT)**.
It simulates an EV battery pack and its Battery Management System (BMS), then detects three
simulated cyberattacks using SHA-256 integrity checks, role-based access control and command validation.

> All battery values are **simulated**. No hardware, no paid APIs, and no real vehicle, charger or network
> is ever attacked. Every attack runs only against this app's own local SQLite files and login.

## 1. Run it (Windows PowerShell)

```powershell
cd VoltShield
python -m venv .venv
.\.venv\Scripts\Activate.ps1
# If activation is blocked:  Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
pip install -r requirements.txt
python selftest.py          # optional: 26 automated backend checks
streamlit run app.py
```

Open http://localhost:8501. The database (`data/battery.db`) and demo users are created automatically.

| Role | Username | Password | Can do |
|---|---|---|---|
| Administrator | `admin` | `Admin@123` | Everything, including attack simulation, BMS limits, reset |
| Viewer | `viewer` | `Viewer@123` | View dashboards, alerts, reports, export CSV |

## 2. Architecture

```
Battery Simulation (battery_simulator.py)
        |
        v
Battery Management System (bms_monitor.py)  -> warnings for voltage / current / temperature / SOC
        |
        v
Cybersecurity Detection Engine (attack_detector.py)
        +-- Sensor tampering detection
        +-- Unauthorized access detection
        +-- Charging command validation
        |
        v
SHA-256 Data Integrity Verification (integrity_check.py)
        |
        v
SQLite Database (database.py)  -> battery.db (readings, alerts, users) + vault.db (protected hashes)
        |
        v
Streamlit Dashboard (app.py + pages/)  -> alerts, graphs, reports, CSV
```

`modules/ui.py` holds shared styling and the glue that sends one reading through the whole pipeline.
`authentication.py` sits beside the pipeline and guards every page and every administrative action.

### How integrity protection works
1. When a reading is saved, its fields are hashed with **HMAC-SHA256** (Python `hashlib` + `hmac`) using a secret key in `data/integrity.key`.
2. The trusted hash and a golden copy of the reading are stored in a **separate database** (`data/vault.db`).
3. To verify, the hash is recomputed from the record in `battery.db` and compared with the vault using a constant-time comparison.
4. Editing a value, or even overwriting the `integrity_hash` column, is caught because the attacker has neither the key nor the vault.
5. "Reset simulation" restores damaged records from the vault copy.

### The three attacks
| Attack | What really happens | Detection |
|---|---|---|
| Sensor data tampering | A stored temperature or voltage is overwritten in `battery.db` | Hash mismatch against the vault + spike / SOC-voltage plausibility checks. Severity HIGH, CRITICAL if the value is physically impossible |
| Unauthorized access | Wrong passwords are tried against the real login function | Credentials rejected, attempts counted, severity rises with attempts (LOW to CRITICAL, one level higher for the admin account) |
| Charging command manipulation | An unauthenticated sender requests 350 A charging | Permission check + safety limits (max charge current, SOC, temperature). Rejected and logged |

Real failed sign-ins on the login page are also logged as alerts, with a 30-second lockout after 5 failures.

## 3. Project structure

```
VoltShield/
├── app.py                      Login, sidebar navigation, Home dashboard
├── selftest.py                 Automated backend tests
├── requirements.txt
├── .streamlit/config.toml      Dark navy theme
├── modules/
│   ├── battery_simulator.py    Charge / discharge physics (OCV curve, coulomb counting, thermal lag)
│   ├── bms_monitor.py          Configurable limits and warning levels
│   ├── attack_detector.py      Anomaly, tampering, login and command checks
│   ├── integrity_check.py      HMAC-SHA256 hashing and the protected vault
│   ├── authentication.py       PBKDF2 password hashing, roles, permissions
│   ├── database.py             SQLite tables and parameterized queries
│   └── ui.py                   Shared styling and pipeline helper
├── pages/
│   ├── 1_Battery_Monitoring.py
│   ├── 2_Attack_Simulation.py
│   ├── 3_Security_Alerts.py
│   └── 4_Reports.py
└── data/battery.db             Created automatically
```

## 4. Test checklist

1. `python selftest.py` shows `26 passed, 0 failed`.
2. Sign in with a wrong password: an error appears and an "Unauthorized Access" alert is stored.
3. Sign in as `admin`. Home shows metric cards; press **Generate 60 sample readings**.
4. Battery monitoring: press **Start simulation**. Charts update every few seconds and readings are saved. Raise the load factor to 2.0 to trigger BMS warnings.
5. Attack simulation: run all three attacks. Each shows a detection log and creates an alert.
6. Security alerts: filter by severity, type and status; download the CSV.
7. Reports: tampered readings appear as red crosses on the history charts; download both CSVs.
8. Press **Reset simulation**: the tampered reading is restored and the tampering alert becomes "Resolved".
9. Sign out, sign in as `viewer`: the Attack simulation page is denied.

## 5. Demonstration script (about 5 minutes)

1. **Intro (30 s):** "VoltShield simulates an EV battery pack with a BMS and shows how cyberattacks on it are detected."
2. **Home + monitoring (60 s):** Generate readings, start the simulation, point to voltage, current, temperature and SOC, then raise the load to show a BMS warning.
3. **Tampering (60 s):** Run attack 1. Show the hash before (PASS) and after (FAIL), and the alert.
4. **Unauthorized access (45 s):** Run attack 2 against `admin`. Show rejected attempts and the severity.
5. **Charging manipulation (45 s):** Run attack 3. Then use the command console as Administrator with 60 A to show a valid command is accepted.
6. **Alerts + reports (45 s):** Show the alert table, the suspicious point on the temperature chart and the CSV export.
7. **Reset + roles (30 s):** Reset to restore the data, then log in as viewer to show access denied.

## 6. Viva questions and answers

**Q1. What does a BMS do?**
It monitors cell/pack voltage, current, temperature and SOC, keeps them inside safe limits, estimates SOC and health, and protects the pack by limiting or stopping charge and discharge.

**Q2. Why is battery data a cybersecurity target?**
Forged sensor data can hide overheating or overcharging and lead to thermal runaway; forged commands can overcharge a pack; stolen access gives control of vehicle functions.

**Q3. How is SOC calculated here?**
By coulomb counting: SOC changes by current × time ÷ capacity. Voltage comes from an open-circuit-voltage curve plus the I×R drop.

**Q4. What is SHA-256 and why use it?**
A hash function that gives a 256-bit fingerprint of data. Any change gives a completely different hash, so modification is detectable.

**Q5. Why HMAC and a separate vault instead of a plain hash stored next to the data?**
Anyone who can edit the data could recompute and replace a plain hash. HMAC needs a secret key, and the trusted hashes live in a different database, so tampering cannot be hidden.

**Q6. How are passwords stored?**
As salted PBKDF2-HMAC-SHA256 hashes with 200,000 iterations. The password itself is never stored, and the comparison is constant-time.

**Q7. What is role-based access control?**
Permissions depend on the role. Administrators can run attacks, change limits and reset; viewers can only view and export.

**Q8. How is a malicious charging command stopped?**
Two checks: is the sender authorised, and is the command safe (charge current limit, SOC, temperature). Failing either rejects it and logs an incident.

**Q9. How does severity work?**
Tampering is HIGH, or CRITICAL if the value is physically impossible. Login attacks grow from LOW to CRITICAL with the number of failed attempts. Command attacks add up violations: one gives MEDIUM, two HIGH, three or more CRITICAL.

**Q10. How do you prevent SQL injection?**
Every query uses `?` placeholders, so user input is treated as data, never as SQL.

**Q11. What are the limits of this project?**
Values are simulated, there is no real CAN bus or hardware, and the vault is a local file. A real system would use a hardware security module, signed firmware and encrypted communication.

**Q12. What is thermal runaway?**
A self-reinforcing overheating of a Li-ion cell, where heat triggers reactions that create more heat. It is why temperature data must be trustworthy.
