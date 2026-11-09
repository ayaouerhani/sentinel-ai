import sqlite3
from datetime import datetime

import joblib
import pandas as pd

DB_PATH = "data/sentinel.db"
SCAN_MIN_PORTS = 20     # >= 20 ports mokhtalfin = PortScan
SCAN_CRIT_PORTS = 100   # >= 100 ports = Critical

bundle = joblib.load("models/rf_cic.joblib")
model, FEATURES = bundle["model"], bundle["features"]
flows = pd.read_csv("data/flows_live.csv")
now = datetime.now().isoformat(timespec="seconds")
alerts = []

# ---------- 1. Rule: PortScan (corrélation par IP) ----------
no_data = flows[
    (flows["proto"] == "TCP")
    & (flows["fwd_bytes"] == 0) & (flows["bwd_bytes"] == 0)
    & (flows["total_pkts"] <= 3)
]
ports_per_pair = no_data.groupby(["src", "dst"])["dport"].nunique()
scan_pairs = set()
for (src, dst), n in ports_per_pair[ports_per_pair >= SCAN_MIN_PORTS].items():
    scan_pairs.add((src, dst))
    sev = "Critical" if n >= SCAN_CRIT_PORTS else "High"
    alerts.append((now, src, dst, "RULE", "PortScan", sev, f"{n} ports distincts sondés"))

# ---------- 2. Model ML (CIC) ----------
X = pd.DataFrame({
    "Destination Port": flows["dport"],
    "Flow Duration": flows["duration"] * 1_000_000,   # thawéni -> microsecondes
    "Total Fwd Packets": flows["fwd_pkts"],
    "Total Backward Packets": flows["bwd_pkts"],
    "Total Length of Fwd Packets": flows["fwd_bytes"],
    "Total Length of Bwd Packets": flows["bwd_bytes"],
    "SYN Flag Count": flows["syn"],
    "FIN Flag Count": flows["fin"],
    "RST Flag Count": flows["rst"],
})[FEATURES].astype("float32")

proba = model.predict_proba(X)
flows["pred"] = model.classes_[proba.argmax(axis=1)]
flows["confidence"] = proba.max(axis=1)

ml = flows[flows["pred"] != "Normal"]
for _, r in ml.iterrows():
    if (r["src"], r["dst"]) in scan_pairs:
        continue  # deja couvert par el rule PortScan
    c = r["confidence"]
    sev = "High" if c >= 0.9 else ("Medium" if c >= 0.7 else "Low")
    alerts.append((now, r["src"], r["dst"], "ML", r["pred"], sev,
                   f"{r['pred']} (confidence {c:.2f}, port {int(r['dport'])})"))

# ---------- 3. SQLite ----------
conn = sqlite3.connect(DB_PATH)
conn.execute("""
    CREATE TABLE IF NOT EXISTS live_alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT, src TEXT, dst TEXT,
        detected_by TEXT, attack_type TEXT, severity TEXT, detail TEXT
    )""")
conn.executemany(
    """INSERT INTO live_alerts
       (timestamp, src, dst, detected_by, attack_type, severity, detail)
       VALUES (?,?,?,?,?,?,?)""", alerts)
conn.commit()
conn.close()

print(f"Flows analysés: {len(flows)} | Alerts: {len(alerts)}")
for a in alerts:
    print(f"[{a[5]:8}] {a[4]:10} {a[1]} -> {a[2]} | {a[3]} | {a[6]}")