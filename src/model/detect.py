import sqlite3
from datetime import datetime, timedelta

import joblib
import pandas as pd

from common import load

N_EVENTS = 500  # 9addech men connexion nsimulou
DB_PATH = "data/sentinel.db"

rf = joblib.load("models/rf_nsl_kdd.joblib")
bundle = joblib.load("models/if_nsl_kdd.joblib")
pre, iso = bundle["pre"], bundle["iso"]


def severity(rf_flag, if_flag, p, score):
    """Niveau de gravité selon el accord bin el 2 models."""
    if rf_flag and if_flag:
        return "Critical" if p >= 0.9 else "High"
    if rf_flag:
        return "High" if p >= 0.9 else "Medium"
    return "Medium" if score < -0.05 else "Low"  # IF bark


def detect(X):
    p = rf.predict_proba(X)[:, 1]           # proba attaque (RF)
    rf_flag = p >= 0.5
    Xt = pre.transform(X)
    score = iso.decision_function(Xt)       # < 0 = anomalie
    if_flag = iso.predict(Xt) == -1
    return p, rf_flag, score, if_flag


def init_db(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            protocol TEXT,
            service TEXT,
            flag TEXT,
            src_bytes INTEGER,
            dst_bytes INTEGER,
            rf_prob REAL,
            if_score REAL,
            detected_by TEXT,
            severity TEXT,
            actual_label TEXT
        )
    """)


# Simulation: n9ou el connexions men test set (fi live bech yjiw men Scapy)
X_test, y_test = load("data/KDDTest+.txt")
sample = X_test.sample(N_EVENTS, random_state=1)
actual = y_test.loc[sample.index]

p, rf_flag, score, if_flag = detect(sample)

now = datetime.now()
rows = []
for i, (idx, r) in enumerate(sample.iterrows()):
    if not (rf_flag[i] or if_flag[i]):
        continue  # trafic normal: ma n3amlou alert
    by = "RF+IF" if (rf_flag[i] and if_flag[i]) else ("RF" if rf_flag[i] else "IF")
    ts = (now - timedelta(seconds=(N_EVENTS - i) * 2)).isoformat(timespec="seconds")
    rows.append((
        ts, r["protocol_type"], r["service"], r["flag"],
        int(r["src_bytes"]), int(r["dst_bytes"]),
        float(p[i]), float(score[i]), by,
        severity(rf_flag[i], if_flag[i], p[i], score[i]),
        "Attack" if actual.loc[idx] == 1 else "Normal",
    ))

conn = sqlite3.connect(DB_PATH)
init_db(conn)
conn.executemany(
    """INSERT INTO alerts (timestamp, protocol, service, flag, src_bytes, dst_bytes,
       rf_prob, if_score, detected_by, severity, actual_label)
       VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
    rows,
)
conn.commit()

df = pd.read_sql("SELECT * FROM alerts", conn)
conn.close()

print(f"Connexions analysées: {N_EVENTS} | Alerts générées: {len(rows)}")
print("\nAlerts par severity:")
print(df["severity"].value_counts().to_string())
print("\nSeverity vs réalité (actual_label):")
print(pd.crosstab(df["severity"], df["actual_label"]).to_string())