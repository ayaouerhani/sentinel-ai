import sqlite3
import subprocess
import sys
from pathlib import Path
import altair as alt
import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parents[2]
DB_PATH = ROOT / "data" / "sentinel.db"
SEVERITIES = ["Critical", "High", "Medium", "Low"]

st.set_page_config(page_title="SENTINEL AI", page_icon="🛡️", layout="wide")
st.title("🛡️ SENTINEL AI: Intelligent Mini SOC")
st.caption("Detection hybride: Random Forest + Isolation Forest")


def load_alerts():
    if not DB_PATH.exists():
        return None
    conn = sqlite3.connect(DB_PATH)
    try:
        return pd.read_sql("SELECT * FROM alerts", conn)
    except Exception:
        return None
    finally:
        conn.close()


# ---------- Sidebar ----------
st.sidebar.header("Controls")

if st.sidebar.button("🔄 Relancer la simulation"):
    with st.spinner("Analyse du trafic en cours..."):
        DB_PATH.unlink(missing_ok=True)  # nebdaw men zero
        result = subprocess.run(
            [sys.executable, str(ROOT / "src" / "model" / "detect.py")],
            cwd=ROOT, capture_output=True, text=True,
        )
    if result.returncode == 0:
        st.sidebar.success("Simulation terminée")
    else:
        st.sidebar.error("Erreur pendant la simulation")
        st.sidebar.code(result.stderr[-1500:])

df = load_alerts()

if df is None or df.empty:
    st.info("Aucune alerte. Clique sur « Relancer la simulation » ou lance `python src\\model\\detect.py`.")
    st.stop()

sev_filter = st.sidebar.multiselect("Severity", SEVERITIES, default=SEVERITIES)
by_filter = st.sidebar.multiselect(
    "Détecté par", sorted(df["detected_by"].unique()), default=sorted(df["detected_by"].unique())
)

fdf = df[df["severity"].isin(sev_filter) & df["detected_by"].isin(by_filter)]

# ---------- KPIs ----------
true_attacks = (fdf["actual_label"] == "Attack").sum()
precision = true_attacks / len(fdf) * 100 if len(fdf) else 0

c1, c2, c3, c4 = st.columns(4)
c1.metric("Total alerts", len(fdf))
c2.metric("🔴 Critical", int((fdf["severity"] == "Critical").sum()))
c3.metric("🟠 High", int((fdf["severity"] == "High").sum()))
c4.metric("Précision (simulation)", f"{precision:.1f}%")

st.divider()

# ---------- Graphs ----------
left, right = st.columns(2)

with left:
    st.subheader("Alerts par severity")
    sev_counts = fdf["severity"].value_counts().reindex(SEVERITIES).fillna(0)
    sev_df = sev_counts.rename_axis("severity").reset_index(name="count")
    chart = alt.Chart(sev_df).mark_bar().encode(
        x=alt.X("severity:N", sort=SEVERITIES, title=None,
                axis=alt.Axis(labelAngle=0)),
        y=alt.Y("count:Q", scale=alt.Scale(domainMin=0), title="Alerts"),
        color=alt.Color(
            "severity:N",
            scale=alt.Scale(domain=SEVERITIES,
                            range=["#d62728", "#ff7f0e", "#f2c200", "#2ca02c"]),
            legend=None,
        ),
    )
    st.altair_chart(chart, width="stretch")

with right:
    st.subheader("Top 10 services ciblés")
    st.bar_chart(fdf["service"].value_counts().head(10))

left2, right2 = st.columns(2)

with left2:
    st.subheader("Détecté par")
    st.bar_chart(fdf["detected_by"].value_counts())

with right2:
    st.subheader("Protocoles")
    st.bar_chart(fdf["protocol"].value_counts())

st.divider()

# ---------- Table ----------
st.subheader("Dernières alertes")
cols = ["timestamp", "severity", "detected_by", "protocol", "service", "flag",
        "src_bytes", "dst_bytes", "rf_prob", "if_score", "actual_label"]
table = fdf.sort_values("timestamp", ascending=False)[cols].head(100)
st.dataframe(table, use_container_width=True, hide_index=True)
st.caption("`actual_label` mawjouda fil simulation bark (fil live capture ma fammech label).")