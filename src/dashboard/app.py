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
SEV_COLORS = ["#d62728", "#ff7f0e", "#f2c200", "#2ca02c"]

st.set_page_config(page_title="SENTINEL AI", page_icon="🛡️", layout="wide")
st.title("🛡️ SENTINEL AI: Intelligent Mini SOC")
st.caption("Detection hybride: Machine Learning + règles de corrélation")


def read_table(name):
    if not DB_PATH.exists():
        return None
    conn = sqlite3.connect(DB_PATH)
    try:
        return pd.read_sql(f"SELECT * FROM {name}", conn)
    except Exception:
        return None
    finally:
        conn.close()


def run_sql(sql):
    conn = sqlite3.connect(DB_PATH)
    conn.execute(sql)
    conn.commit()
    conn.close()


def severity_chart(df):
    counts = df["severity"].value_counts().reindex(SEVERITIES).fillna(0)
    sev_df = counts.rename_axis("severity").reset_index(name="count")
    chart = alt.Chart(sev_df).mark_bar().encode(
        x=alt.X("severity:N", sort=SEVERITIES, title=None,
                axis=alt.Axis(labelAngle=0)),
        y=alt.Y("count:Q", scale=alt.Scale(domainMin=0), title="Alerts"),
        color=alt.Color(
            "severity:N",
            scale=alt.Scale(domain=SEVERITIES, range=SEV_COLORS),
            legend=None,
        ),
    )
    st.altair_chart(chart, width="stretch")


# ======================= TAB 1: LIVE =======================
def render_live():
    st.subheader("Capture et détection en direct")
    c1, c2, c3, c4 = st.columns([2, 2, 2, 2])
    iface_ip = c1.text_input("IP de l'interface à surveiller", "192.168.1.146")
    duration = c2.slider("Durée de capture (s)", 10, 120, 30)
    run = c3.button("▶️ Lancer capture + détection")
    clear = c4.button("🗑️ Vider les alertes live")

    if clear and DB_PATH.exists():
        run_sql("DROP TABLE IF EXISTS live_alerts")
        st.success("Alertes live supprimées")

    if run:
        with st.spinner(f"Capture en cours ({duration}s)... génère du trafic !"):
            cap = subprocess.run(
                [sys.executable, str(ROOT / "src" / "capture" / "sniff.py"),
                 str(duration), iface_ip],
                cwd=ROOT, capture_output=True, text=True,
            )
        if cap.returncode != 0:
            st.error("La capture a échoué (Npcap, IP de l'interface, droits admin ?)")
            st.code((cap.stdout + cap.stderr)[-1500:])
        else:
            det = subprocess.run(
                [sys.executable, str(ROOT / "src" / "model" / "detect_live.py")],
                cwd=ROOT, capture_output=True, text=True,
            )
            if det.returncode == 0:
                st.success("Analyse terminée")
                st.code(det.stdout[-1500:])
            else:
                st.error("Erreur pendant la détection")
                st.code(det.stderr[-1500:])

    df = read_table("live_alerts")
    if df is None or df.empty:
        st.info("Aucune alerte live. Lance une capture (ou un scan nmap sur ta VM de test).")
        return

    sev_filter = st.multiselect("Severity", SEVERITIES, default=SEVERITIES, key="live_sev")
    fdf = df[df["severity"].isin(sev_filter)]

    k1, k2, k3, k4 = st.columns(4)
    k1.metric("Total alerts", len(fdf))
    k2.metric("🔴 Critical", int((fdf["severity"] == "Critical").sum()))
    k3.metric("🟠 High", int((fdf["severity"] == "High").sum()))
    k4.metric("IPs sources distinctes", fdf["src"].nunique())

    st.divider()
    left, mid, right = st.columns(3)
    with left:
        st.markdown("**Par severity**")
        severity_chart(fdf)
    with mid:
        st.markdown("**Par type d'attaque**")
        st.bar_chart(fdf["attack_type"].value_counts())
    with right:
        st.markdown("**Top IPs sources**")
        st.bar_chart(fdf["src"].value_counts().head(10))

    st.markdown("**Dernières alertes**")
    cols = ["timestamp", "severity", "attack_type", "src", "dst", "detected_by", "detail"]
    st.dataframe(
        fdf.sort_values(["timestamp", "id"], ascending=False)[cols].head(100),
        width="stretch", hide_index=True,
    )


# ======================= TAB 2: SIMULATION =======================
def render_simulation():
    st.subheader("Simulation sur NSL-KDD (RF + Isolation Forest)")
    if st.button("🔄 Relancer la simulation"):
        with st.spinner("Analyse du trafic en cours..."):
            if DB_PATH.exists():
                run_sql("DROP TABLE IF EXISTS alerts")
            result = subprocess.run(
                [sys.executable, str(ROOT / "src" / "model" / "detect.py")],
                cwd=ROOT, capture_output=True, text=True,
            )
        if result.returncode == 0:
            st.success("Simulation terminée")
        else:
            st.error("Erreur pendant la simulation")
            st.code(result.stderr[-1500:])

    df = read_table("alerts")
    if df is None or df.empty:
        st.info("Aucune alerte de simulation. Clique sur « Relancer la simulation ».")
        return

    f1, f2 = st.columns(2)
    sev_filter = f1.multiselect("Severity", SEVERITIES, default=SEVERITIES, key="sim_sev")
    by_all = sorted(df["detected_by"].unique())
    by_filter = f2.multiselect("Détecté par", by_all, default=by_all, key="sim_by")
    fdf = df[df["severity"].isin(sev_filter) & df["detected_by"].isin(by_filter)]

    true_attacks = (fdf["actual_label"] == "Attack").sum()
    precision = true_attacks / len(fdf) * 100 if len(fdf) else 0

    k1, k2, k3, k4 = st.columns(4)
    k1.metric("Total alerts", len(fdf))
    k2.metric("🔴 Critical", int((fdf["severity"] == "Critical").sum()))
    k3.metric("🟠 High", int((fdf["severity"] == "High").sum()))
    k4.metric("Précision (simulation)", f"{precision:.1f}%")

    st.divider()
    left, right = st.columns(2)
    with left:
        st.markdown("**Alerts par severity**")
        severity_chart(fdf)
    with right:
        st.markdown("**Top 10 services ciblés**")
        st.bar_chart(fdf["service"].value_counts().head(10))

    left2, right2 = st.columns(2)
    with left2:
        st.markdown("**Détecté par**")
        st.bar_chart(fdf["detected_by"].value_counts())
    with right2:
        st.markdown("**Protocoles**")
        st.bar_chart(fdf["protocol"].value_counts())

    st.markdown("**Dernières alertes**")
    cols = ["timestamp", "severity", "detected_by", "protocol", "service", "flag",
            "src_bytes", "dst_bytes", "rf_prob", "if_score", "actual_label"]
    st.dataframe(
        fdf.sort_values("timestamp", ascending=False)[cols].head(100),
        width="stretch", hide_index=True,
    )


tab_live, tab_sim = st.tabs(["🔴 Live Alerts", "🧪 Simulation (NSL-KDD)"])
with tab_live:
    render_live()
with tab_sim:
    render_simulation()