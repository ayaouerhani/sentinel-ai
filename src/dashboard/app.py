import locale
import sqlite3
import subprocess
import sys
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parents[2]
DB_PATH = ROOT / "data" / "sentinel.db"
LOG_PATH = ROOT / "data" / "monitor.log"
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


@st.cache_resource
def monitor_state():
    # dictionnaire partagé: garde le process du monitoring entre les reruns
    return {"proc": None}


# ======================= TAB 1: LIVE =======================
def render_live():
    st.subheader("Monitoring continu (capture → détection → alertes)")
    state = monitor_state()
    proc = state["proc"]
    running = proc is not None and proc.poll() is None

    c1, c2, c3, c4 = st.columns(4)
    iface_ip = c1.text_input("IP de l'interface", "192.168.200.1", disabled=running)
    window = c2.slider("Fenêtre d'analyse (s)", 10, 60, 20, disabled=running)

    if running:
        if c3.button("⏹️ Arrêter le monitoring"):
            proc.terminate()
            state["proc"] = None
            st.rerun()
    else:
        if c3.button("▶️ Démarrer le monitoring"):
            log = open(LOG_PATH, "w", encoding="utf-8")
            state["proc"] = subprocess.Popen(
                [sys.executable, str(ROOT / "src" / "monitor.py"), iface_ip, str(window)],
                cwd=ROOT, stdout=log, stderr=subprocess.STDOUT,
            )
            st.rerun()

    if c4.button("🗑️ Vider les alertes live") and DB_PATH.exists():
        run_sql("DROP TABLE IF EXISTS live_alerts")
        st.rerun()

    if running:
        st.success("🟢 Monitoring actif : fenêtres de capture en boucle")
    else:
        st.info("⚫ Monitoring arrêté")

    @st.fragment(run_every="5s" if running else None)
    def live_view():
        if LOG_PATH.exists():
            lines = LOG_PATH.read_text(                                  # <-- fix accents
                encoding=locale.getpreferredencoding(False), errors="replace"
            ).splitlines()[-6:]
            with st.expander("Journal du monitoring", expanded=running):
                st.code("\n".join(lines) or "(vide)")

        df = read_table("live_alerts")
        if df is None or df.empty:
            st.info("Aucune alerte live pour l'instant.")
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

    live_view()


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


tab_live, tab_sim = st.tabs(["🔴 Live Monitoring", "🧪 Simulation (NSL-KDD)"])
with tab_live:
    render_live()
with tab_sim:
    render_simulation()