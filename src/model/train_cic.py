import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split

FEATURES = [
    "Destination Port", "Flow Duration", "Total Fwd Packets",
    "Total Backward Packets", "Total Length of Fwd Packets",
    "Total Length of Bwd Packets", "SYN Flag Count", "FIN Flag Count",
    "RST Flag Count",
]

# Nجمّعو el attaques f familles (type de menace)
FAMILY = {
    "BENIGN": "Normal",
    "DoS Hulk": "DoS", "DoS GoldenEye": "DoS",
    "DoS slowloris": "DoS", "DoS Slowhttptest": "DoS",
    "DDoS": "DDoS",
    "PortScan": "PortScan",
    "FTP-Patator": "BruteForce", "SSH-Patator": "BruteForce",
    "Web Attack - Brute Force": "WebAttack", "Web Attack - XSS": "WebAttack",
    "Bot": "Bot",
}

df = pd.read_parquet("data/cic/cic_all.parquet")
df["Label"] = df["Label"].str.replace(" - - ", " - ").str.replace("--", "-")
df["family"] = df["Label"].map(FAMILY)
df = df.dropna(subset=["family"])   # na77i Infiltration, Heartbleed, SQLi (sghar barcha)

X = df[FEATURES].astype("float32")
y = df["family"]
print("Lignes:", len(df))
print(y.value_counts().to_string(), "\n")

X_tr, X_te, y_tr, y_te = train_test_split(
    X, y, test_size=0.3, stratify=y, random_state=42
)

rf = RandomForestClassifier(
    n_estimators=60, max_depth=25, class_weight="balanced_subsample",
    n_jobs=-1, random_state=42,
)
print("Training...")
rf.fit(X_tr, y_tr)

pred = rf.predict(X_te)
print(classification_report(y_te, pred, digits=3))

# Binary: Normal vs Attack
bin_true, bin_pred = y_te == "Normal", pred == "Normal"
fn = ((~bin_true) & bin_pred).sum()
print(f"Attaques ratées (prédites Normal): {fn} / {(~bin_true).sum()}")
print(f"Fausses alertes (Normal prédit attaque): {(bin_true & ~bin_pred).sum()} / {bin_true.sum()}")

imp = pd.Series(rf.feature_importances_, index=FEATURES).sort_values(ascending=False)
print("\nImportance des features:\n", imp.round(3).to_string())

joblib.dump({"model": rf, "features": FEATURES}, "models/rf_cic.joblib", compress=3)
print("\nModel saved: models/rf_cic.joblib")