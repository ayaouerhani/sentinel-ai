import joblib
import pandas as pd

bundle = joblib.load("models/rf_cic.joblib")
model, FEATURES = bundle["model"], bundle["features"]

flows = pd.read_csv("data/flows_live.csv")

X = pd.DataFrame({
    "Destination Port": flows["dport"],
    "Flow Duration": flows["duration"] * 1_000_000,   # thawéni -> microsecondes (CIC)
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
flows["confidence"] = proba.max(axis=1).round(3)

print(f"Flows: {len(flows)}\n")
print(flows["pred"].value_counts().to_string())

cols = ["proto", "src", "sport", "dst", "dport", "duration",
        "total_pkts", "total_bytes", "pred", "confidence"]
flagged = flows[flows["pred"] != "Normal"]
print(f"\nFlows flaggés (fausses alertes, trafic 3adi): {len(flagged)}")
print(flagged[cols].sort_values("confidence", ascending=False).head(20).to_string(index=False))