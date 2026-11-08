import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import IsolationForest
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.preprocessing import OneHotEncoder

from common import CATEGORICAL, load

X_train, y_train = load("data/KDDTrain+.txt")
X_test, y_test = load("data/KDDTest+.txt")

rows = []


def add(name, pred):
    rows.append({
        "model": name,
        "accuracy": accuracy_score(y_test, pred),
        "precision_attack": precision_score(y_test, pred),
        "recall_attack": recall_score(y_test, pred),
        "f1_attack": f1_score(y_test, pred),
    })


# 1. Random Forest (baseline)
rf = joblib.load("models/rf_nsl_kdd.joblib")
rf_pred = rf.predict(X_test)
add("Random Forest", rf_pred)

# 2. Isolation Forest: yetdarreb 3la el trafic NORMAL bark
pre = ColumnTransformer(
    [("cat", OneHotEncoder(handle_unknown="ignore", sparse_output=False), CATEGORICAL)],
    remainder="passthrough",
)
pre.fit(X_train)
X_normal = pre.transform(X_train[y_train == 0])
X_test_t = pre.transform(X_test)

if_preds = {}
for c in [0.01, 0.05, 0.10, 0.20]:
    iso = IsolationForest(n_estimators=200, contamination=c, n_jobs=-1, random_state=42)
    iso.fit(X_normal)
    pred = (iso.predict(X_test_t) == -1).astype(int)  # -1 = anomalie = Attack
    if_preds[c] = pred
    add(f"Isolation Forest (contamination={c})", pred)

# 3. Hybrid: Attack ken RF wala IF y9oul anomalie
for c in [0.05, 0.10]:
    add(f"Hybrid RF + IF (c={c})", np.logical_or(rf_pred, if_preds[c]).astype(int))

print(pd.DataFrame(rows).round(3).to_string(index=False))