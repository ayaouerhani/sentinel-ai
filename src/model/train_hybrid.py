import joblib
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import OneHotEncoder

from common import CATEGORICAL, load

X_train, y_train = load("data/KDDTrain+.txt")

pre = ColumnTransformer(
    [("cat", OneHotEncoder(handle_unknown="ignore", sparse_output=False), CATEGORICAL)],
    remainder="passthrough",
)
pre.fit(X_train)

# IF yetdarreb 3la el trafic NORMAL bark
X_normal = pre.transform(X_train[y_train == 0])
iso = IsolationForest(
    n_estimators=200, contamination=0.05, n_jobs=-1, random_state=42
).fit(X_normal)

joblib.dump({"pre": pre, "iso": iso}, "models/if_nsl_kdd.joblib")
print("Isolation Forest saved.")