import joblib
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder

COLS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate", "label", "difficulty",
]
CATEGORICAL = ["protocol_type", "service", "flag"]


def load(path):
    df = pd.read_csv(path, names=COLS)
    y = (df["label"] != "normal").astype(int)  # 0 = Normal, 1 = Attack
    X = df.drop(columns=["label", "difficulty"])
    return X, y


X_train, y_train = load("data/KDDTrain+.txt")
X_test, y_test = load("data/KDDTest+.txt")
print("Train:", X_train.shape, "| Test:", X_test.shape)

pre = ColumnTransformer(
    [("cat", OneHotEncoder(handle_unknown="ignore"), CATEGORICAL)],
    remainder="passthrough",
)
model = Pipeline([
    ("pre", pre),
    ("rf", RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=42)),
])

model.fit(X_train, y_train)
pred = model.predict(X_test)

print("Accuracy:", round(accuracy_score(y_test, pred), 4))
print(confusion_matrix(y_test, pred))
print(classification_report(y_test, pred, target_names=["Normal", "Attack"]))

joblib.dump(model, "models/rf_nsl_kdd.joblib")
print("Model saved.")