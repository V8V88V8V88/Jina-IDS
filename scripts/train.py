import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.preprocessing import StandardScaler, OneHotEncoder, LabelEncoder
from sklearn.compose import ColumnTransformer
from imblearn.over_sampling import SMOTE
from xgboost import XGBClassifier
from sklearn.pipeline import Pipeline
from sklearn.metrics import accuracy_score, classification_report

df = pd.read_csv("data/raw/cybersecurity_intrusion_data.csv")

df = df.drop(columns=["session_id"], errors="ignore")

df["failed_login_ratio"] = df["failed_logins"] / (df["login_attempts"] + 1)  # Avoid division by zero

for col in df.select_dtypes(include=["number"]).columns:
    df[col] = df[col].fillna(df[col].mean())
for col in df.select_dtypes(include=["object"]).columns:
    df[col] = df[col].fillna(df[col].mode()[0])

X = df.drop(columns=["attack_detected"])
y = df["attack_detected"]

categorical_cols = X.select_dtypes(include=["object"]).columns
encoder = OneHotEncoder(handle_unknown="ignore", sparse_output=False)
encoded_cats = encoder.fit_transform(X[categorical_cols])
encoded_cat_columns = encoder.get_feature_names_out(categorical_cols)

X_encoded = pd.DataFrame(encoded_cats, columns=encoded_cat_columns)
X_encoded.index = X.index

X = X.drop(columns=categorical_cols)
X = pd.concat([X, X_encoded], axis=1)

X_resampled, y_resampled = SMOTE().fit_resample(X, y)

X_train, X_test, y_train, y_test = train_test_split(X_resampled, y_resampled, test_size=0.2, random_state=42)

scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

xgb = XGBClassifier(n_estimators=200, learning_rate=0.1, max_depth=7, subsample=1.0, use_label_encoder=False, eval_metric="logloss")
xgb.fit(X_train_scaled, y_train)

y_pred = xgb.predict(X_test_scaled)
accuracy = accuracy_score(y_test, y_pred)

print(f"\n✅ Model Accuracy: {accuracy * 100:.2f}%")
print("\n📊 Classification Report:\n", classification_report(y_test, y_pred))

joblib.dump((xgb, scaler, encoder), "data/models/anomaly_model.pkl")
print("\n✅ Model saved successfully.")
