import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import joblib

df = pd.read_csv("data/raw/cybersecurity_intrusion_data.csv")

df = df.drop(["session_id", "browser_type"], axis=1)

df = pd.get_dummies(df, columns=["protocol_type", "encryption_used"], drop_first=True)

X = df.drop("attack_detected", axis=1)
y = df["attack_detected"]

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)

joblib.dump((X_train, X_test, y_train, y_test), "data/processed_data.pkl")
joblib.dump(scaler, "data/scaler.pkl")
print("Preprocessing complete. Data saved.")
