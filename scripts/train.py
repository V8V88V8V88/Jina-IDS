import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from xgboost import XGBClassifier
from sklearn.metrics import accuracy_score
import joblib

# Load dataset
df = pd.read_csv("data/cybersecurity_intrusion_data.csv")

# Encode categorical features
categorical_features = ['protocol_type', 'encryption_used', 'browser_type', 'unusual_time_access']
label_encoders = {}
for col in categorical_features:
    le = LabelEncoder()
    df[col] = le.fit_transform(df[col])
    label_encoders[col] = le

# Feature selection
X = df.drop(columns=['session_id', 'attack_detected'])  # Drop unnecessary columns
y = df['attack_detected']

# Split data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Scale numerical features
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)

# Train model with hyperparameter tuning
model = XGBClassifier(n_estimators=200, max_depth=8, learning_rate=0.05, subsample=0.8, colsample_bytree=0.8)
model.fit(X_train, y_train)

# Evaluate model
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"✅ Model Accuracy: {accuracy * 100:.2f}%")

# Save model and preprocessing objects
joblib.dump(model, "data/models/anomaly_model.pkl")
joblib.dump(scaler, "data/models/scaler.pkl")
joblib.dump(label_encoders, "data/models/label_encoders.pkl")
