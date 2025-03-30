import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score

# Load processed data
X_train, X_test, y_train, y_test = joblib.load("data/processed_data.pkl")

# Train a model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Evaluate the model
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"Model Accuracy: {accuracy * 100:.2f}%")

# Save the trained model
joblib.dump(model, "data/models/anomaly_model.pkl")
print("Model saved successfully.")
