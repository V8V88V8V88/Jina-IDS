import joblib

class AnomalyModel:
    def __init__(self, model_file="data/models/anomaly_model.pkl"):
        self.model_file = model_file
        self.model = joblib.load(self.model_file)

    def predict(self, features):
        return self.model.predict([features])
