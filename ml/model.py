import os
import joblib

class AnomalyModel:
    def __init__(self):
        self.model_file = "data/models/anomaly_model.pkl"
        if not os.path.exists(self.model_file):
            raise FileNotFoundError(f"Model file not found: {self.model_file}")
        self.model = joblib.load(self.model_file)
