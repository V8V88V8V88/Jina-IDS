from ml.feature_extraction import FeatureExtractor
from ml.model import AnomalyModel

extractor = FeatureExtractor()
model = AnomalyModel()

def predict_packet(packet):
    features = extractor.extract(packet)
    prediction = model.predict(features)
    if prediction == -1:
        print("Anomalous packet detected!")
    else:
        print("Packet is normal.")
