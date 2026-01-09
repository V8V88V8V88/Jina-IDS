"""
Jina IDS - Machine Learning Anomaly Detection Module
Professional ML-based Network Anomaly Detection
"""

import warnings
warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")

import logging
import os
import joblib
import numpy as np
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass
from datetime import datetime
from collections import deque

logger = logging.getLogger("JinaIDS.ML")


@dataclass
class MLPrediction:
    """Result of ML prediction."""
    is_anomaly: bool
    score: float
    confidence: float
    features_used: List[str]
    model_name: str
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()


class FeatureExtractor:
    """
    Extract features from network packets for ML analysis.
    
    Features extracted:
    - Protocol type (encoded)
    - Packet length
    - TTL
    - Source/Destination port ranges
    - Payload characteristics
    - Flow-level features
    """
    
    PROTOCOL_MAP = {
        "TCP": 0,
        "UDP": 1,
        "ICMP": 2,
        "DNS": 3,
        "HTTP": 4,
        "HTTPS": 5,
        "IPv6": 6,
        "ARP": 7,
        "UNKNOWN": 8
    }
    
    PORT_RANGES = {
        "system": (0, 1023),
        "registered": (1024, 49151),
        "dynamic": (49152, 65535)
    }
    
    def __init__(self):
        self.feature_names = [
            "protocol_encoded",
            "packet_length",
            "ttl",
            "src_port",
            "dst_port",
            "src_port_range",
            "dst_port_range",
            "is_well_known_port",
            "payload_length",
            "payload_entropy",
            "has_payload",
            "is_encrypted_port"
        ]
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of payload."""
        if not data:
            return 0.0
        
        byte_counts = np.zeros(256)
        for byte in data:
            byte_counts[byte] += 1
        
        probabilities = byte_counts / len(data)
        probabilities = probabilities[probabilities > 0]
        
        return -np.sum(probabilities * np.log2(probabilities))
    
    def _get_port_range(self, port: int) -> int:
        """Encode port into range category."""
        if port <= 1023:
            return 0  # System/well-known
        elif port <= 49151:
            return 1  # Registered
        else:
            return 2  # Dynamic/ephemeral
    
    def extract(self, packet) -> np.ndarray:
        """Extract features from a packet."""
        try:
            # Protocol encoding
            protocol = getattr(packet, 'protocol', 'UNKNOWN')
            protocol_encoded = self.PROTOCOL_MAP.get(protocol, 8)
            
            # Basic packet info
            packet_length = getattr(packet, 'length', 0)
            ttl = getattr(packet, 'ttl', 0)
            src_port = getattr(packet, 'src_port', 0)
            dst_port = getattr(packet, 'dst_port', 0)
            
            # Port range encoding
            src_port_range = self._get_port_range(src_port)
            dst_port_range = self._get_port_range(dst_port)
            
            # Well-known port check
            is_well_known = 1 if dst_port <= 1023 else 0
            
            # Payload features
            payload = getattr(packet, 'payload', b'')
            payload_length = len(payload) if payload else 0
            payload_entropy = self._calculate_entropy(payload) if payload else 0
            has_payload = 1 if payload_length > 0 else 0
            
            # Encrypted port check (HTTPS, SSH, etc.)
            encrypted_ports = {443, 8443, 22, 465, 993, 995}
            is_encrypted_port = 1 if dst_port in encrypted_ports else 0
            
            features = np.array([
                protocol_encoded,
                packet_length,
                ttl,
                src_port,
                dst_port,
                src_port_range,
                dst_port_range,
                is_well_known,
                payload_length,
                payload_entropy,
                has_payload,
                is_encrypted_port
            ], dtype=np.float32)
            
            return features
            
        except Exception as e:
            logger.debug(f"Feature extraction error: {e}")
            return np.zeros(len(self.feature_names), dtype=np.float32)
    
    def extract_batch(self, packets: List) -> np.ndarray:
        """Extract features from multiple packets."""
        return np.array([self.extract(pkt) for pkt in packets])


class MLAnomalyDetector:
    """
    Machine Learning based anomaly detector.
    
    Supports:
    - Pre-trained XGBoost classifier
    - Isolation Forest for unsupervised detection
    - Statistical baseline detection
    """
    
    def __init__(self, model_path: str = "data/models/anomaly_model.pkl"):
        self.model_path = model_path
        self.feature_extractor = FeatureExtractor()
        
        self.model = None
        self.scaler = None
        self.encoder = None
        self.model_type = None
        
        # Statistical baseline (fallback)
        self.baseline_enabled = True
        self.packet_history = deque(maxlen=1000)
        self.baseline_stats: Dict[str, Dict] = {}
        
        # Load model
        self._load_model()
    
    def _load_model(self):
        """Load pre-trained model if available."""
        if not os.path.exists(self.model_path):
            logger.info(f"No pre-trained model found at {self.model_path}")
            logger.info("Using statistical baseline detection")
            self.model_type = "baseline"
            return
        
        try:
            loaded = joblib.load(self.model_path)
            
            # Handle different model formats
            if isinstance(loaded, tuple):
                if len(loaded) == 3:
                    self.model, self.scaler, self.encoder = loaded
                elif len(loaded) == 2:
                    self.model, self.scaler = loaded
                else:
                    self.model = loaded[0]
            else:
                self.model = loaded
            
            # Determine model type
            model_class = type(self.model).__name__
            if "XGB" in model_class:
                self.model_type = "xgboost"
            elif "IsolationForest" in model_class:
                self.model_type = "isolation_forest"
            elif "RandomForest" in model_class:
                self.model_type = "random_forest"
            else:
                self.model_type = "unknown"
            
            logger.info(f"Loaded {self.model_type} model from {self.model_path}")
            
        except Exception as e:
            logger.warning(f"Could not load model: {e}")
            logger.info("Falling back to statistical baseline detection")
            self.model_type = "baseline"
    
    def _update_baseline(self, features: np.ndarray):
        """Update statistical baseline with new packet."""
        self.packet_history.append(features)
        
        if len(self.packet_history) >= 100:
            # Calculate baseline statistics
            history_array = np.array(list(self.packet_history))
            
            self.baseline_stats = {
                "mean": np.mean(history_array, axis=0),
                "std": np.std(history_array, axis=0),
                "min": np.min(history_array, axis=0),
                "max": np.max(history_array, axis=0)
            }
    
    def _predict_baseline(self, features: np.ndarray) -> MLPrediction:
        """Predict using statistical baseline."""
        self._update_baseline(features)
        
        if not self.baseline_stats:
            return MLPrediction(
                is_anomaly=False,
                score=0.0,
                confidence=0.0,
                features_used=self.feature_extractor.feature_names,
                model_name="baseline"
            )
        
        # Calculate z-scores
        mean = self.baseline_stats["mean"]
        std = self.baseline_stats["std"]
        std = np.where(std == 0, 1, std)  # Avoid division by zero
        
        z_scores = np.abs((features - mean) / std)
        max_z = np.max(z_scores)
        
        # Anomaly if z-score > 3 (3 standard deviations)
        is_anomaly = max_z > 3.0
        score = min(max_z / 5.0, 1.0)  # Normalize to 0-1
        
        return MLPrediction(
            is_anomaly=is_anomaly,
            score=score,
            confidence=min(len(self.packet_history) / 100, 1.0),
            features_used=self.feature_extractor.feature_names,
            model_name="baseline"
        )
    
    def _predict_ml(self, features: np.ndarray) -> MLPrediction:
        """Predict using ML model."""
        try:
            # Scale features if scaler available
            if self.scaler:
                features_scaled = self.scaler.transform(features.reshape(1, -1))
            else:
                features_scaled = features.reshape(1, -1)
            
            if self.model_type == "isolation_forest":
                # Isolation Forest returns -1 for anomaly, 1 for normal
                prediction = self.model.predict(features_scaled)[0]
                score = -self.model.decision_function(features_scaled)[0]
                is_anomaly = prediction == -1
            else:
                # Classification model (XGBoost, RandomForest)
                prediction = self.model.predict(features_scaled)[0]
                
                if hasattr(self.model, 'predict_proba'):
                    proba = self.model.predict_proba(features_scaled)[0]
                    score = max(proba) if len(proba) > 1 else proba[0]
                else:
                    score = 1.0 if prediction else 0.0
                
                is_anomaly = bool(prediction)
            
            return MLPrediction(
                is_anomaly=is_anomaly,
                score=float(score),
                confidence=0.9,  # ML model confidence
                features_used=self.feature_extractor.feature_names,
                model_name=self.model_type
            )
            
        except Exception as e:
            logger.debug(f"ML prediction error: {e}")
            return self._predict_baseline(features)
    
    def predict(self, packet) -> MLPrediction:
        """Predict if packet is anomalous."""
        # Extract features
        features = self.feature_extractor.extract(packet)
        
        # Use appropriate prediction method
        if self.model_type == "baseline" or self.model is None:
            return self._predict_baseline(features)
        else:
            return self._predict_ml(features)
    
    def predict_batch(self, packets: List) -> List[MLPrediction]:
        """Predict on multiple packets."""
        return [self.predict(pkt) for pkt in packets]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get detector statistics."""
        return {
            "model_type": self.model_type,
            "model_loaded": self.model is not None,
            "scaler_loaded": self.scaler is not None,
            "baseline_samples": len(self.packet_history),
            "baseline_ready": bool(self.baseline_stats)
        }


# Backward compatibility
AnomalyModel = MLAnomalyDetector


def predict_packet(packet) -> Optional[MLPrediction]:
    """Convenience function for backward compatibility."""
    try:
        detector = MLAnomalyDetector()
        result = detector.predict(packet)
        
        if result.is_anomaly:
            logger.warning(f"Anomalous packet detected! Score: {result.score:.2f}")
        
        return result
    except Exception as e:
        logger.error(f"Prediction error: {e}")
        return None


if __name__ == "__main__":
    # Test the ML detector
    from dataclasses import dataclass
    
    logging.basicConfig(level=logging.INFO)
    
    @dataclass
    class TestPacket:
        protocol: str = "TCP"
        length: int = 100
        ttl: int = 64
        src_port: int = 45678
        dst_port: int = 80
        payload: bytes = b"normal content"
    
    detector = MLAnomalyDetector()
    print(f"Detector stats: {detector.get_stats()}")
    
    # Test normal packet
    normal_pkt = TestPacket()
    result = detector.predict(normal_pkt)
    print(f"\nNormal packet - Anomaly: {result.is_anomaly}, Score: {result.score:.3f}")
    
    # Test anomalous packet (weird port, high entropy payload)
    anomalous_pkt = TestPacket(
        dst_port=31337,
        payload=os.urandom(500),
        ttl=1
    )
    
    # Build baseline with normal packets first
    for _ in range(200):
        detector.predict(normal_pkt)
    
    result = detector.predict(anomalous_pkt)
    print(f"Anomalous packet - Anomaly: {result.is_anomaly}, Score: {result.score:.3f}")
