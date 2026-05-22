import logging
import random

logger = logging.getLogger("SOC-AnomalyML")

try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    logger.warning("scikit-learn or numpy not installed. Falling back to Heuristic Z-Score Anomaly detection.")

class AnomalyDetector:
    def __init__(self):
        self.is_trained = False
        self.clf = None
        self.historical_features = []
        
        # Pre-populate with typical safe baseline network flows to auto-train
        if SKLEARN_AVAILABLE:
            try:
                # Generate 100 typical normal baseline points:
                # [flow_bytes_s, flow_packets_s, packet_length_std]
                baseline = [
                    [random.randint(1000, 15000), random.randint(10, 200), random.randint(50, 150)]
                    for _ in range(100)
                ]
                X = np.array(baseline)
                self.clf = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
                self.clf.fit(X)
                self.is_trained = True
                logger.info("Isolation Forest successfully initialized and pre-trained with base telemetry.")
            except Exception as e:
                logger.error(f"Error training Isolation Forest: {e}. Anomaly detection will use statistical rules.")
                self.is_trained = False

    def predict_anomaly(self, flow_bytes_s: float, flow_packets_s: float, packet_length_std: float) -> tuple[bool, float]:
        """
        Returns:
            (is_anomaly: bool, anomaly_probability: float)
        """
        # Save feature to history pool
        self.historical_features.append([flow_bytes_s, flow_packets_s, packet_length_std])
        if len(self.historical_features) > 1000:
            self.historical_features.pop(0) # Keep sliding window
            
        # Isolation Forest Prediction
        if SKLEARN_AVAILABLE and self.is_trained and self.clf is not None:
            try:
                X = np.array([[flow_bytes_s, flow_packets_s, packet_length_std]])
                prediction = self.clf.predict(X)[0] # -1 for anomaly, 1 for normal
                # decision_function outputs values in range [-0.5, 0.5] (closer to -0.5 is anomalous)
                score = float(self.clf.decision_function(X)[0])
                # Convert to 0.0 - 1.0 probability
                anomaly_prob = float(np.clip((0.5 - score) / 1.0, 0.0, 1.0))
                
                is_anomaly = (prediction == -1)
                return is_anomaly, anomaly_prob
            except Exception as e:
                logger.error(f"Prediction failed in Isolation Forest: {e}")
                
        # Statistical Fallback Method (Heuristic Z-Score)
        # Assumes values exceeding 3x typical threshold bounds are anomalies
        is_anomaly = False
        score_accumulator = 0.0
        
        if flow_bytes_s > 300000:
            is_anomaly = True
            score_accumulator += 0.4
        if flow_packets_s > 2000:
            is_anomaly = True
            score_accumulator += 0.4
        if packet_length_std > 300:
            is_anomaly = True
            score_accumulator += 0.2
            
        return is_anomaly, min(score_accumulator, 1.0)

# Export a single global instance
anomaly_detector = AnomalyDetector()
