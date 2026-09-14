"""
God's Eye — ML Threat Classifier
Uses trained models to classify and score cybersecurity threats.
"""

import json
import os
import pickle
import time
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional, Any
import numpy as np

from ml_features import TrafficFeatures, FeatureNormalizer


@dataclass
class ThreatPrediction:
    """Container for ML threat prediction."""
    threat_type: str
    confidence: float
    risk_score: float
    severity: str
    feature_importance: Dict[str, float] = field(default_factory=dict)
    model_version: str = "1.0.0"
    inference_time_ms: float = 0.0
    
    def to_dict(self) -> dict:
        return {
            'threat_type': self.threat_type,
            'confidence': round(self.confidence, 3),
            'risk_score': round(self.risk_score, 1),
            'severity': self.severity,
            'feature_importance': self.feature_importance,
            'model_version': self.model_version,
            'inference_time_ms': round(self.inference_time_ms, 2),
        }


class ThreatClassifier:
    """
    ML-based threat classifier using ensemble of models.
    
    This classifier uses a combination of:
    1. Rule-based heuristics (baseline)
    2. Statistical anomaly detection
    3. Pattern matching with learned signatures
    """
    
    THREAT_TYPES = [
        'Port Scanning', 'DDoS Attack', 'Brute Force Attack',
        'Data Exfiltration', 'DNS Tunneling', 'Malware C2 Beacon',
        'SYN Flood Attack', 'Reconnaissance', 'SQL Injection',
        'XSS Attempt', 'Privilege Escalation', 'Lateral Movement'
    ]
    
    SEVERITY_LEVELS = ['critical', 'high', 'medium', 'low']
    
    def __init__(self, model_path: Optional[str] = None):
        self.model_path = model_path or os.path.join(os.path.dirname(__file__), 'models')
        self.normalizer = FeatureNormalizer()
        self.models = {}
        self.model_metadata = {}
        self._initialized = False
        
        # Thresholds for each threat type (can be learned from data)
        self.thresholds = {
            'Port Scanning': {'confidence': 0.65, 'severity_boost': 0.1},
            'DDoS Attack': {'confidence': 0.70, 'severity_boost': 0.15},
            'Brute Force Attack': {'confidence': 0.68, 'severity_boost': 0.1},
            'Data Exfiltration': {'confidence': 0.60, 'severity_boost': 0.2},
            'DNS Tunneling': {'confidence': 0.62, 'severity_boost': 0.1},
            'Malware C2 Beacon': {'confidence': 0.65, 'severity_boost': 0.15},
            'SYN Flood Attack': {'confidence': 0.72, 'severity_boost': 0.15},
            'Reconnaissance': {'confidence': 0.55, 'severity_boost': 0.05},
        }
    
    def initialize(self):
        """Initialize the classifier, loading any saved models."""
        if self._initialized:
            return
        
        # Try to load pre-trained models
        if os.path.exists(self.model_path):
            self._load_models()
        
        self._initialized = True
    
    def _load_models(self):
        """Load trained models from disk."""
        try:
            # Load normalizer
            norm_path = os.path.join(self.model_path, 'normalizer.pkl')
            if os.path.exists(norm_path):
                with open(norm_path, 'rb') as f:
                    self.normalizer = pickle.load(f)
            
            # Load classifier models
            models_path = os.path.join(self.model_path, 'classifier.pkl')
            if os.path.exists(models_path):
                with open(models_path, 'rb') as f:
                    self.models = pickle.load(f)
            
            # Load metadata
            meta_path = os.path.join(self.model_path, 'metadata.json')
            if os.path.exists(meta_path):
                with open(meta_path, 'r') as f:
                    self.model_metadata = json.load(f)
            
            print(f"[ML] Loaded models from {self.model_path}")
        except Exception as e:
            print(f"[ML] Could not load models: {e}")
            print("[ML] Using rule-based detection as fallback")
    
    def predict(self, features: TrafficFeatures) -> List[ThreatPrediction]:
        """
        Predict threats from extracted features.
        
        Args:
            features: Extracted traffic features
            
        Returns:
            List of ThreatPrediction objects
        """
        if not self._initialized:
            self.initialize()
        
        start_time = time.time()
        predictions = []
        
        # Rule-based predictions (baseline)
        rule_predictions = self._rule_based_predict(features)
        predictions.extend(rule_predictions)
        
        # Statistical anomaly detection
        anomaly_predictions = self._anomaly_detect(features)
        predictions.extend(anomaly_predictions)
        
        # ML model predictions (if available)
        if self.models:
            ml_predictions = self._ml_predict(features)
            predictions.extend(ml_predictions)
        
        # Calculate inference time
        inference_time = (time.time() - start_time) * 1000
        
        # Update inference times
        for pred in predictions:
            pred.inference_time_ms = inference_time / len(predictions) if predictions else 0
        
        return predictions
    
    def _rule_based_predict(self, features: TrafficFeatures) -> List[ThreatPrediction]:
        """Rule-based threat detection."""
        predictions = []
        
        # Port Scanning
        if features.port_scan_score > 0.6:
            confidence = min(0.95, features.port_scan_score + self.thresholds['Port Scanning']['severity_boost'])
            severity = self._determine_severity(confidence, 'Port Scanning')
            predictions.append(ThreatPrediction(
                threat_type='Port Scanning',
                confidence=confidence,
                risk_score=confidence * 10 * 1.2,
                severity=severity,
                feature_importance={'port_scan_score': features.port_scan_score,
                                   'unique_dst_ports': features.unique_dst_ports},
                model_version='rule_v1'
            ))
        
        # DDoS / SYN Flood
        if features.dls_score > 0.65:
            confidence = min(0.95, features.dls_score + self.thresholds['DDoS Attack']['severity_boost'])
            severity = self._determine_severity(confidence, 'DDoS Attack')
            predictions.append(ThreatPrediction(
                threat_type='DDoS Attack',
                confidence=confidence,
                risk_score=confidence * 10 * 1.5,
                severity=severity,
                feature_importance={'dls_score': features.dls_score,
                                   'syn_count': features.syn_count,
                                   'packets_per_second': features.packets_per_second},
                model_version='rule_v1'
            ))
        
        # SYN Flood (specific DDoS variant)
        if features.syn_ack_ratio > 3 and features.syn_count > 30:
            confidence = min(0.95, 0.7 + features.syn_ack_ratio * 0.05)
            severity = self._determine_severity(confidence, 'SYN Flood Attack')
            predictions.append(ThreatPrediction(
                threat_type='SYN Flood Attack',
                confidence=confidence,
                risk_score=confidence * 10 * 1.5,
                severity=severity,
                feature_importance={'syn_ack_ratio': features.syn_ack_ratio,
                                   'syn_count': features.syn_count},
                model_version='rule_v1'
            ))
        
        # Brute Force
        if features.bf_score > 0.6:
            confidence = min(0.95, features.bf_score + self.thresholds['Brute Force Attack']['severity_boost'])
            severity = self._determine_severity(confidence, 'Brute Force Attack')
            predictions.append(ThreatPrediction(
                threat_type='Brute Force Attack',
                confidence=confidence,
                risk_score=confidence * 10 * 1.2,
                severity=severity,
                feature_importance={'bf_score': features.bf_score},
                model_version='rule_v1'
            ))
        
        # Data Exfiltration
        if features.exfil_score > 0.55:
            confidence = min(0.95, features.exfil_score + self.thresholds['Data Exfiltration']['severity_boost'])
            severity = self._determine_severity(confidence, 'Data Exfiltration')
            predictions.append(ThreatPrediction(
                threat_type='Data Exfiltration',
                confidence=confidence,
                risk_score=confidence * 10 * 1.5,
                severity=severity,
                feature_importance={'exfil_score': features.exfil_score,
                                   'is_outbound_dominant': features.is_outbound_dominant},
                model_version='rule_v1'
            ))
        
        # DNS Tunneling
        if features.tunnel_score > 0.5:
            confidence = min(0.95, features.tunnel_score + self.thresholds['DNS Tunneling']['severity_boost'])
            severity = self._determine_severity(confidence, 'DNS Tunneling')
            predictions.append(ThreatPrediction(
                threat_type='DNS Tunneling',
                confidence=confidence,
                risk_score=confidence * 10 * 1.2,
                severity=severity,
                feature_importance={'tunnel_score': features.tunnel_score,
                                   'dns_count': features.dns_count},
                model_version='rule_v1'
            ))
        
        # Reconnaissance
        if features.port_scan_score > 0.4 and features.icmp_count > 20:
            confidence = min(0.90, 0.6 + features.icmp_count * 0.005)
            severity = self._determine_severity(confidence, 'Reconnaissance')
            predictions.append(ThreatPrediction(
                threat_type='Reconnaissance',
                confidence=confidence,
                risk_score=confidence * 10 * 1.0,
                severity=severity,
                feature_importance={'port_scan_score': features.port_scan_score,
                                   'icmp_count': features.icmp_count},
                model_version='rule_v1'
            ))
        
        return predictions
    
    def _anomaly_detect(self, features: TrafficFeatures) -> List[ThreatPrediction]:
        """Statistical anomaly detection for unknown threats."""
        predictions = []
        
        # Z-score based anomaly detection (simplified without trained model)
        # In production, this would use Isolation Forest or Autoencoder
        
        anomaly_score = 0.0
        anomaly_indicators = []
        
        # High packet rate anomaly
        if features.packets_per_second > 500:
            anomaly_score += 0.3
            anomaly_indicators.append(('packets_per_second', features.packets_per_second))
        
        # Unusual entropy (encrypted or obfuscated traffic)
        if features.dst_port_entropy > 3.5:
            anomaly_score += 0.2
            anomaly_indicators.append(('dst_port_entropy', features.dst_port_entropy))
        
        # High SYN ratio without corresponding ACKs
        if features.syn_ack_ratio > 5:
            anomaly_score += 0.25
            anomaly_indicators.append(('syn_ack_ratio', features.syn_ack_ratio))
        
        # Unusual packet size distribution
        if features.std_packet_size > 500 and features.avg_packet_size < 200:
            anomaly_score += 0.15
            anomaly_indicators.append(('packet_size_anomaly', features.std_packet_size))
        
        if anomaly_score > 0.5:
            confidence = min(0.85, anomaly_score)
            predictions.append(ThreatPrediction(
                threat_type='Anomalous Activity',
                confidence=confidence,
                risk_score=confidence * 8,
                severity=self._determine_severity(confidence, 'Anomalous Activity'),
                feature_importance=dict(anomaly_indicators),
                model_version='anomaly_v1'
            ))
        
        return predictions
    
    def _ml_predict(self, features: TrafficFeatures) -> List[ThreatPrediction]:
        """ML model-based predictions."""
        predictions = []
        
        try:
            # Normalize features
            feature_vector = self.normalizer.normalize(features)
            
            # Use each model in the ensemble
            for model_name, model in self.models.items():
                if hasattr(model, 'predict_proba'):
                    proba = model.predict_proba(feature_vector.reshape(1, -1))[0]
                    predicted_class = np.argmax(proba)
                    confidence = proba[predicted_class]
                    
                    if confidence > 0.6:
                        threat_type = self.THREAT_TYPES[predicted_class] if predicted_class < len(self.THREAT_TYPES) else 'Unknown'
                        predictions.append(ThreatPrediction(
                            threat_type=threat_type,
                            confidence=float(confidence),
                            risk_score=float(confidence * 10),
                            severity=self._determine_severity(confidence, threat_type),
                            feature_importance=self._get_feature_importance(model, feature_vector),
                            model_version=f'ml_{model_name}'
                        ))
        except Exception as e:
            print(f"[ML] Prediction error: {e}")
        
        return predictions
    
    def _get_feature_importance(self, model, features: np.ndarray) -> Dict[str, float]:
        """Extract feature importance from model."""
        importance = {}
        
        if hasattr(model, 'feature_importances_'):
            names = TrafficFeatures().feature_names
            importances = model.feature_importances_
            # Get top 5 most important features
            top_indices = np.argsort(importances)[-5:][::-1]
            for idx in top_indices:
                if idx < len(names):
                    importance[names[idx]] = float(importances[idx])
        
        return importance
    
    def _determine_severity(self, confidence: float, threat_type: str) -> str:
        """Determine threat severity based on confidence and type."""
        # Critical threats
        critical_types = ['DDoS Attack', 'SYN Flood Attack', 'Data Exfiltration', 'Malware C2 Beacon']
        if threat_type in critical_types:
            if confidence > 0.8:
                return 'critical'
            elif confidence > 0.65:
                return 'high'
            return 'medium'
        
        # High severity threats
        high_types = ['Brute Force Attack', 'Port Scanning', 'DNS Tunneling']
        if threat_type in high_types:
            if confidence > 0.75:
                return 'high'
            elif confidence > 0.6:
                return 'medium'
            return 'low'
        
        # Default severity calculation
        if confidence > 0.8:
            return 'high'
        elif confidence > 0.6:
            return 'medium'
        return 'low'


class ModelTrainer:
    """
    Trains ML models for threat classification.
    
    Note: This is a training module that would be run offline.
    The trained models are then loaded by ThreatClassifier.
    """
    
    def __init__(self):
        self.training_data = []
        self.labels = []
    
    def add_training_sample(self, features: TrafficFeatures, label: str):
        """Add a labeled training sample."""
        self.training_data.append(features.to_vector())
        self.labels.append(label)
    
    def train(self, output_path: str) -> Dict[str, Any]:
        """
        Train models on the collected data.
        
        Returns:
            Training metrics and metadata
        """
        if not self.training_data:
            print("[ML] No training data available")
            return {}
        
        X = np.array(self.training_data)
        y = np.array(self.labels)
        
        metrics = {
            'samples': len(X),
            'features': X.shape[1],
            'classes': list(set(y)),
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        }
        
        try:
            # Try to use scikit-learn if available
            from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
            from sklearn.model_selection import train_test_split
            from sklearn.metrics import classification_report, accuracy_score
            from sklearn.preprocessing import StandardScaler
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42, stratify=y
            )
            
            # Scale features
            scaler = StandardScaler()
            X_train_scaled = scaler.fit_transform(X_train)
            X_test_scaled = scaler.transform(X_test)
            
            # Train Random Forest
            rf_model = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42,
                n_jobs=-1
            )
            rf_model.fit(X_train_scaled, y_train)
            rf_pred = rf_model.predict(X_test_scaled)
            
            # Train Gradient Boosting
            gb_model = GradientBoostingClassifier(
                n_estimators=100,
                max_depth=5,
                random_state=42
            )
            gb_model.fit(X_train_scaled, y_train)
            gb_pred = gb_model.predict(X_test_scaled)
            
            # Save models
            os.makedirs(output_path, exist_ok=True)
            
            # Save normalizer/scaler
            with open(os.path.join(output_path, 'normalizer.pkl'), 'wb') as f:
                pickle.dump(scaler, f)
            
            # Save models
            models = {'random_forest': rf_model, 'gradient_boosting': gb_model}
            with open(os.path.join(output_path, 'classifier.pkl'), 'wb') as f:
                pickle.dump(models, f)
            
            # Save metadata
            metrics['rf_accuracy'] = float(accuracy_score(y_test, rf_pred))
            metrics['gb_accuracy'] = float(accuracy_score(y_test, gb_pred))
            metrics['report'] = classification_report(y_test, rf_pred, output_dict=True)
            
            with open(os.path.join(output_path, 'metadata.json'), 'w') as f:
                json.dump(metrics, f, indent=2)
            
            print(f"[ML] Models trained and saved to {output_path}")
            print(f"[ML] Random Forest accuracy: {metrics['rf_accuracy']:.3f}")
            print(f"[ML] Gradient Boosting accuracy: {metrics['gb_accuracy']:.3f}")
            
        except ImportError:
            print("[ML] scikit-learn not available. Training skipped.")
            print("[ML] Install with: pip install scikit-learn")
        
        return metrics


# Global classifier instance
classifier = ThreatClassifier()
