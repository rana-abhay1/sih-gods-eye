"""
God's Eye — ML Streaming Inference Engine
Processes traffic in sliding windows and performs real-time threat detection.
"""

import time
import threading
import collections
from dataclasses import dataclass, field
from typing import List, Dict, Callable, Optional, Any
from collections import deque

from ml_features import MLFeatureExtractor, TrafficFeatures
from ml_classifier import ThreatClassifier, ThreatPrediction
from threat_detector import Threat, Evidence


@dataclass
class AnalysisWindow:
    """Container for a time-window of traffic analysis."""
    window_id: str
    start_time: float
    end_time: float
    packets: list
    features: Optional[TrafficFeatures] = None
    predictions: List[ThreatPrediction] = field(default_factory=list)
    threats: List[Threat] = field(default_factory=list)
    
    @property
    def duration(self) -> float:
        return self.end_time - self.start_time
    
    @property
    def packet_count(self) -> int:
        return len(self.packets)


class StreamingInferenceEngine:
    """
    Real-time streaming inference engine using sliding windows.
    
    Features:
    - Sliding window analysis for continuous traffic
    - Overlap between windows for temporal continuity
    - Real-time feature extraction and ML inference
    - Automatic threat correlation across windows
    """
    
    def __init__(self, 
                 window_size: float = 10.0,
                 slide_interval: float = 5.0,
                 min_packets: int = 10):
        """
        Initialize the streaming inference engine.
        
        Args:
            window_size: Analysis window size in seconds
            slide_interval: Time between window slides
            min_packets: Minimum packets required for analysis
        """
        self.window_size = window_size
        self.slide_interval = slide_interval
        self.min_packets = min_packets
        
        self.feature_extractor = MLFeatureExtractor()
        self.classifier = ThreatClassifier()
        
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._packet_buffer = deque(maxlen=50000)
        self._lock = threading.Lock()
        
        # Sliding window management
        self._windows: deque[AnalysisWindow] = deque(maxlen=100)
        self._window_counter = 0
        
        # Callbacks
        self._on_threat_detected: Optional[Callable] = None
        self._on_window_analyzed: Optional[Callable] = None
        
        # Statistics
        self._stats = {
            'windows_analyzed': 0,
            'threats_detected': 0,
            'total_packets_processed': 0,
            'avg_inference_time_ms': 0.0,
            'avg_confidence': 0.0,
        }
        
        # Threat correlation
        self._recent_threats: deque = deque(maxlen=100)
        self._threat_correlation_window = 30.0  # seconds
    
    @property
    def is_running(self) -> bool:
        return self._running
    
    @property
    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return dict(self._stats)
    
    def set_local_ip(self, ip: str):
        """Set the local IP for directional analysis."""
        self.feature_extractor.set_local_ip(ip)
    
    def set_callbacks(self, 
                      on_threat_detected: Optional[Callable] = None,
                      on_window_analyzed: Optional[Callable] = None):
        """Set callback functions for events."""
        self._on_threat_detected = on_threat_detected
        self._on_window_analyzed = on_window_analyzed
    
    def start(self):
        """Start the streaming inference engine."""
        if self._running:
            return
        
        self._running = True
        self._thread = threading.Thread(target=self._inference_loop, daemon=True)
        self._thread.start()
        
        print(f"[ML Inference] Started with window={self.window_size}s, slide={self.slide_interval}s")
    
    def stop(self):
        """Stop the streaming inference engine."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None
        print("[ML Inference] Stopped")
    
    def ingest_packet(self, packet):
        """Add a packet to the buffer for analysis."""
        with self._lock:
            self._packet_buffer.append(packet)
            self._stats['total_packets_processed'] += 1
    
    def _inference_loop(self):
        """Main inference loop."""
        while self._running:
            try:
                # Wait for slide interval
                time.sleep(self.slide_interval)
                
                if not self._running:
                    break
                
                # Perform window analysis
                self._analyze_window()
                
            except Exception as e:
                print(f"[ML Inference] Error in inference loop: {e}")
                time.sleep(1)
    
    def _analyze_window(self):
        """Analyze a sliding window of traffic."""
        with self._lock:
            if len(self._packet_buffer) < self.min_packets:
                return
            
            # Extract window of packets
            window_packets = list(self._packet_buffer)
            
            # Create analysis window
            self._window_counter += 1
            now = time.time()
            window = AnalysisWindow(
                window_id=f"W-{self._window_counter:06d}",
                start_time=now - self.window_size,
                end_time=now,
                packets=window_packets
            )
        
        # Extract features
        try:
            features = self.feature_extractor.extract_features(window.packets)
            window.features = features
        except Exception as e:
            print(f"[ML Inference] Feature extraction error: {e}")
            return
        
        # Run ML inference
        try:
            predictions = self.classifier.predict(features)
            window.predictions = predictions
        except Exception as e:
            print(f"[ML Inference] Prediction error: {e}")
            return
        
        # Convert predictions to Threat objects
        threats = self._predictions_to_threats(predictions, window)
        window.threats = threats
        
        # Correlate with recent threats
        correlated_threats = self._correlate_threats(threats)
        
        # Update statistics
        self._update_stats(window, correlated_threats)
        
        # Store window
        with self._lock:
            self._windows.append(window)
        
        # Trigger callbacks
        if correlated_threats and self._on_threat_detected:
            self._on_threat_detected(correlated_threats, window)
        
        if self._on_window_analyzed:
            self._on_window_analyzed(window)
    
    def _predictions_to_threats(self, predictions: List[ThreatPrediction], 
                                 window: AnalysisWindow) -> List[Threat]:
        """Convert ML predictions to Threat objects."""
        threats = []
        ts_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        
        for i, pred in enumerate(predictions):
            threat_id = f"ML-{window.window_id}-{i+1:02d}"
            
            # Generate evidence based on predictions
            evidence = self._generate_evidence(pred, window)
            
            # Determine source/destination from features
            source_ip, dest_ip = self._infer_ips(window)
            
            threat = Threat(
                id=threat_id,
                type=pred.threat_type,
                severity=pred.severity,
                confidence=pred.confidence,
                source_ip=source_ip,
                source_port=0,
                dest_ip=dest_ip,
                dest_port=0,
                protocol=self._infer_protocol(window),
                timestamp=ts_str,
                packets_analyzed=window.packet_count,
                bytes_transferred=window.features.total_bytes if window.features else 0,
                status='active',
                risk_score=pred.risk_score,
                evidence=evidence,
            )
            threats.append(threat)
        
        return threats
    
    def _generate_evidence(self, prediction: ThreatPrediction, 
                           window: AnalysisWindow) -> list:
        """Generate detailed evidence for a threat prediction."""
        evidence_list = []
        features = window.features
        
        if not features:
            return evidence_list
        
        # ML Prediction Evidence
        evidence_list.append(Evidence(
            type='ML Classification',
            detail=f"Model: {prediction.model_version}\n"
                   f"Confidence: {prediction.confidence:.1%}\n"
                   f"Risk Score: {prediction.risk_score:.1f}/10\n"
                   f"Inference Time: {prediction.inference_time_ms:.2f}ms",
            timestamp=time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        ).__dict__)
        
        # Feature Evidence
        feature_evidence = self._format_feature_evidence(features, prediction)
        if feature_evidence:
            evidence_list.append(Evidence(
                type='Feature Analysis',
                detail=feature_evidence,
                timestamp=time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
            ).__dict__)
        
        # Traffic Statistics Evidence
        stats_evidence = (
            f"Window Duration: {window.duration:.1f}s\n"
            f"Packets Analyzed: {window.packet_count}\n"
            f"Total Bytes: {features.total_bytes:,}\n"
            f"Packets/sec: {features.packets_per_second:.1f}\n"
            f"Unique Source IPs: {features.unique_src_ips}\n"
            f"Unique Dest Ports: {features.unique_dst_ports}"
        )
        evidence_list.append(Evidence(
            type='Traffic Statistics',
            detail=stats_evidence,
            timestamp=time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        ).__dict__)
        
        # Protocol Distribution Evidence
        proto_evidence = (
            f"TCP: {features.tcp_count} ({features.tcp_count/max(window.packet_count,1)*100:.1f}%)\n"
            f"UDP: {features.udp_count} ({features.udp_count/max(window.packet_count,1)*100:.1f}%)\n"
            f"ICMP: {features.icmp_count}\n"
            f"DNS: {features.dns_count}"
        )
        evidence_list.append(Evidence(
            type='Protocol Distribution',
            detail=proto_evidence,
            timestamp=time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        ).__dict__)
        
        return evidence_list
    
    def _format_feature_evidence(self, features: TrafficFeatures, 
                                  prediction: ThreatPrediction) -> str:
        """Format feature importance as human-readable evidence."""
        if not prediction.feature_importance:
            return ""
        
        lines = ["Key Indicators:"]
        for feature, value in sorted(prediction.feature_importance.items(), 
                                      key=lambda x: x[1], reverse=True)[:5]:
            # Format based on feature name
            if 'score' in feature:
                lines.append(f"  • {feature}: {value:.3f}")
            elif 'count' in feature:
                lines.append(f"  • {feature}: {value}")
            elif 'entropy' in feature:
                lines.append(f"  • {feature}: {value:.2f}")
            elif 'ratio' in feature:
                lines.append(f"  • {feature}: {value:.1%}")
            else:
                lines.append(f"  • {feature}: {value:.2f}")
        
        return "\n".join(lines)
    
    def _infer_ips(self, window: AnalysisWindow) -> tuple:
        """Infer source and destination IPs from window."""
        if not window.packets:
            return ("unknown", "unknown")
        
        # Find most common source and destination
        src_ips = collections.Counter(p.src_ip for p in window.packets)
        dst_ips = collections.Counter(p.dst_ip for p in window.packets)
        
        most_common_src = src_ips.most_common(1)[0][0] if src_ips else "unknown"
        most_common_dst = dst_ips.most_common(1)[0][0] if dst_ips else "unknown"
        
        return (most_common_src, most_common_dst)
    
    def _infer_protocol(self, window: AnalysisWindow) -> str:
        """Infer dominant protocol from window."""
        if not window.packets:
            return "Unknown"
        
        proto_counts = collections.Counter(p.protocol for p in window.packets)
        if proto_counts:
            return proto_counts.most_common(1)[0][0]
        return "Unknown"
    
    def _correlate_threats(self, threats: List[Threat]) -> List[Threat]:
        """Correlate new threats with recent threats to reduce false positives."""
        if not threats:
            return []
        
        now = time.time()
        correlated = []
        
        # Get recent threats within correlation window
        with self._lock:
            recent = [
                t for t in self._recent_threats
                if now - self._parse_timestamp(t.timestamp) < self._threat_correlation_window
            ]
        
        for threat in threats:
            # Check for similar recent threats
            similar = [
                r for r in recent
                if r.type == threat.type and
                   self._calculate_similarity(r, threat) > 0.7
            ]
            
            if len(similar) >= 2:
                # Boost confidence if multiple similar threats detected
                threat.confidence = min(0.99, threat.confidence * 1.1)
                threat.risk_score = min(10.0, threat.risk_score * 1.15)
                
                # Add correlation evidence
                threat.evidence.append(Evidence(
                    type='Threat Correlation',
                    detail=f"Correlated with {len(similar)} similar threats in "
                           f"the last {self._threat_correlation_window:.0f} seconds. "
                           f"This increases confidence in the detection.",
                    timestamp=time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
                ).__dict__)
            
            correlated.append(threat)
        
        # Update recent threats buffer
        with self._lock:
            self._recent_threats.extend(threats)
            # Remove old threats
            self._recent_threats = deque(
                [t for t in self._recent_threats 
                 if now - self._parse_timestamp(t.timestamp) < self._threat_correlation_window * 2],
                maxlen=100
            )
        
        return correlated
    
    def _parse_timestamp(self, ts_str: str) -> float:
        """Parse timestamp string to float."""
        try:
            return time.mktime(time.strptime(ts_str, '%Y-%m-%d %H:%M:%S'))
        except:
            return time.time()
    
    def _calculate_similarity(self, threat1: Threat, threat2: Threat) -> float:
        """Calculate similarity between two threats."""
        similarity = 0.0
        
        # Same type
        if threat1.type == threat2.type:
            similarity += 0.5
        
        # Similar source IPs
        if threat1.source_ip == threat2.source_ip:
            similarity += 0.3
        
        # Similar destination
        if threat1.dest_ip == threat2.dest_ip:
            similarity += 0.2
        
        return similarity
    
    def _update_stats(self, window: AnalysisWindow, threats: List[Threat]):
        """Update inference statistics."""
        with self._lock:
            self._stats['windows_analyzed'] += 1
            self._stats['threats_detected'] += len(threats)
            
            # Update average inference time
            if window.predictions:
                avg_time = sum(p.inference_time_ms for p in window.predictions) / len(window.predictions)
                n = self._stats['windows_analyzed']
                self._stats['avg_inference_time_ms'] = (
                    (self._stats['avg_inference_time_ms'] * (n-1) + avg_time) / n
                )
            
            # Update average confidence
            if threats:
                avg_conf = sum(t.confidence for t in threats) / len(threats)
                n = self._stats['threats_detected']
                self._stats['avg_confidence'] = (
                    (self._stats['avg_confidence'] * (n-1) + avg_conf) / n
                )
    
    def get_recent_windows(self, count: int = 10) -> List[AnalysisWindow]:
        """Get recent analysis windows."""
        with self._lock:
            return list(self._windows)[-count:]
    
    def get_threat_history(self, count: int = 50) -> List[Threat]:
        """Get recent threat history."""
        with self._lock:
            all_threats = []
            for window in self._windows:
                all_threats.extend(window.threats)
            return all_threats[-count:]


# Global inference engine instance
inference_engine = StreamingInferenceEngine()
