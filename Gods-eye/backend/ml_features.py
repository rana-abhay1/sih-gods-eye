"""
God's Eye — ML Feature Extraction Module
Extracts statistical and behavioral features from network traffic for ML-based threat detection.
"""

import math
import time
import collections
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional
import numpy as np


@dataclass
class TrafficFeatures:
    """Container for extracted traffic features."""
    # Basic statistics
    total_packets: int = 0
    total_bytes: int = 0
    duration: float = 0.0
    
    # IP features
    unique_src_ips: int = 0
    unique_dst_ips: int = 0
    src_ip_entropy: float = 0.0
    dst_ip_entropy: float = 0.0
    
    # Port features
    unique_src_ports: int = 0
    unique_dst_ports: int = 0
    dst_port_entropy: float = 0.0
    
    # Protocol features
    tcp_count: int = 0
    udp_count: int = 0
    icmp_count: int = 0
    dns_count: int = 0
    http_count: int = 0
    https_count: int = 0
    
    # TCP flag features
    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    psh_count: int = 0
    syn_ack_ratio: float = 0.0
    
    # Size features
    avg_packet_size: float = 0.0
    max_packet_size: int = 0
    min_packet_size: int = 0
    std_packet_size: float = 0.0
    avg_payload_size: float = 0.0
    
    # Temporal features
    packets_per_second: float = 0.0
    bytes_per_second: float = 0.0
    inter_arrival_time_mean: float = 0.0
    inter_arrival_time_std: float = 0.0
    
    # Behavioral features
    is_outbound_dominant: float = 0.0
    port_scan_score: float = 0.0
    dls_score: float = 0.0  # DDoS likelihood score
    bf_score: float = 0.0  # Brute force score
    exfil_score: float = 0.0  # Exfiltration score
    tunnel_score: float = 0.0  # Tunneling score
    
    # Additional derived features
    payload_ratio: float = 0.0
    small_packet_ratio: float = 0.0  # Packets < 100 bytes
    large_packet_ratio: float = 0.0  # Packets > 1000 bytes
    
    def to_vector(self) -> np.ndarray:
        """Convert features to numpy array for ML model input."""
        return np.array([
            self.total_packets,
            self.total_bytes,
            self.duration,
            self.unique_src_ips,
            self.unique_dst_ips,
            self.src_ip_entropy,
            self.dst_ip_entropy,
            self.unique_src_ports,
            self.unique_dst_ports,
            self.dst_port_entropy,
            self.tcp_count,
            self.udp_count,
            self.icmp_count,
            self.dns_count,
            self.http_count,
            self.https_count,
            self.syn_count,
            self.ack_count,
            self.fin_count,
            self.rst_count,
            self.psh_count,
            self.syn_ack_ratio,
            self.avg_packet_size,
            self.max_packet_size,
            self.min_packet_size,
            self.std_packet_size,
            self.avg_payload_size,
            self.packets_per_second,
            self.bytes_per_second,
            self.inter_arrival_time_mean,
            self.inter_arrival_time_std,
            self.is_outbound_dominant,
            self.port_scan_score,
            self.dls_score,
            self.bf_score,
            self.exfil_score,
            self.tunnel_score,
            self.payload_ratio,
            self.small_packet_ratio,
            self.large_packet_ratio,
        ], dtype=np.float32)
    
    @property
    def feature_names(self) -> List[str]:
        """Return feature names for interpretability."""
        return [
            'total_packets', 'total_bytes', 'duration',
            'unique_src_ips', 'unique_dst_ips', 'src_ip_entropy', 'dst_ip_entropy',
            'unique_src_ports', 'unique_dst_ports', 'dst_port_entropy',
            'tcp_count', 'udp_count', 'icmp_count', 'dns_count', 'http_count', 'https_count',
            'syn_count', 'ack_count', 'fin_count', 'rst_count', 'psh_count', 'syn_ack_ratio',
            'avg_packet_size', 'max_packet_size', 'min_packet_size', 'std_packet_size', 'avg_payload_size',
            'packets_per_second', 'bytes_per_second',
            'inter_arrival_time_mean', 'inter_arrival_time_std',
            'is_outbound_dominant', 'port_scan_score', 'dls_score', 'bf_score', 'exfil_score', 'tunnel_score',
            'payload_ratio', 'small_packet_ratio', 'large_packet_ratio',
        ]


class MLFeatureExtractor:
    """Extracts ML features from raw packet data."""
    
    def __init__(self):
        self._known_internal_ips = set()
        self._local_ip = None
    
    def set_local_ip(self, ip: str):
        """Set the local IP for directional analysis."""
        self._local_ip = ip
    
    def extract_features(self, packets: list) -> TrafficFeatures:
        """
        Extract comprehensive ML features from a list of packets.
        
        Args:
            packets: List of packet objects (PacketInfo or LivePacket)
            
        Returns:
            TrafficFeatures object with extracted features
        """
        features = TrafficFeatures()
        
        if not packets:
            return features
        
        # Basic counts
        features.total_packets = len(packets)
        features.total_bytes = sum(p.size for p in packets)
        
        # Temporal analysis
        timestamps = [p.timestamp for p in packets]
        if len(timestamps) > 1:
            features.duration = max(timestamps) - min(timestamps)
            
            # Inter-arrival times
            sorted_ts = sorted(timestamps)
            iats = [sorted_ts[i+1] - sorted_ts[i] for i in range(len(sorted_ts)-1)]
            features.inter_arrival_time_mean = float(np.mean(iats)) if iats else 0.0
            features.inter_arrival_time_std = float(np.std(iats)) if iats else 0.0
        
        # Rate calculations
        if features.duration > 0:
            features.packets_per_second = features.total_packets / features.duration
            features.bytes_per_second = features.total_bytes / features.duration
        
        # IP analysis
        src_ips = [p.src_ip for p in packets]
        dst_ips = [p.dst_ip for p in packets]
        features.unique_src_ips = len(set(src_ips))
        features.unique_dst_ips = len(set(dst_ips))
        features.src_ip_entropy = self._calculate_entropy(src_ips)
        features.dst_ip_entropy = self._calculate_entropy(dst_ips)
        
        # Port analysis
        src_ports = [p.src_port for p in packets if p.src_port > 0]
        dst_ports = [p.dst_port for p in packets if p.dst_port > 0]
        features.unique_src_ports = len(set(src_ports))
        features.unique_dst_ports = len(set(dst_ports))
        features.dst_port_entropy = self._calculate_entropy(dst_ports)
        
        # Protocol analysis
        protocols = [p.protocol for p in packets]
        features.tcp_count = protocols.count('TCP')
        features.udp_count = protocols.count('UDP')
        features.icmp_count = protocols.count('ICMP')
        features.dns_count = protocols.count('DNS')
        features.http_count = sum(1 for p in packets if p.dst_port in (80, 8080))
        features.https_count = sum(1 for p in packets if p.dst_port in (443, 8443))
        
        # TCP flag analysis
        for p in packets:
            flags = p.flags if hasattr(p, 'flags') else ''
            if 'SYN' in flags:
                features.syn_count += 1
            if 'ACK' in flags:
                features.ack_count += 1
            if 'FIN' in flags:
                features.fin_count += 1
            if 'RST' in flags:
                features.rst_count += 1
            if 'PSH' in flags:
                features.psh_count += 1
        
        # SYN/ACK ratio (important for DDoS detection)
        if features.ack_count > 0:
            features.syn_ack_ratio = features.syn_count / features.ack_count
        else:
            features.syn_ack_ratio = features.syn_count
        
        # Size analysis
        sizes = [p.size for p in packets]
        features.avg_packet_size = float(np.mean(sizes))
        features.max_packet_size = max(sizes)
        features.min_packet_size = min(sizes)
        features.std_packet_size = float(np.std(sizes))
        
        payload_sizes = [p.payload_len for p in packets if p.has_payload]
        if payload_sizes:
            features.avg_payload_size = float(np.mean(payload_sizes))
            features.payload_ratio = len(payload_sizes) / len(packets)
        
        # Packet size distribution
        features.small_packet_ratio = sum(1 for s in sizes if s < 100) / len(sizes)
        features.large_packet_ratio = sum(1 for s in sizes if s > 1000) / len(sizes)
        
        # Directional analysis
        if self._local_ip:
            outbound = sum(1 for p in packets if p.src_ip == self._local_ip)
            inbound = sum(1 for p in packets if p.dst_ip == self._local_ip)
            total = outbound + inbound
            features.is_outbound_dominant = outbound / total if total > 0 else 0.5
        
        # Behavioral scores (heuristic-based for ML features)
        features.port_scan_score = self._calculate_port_scan_score(packets)
        features.dls_score = self._calculate_ddos_score(packets, features)
        features.bf_score = self._calculate_brute_force_score(packets, features)
        features.exfil_score = self._calculate_exfil_score(packets, features)
        features.tunnel_score = self._calculate_tunnel_score(packets, features)
        
        return features
    
    def _calculate_entropy(self, values: list) -> float:
        """Calculate Shannon entropy of a distribution."""
        if not values:
            return 0.0
        
        counter = collections.Counter(values)
        total = len(values)
        entropy = 0.0
        
        for count in counter.values():
            if count > 0:
                p = count / total
                entropy -= p * math.log2(p)
        
        return entropy
    
    def _calculate_port_scan_score(self, packets: list) -> float:
        """Calculate port scan likelihood score."""
        dst_ports = [p.dst_port for p in packets if p.dst_port > 0]
        if not dst_ports:
            return 0.0
        
        unique_ports = len(set(dst_ports))
        total = len(dst_ports)
        
        # High port diversity relative to packet count suggests scanning
        port_diversity = unique_ports / total if total > 0 else 0
        
        # Many different ports from few sources
        src_ips = set(p.src_ip for p in packets)
        src_to_port_ratio = len(src_ips) / unique_ports if unique_ports > 0 else 0
        
        score = min(1.0, (port_diversity * 10 + src_to_port_ratio) / 2)
        return score
    
    def _calculate_ddos_score(self, packets: list, features: TrafficFeatures) -> float:
        """Calculate DDoS likelihood score."""
        if features.total_packets < 10:
            return 0.0
        
        # High packet rate
        pps_score = min(1.0, features.packets_per_second / 1000)
        
        # Many unique sources
        src_diversity = min(1.0, features.unique_src_ips / 50)
        
        # High SYN ratio
        syn_score = min(1.0, features.syn_count / max(features.total_packets, 1) * 2)
        
        # Low unique destination ports (targeting specific service)
        port_concentration = 1.0 - min(1.0, features.unique_dst_ports / 20)
        
        score = (pps_score * 0.4 + src_diversity * 0.3 + syn_score * 0.2 + port_concentration * 0.1)
        return min(1.0, score)
    
    def _calculate_brute_force_score(self, packets: list, features: TrafficFeatures) -> float:
        """Calculate brute force attack likelihood score."""
        # High concentration on specific port
        dst_ports = [p.dst_port for p in packets if p.dst_port > 0]
        if not dst_ports:
            return 0.0
        
        counter = collections.Counter(dst_ports)
        if not counter:
            return 0.0
        
        max_port, max_count = counter.most_common(1)[0]
        
        # Sensitive ports (SSH, RDP, FTP, etc.)
        sensitive_ports = {22, 23, 3389, 21, 3306, 5432, 5900, 6379}
        port_sensitivity = 1.0 if max_port in sensitive_ports else 0.5
        
        # Concentration score
        concentration = max_count / len(dst_ports)
        
        # From single source
        src_ips = [p.src_ip for p in packets if p.dst_port == max_port]
        src_concentration = len(set(src_ips)) == 1
        
        score = concentration * port_sensitivity * (1.2 if src_concentration else 0.8)
        return min(1.0, score)
    
    def _calculate_exfil_score(self, packets: list, features: TrafficFeatures) -> float:
        """Calculate data exfiltration likelihood score."""
        if features.total_bytes < 10000:
            return 0.0
        
        # High outbound traffic
        outbound_score = features.is_outbound_dominant if features.is_outbound_dominant else 0.5
        
        # Large payloads
        payload_score = min(1.0, features.avg_payload_size / 1000) if features.avg_payload_size > 0 else 0
        
        # Sustained transfer (not bursty)
        sustained = 1.0 if features.duration > 5 and features.packets_per_second > 10 else 0.3
        
        # Mixed protocols (potential evasion)
        proto_diversity = len(set(p.protocol for p in packets)) / 3
        
        score = (outbound_score * 0.3 + payload_score * 0.3 + sustained * 0.2 + min(1.0, proto_diversity) * 0.2)
        return min(1.0, score)
    
    def _calculate_tunnel_score(self, packets: list, features: TrafficFeatures) -> float:
        """Calculate tunneling likelihood score."""
        # High DNS traffic
        dns_ratio = features.dns_count / max(features.total_packets, 1)
        dns_score = min(1.0, dns_ratio * 3)
        
        # DNS packets with large payloads (unusual)
        dns_packets = [p for p in packets if p.protocol == 'DNS' and p.has_payload]
        dns_large_payload = sum(1 for p in dns_packets if p.payload_len > 100)
        large_dns_score = min(1.0, dns_large_payload / max(len(dns_packets), 1) * 2) if dns_packets else 0
        
        # Regular intervals (beaconing)
        regularity_score = 0.0
        if features.inter_arrival_time_std > 0 and features.inter_arrival_time_mean > 0:
            cv = features.inter_arrival_time_std / features.inter_arrival_time_mean
            regularity_score = max(0, 1.0 - cv)  # Low CV = regular
        
        score = (dns_score * 0.4 + large_dns_score * 0.3 + regularity_score * 0.3)
        return min(1.0, score)


class FeatureNormalizer:
    """Normalizes features for ML model input."""
    
    def __init__(self):
        self._means = None
        self._stds = None
        self._fitted = False
    
    def fit(self, features_list: List[TrafficFeatures]):
        """Fit normalizer on a list of features."""
        vectors = np.array([f.to_vector() for f in features_list])
        self._means = np.mean(vectors, axis=0)
        self._stds = np.std(vectors, axis=0)
        self._stds[self._stds == 0] = 1  # Avoid division by zero
        self._fitted = True
    
    def normalize(self, features: TrafficFeatures) -> np.ndarray:
        """Normalize a single feature vector."""
        if not self._fitted:
            return features.to_vector()
        
        return (features.to_vector() - self._means) / self._stds
