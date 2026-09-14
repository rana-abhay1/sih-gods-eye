"""
God's Eye — Live Traffic Capture Module
Captures packets from a network interface in real time.
Falls back to simulated traffic generation if root access is unavailable.
"""

import collections
import time
import threading
import random
import socket
from dataclasses import dataclass
from typing import Callable, Optional

try:
    from scapy.all import IP, TCP, UDP, ICMP, DNS, Raw, sniff, conf, get_if_list
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from threat_detector import extract_features, Threat, Evidence


# ──────────────────────────── Configuration ────────────────────────────

WINDOW_SECONDS = 10
MAX_BUFFER_SIZE = 50000
SIM_PACKETS_PER_SEC = 80  # Fallback simulation rate


# ──────────────────────────── Packet Info ────────────────────────────

@dataclass
class LivePacket:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    size: int
    flags: str
    timestamp: float
    payload_len: int
    has_payload: bool


# ──────────────────────────── Helpers ────────────────────────────

def _random_ip():
    return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def _local_ip():
    """Get the local IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "192.168.1.1"

def _generate_sim_packet():
    """Generate a realistic-looking packet for simulation mode."""
    local_ip = _local_ip()
    is_outbound = random.random() > 0.3

    if is_outbound:
        src_ip = local_ip
        dst_ip = _random_ip()
    else:
        src_ip = _random_ip()
        dst_ip = local_ip

    proto = random.choices(
        ['TCP', 'UDP', 'DNS', 'ICMP'],
        weights=[60, 20, 15, 5]
    )[0]

    common_ports = [80, 443, 53, 22, 8080, 3306, 8443, 21, 25, 110, 3389, 445]
    dst_port = random.choice(common_ports)
    src_port = random.randint(1024, 65535)
    size = random.randint(64, 1500)
    flags = ''
    payload_len = 0
    has_payload = False

    if proto == 'TCP':
        flag_combos = ['SYN', 'SYN|ACK', 'ACK', 'PSH|ACK', 'FIN|ACK', 'RST']
        flags = random.choice(flag_combos)
        if 'PSH' in flags:
            payload_len = random.randint(100, 1400)
            has_payload = True
    elif proto == 'DNS':
        dst_port = 53
        payload_len = random.randint(20, 200)
        has_payload = True

    return LivePacket(
        src_ip=src_ip, dst_ip=dst_ip,
        src_port=src_port, dst_port=dst_port,
        protocol=proto, size=size, flags=flags,
        timestamp=time.time(),
        payload_len=payload_len, has_payload=has_payload,
    )


# ──────────────────────────── Capture Engine ────────────────────────────

class LiveCaptureEngine:
    def __init__(self):
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._analysis_thread: Optional[threading.Thread] = None
        self._sniffer = None
        self._interface: Optional[str] = None
        self._packets: list[LivePacket] = []
        self._lock = threading.Lock()
        self._window_start = time.time()
        self._callback: Optional[Callable] = None
        self._sim_mode = False
        self._error_message = ''
        self._stats = {
            'total_packets': 0, 'suspicious_packets': 0, 'normal_packets': 0,
            'pps': 0, 'bytes_per_sec': 0,
            'unique_src_ips': set(), 'unique_dst_ips': set(),
            'protocols': collections.Counter(),
            'ml_threats_detected': 0, 'ml_windows_analyzed': 0,
            'ml_total_inference_ms': 0.0,
        }
        self._last_pps_calc = time.time()
        self._last_pps_count = 0

    @property
    def is_running(self):
        return self._running

    @property
    def interface(self):
        return self._interface

    @property
    def sim_mode(self):
        return self._sim_mode

    @property
    def error_message(self):
        return self._error_message

    @property
    def stats(self):
        with self._lock:
            s = dict(self._stats)
            s['unique_src_ips'] = len(s['unique_src_ips'])
            s['unique_dst_ips'] = len(s['unique_dst_ips'])
            s['protocols'] = dict(s['protocols'])
            s['buffer_size'] = len(self._packets)
            s['uptime'] = round(time.time() - self._window_start, 1) if self._running else 0
            # ML stats
            ml_windows = s.get('ml_windows_analyzed', 0)
            s['ml_threats_detected'] = s.get('ml_threats_detected', 0)
            s['ml_windows_analyzed'] = ml_windows
            s['ml_avg_inference_ms'] = round(s.get('ml_total_inference_ms', 0) / max(ml_windows, 1), 2)
            return s

    def get_available_interfaces(self) -> list:
        if SCAPY_AVAILABLE:
            try:
                ifaces = get_if_list()
                return [str(i) for i in ifaces] if ifaces else ['eth0', 'wlan0', 'lo']
            except Exception:
                pass
        return ['eth0', 'wlan0', 'lo']

    def start(self, interface: Optional[str] = None, callback: Optional[Callable] = None):
        if self._running:
            return {'status': 'already_running', 'interface': self._interface}

        self._running = True
        self._interface = interface
        self._callback = callback
        self._packets = []
        self._window_start = time.time()
        self._error_message = ''
        self._sim_mode = False
        self._stats = {
            'total_packets': 0, 'suspicious_packets': 0, 'normal_packets': 0,
            'pps': 0, 'bytes_per_sec': 0,
            'unique_src_ips': set(), 'unique_dst_ips': set(),
            'protocols': collections.Counter(),
            'ml_threats_detected': 0, 'ml_windows_analyzed': 0,
            'ml_total_inference_ms': 0.0,
        }

        # Try real capture first, fall back to simulation
        if SCAPY_AVAILABLE:
            self._thread = threading.Thread(target=self._try_real_capture, daemon=True)
            self._thread.start()
        else:
            self._start_simulation()

        # Analysis thread
        self._analysis_thread = threading.Thread(target=self._analysis_loop, daemon=True)
        self._analysis_thread.start()

        mode = 'simulation' if self._sim_mode else 'real capture'
        return {'status': 'started', 'interface': interface or 'default', 'mode': mode}

    def stop(self):
        if not self._running:
            return {'status': 'not_running'}

        self._running = False
        if self._sniffer:
            try:
                self._sniffer.stop()
            except Exception:
                pass
            self._sniffer = None

        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None

        final_stats = self.stats
        self._packets = []

        return {'status': 'stopped', 'final_stats': final_stats, 'sim_mode': self._sim_mode}

    def _try_real_capture(self):
        """Attempt real scapy capture. Falls back to simulation on permission error."""
        try:
            bpf_filter = 'ip'
            self._sniffer = sniff(
                iface=self._interface,
                prn=self._packet_handler,
                filter=bpf_filter,
                store=False,
                stop_filter=lambda _: not self._running,
            )
        except PermissionError:
            self._error_message = 'Permission denied. Falling back to simulation mode. Run with sudo for real capture.'
            self._start_simulation()
        except OSError as e:
            self._error_message = f'Interface error: {e}. Falling back to simulation.'
            self._start_simulation()
        except Exception as e:
            self._error_message = f'Capture error: {e}. Falling back to simulation.'
            self._start_simulation()

    def _start_simulation(self):
        """Start simulated packet generation."""
        self._sim_mode = True
        self._error_message = ''
        self._thread = threading.Thread(target=self._simulation_loop, daemon=True)
        self._thread.start()

    def _simulation_loop(self):
        """Generate realistic simulated packets."""
        while self._running:
            # Generate a burst of packets
            burst_size = random.randint(3, 12)
            for _ in range(burst_size):
                if not self._running:
                    return
                pkt = _generate_sim_packet()
                self._process_packet(pkt)

            # Sleep to simulate realistic packet rate
            time.sleep(1.0 / SIM_PACKETS_PER_SEC)

    def _packet_handler(self, pkt):
        """Called for each real captured packet."""
        if not self._running or not pkt.haslayer(IP):
            return

        ip = pkt[IP]
        src_port = dst_port = 0
        proto = 'IP'
        flags = ''
        size = len(pkt)
        payload_len = 0
        has_payload = False

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            src_port, dst_port = tcp.sport, tcp.dport
            proto = 'TCP'
            flag_list = []
            if tcp.flags & 0x02: flag_list.append('SYN')
            if tcp.flags & 0x10: flag_list.append('ACK')
            if tcp.flags & 0x01: flag_list.append('FIN')
            if tcp.flags & 0x04: flag_list.append('RST')
            if tcp.flags & 0x08: flag_list.append('PSH')
            flags = '|'.join(flag_list)
        elif pkt.haslayer(UDP):
            src_port, dst_port = pkt[UDP].sport, pkt[UDP].dport
            proto = 'UDP'
            if pkt.haslayer(DNS):
                proto = 'DNS'
        elif pkt.haslayer(ICMP):
            proto = 'ICMP'

        if pkt.haslayer(Raw):
            payload_len = len(pkt[Raw].load)
            has_payload = True

        self._process_packet(LivePacket(
            src_ip=ip.src, dst_ip=ip.dst,
            src_port=src_port, dst_port=dst_port,
            protocol=proto, size=size, flags=flags,
            timestamp=float(pkt.time),
            payload_len=payload_len, has_payload=has_payload,
        ))

    def _process_packet(self, live_pkt: LivePacket):
        """Process a packet (from real capture or simulation)."""
        with self._lock:
            self._packets.append(live_pkt)
            if len(self._packets) > MAX_BUFFER_SIZE:
                self._packets = self._packets[-MAX_BUFFER_SIZE:]

            self._stats['total_packets'] += 1
            self._stats['unique_src_ips'].add(live_pkt.src_ip)
            self._stats['unique_dst_ips'].add(live_pkt.dst_ip)
            self._stats['protocols'][live_pkt.protocol] += 1

            now = time.time()
            elapsed = now - self._last_pps_calc
            if elapsed >= 1.0:
                self._stats['pps'] = round(
                    (self._stats['total_packets'] - self._last_pps_count) / elapsed
                )
                self._stats['bytes_per_sec'] = round(live_pkt.size / elapsed)
                self._last_pps_calc = now
                self._last_pps_count = self._stats['total_packets']

    def _analysis_loop(self):
        """Periodically analyze buffered packets and emit threats."""
        # Import ML components lazily to avoid circular imports
        try:
            from ml_features import MLFeatureExtractor
            from ml_classifier import ThreatClassifier
            ml_extractor = MLFeatureExtractor()
            ml_classifier = ThreatClassifier()
        except ImportError:
            ml_extractor = None
            ml_classifier = None

        while self._running:
            time.sleep(WINDOW_SECONDS)
            if not self._running:
                break

            with self._lock:
                window_packets = list(self._packets)
                self._packets = []
                self._window_start = time.time()

            if not window_packets or len(window_packets) < 10:
                continue

            features = extract_features(window_packets)
            if not features:
                continue

            # Rule-based detection (existing)
            threats = self._detect_window_threats(features, window_packets)

            # ML-based detection (new)
            ml_predictions = []
            ml_features_dict = {}
            if ml_extractor and ml_classifier:
                try:
                    ml_features = ml_extractor.extract_features(window_packets)
                    ml_predictions = ml_classifier.predict(ml_features)
                    ml_features_dict = {
                        'src_ip_entropy': round(ml_features.src_ip_entropy, 2),
                        'dst_ip_entropy': round(ml_features.dst_ip_entropy, 2),
                        'port_scan_score': round(ml_features.port_scan_score, 3),
                        'ddos_score': round(ml_features.dls_score, 3),
                        'brute_force_score': round(ml_features.bf_score, 3),
                        'exfil_score': round(ml_features.exfil_score, 3),
                        'tunnel_score': round(ml_features.tunnel_score, 3),
                        'syn_ack_ratio': round(ml_features.syn_ack_ratio, 3),
                        'avg_payload_size': round(ml_features.avg_payload_size, 1),
                    }
                    # Convert ML predictions to Threat objects
                    ts_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
                    src_ips = [p.src_ip for p in window_packets]
                    dst_ips = [p.dst_ip for p in window_packets]
                    most_common_src = max(set(src_ips), key=src_ips.count) if src_ips else 'unknown'
                    most_common_dst = max(set(dst_ips), key=dst_ips.count) if dst_ips else 'unknown'
                    for pred in ml_predictions:
                        pred_dict = pred.to_dict()
                        ml_threat = Threat(
                            id=f"ML-{len(threats)+1:04d}",
                            type=pred_dict['threat_type'],
                            severity=pred_dict['severity'],
                            confidence=pred_dict['confidence'],
                            source_ip=most_common_src,
                            source_port=0,
                            dest_ip=most_common_dst,
                            dest_port=0,
                            protocol='Mixed',
                            timestamp=ts_str,
                            packets_analyzed=features.get('total_packets', 0),
                            bytes_transferred=features.get('total_bytes', 0),
                            status='active',
                            risk_score=pred_dict['risk_score'],
                            evidence=[Evidence(
                                type='ML Classification',
                                detail=f"Model: {pred_dict['model_version']}\nConfidence: {pred_dict['confidence']:.1%}\nRisk Score: {pred_dict['risk_score']:.1f}/10\nInference Time: {pred_dict['inference_time_ms']:.2f}ms",
                                timestamp=ts_str,
                            ).__dict__],
                        )
                        threats.append(ml_threat)
                except Exception as e:
                    print(f"[ML] Analysis error: {e}")

            # Update ML stats
            with self._lock:
                self._stats['ml_windows_analyzed'] += 1
                self._stats['ml_threats_detected'] += len(ml_predictions)
                if ml_predictions:
                    avg_time = sum(p.inference_time_ms for p in ml_predictions) / len(ml_predictions)
                    self._stats['ml_total_inference_ms'] += avg_time

            suspicious_count = sum(1 for t in threats if t.severity in ('critical', 'high'))
            with self._lock:
                self._stats['suspicious_packets'] += suspicious_count
                self._stats['normal_packets'] += max(0, len(window_packets) - suspicious_count)

            if self._callback and threats:
                self._callback({
                    'type': 'threats',
                    'threats': [t.to_dict() for t in threats],
                    'window_packets': len(window_packets),
                    'ml_threat_count': len(ml_predictions),
                    'features': {
                        'total_packets': features.get('total_packets', 0),
                        'pps': features.get('pps', 0),
                        'unique_src_ips': features.get('unique_src_ips', 0),
                        'unique_dst_ports': features.get('unique_dst_ports', 0),
                        'protocols': features.get('protocols', {}),
                        **ml_features_dict,
                    },
                })

    def _detect_window_threats(self, features: dict, packets: list) -> list:
        threats = []
        ts_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        counter = 0

        def make_threat(**kwargs):
            nonlocal counter
            counter += 1
            return Threat(id=f"LIVE-{counter:04d}", status='active', **kwargs)

        # 1. Port Scanning
        unique_ports = features.get('unique_dst_ports', 0)
        if unique_ports > 15 or (features.get('pps', 0) > 50 and unique_ports > 8):
            top_src = features.get('top_src_ip', ('unknown', 0))
            conf_val = min(0.78 + (unique_ports // 50) * 0.05, 0.99)
            threats.append(make_threat(
                type='Port Scanning', severity='high', confidence=conf_val,
                source_ip=top_src[0] if isinstance(top_src, tuple) else 'unknown',
                source_port=0, dest_ip='multiple targets', dest_port=0,
                protocol='TCP', timestamp=ts_str,
                packets_analyzed=features['total_packets'],
                bytes_transferred=features.get('total_bytes', 0),
                risk_score=round(conf_val * 10 * 1.2, 1),
                evidence=[Evidence(type='Live Port Scan Detection',
                    detail=f"[LIVE] Scanned {unique_ports} unique ports in {WINDOW_SECONDS}s window. Rate: {features.get('pps', 0):.1f} pps.",
                    timestamp=ts_str).__dict__],
            ))

        # 2. SYN Flood
        syn_ratio = features.get('syn_ratio', 0)
        if syn_ratio > 0.4 and features.get('syn_count', 0) > 20:
            conf_val = min(0.88 + syn_ratio * 0.1, 0.99)
            threats.append(make_threat(
                type='SYN Flood Attack', severity='critical', confidence=conf_val,
                source_ip='distributed', source_port=0, dest_ip='target', dest_port=0,
                protocol='TCP', timestamp=ts_str,
                packets_analyzed=features['total_packets'],
                bytes_transferred=features.get('total_bytes', 0),
                risk_score=round(conf_val * 10 * 1.5, 1),
                evidence=[Evidence(type='Live SYN Flood Detection',
                    detail=f"[LIVE] SYN ratio: {syn_ratio*100:.1f}% ({features['syn_count']} SYN / {features['total_packets']} total). Rate: {features.get('pps', 0):.1f} pps.",
                    timestamp=ts_str).__dict__],
            ))

        # 3. DDoS
        if features.get('pps', 0) > 200 and features.get('unique_src_ips', 0) > 10:
            conf_val = min(0.85 + (features['unique_src_ips'] // 50) * 0.03, 0.99)
            threats.append(make_threat(
                type='DDoS Attack', severity='critical', confidence=conf_val,
                source_ip='distributed', source_port=0, dest_ip='target', dest_port=0,
                protocol='Mixed', timestamp=ts_str,
                packets_analyzed=features['total_packets'],
                bytes_transferred=features.get('total_bytes', 0),
                risk_score=round(conf_val * 10 * 1.5, 1),
                evidence=[Evidence(type='Live DDoS Detection',
                    detail=f"[LIVE] High-volume: {features.get('pps', 0):.1f} pps from {features.get('unique_src_ips', 0)} sources.",
                    timestamp=ts_str).__dict__],
            ))

        # 4. Brute Force
        top_port_info = features.get('top_dst_port', ('', 0))
        if isinstance(top_port_info, tuple) and len(top_port_info) == 2:
            top_port, top_port_count = top_port_info
            if top_port in (22, 23, 3389, 21, 3306, 5432) and top_port_count > 30:
                conf_val = min(0.82 + (top_port_count // 100) * 0.05, 0.99)
                threats.append(make_threat(
                    type='Brute Force Attack',
                    severity='high' if top_port in (22, 3389) else 'medium',
                    confidence=conf_val, source_ip='attacker', source_port=0,
                    dest_ip='target', dest_port=top_port, protocol='TCP',
                    timestamp=ts_str, packets_analyzed=features['total_packets'],
                    bytes_transferred=features.get('total_bytes', 0),
                    risk_score=round(conf_val * 10 * 1.2, 1),
                    evidence=[Evidence(type='Live Brute Force Detection',
                        detail=f"[LIVE] {top_port_count} connection attempts to port {top_port} in {WINDOW_SECONDS}s.",
                        timestamp=ts_str).__dict__],
                ))

        # 5. Data Exfiltration
        avg_payload = features.get('avg_payload', 0)
        payload_ratio = features.get('payload_ratio', 0)
        if avg_payload > 800 and payload_ratio > 0.6 and features.get('total_bytes', 0) > 50000:
            threats.append(make_threat(
                type='Data Exfiltration', severity='critical', confidence=0.75,
                source_ip='internal', source_port=0, dest_ip='external', dest_port=0,
                protocol='TCP', timestamp=ts_str,
                packets_analyzed=features['total_packets'],
                bytes_transferred=features.get('total_bytes', 0),
                risk_score=7.5,
                evidence=[Evidence(type='Live Exfiltration Detection',
                    detail=f"[LIVE] High payload ratio: {payload_ratio*100:.1f}%. Avg: {avg_payload:.0f} bytes.",
                    timestamp=ts_str).__dict__],
            ))

        # 6. DNS Tunneling
        dns_count = features.get('dns_count', 0)
        total = features.get('total_packets', 1)
        if dns_count > 50 and dns_count / max(total, 1) > 0.3:
            threats.append(make_threat(
                type='DNS Tunneling', severity='high', confidence=0.80,
                source_ip='internal', source_port=53, dest_ip='DNS server', dest_port=53,
                protocol='DNS', timestamp=ts_str,
                packets_analyzed=features['total_packets'],
                bytes_transferred=features.get('total_bytes', 0),
                risk_score=8.0,
                evidence=[Evidence(type='Live DNS Tunnel Detection',
                    detail=f"[LIVE] {dns_count} DNS packets ({dns_count/max(total,1)*100:.1f}% of traffic).",
                    timestamp=ts_str).__dict__],
            ))

        return threats


# ──────────────────────────── Singleton ────────────────────────────
engine = LiveCaptureEngine()
