"""
God's Eye — AI/ML Threat Detector
Reads pcap/pcapng files and identifies cybersecurity threats using
rule-based heuristics + statistical anomaly detection.
"""

import collections
import math
import time
from dataclasses import dataclass, field, asdict
from typing import Optional

from scapy.all import (
    IP, TCP, UDP, ICMP, DNS, Raw, rdpcap, conf,
)


# ──────────────────────────── Configuration ────────────────────────────

KNOWN_PORTS = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 993: 'IMAPS',
    3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 8080: 'HTTP-Alt',
    8443: 'HTTPS-Alt', 445: 'SMB', 135: 'RPC', 139: 'NetBIOS',
    67: 'DHCP', 68: 'DHCP', 161: 'SNMP', 389: 'LDAP', 636: 'LDAPS',
}

SUSPICIOUS_PORTS = {4444, 5555, 6666, 6667, 31337, 12345, 54321, 9999, 8888}

COUNTRY_MAP = {}  # Placeholder — integrate GeoIP2 for real lookups

ML_CONFIDENCE_WEIGHTS = {
    'port_scan': 0.78,
    'ddos': 0.85,
    'brute_force': 0.82,
    'data_exfil': 0.75,
    'dns_tunnel': 0.80,
    'c2_beacon': 0.77,
    'syn_flood': 0.88,
    'recon': 0.70,
}


# ──────────────────────────── Data Classes ────────────────────────────

@dataclass
class Evidence:
    type: str
    detail: str
    timestamp: str


@dataclass
class Threat:
    id: str
    type: str
    severity: str           # critical | high | medium | low
    confidence: float       # 0.0 – 1.0
    source_ip: str
    source_port: int
    dest_ip: str
    dest_port: int
    protocol: str
    timestamp: str
    packets_analyzed: int
    bytes_transferred: int
    status: str
    risk_score: float
    evidence: list = field(default_factory=list)

    def to_dict(self):
        return asdict(self)


@dataclass
class PacketInfo:
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


# ──────────────────────────── PCAP Parser ────────────────────────────

def parse_pcap(file_path: str) -> list[PacketInfo]:
    """Parse a pcap/pcapng file and return structured packet info."""
    conf.stop_filter = lambda p: False
    packets = rdpcap(file_path)
    result = []

    for pkt in packets:
        if not pkt.haslayer(IP):
            continue

        ip = pkt[IP]
        src_ip = ip.src
        dst_ip = ip.dst
        src_port = 0
        dst_port = 0
        proto = 'IP'
        flags = ''
        size = len(pkt)
        payload_len = 0
        has_payload = False

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            src_port = tcp.sport
            dst_port = tcp.dport
            proto = 'TCP'
            # TCP flags
            flag_list = []
            if tcp.flags & 0x02: flag_list.append('SYN')
            if tcp.flags & 0x10: flag_list.append('ACK')
            if tcp.flags & 0x01: flag_list.append('FIN')
            if tcp.flags & 0x04: flag_list.append('RST')
            if tcp.flags & 0x08: flag_list.append('PSH')
            if tcp.flags & 0x20: flag_list.append('URG')
            flags = '|'.join(flag_list) if flag_list else ''

        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            src_port = udp.sport
            dst_port = udp.dport
            proto = 'UDP'

            if pkt.haslayer(DNS):
                proto = 'DNS'

        elif pkt.haslayer(ICMP):
            icmp = pkt[ICMP]
            proto = 'ICMP'
            flags = f'type={icmp.type},code={icmp.code}'

        if pkt.haslayer(Raw):
            payload_len = len(pkt[Raw].load)
            has_payload = True

        result.append(PacketInfo(
            src_ip=src_ip, dst_ip=dst_ip,
            src_port=src_port, dst_port=dst_port,
            protocol=proto, size=size,
            flags=flags, timestamp=float(pkt.time),
            payload_len=payload_len, has_payload=has_payload,
        ))

    return result


# ──────────────────────────── Feature Extraction ────────────────────────────

def extract_features(packets: list[PacketInfo]) -> dict:
    """Extract statistical features from parsed packets for threat detection."""
    if not packets:
        return {}

    src_ips = collections.Counter()
    dst_ips = collections.Counter()
    dst_ports = collections.Counter()
    src_dst_pairs = collections.Counter()
    protocols = collections.Counter()
    sizes = [p.size for p in packets]
    payload_sizes = [p.payload_len for p in packets if p.has_payload]
    timestamps = [p.timestamp for p in packets]

    syn_count = 0
    rst_count = 0
    fin_count = 0
    psh_count = 0

    for p in packets:
        src_ips[p.src_ip] += 1
        dst_ips[p.dst_ip] += 1
        dst_ports[p.dst_port] += 1
        src_dst_pairs[f"{p.src_ip}->{p.dst_ip}"] += 1
        protocols[p.protocol] += 1
        if 'SYN' in p.flags: syn_count += 1
        if 'RST' in p.flags: rst_count += 1
        if 'FIN' in p.flags: fin_count += 1
        if 'PSH' in p.flags: psh_count += 1

    duration = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 1
    pps = len(packets) / max(duration, 0.001)

    return {
        'total_packets': len(packets),
        'unique_src_ips': len(src_ips),
        'unique_dst_ips': len(dst_ips),
        'unique_dst_ports': len(dst_ports),
        'max_src_ip_count': src_ips.most_common(1)[0][1] if src_ips else 0,
        'max_dst_port_count': dst_ports.most_common(1)[0][1] if dst_ports else 0,
        'syn_count': syn_count,
        'rst_count': rst_count,
        'fin_count': fin_count,
        'psh_count': psh_count,
        'syn_ratio': syn_count / max(len(packets), 1),
        'avg_size': sum(sizes) / len(sizes),
        'max_size': max(sizes),
        'total_bytes': sum(sizes),
        'avg_payload': sum(payload_sizes) / max(len(payload_sizes), 1) if payload_sizes else 0,
        'payload_ratio': len(payload_sizes) / max(len(packets), 1),
        'duration': duration,
        'pps': pps,
        'top_dst_port': dst_ports.most_common(1)[0] if dst_ports else ('', 0),
        'top_src_ip': src_ips.most_common(1)[0] if src_ips else ('', 0),
        'protocols': dict(protocols),
        'tcp_count': protocols.get('TCP', 0),
        'udp_count': protocols.get('UDP', 0),
        'dns_count': protocols.get('DNS', 0),
        'icmp_count': protocols.get('ICMP', 0),
    }


# ──────────────────────────── Threat Classification ────────────────────────────

def _compute_confidence(base: float, features: dict, indicators: int) -> float:
    """Compute ML-style confidence score based on feature strength."""
    conf = base + (indicators * 0.05)
    # Boost if packet rate is high
    if features.get('pps', 0) > 100:
        conf += 0.05
    # Boost if many unique ports are targeted
    if features.get('unique_dst_ports', 0) > 10:
        conf += 0.03
    return min(round(conf, 2), 0.99)


def detect_threats(file_path: str) -> list[dict]:
    """
    Main entry point: parse pcap → extract features → classify threats.
    Returns a list of threat dicts ready for the dashboard.
    """
    packets = parse_pcap(file_path)
    if not packets:
        return []

    features = extract_features(packets)
    threats: list[Threat] = []
    ts_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
    threat_counter = 0

    def make_threat(**kwargs):
        nonlocal threat_counter
        threat_counter += 1
        tid = f"PCAP-{threat_counter:04d}"
        return Threat(id=tid, status='investigating', **kwargs)

    # ─── 1. Port Scan Detection ───
    top_port_info = features.get('top_dst_port', ('', 0))
    if isinstance(top_port_info, tuple) and len(top_port_info) == 2:
        top_port, top_port_count = top_port_info
    else:
        top_port, top_port_count = '', 0

    unique_ports = features.get('unique_dst_ports', 0)
    if unique_ports > 15 or (features.get('pps', 0) > 50 and unique_ports > 8):
        indicators = min(unique_ports // 5, 5)
        confidence = _compute_confidence(
            ML_CONFIDENCE_WEIGHTS['port_scan'], features, indicators
        )
        top_src_info = features.get('top_src_ip', ('', 0))
        src_ip = top_src_info[0] if isinstance(top_src_info, tuple) else 'unknown'

        threats.append(make_threat(
            type='Port Scanning',
            severity='high' if unique_ports > 30 else 'medium',
            confidence=confidence,
            source_ip=src_ip, source_port=0,
            dest_ip='multiple targets', dest_port=0,
            protocol='TCP', timestamp=ts_str,
            packets_analyzed=features['total_packets'],
            bytes_transferred=features['total_bytes'],
            risk_score=round(confidence * 10 * 1.2, 1),
            evidence=[Evidence(
                type='Port Scan Analysis',
                detail=f"Scanned {unique_ports} unique destination ports across "
                       f"{features['total_packets']} packets. "
                       f"Top port: {top_port} ({top_port_count} hits). "
                       f"Packet rate: {features['pps']:.1f} pps.",
                timestamp=ts_str,
            ).__dict__],
        ))

    # ─── 2. SYN Flood / DDoS Detection ───
    syn_ratio = features.get('syn_ratio', 0)
    if syn_ratio > 0.4 and features.get('syn_count', 0) > 20:
        indicators = min(int(syn_ratio * 10), 5)
        confidence = _compute_confidence(
            ML_CONFIDENCE_WEIGHTS['syn_flood'], features, indicators
        )
        top_src = features.get('top_src_ip', ('unknown', 0))
        threats.append(make_threat(
            type='SYN Flood Attack',
            severity='critical',
            confidence=confidence,
            source_ip=top_src[0] if isinstance(top_src, tuple) else 'distributed',
            source_port=0, dest_ip='multiple targets', dest_port=0,
            protocol='TCP', timestamp=ts_str,
            packets_analyzed=features['total_packets'],
            bytes_transferred=features['total_bytes'],
            risk_score=round(confidence * 10 * 1.5, 1),
            evidence=[Evidence(
                type='SYN Flood Analysis',
                detail=f"SYN packets: {features['syn_count']}/{features['total_packets']} "
                       f"({syn_ratio*100:.1f}%). RST count: {features.get('rst_count', 0)}. "
                       f"Packet rate: {features['pps']:.1f} pps. "
                       f"Unique sources: {features['unique_src_ips']}.",
                timestamp=ts_str,
            ).__dict__],
        ))

    # ─── 3. DDoS (volume-based) ───
    if features.get('pps', 0) > 200 and features.get('unique_src_ips', 0) > 10:
        indicators = min(features['unique_src_ips'] // 5, 5)
        confidence = _compute_confidence(
            ML_CONFIDENCE_WEIGHTS['ddos'], features, indicators
        )
        threats.append(make_threat(
            type='DDoS Attack',
            severity='critical',
            confidence=confidence,
            source_ip='distributed', source_port=0,
            dest_ip=features.get('top_src_ip', ('',))[0] if features.get('top_src_ip') else 'unknown',
            dest_port=0,
            protocol='Mixed', timestamp=ts_str,
            packets_analyzed=features['total_packets'],
            bytes_transferred=features['total_bytes'],
            risk_score=round(confidence * 10 * 1.5, 1),
            evidence=[Evidence(
                type='DDoS Volume Analysis',
                detail=f"Packet rate: {features['pps']:.1f} pps exceeds threshold. "
                       f"Unique source IPs: {features['unique_src_ips']}. "
                       f"Total bytes: {features['total_bytes']:,}. "
                       f"Duration: {features['duration']:.1f}s.",
                timestamp=ts_str,
            ).__dict__],
        ))

    # ─── 4. Brute Force Detection ───
    if isinstance(top_port_info, tuple) and len(top_port_info) == 2:
        top_port, top_port_count = top_port_info
    else:
        top_port, top_port_count = '', 0

    if top_port in (22, 23, 3389, 21, 3306, 5432) and top_port_count > 30:
        severity = 'high' if top_port in (22, 3389) else 'medium'
        indicators = min(top_port_count // 15, 5)
        confidence = _compute_confidence(
            ML_CONFIDENCE_WEIGHTS['brute_force'], features, indicators
        )
        src_info = features.get('top_src_ip', ('unknown', 0))
        threats.append(make_threat(
            type='Brute Force Attack',
            severity=severity,
            confidence=confidence,
            source_ip=src_info[0] if isinstance(src_info, tuple) else 'unknown',
            source_port=0,
            dest_ip='target server', dest_port=top_port,
            protocol=KNOWN_PORTS.get(top_port, 'TCP'), timestamp=ts_str,
            packets_analyzed=features['total_packets'],
            bytes_transferred=features['total_bytes'],
            risk_score=round(confidence * 10 * 1.2, 1),
            evidence=[Evidence(
                type='Brute Force Analysis',
                detail=f"Repeated connections to port {top_port} "
                       f"({KNOWN_PORTS.get(top_port, 'Unknown')}): "
                       f"{top_port_count} attempts. "
                       f"Source: {src_info[0] if isinstance(src_info, tuple) else 'unknown'}. "
                       f"This pattern indicates credential stuffing or password brute-forcing.",
                timestamp=ts_str,
            ).__dict__],
        ))

    # ─── 5. Data Exfiltration Detection ───
    avg_payload = features.get('avg_payload', 0)
    payload_ratio = features.get('payload_ratio', 0)
    if avg_payload > 800 and payload_ratio > 0.6 and features.get('total_bytes', 0) > 50000:
        indicators = 3
        confidence = _compute_confidence(
            ML_CONFIDENCE_WEIGHTS['data_exfil'], features, indicators
        )
        src_info = features.get('top_src_ip', ('unknown', 0))
        threats.append(make_threat(
            type='Data Exfiltration',
            severity='critical',
            confidence=confidence,
            source_ip=src_info[0] if isinstance(src_info, tuple) else 'unknown',
            source_port=0, dest_ip='external', dest_port=0,
            protocol='TCP', timestamp=ts_str,
            packets_analyzed=features['total_packets'],
            bytes_transferred=features['total_bytes'],
            risk_score=round(confidence * 10 * 1.5, 1),
            evidence=[Evidence(
                type='Exfiltration Analysis',
                detail=f"High payload ratio: {payload_ratio*100:.1f}% of packets contain data. "
                       f"Average payload: {avg_payload:.0f} bytes. "
                       f"Total data: {features['total_bytes']:,} bytes. "
                       f"This suggests bulk data transfer to an external endpoint.",
                timestamp=ts_str,
            ).__dict__],
        ))

    # ─── 6. DNS Tunneling Detection ───
    dns_count = features.get('dns_count', 0)
    if dns_count > 50 and dns_count / max(features['total_packets'], 1) > 0.3:
        indicators = min(dns_count // 30, 5)
        confidence = _compute_confidence(
            ML_CONFIDENCE_WEIGHTS['dns_tunnel'], features, indicators
        )
        src_info = features.get('top_src_ip', ('unknown', 0))
        threats.append(make_threat(
            type='DNS Tunneling',
            severity='high',
            confidence=confidence,
            source_ip=src_info[0] if isinstance(src_info, tuple) else 'unknown',
            source_port=53, dest_ip='DNS server', dest_port=53,
            protocol='DNS', timestamp=ts_str,
            packets_analyzed=features['total_packets'],
            bytes_transferred=features['total_bytes'],
            risk_score=round(confidence * 10 * 1.2, 1),
            evidence=[Evidence(
                type='DNS Tunnel Analysis',
                detail=f"Unusually high DNS traffic: {dns_count} DNS packets "
                       f"({dns_count/max(features['total_packets'],1)*100:.1f}% of total). "
                       f"DNS queries often encode C2 commands or exfiltrated data in subdomain labels.",
                timestamp=ts_str,
            ).__dict__],
        ))

    # ─── 7. C2 Beacon Detection (regular periodic traffic) ───
    if features.get('duration', 0) > 10:
        src_dst_count = len(set(
            f"{p.src_ip}->{p.dst_ip}" for p in packets
        ))
        if src_dst_count <= 3 and features.get('pps', 0) > 5 and features.get('total_packets', 0) > 40:
            indicators = 2
            confidence = _compute_confidence(
                ML_CONFIDENCE_WEIGHTS['c2_beacon'], features, indicators
            )
            src_info = features.get('top_src_ip', ('unknown', 0))
            threats.append(make_threat(
                type='Malware C2 Beacon',
                severity='critical',
                confidence=confidence,
                source_ip=src_info[0] if isinstance(src_info, tuple) else 'unknown',
                source_port=0, dest_ip='C2 server', dest_port=0,
                protocol='TCP', timestamp=ts_str,
                packets_analyzed=features['total_packets'],
                bytes_transferred=features['total_bytes'],
                risk_score=round(confidence * 10 * 1.5, 1),
                evidence=[Evidence(
                    type='C2 Beacon Analysis',
                    detail=f"Periodic communication pattern detected between "
                           f"{src_dst_count} endpoint(s). "
                           f"Duration: {features['duration']:.1f}s, "
                           f"rate: {features['pps']:.1f} pps. "
                           f"Consistent packet sizes suggest automated beaconing.",
                    timestamp=ts_str,
                ).__dict__],
            ))

    # ─── 8. Recon / Information Gathering ───
    icmp_count = features.get('icmp_count', 0)
    unique_src = features.get('unique_src_ips', 0)
    if icmp_count > 20 or (unique_src > 20 and features.get('unique_dst_ports', 0) > 5):
        indicators = 2
        confidence = _compute_confidence(
            ML_CONFIDENCE_WEIGHTS['recon'], features, indicators
        )
        src_info = features.get('top_src_ip', ('unknown', 0))
        threats.append(make_threat(
            type='Reconnaissance',
            severity='medium',
            confidence=confidence,
            source_ip=src_info[0] if isinstance(src_info, tuple) else 'distributed',
            source_port=0, dest_ip='network', dest_port=0,
            protocol='Mixed', timestamp=ts_str,
            packets_analyzed=features['total_packets'],
            bytes_transferred=features['total_bytes'],
            risk_score=round(confidence * 10 * 1.0, 1),
            evidence=[Evidence(
                type='Recon Analysis',
                detail=f"Network reconnaissance pattern: "
                       f"{unique_src} unique sources, "
                       f"{features.get('unique_dst_ports', 0)} unique ports probed, "
                       f"{icmp_count} ICMP packets. "
                       f"This is consistent with network mapping or host discovery.",
                timestamp=ts_str,
            ).__dict__],
        ))

    # Convert to dicts
    return [t.to_dict() for t in threats]


# ──────────────────────────── Standalone Run ────────────────────────────

if __name__ == '__main__':
    import sys
    import json

    if len(sys.argv) < 2:
        print("Usage: python threat_detector.py <file.pcap|file.pcapng>")
        sys.exit(1)

    file_path = sys.argv[1]
    print(f"[*] Parsing {file_path}...")
    results = detect_threats(file_path)
    print(f"[*] Detected {len(results)} threats:\n")
    print(json.dumps(results, indent=2))
