// Mock threat intelligence data for the SIH Cybersecurity Dashboard
// Simulates one-directional IP traffic analysis

const THREAT_TYPES = [
  { type: 'DDoS Attack', severity: 'critical', icon: '⚡' },
  { type: 'Port Scanning', severity: 'high', icon: '🔍' },
  { type: 'Brute Force', severity: 'high', icon: '🔑' },
  { type: 'Data Exfiltration', severity: 'critical', icon: '📤' },
  { type: 'Malware C2', severity: 'critical', icon: '🦠' },
  { type: 'SQL Injection', severity: 'medium', icon: '💉' },
  { type: 'XSS Attempt', severity: 'medium', icon: '🌐' },
  { type: 'DNS Tunneling', severity: 'high', icon: '🚇' },
  { type: 'Phishing', severity: 'medium', icon: '🎣' },
  { type: 'Ransomware', severity: 'critical', icon: '🔒' },
  { type: 'Privilege Escalation', severity: 'high', icon: '⬆️' },
  { type: 'Lateral Movement', severity: 'high', icon: '↔️' },
  { type: 'Crypto Mining', severity: 'medium', icon: '⛏️' },
  { type: 'Zero-Day Exploit', severity: 'critical', icon: '⚠️' },
]

const COUNTRIES = [
  'United States', 'China', 'Russia', 'North Korea', 'Iran',
  'Brazil', 'Germany', 'India', 'Netherlands', 'Unknown'
]

const PROTOCOLS = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'DNS', 'SMTP', 'SSH', 'FTP']
const PORTS = [22, 53, 80, 443, 3306, 8080, 8443, 21, 25, 110, 143, 993, 3389, 445, 135]
const EVIDENCE_TYPES = ['Packet Capture', 'Log Entry', 'NetFlow Record', 'DNS Query', 'HTTP Request', 'SSL Certificate']

function randomFrom(arr) {
  return arr[Math.floor(Math.random() * arr.length)]
}

function randomBetween(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min
}

function generateIP() {
  return `${randomBetween(1, 223)}.${randomBetween(0, 255)}.${randomBetween(0, 255)}.${randomBetween(1, 254)}`
}

function generateThreatId() {
  return `THR-${randomBetween(1000, 9999)}`
}

function generateTimestamp(hoursBack = 24) {
  const now = Date.now()
  return new Date(now - randomBetween(0, hoursBack * 60 * 60 * 1000))
}

function formatTimestamp(date) {
  return date.toISOString().replace('T', ' ').slice(0, 19)
}

function generateEvidence(threat) {
  const evidenceCount = randomBetween(1, 4)
  const evidence = []
  
  for (let i = 0; i < evidenceCount; i++) {
    const type = randomFrom(EVIDENCE_TYPES)
    let detail = ''
    
    switch (type) {
      case 'Packet Capture':
        detail = `Captured ${randomBetween(50, 5000)} packets from ${threat.sourceIP} to ${threat.destIP} on port ${threat.port} using ${threat.protocol}. Payload size: ${randomBetween(64, 1500)} bytes. Pattern: ${randomFrom(['Suspicious payload pattern detected', 'Unusual packet fragmentation', 'Abnormal TTL value observed', 'Encoded shellcode in payload'])}`
        break
      case 'Log Entry':
        detail = `[${randomFrom(['AUTH', 'SYS', 'NET', 'APP', 'SEC'])}] ${randomFrom(['Failed authentication attempt', 'Unusual login pattern', 'Configuration change detected', 'Service restart triggered', 'Access denied'])} from ${threat.sourceIP} — ${randomFrom(['3 consecutive failures', 'off-hours access', 'privilege escalation attempt', 'unusual geo-location'])}`
        break
      case 'NetFlow Record':
        detail = `Flow: ${threat.sourceIP}:${randomBetween(1024, 65535)} → ${threat.destIP}:${threat.port} | Protocol: ${threat.protocol} | Duration: ${randomBetween(1, 3600)}s | Bytes: ${randomBetween(1024, 10485760)} | Packets: ${randomBetween(10, 50000)}`
        break
      case 'DNS Query':
        detail = `Query: ${randomFrom(['suspicious-domain.xyz', 'bit.ly/random123', 'ngrok.io', 'pastebin.com/raw/abc123', 'dl.dropboxusercontent.com/s/abc'])} Type: A | Response: ${generateIP()} | TTL: ${randomBetween(30, 300)} | Recursive: No`
        break
      case 'HTTP Request':
        detail = `${randomFrom(['GET', 'POST', 'PUT'])} ${randomFrom(['/admin/config', '/api/users', '/wp-login.php', '/.env', '/phpmyadmin', '/cgi-bin/test'])} HTTP/1.1 | Status: ${randomFrom([200, 403, 404, 500])} | User-Agent: ${randomFrom(['curl/7.68', 'python-requests/2.28', 'Mozilla/4.0', 'Nmap Scripting Engine'])}`
        break
      case 'SSL Certificate':
        detail = `Certificate: CN=${threat.sourceIP} | Issuer: ${randomFrom(['Self-Signed', 'Let\'s Encrypt', 'Unknown CA', 'Expired 2024-01-01'])} | SAN: ${generateIP()} | Valid: ${randomFrom(['No', 'Expired', 'Mismatched domain'])}`
        break
    }
    
    evidence.push({ type, detail, timestamp: formatTimestamp(generateTimestamp(2)) })
  }
  
  return evidence
}

export function generateThreat() {
  const threatType = randomFrom(THREAT_TYPES)
  const confidence = Math.round((Math.random() * 0.6 + 0.4) * 100) / 100
  
  const threat = {
    id: generateThreatId(),
    type: threatType.type,
    severity: threatType.severity,
    icon: threatType.icon,
    confidence,
    sourceIP: generateIP(),
    sourceCountry: randomFrom(COUNTRIES),
    destIP: generateIP(),
    destPort: randomFrom(PORTS),
    port: randomFrom(PORTS),
    protocol: randomFrom(PROTOCOLS),
    timestamp: formatTimestamp(generateTimestamp(0)),
    rawTimestamp: generateTimestamp(0),
    packetsAnalyzed: randomBetween(100, 100000),
    bytesTransferred: randomBetween(1024, 104857600),
    status: randomFrom(['active', 'contained', 'mitigated', 'investigating']),
    evidence: [],
    riskScore: Math.round(confidence * 10 * (threatType.severity === 'critical' ? 1.5 : threatType.severity === 'high' ? 1.2 : 1)),
  }
  
  threat.evidence = generateEvidence(threat)
  return threat
}

export function generateInitialThreats(count = 25) {
  const threats = []
  for (let i = 0; i < count; i++) {
    threats.push(generateThreat())
  }
  return threats.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
}

export function generateTrafficPacket() {
  const isSuspicious = Math.random() > 0.7
  const srcIP = generateIP()
  const dstIP = generateIP()
  const protocol = randomFrom(PROTOCOLS)
  const port = randomFrom(PORTS)
  const size = randomBetween(64, 1500)
  
  return {
    id: Math.random().toString(36).slice(2, 10),
    srcIP,
    dstIP,
    srcPort: randomBetween(1024, 65535),
    dstPort: port,
    protocol,
    size,
    timestamp: formatTimestamp(new Date()),
    isSuspicious,
    flag: isSuspicious ? randomFrom(['[SUSPICIOUS]', '[ALERT]', '[THREAT]']) : '[NORMAL]',
    severity: isSuspicious ? randomFrom(['high', 'critical', 'medium']) : 'low',
  }
}

export function generateTrafficHistory(hours = 24, points = 48) {
  const now = Date.now()
  const interval = (hours * 60 * 60 * 1000) / points
  const data = []
  
  for (let i = 0; i < points; i++) {
    const time = new Date(now - (points - i) * interval)
    const baseTraffic = 500 + Math.sin(i / 4) * 200
    const threatSpike = i > points - 6 ? randomBetween(50, 200) : 0
    
    data.push({
      timestamp: formatTimestamp(time),
      totalPackets: Math.round(baseTraffic + randomBetween(-100, 100) + threatSpike),
      suspiciousPackets: Math.round(threatSpike + randomBetween(0, 30)),
      normalPackets: Math.round(baseTraffic + randomBetween(-100, 100)),
    })
  }
  
  return data
}

export const INTERNAL_IPS = [
  '192.168.1.1', '192.168.1.10', '192.168.1.20', '192.168.1.50',
  '10.0.0.1', '10.0.0.5', '10.0.0.10', '10.0.0.25',
]

export const NETWORK_NODES = [
  { id: 'firewall', label: 'Firewall', type: 'security', x: 50, y: 30 },
  { id: 'ids', label: 'IDS/IPS', type: 'security', x: 50, y: 50 },
  { id: 'siem', label: 'SIEM', type: 'security', x: 50, y: 70 },
  { id: 'webserver', label: 'Web Server', type: 'server', x: 80, y: 30 },
  { id: 'db', label: 'Database', type: 'server', x: 80, y: 50 },
  { id: 'app', label: 'App Server', type: 'server', x: 80, y: 70 },
  { id: 'monitor', label: 'Monitor', type: 'monitor', x: 20, y: 50 },
]

export const SEVERITY_CONFIG = {
  critical: { color: '#ef4444', bg: 'rgba(239,68,68,0.15)', label: 'CRITICAL' },
  high: { color: '#f97316', bg: 'rgba(249,115,22,0.15)', label: 'HIGH' },
  medium: { color: '#eab308', bg: 'rgba(234,179,8,0.15)', label: 'MEDIUM' },
  low: { color: '#22c55e', bg: 'rgba(34,197,94,0.15)', label: 'LOW' },
}
