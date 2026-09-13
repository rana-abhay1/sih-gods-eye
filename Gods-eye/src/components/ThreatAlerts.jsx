import { SEVERITY_CONFIG } from '../data/threats'

const TYPE_ICONS = {
  'DDoS Attack': '⚡', 'Port Scanning': '🔍', 'Brute Force': '🔑',
  'Data Exfiltration': '📤', 'Malware C2': '🦠', 'SQL Injection': '💉',
  'XSS Attempt': '🌐', 'DNS Tunneling': '🚇', 'Phishing': '🎣',
  'Ransomware': '🔒', 'Privilege Escalation': '⬆️', 'Lateral Movement': '↔️',
  'Crypto Mining': '⛏️', 'Zero-Day Exploit': '⚠️', 'SYN Flood Attack': '⚡',
  'Reconnaissance': '🔍',
}

export default function ThreatAlerts({ threats, selectedThreat, onSelectThreat }) {
  const getSeverityConfig = (severity) => SEVERITY_CONFIG[severity] || SEVERITY_CONFIG.low

  const getConfidenceBar = (confidence) => {
    const pct = Math.round(confidence * 100)
    let color = '#22c55e'
    if (pct > 80) color = '#ef4444'
    else if (pct > 60) color = '#f59e0b'
    return (
      <div className="confidence-bar">
        <div
          className="confidence-bar__fill"
          style={{ width: `${pct}%`, backgroundColor: color }}
        ></div>
        <span className="confidence-bar__label">{pct}%</span>
      </div>
    )
  }

  return (
    <div className="threat-alerts">
      <div className="threat-alerts__header">
        <span className="threat-alerts__title">🚨 Threat Detection Alerts</span>
        <div className="threat-alerts__filters">
          <span className="threat-alerts__filter threat-alerts__filter--all">All ({threats.length})</span>
          <span className="threat-alerts__filter" style={{ color: SEVERITY_CONFIG.critical.color }}>
            Critical ({threats.filter(t => t.severity === 'critical').length})
          </span>
          <span className="threat-alerts__filter" style={{ color: SEVERITY_CONFIG.high.color }}>
            High ({threats.filter(t => t.severity === 'high').length})
          </span>
        </div>
      </div>
      <div className="threat-alerts__table-wrap">
        {threats.length === 0 ? (
          <div className="traffic-empty" style={{ padding: '32px' }}>
            No threats detected yet. Start a live capture or upload a PCAP file.
          </div>
        ) : (
          <table className="threat-alerts__table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Type</th>
                <th>Severity</th>
                <th>Confidence</th>
                <th>Source</th>
                <th>Destination</th>
                <th>Protocol</th>
                <th>Status</th>
                <th>Time</th>
              </tr>
            </thead>
            <tbody>
              {threats.map(threat => {
                const sev = getSeverityConfig(threat.severity)
                const isSelected = selectedThreat?.id === threat.id
                const icon = threat.icon || TYPE_ICONS[threat.type] || '⚠️'
                const srcIP = threat.sourceIP || threat.source_ip || 'unknown'
                const dstIP = threat.destIP || threat.dest_ip || 'unknown'
                const ts = threat.timestamp || ''
                return (
                  <tr
                    key={threat.id}
                    className={`threat-alerts__row ${isSelected ? 'threat-alerts__row--selected' : ''}`}
                    onClick={() => onSelectThreat(threat)}
                  >
                    <td className="threat-alerts__id">{threat.id}</td>
                    <td className="threat-alerts__type">
                      <span>{icon}</span> {threat.type}
                    </td>
                    <td>
                      <span
                        className="threat-alerts__severity"
                        style={{ color: sev.color, backgroundColor: sev.bg }}
                      >
                        {sev.label}
                      </span>
                    </td>
                    <td>{getConfidenceBar(threat.confidence)}</td>
                    <td className="threat-alerts__ip">
                      <span>{srcIP}</span>
                    </td>
                    <td className="threat-alerts__ip">{dstIP}</td>
                    <td>
                      <span className="threat-alerts__protocol">{threat.protocol}</span>
                    </td>
                    <td>
                      <span className={`threat-alerts__status threat-alerts__status--${threat.status}`}>
                        {threat.status}
                      </span>
                    </td>
                    <td className="threat-alerts__time">
                      {ts.split(' ')[1] || ts.slice(11, 19) || ''}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
