export default function StatsCards({ stats, threats, captureRunning }) {
  const criticalCount = threats.filter(t => t.severity === 'critical').length
  const avgConfidence = threats.length > 0
    ? Math.round(threats.reduce((sum, t) => sum + t.confidence, 0) / threats.length * 100)
    : 0

  // Count ML-based threats vs rule-based
  const mlThreats = threats.filter(t => t.model_version && t.model_version.startsWith('ml_'))
  const ruleThreats = threats.filter(t => !t.model_version || t.model_version.startsWith('rule_'))

  const cards = [
    {
      label: 'Total Packets',
      value: stats.totalPackets.toLocaleString(),
      sub: captureRunning ? `${stats.packetsPerSecond} pps` : 'No capture',
      icon: 'fa-solid fa-cubes',
      color: '#ffffff',
    },
    {
      label: 'Suspicious Traffic',
      value: stats.suspiciousPackets.toLocaleString(),
      sub: stats.totalPackets > 0 ? `${Math.round((stats.suspiciousPackets / stats.totalPackets) * 100)}% flagged` : '0% flagged',
      icon: 'fa-solid fa-shield-virus',
      color: '#aaaaaa',
    },
    {
      label: 'Threats Detected',
      value: threats.length,
      sub: `${criticalCount} critical`,
      icon: 'fa-solid fa-skull-crossbones',
      color: '#ffffff',
    },
    {
      label: 'Avg Confidence',
      value: `${avgConfidence}%`,
      sub: threats.length > 0 ? 'ML Ensemble' : 'Awaiting data',
      icon: 'fa-solid fa-brain',
      color: '#cccccc',
    },
    {
      label: 'Bandwidth',
      value: `${stats.bandwidthMbps}`,
      sub: 'Mbps',
      icon: 'fa-solid fa-signal',
      color: '#999999',
    },
    {
      label: 'Active Connections',
      value: stats.activeConnections,
      sub: captureRunning ? 'Tracked' : 'Idle',
      icon: 'fa-solid fa-link',
      color: '#bbbbbb',
    },
  ]

  return (
    <div className="stats-grid">
      {cards.map((card, i) => (
        <div key={i} className="stats-card" style={{ '--card-accent': card.color }}>
          <div className="stats-card__icon"><i className={card.icon}></i></div>
          <div className="stats-card__content">
            <span className="stats-card__label">{card.label}</span>
            <span className="stats-card__value">{card.value}</span>
            <span className="stats-card__sub">{card.sub}</span>
          </div>
          <div className="stats-card__glow"></div>
        </div>
      ))}
    </div>
  )
}
