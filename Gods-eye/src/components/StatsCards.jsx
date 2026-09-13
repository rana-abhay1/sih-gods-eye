export default function StatsCards({ stats, threats, captureRunning }) {
  const criticalCount = threats.filter(t => t.severity === 'critical').length
  const avgConfidence = threats.length > 0
    ? Math.round(threats.reduce((sum, t) => sum + t.confidence, 0) / threats.length * 100)
    : 0

  const cards = [
    {
      label: 'Total Packets',
      value: stats.totalPackets.toLocaleString(),
      sub: captureRunning ? `${stats.packetsPerSecond} pps` : 'No capture',
      icon: '📦',
      color: '#3b82f6',
    },
    {
      label: 'Suspicious Traffic',
      value: stats.suspiciousPackets.toLocaleString(),
      sub: stats.totalPackets > 0 ? `${Math.round((stats.suspiciousPackets / stats.totalPackets) * 100)}% flagged` : '0% flagged',
      icon: '⚠️',
      color: '#f59e0b',
    },
    {
      label: 'Threats Detected',
      value: threats.length,
      sub: `${criticalCount} critical`,
      icon: '🚨',
      color: '#ef4444',
    },
    {
      label: 'Avg Confidence',
      value: `${avgConfidence}%`,
      sub: threats.length > 0 ? 'ML Model' : 'Awaiting data',
      icon: '🧠',
      color: '#8b5cf6',
    },
    {
      label: 'Bandwidth',
      value: `${stats.bandwidthMbps}`,
      sub: 'Mbps',
      icon: '📡',
      color: '#06b6d4',
    },
    {
      label: 'Active Connections',
      value: stats.activeConnections,
      sub: captureRunning ? 'Tracked' : 'Idle',
      icon: '🔗',
      color: '#10b981',
    },
  ]

  return (
    <div className="stats-grid">
      {cards.map((card, i) => (
        <div key={i} className="stats-card" style={{ '--card-accent': card.color }}>
          <div className="stats-card__icon">{card.icon}</div>
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
