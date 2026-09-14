import { SEVERITY_CONFIG } from '../data/threats'

export default function ThreatBreakdown({ threats }) {
  const bySeverity = [
    { label: 'Critical', count: threats.filter(t => t.severity === 'critical').length, color: SEVERITY_CONFIG.critical.color },
    { label: 'High', count: threats.filter(t => t.severity === 'high').length, color: SEVERITY_CONFIG.high.color },
    { label: 'Medium', count: threats.filter(t => t.severity === 'medium').length, color: SEVERITY_CONFIG.medium.color },
    { label: 'Low', count: threats.filter(t => t.severity === 'low').length, color: SEVERITY_CONFIG.low.color },
  ]

  const total = threats.length || 1
  let cumulativeAngle = 0

  const svgSize = 120
  const cx = svgSize / 2
  const cy = svgSize / 2
  const radius = 45

  const arcs = bySeverity.map(sev => {
    const angle = (sev.count / total) * 360
    const startAngle = cumulativeAngle
    cumulativeAngle += angle

    const startRad = (startAngle - 90) * (Math.PI / 180)
    const endRad = (startAngle + angle - 90) * (Math.PI / 180)

    const x1 = cx + radius * Math.cos(startRad)
    const y1 = cy + radius * Math.sin(startRad)
    const x2 = cx + radius * Math.cos(endRad)
    const y2 = cy + radius * Math.sin(endRad)

    const largeArc = angle > 180 ? 1 : 0

    return {
      ...sev,
      path: `M ${cx} ${cy} L ${x1} ${y1} A ${radius} ${radius} 0 ${largeArc} 1 ${x2} ${y2} Z`,
    }
  })

  // Top threats by type
  const typeCount = {}
  threats.forEach(t => { typeCount[t.type] = (typeCount[t.type] || 0) + 1 })
  const topTypes = Object.entries(typeCount)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6)

  return (
    <div className="threat-breakdown">
      <h3 className="threat-breakdown__title"><i className="fa-solid fa-chart-pie" style={{marginRight: '8px'}}></i>Threat Breakdown</h3>
      
      <div className="threat-breakdown__content">
        <div className="threat-breakdown__chart">
          <svg viewBox={`0 0 ${svgSize} ${svgSize}`} className="threat-breakdown__pie">
            {arcs.map((arc, i) => (
              <path key={i} d={arc.path} fill={arc.color} opacity={0.85} stroke="rgba(0,0,0,0.3)" strokeWidth={1} />
            ))}
            <circle cx={cx} cy={cy} r={25} fill="#1a1b2e" />
            <text x={cx} y={cy - 4} fill="white" fontSize={14} textAnchor="middle" fontWeight="bold">{total}</text>
            <text x={cx} y={cy + 10} fill="rgba(255,255,255,0.5)" fontSize={7} textAnchor="middle">TOTAL</text>
          </svg>
        </div>

        <div className="threat-breakdown__legend">
          {bySeverity.map((sev, i) => (
            <div key={i} className="threat-breakdown__legend-item">
              <span className="threat-breakdown__dot" style={{ backgroundColor: sev.color }}></span>
              <span className="threat-breakdown__label">{sev.label}</span>
              <span className="threat-breakdown__count">{sev.count}</span>
            </div>
          ))}
        </div>
      </div>

      <div className="threat-breakdown__top">
        <h4>Top Threat Types</h4>
        {topTypes.map(([type, count]) => (
          <div key={type} className="threat-breakdown__bar-row">
            <span className="threat-breakdown__bar-label">{type}</span>
            <div className="threat-breakdown__bar-track">
              <div
                className="threat-breakdown__bar-fill"
                style={{ width: `${(count / topTypes[0][1]) * 100}%` }}
              ></div>
            </div>
            <span className="threat-breakdown__bar-count">{count}</span>
          </div>
        ))}
      </div>
    </div>
  )
}
