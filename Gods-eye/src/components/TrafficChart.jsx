export default function TrafficChart({ history }) {
  if (!history || history.length === 0) {
    return (
      <div className="traffic-chart">
        <div className="traffic-chart__header">
          <span className="traffic-chart__title">📈 Traffic Volume</span>
        </div>
        <div className="traffic-empty" style={{ padding: '40px' }}>
          No traffic data yet. Start a live capture to see real-time traffic volume.
        </div>
      </div>
    )
  }

  const maxPackets = Math.max(...history.map(h => h.totalPackets))
  const chartWidth = 700
  const chartHeight = 200
  const barWidth = (chartWidth / history.length) * 0.7
  const barGap = (chartWidth / history.length) * 0.3

  const formatTime = (ts) => {
    const parts = ts.split(' ')
    return parts[1] ? parts[1].slice(0, 5) : ''
  }

  return (
    <div className="traffic-chart">
      <div className="traffic-chart__header">
        <span className="traffic-chart__title">📈 Traffic Volume (24h)</span>
        <div className="traffic-chart__legend">
          <span className="traffic-chart__legend-item traffic-chart__legend-item--normal">Normal</span>
          <span className="traffic-chart__legend-item traffic-chart__legend-item--suspicious">Suspicious</span>
        </div>
      </div>
      <div className="traffic-chart__body">
        <svg
          viewBox={`0 0 ${chartWidth} ${chartHeight + 30}`}
          className="traffic-chart__svg"
          preserveAspectRatio="none"
        >
          {/* Grid lines */}
          {[0, 0.25, 0.5, 0.75, 1].map((pct, i) => (
            <line
              key={i}
              x1={0}
              y1={chartHeight * (1 - pct)}
              x2={chartWidth}
              y2={chartHeight * (1 - pct)}
              stroke="rgba(255,255,255,0.06)"
              strokeWidth={1}
            />
          ))}

          {/* Bars */}
          {history.map((point, i) => {
            const x = i * (barWidth + barGap)
            const normalHeight = (point.normalPackets / maxPackets) * chartHeight
            const suspiciousHeight = (point.suspiciousPackets / maxPackets) * chartHeight
            const y = chartHeight - normalHeight - suspiciousHeight

            return (
              <g key={i}>
                {/* Normal traffic (blue) */}
                <rect
                  x={x}
                  y={chartHeight - normalHeight}
                  width={barWidth}
                  height={normalHeight}
                  fill="rgba(59, 130, 246, 0.6)"
                  rx={2}
                />
                {/* Suspicious traffic (red) */}
                {suspiciousHeight > 0 && (
                  <rect
                    x={x}
                    y={y}
                    width={barWidth}
                    height={suspiciousHeight}
                    fill="rgba(239, 68, 68, 0.8)"
                    rx={2}
                  />
                )}
                {/* Time label (every 4th) */}
                {i % 4 === 0 && (
                  <text
                    x={x + barWidth / 2}
                    y={chartHeight + 15}
                    fill="rgba(255,255,255,0.4)"
                    fontSize={8}
                    textAnchor="middle"
                  >
                    {formatTime(point.timestamp)}
                  </text>
                )}
              </g>
            )
          })}
        </svg>
      </div>
    </div>
  )
}
