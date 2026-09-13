import { useMemo } from 'react'
import { SEVERITY_CONFIG } from '../../data/threats'

export default function AnalyticsView({ threats, history, stats }) {
  // Threat type distribution
  const typeDist = useMemo(() => {
    const types = {}
    threats.forEach(t => { types[t.type] = (types[t.type] || 0) + 1 })
    return Object.entries(types).sort((a, b) => b[1] - a[1])
  }, [threats])

  // Country distribution
  const countryDist = useMemo(() => {
    const countries = {}
    threats.forEach(t => { countries[t.sourceCountry] = (countries[t.sourceCountry] || 0) + 1 })
    return Object.entries(countries).sort((a, b) => b[1] - a[1])
  }, [threats])

  // Protocol distribution
  const protoDist = useMemo(() => {
    const protos = {}
    threats.forEach(t => { protos[t.protocol] = (protos[t.protocol] || 0) + 1 })
    return Object.entries(protos).sort((a, b) => b[1] - a[1])
  }, [threats])

  // Confidence histogram
  const confidenceBuckets = useMemo(() => {
    const buckets = [0, 0, 0, 0, 0] // 40-50, 50-60, 60-70, 70-80, 80-100
    threats.forEach(t => {
      const pct = Math.round(t.confidence * 100)
      if (pct < 50) buckets[0]++
      else if (pct < 60) buckets[1]++
      else if (pct < 70) buckets[2]++
      else if (pct < 80) buckets[3]++
      else buckets[4]++
    })
    return [
      { label: '40-50%', count: buckets[0] },
      { label: '50-60%', count: buckets[1] },
      { label: '60-70%', count: buckets[2] },
      { label: '70-80%', count: buckets[3] },
      { label: '80-100%', count: buckets[4] },
    ]
  }, [threats])

  const maxConfBucket = Math.max(...confidenceBuckets.map(b => b.count))

  // Severity over time (from history)
  const severityTimeline = useMemo(() => {
    return history.map(h => ({
      time: h.timestamp.split(' ')[1]?.slice(0, 5),
      suspicious: h.suspiciousPackets,
      normal: h.normalPackets,
    }))
  }, [history])

  const maxTimeline = Math.max(...severityTimeline.map(t => t.normal + t.suspicious))

  // Performance metrics
  const avgConfidence = threats.length > 0
    ? (threats.reduce((s, t) => s + t.confidence, 0) / threats.length * 100).toFixed(1)
    : 0

  const topCountries = countryDist.slice(0, 5)
  const maxCountry = topCountries[0]?.[1] || 1

  return (
    <div className="view-page">
      <div className="view-page__header">
        <h2 className="view-page__title">📈 Analytics & Insights</h2>
        <p className="view-page__subtitle">Threat intelligence analysis and ML model performance</p>
      </div>

      {/* Key metrics */}
      <div className="analytics-metrics">
        <div className="analytics-metric">
          <span className="analytics-metric__value">{threats.length}</span>
          <span className="analytics-metric__label">Total Threats</span>
        </div>
        <div className="analytics-metric analytics-metric--accent">
          <span className="analytics-metric__value">{avgConfidence}%</span>
          <span className="analytics-metric__label">Avg Confidence</span>
        </div>
        <div className="analytics-metric">
          <span className="analytics-metric__value">{threats.filter(t => t.status === 'mitigated').length}</span>
          <span className="analytics-metric__label">Mitigated</span>
        </div>
        <div className="analytics-metric">
          <span className="analytics-metric__value">{((threats.filter(t => t.severity === 'critical').length / Math.max(threats.length, 1)) * 100).toFixed(0)}%</span>
          <span className="analytics-metric__label">Critical Rate</span>
        </div>
        <div className="analytics-metric">
          <span className="analytics-metric__value">{stats.bandwidthMbps}</span>
          <span className="analytics-metric__label">Bandwidth Mbps</span>
        </div>
      </div>

      <div className="analytics-grid">
        {/* Threat Type Distribution */}
        <div className="analytics-card">
          <h3 className="analytics-card__title">Threat Type Distribution</h3>
          <div className="analytics-bars">
            {typeDist.map(([type, count]) => (
              <div key={type} className="analytics-bar-row">
                <span className="analytics-bar-label">{type}</span>
                <div className="analytics-bar-track">
                  <div className="analytics-bar-fill" style={{ width: `${(count / typeDist[0][1]) * 100}%` }}></div>
                </div>
                <span className="analytics-bar-count">{count}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Source Countries */}
        <div className="analytics-card">
          <h3 className="analytics-card__title">Top Source Countries</h3>
          <div className="analytics-bars">
            {topCountries.map(([country, count]) => (
              <div key={country} className="analytics-bar-row">
                <span className="analytics-bar-label">{country}</span>
                <div className="analytics-bar-track">
                  <div className="analytics-bar-fill analytics-bar-fill--cyan" style={{ width: `${(count / maxCountry) * 100}%` }}></div>
                </div>
                <span className="analytics-bar-count">{count}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Confidence Distribution */}
        <div className="analytics-card">
          <h3 className="analytics-card__title">Confidence Score Distribution</h3>
          <div className="analytics-histogram">
            {confidenceBuckets.map((bucket, i) => (
              <div key={i} className="analytics-hist-col">
                <div className="analytics-hist-bar" style={{ height: `${(bucket.count / maxConfBucket) * 100}%` }}>
                  <span className="analytics-hist-value">{bucket.count}</span>
                </div>
                <span className="analytics-hist-label">{bucket.label}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Protocol Breakdown */}
        <div className="analytics-card">
          <h3 className="analytics-card__title">Protocol Breakdown</h3>
          <div className="analytics-bars">
            {protoDist.map(([proto, count]) => (
              <div key={proto} className="analytics-bar-row">
                <span className="analytics-bar-label analytics-bar-label--mono">{proto}</span>
                <div className="analytics-bar-track">
                  <div className="analytics-bar-fill analytics-bar-fill--purple" style={{ width: `${(count / protoDist[0][1]) * 100}%` }}></div>
                </div>
                <span className="analytics-bar-count">{count}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Traffic Timeline */}
        <div className="analytics-card analytics-card--wide">
          <h3 className="analytics-card__title">Traffic Volume Timeline</h3>
          <div className="analytics-timeline">
            <svg viewBox="0 0 700 150" className="analytics-timeline-svg">
              {[0, 0.25, 0.5, 0.75, 1].map((pct, i) => (
                <line key={i} x1={0} y1={150 * (1 - pct)} x2={700} y2={150 * (1 - pct)}
                  stroke="rgba(255,255,255,0.05)" strokeWidth={1} />
              ))}
              {severityTimeline.map((point, i) => {
                const x = (i / severityTimeline.length) * 700
                const barW = (700 / severityTimeline.length) * 0.7
                const normalH = (point.normal / maxTimeline) * 150
                const susH = (point.suspicious / maxTimeline) * 150
                return (
                  <g key={i}>
                    <rect x={x} y={150 - normalH} width={barW} height={normalH}
                      fill="rgba(59,130,246,0.5)" rx={1} />
                    {susH > 0 && (
                      <rect x={x} y={150 - normalH - susH} width={barW} height={susH}
                        fill="rgba(239,68,68,0.7)" rx={1} />
                    )}
                    {i % 8 === 0 && (
                      <text x={x + barW / 2} y={148} fill="rgba(255,255,255,0.3)"
                        fontSize={7} textAnchor="middle">{point.time}</text>
                    )}
                  </g>
                )
              })}
            </svg>
          </div>
        </div>

        {/* Severity Breakdown */}
        <div className="analytics-card analytics-card--wide">
          <h3 className="analytics-card__title">Severity Breakdown</h3>
          <div className="analytics-severity-grid">
            {Object.entries(SEVERITY_CONFIG).map(([sev, config]) => {
              const count = threats.filter(t => t.severity === sev).length
              const pct = threats.length > 0 ? ((count / threats.length) * 100).toFixed(1) : 0
              return (
                <div key={sev} className="analytics-severity-card" style={{ borderColor: config.color }}>
                  <div className="analytics-severity-card__header" style={{ color: config.color }}>
                    <span className="analytics-severity-card__label">{config.label}</span>
                    <span className="analytics-severity-card__count">{count}</span>
                  </div>
                  <div className="analytics-severity-card__bar">
                    <div className="analytics-severity-card__fill"
                      style={{ width: `${pct}%`, backgroundColor: config.color }}></div>
                  </div>
                  <span className="analytics-severity-card__pct">{pct}%</span>
                </div>
              )
            })}
          </div>
        </div>
      </div>
    </div>
  )
}
