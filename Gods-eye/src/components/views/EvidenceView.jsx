import { useState, useMemo } from 'react'

export default function EvidenceView({ threats }) {
  const [selectedThreat, setSelectedThreat] = useState(null)
  const [filterType, setFilterType] = useState('all')

  const allEvidence = useMemo(() => {
    const evidence = []
    threats.forEach(threat => {
      threat.evidence.forEach(ev => {
        evidence.push({ ...ev, threatId: threat.id, threatType: threat.type, severity: threat.severity })
      })
    })
    return evidence.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
  }, [threats])

  const filtered = useMemo(() => {
    if (filterType === 'all') return allEvidence
    return allEvidence.filter(ev => ev.type === filterType)
  }, [allEvidence, filterType])

  const evidenceTypes = useMemo(() => {
    const types = {}
    allEvidence.forEach(ev => { types[ev.type] = (types[ev.type] || 0) + 1 })
    return Object.entries(types).sort((a, b) => b[1] - a[1])
  }, [allEvidence])

  const sevColor = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e' }

  return (
    <div className="view-page">
      <div className="view-page__header">
        <h2 className="view-page__title"><i className="fa-solid fa-link" style={{marginRight: '10px'}}></i>Evidence Chain</h2>
        <p className="view-page__subtitle">Collected forensic evidence from detected threats</p>
      </div>

      {/* Evidence type summary */}
      <div className="evidence-summary-grid">
        {evidenceTypes.map(([type, count]) => (
          <button key={type}
            className={`evidence-summary-card ${filterType === type ? 'evidence-summary-card--active' : ''}`}
            onClick={() => setFilterType(filterType === type ? 'all' : type)}>
            <span className="evidence-summary-card__count">{count}</span>
            <span className="evidence-summary-card__type">{type}</span>
          </button>
        ))}
      </div>

      {/* Evidence list */}
      <div className="evidence-list">
        <div className="evidence-list__header">
          <span>Evidence Items ({filtered.length})</span>
          {filterType !== 'all' && (
            <button className="evidence-clear-btn" onClick={() => setFilterType('all')}>
              Clear Filter
            </button>
          )}
        </div>
        <div className="evidence-list__body">
          {filtered.map((ev, i) => (
            <div key={i} className={`evidence-card ${selectedThreat === i ? 'evidence-card--expanded' : ''}`}
              onClick={() => setSelectedThreat(selectedThreat === i ? null : i)}>
              <div className="evidence-card__header">
                <div className="evidence-card__meta">
                  <span className="evidence-card__type">{ev.type}</span>
                  <span className="severity-badge" style={{
                    color: sevColor[ev.severity],
                    backgroundColor: `${sevColor[ev.severity]}22`
                  }}>{ev.severity?.toUpperCase()}</span>
                </div>
                <div className="evidence-card__ids">
                  <span className="evidence-card__threat-id">{ev.threatId}</span>
                  <span className="evidence-card__time">{ev.timestamp.split(' ')[1]}</span>
                </div>
              </div>
              <div className="evidence-card__threat-type">{ev.threatType}</div>
              {selectedThreat === i && (
                <pre className="evidence-card__detail">{ev.detail}</pre>
              )}
            </div>
          ))}
          {filtered.length === 0 && (
            <div className="traffic-empty">No evidence matches your filter</div>
          )}
        </div>
      </div>
    </div>
  )
}
