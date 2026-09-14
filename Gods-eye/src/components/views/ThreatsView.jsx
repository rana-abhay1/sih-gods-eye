import { useState, useMemo } from 'react'
import { SEVERITY_CONFIG } from '../../data/threats'
import EvidencePanel from '../EvidencePanel'

export default function ThreatsView({ threats, selectedThreat, onSelectThreat }) {
  const [severityFilter, setSeverityFilter] = useState('all')
  const [statusFilter, setStatusFilter] = useState('all')
  const [searchQuery, setSearchQuery] = useState('')
  const [sortField, setSortField] = useState('timestamp')
  const [sortDir, setSortDir] = useState('desc')

  const filtered = useMemo(() => {
    let result = threats
    if (severityFilter !== 'all') result = result.filter(t => t.severity === severityFilter)
    if (statusFilter !== 'all') result = result.filter(t => t.status === statusFilter)
    if (searchQuery) {
      const q = searchQuery.toLowerCase()
      result = result.filter(t =>
        t.id.toLowerCase().includes(q) ||
        t.type.toLowerCase().includes(q) ||
        t.sourceIP.includes(q) ||
        t.destIP.includes(q) ||
        t.sourceCountry.toLowerCase().includes(q)
      )
    }
    result.sort((a, b) => {
      let aVal, bVal
      switch (sortField) {
        case 'confidence': aVal = a.confidence; bVal = b.confidence; break
        case 'riskScore': aVal = a.riskScore; bVal = b.riskScore; break
        case 'timestamp': aVal = new Date(a.timestamp); bVal = new Date(b.timestamp); break
        default: aVal = a.id; bVal = b.id
      }
      return sortDir === 'asc' ? (aVal > bVal ? 1 : -1) : (aVal < bVal ? 1 : -1)
    })
    return result
  }, [threats, severityFilter, statusFilter, searchQuery, sortField, sortDir])

  const toggleSort = (field) => {
    if (sortField === field) setSortDir(d => d === 'asc' ? 'desc' : 'asc')
    else { setSortField(field); setSortDir('desc') }
  }

  const sortIcon = (field) => sortField === field ? (sortDir === 'asc' ? ' ↑' : ' ↓') : ''

  const sevCounts = useMemo(() => ({
    all: threats.length,
    critical: threats.filter(t => t.severity === 'critical').length,
    high: threats.filter(t => t.severity === 'high').length,
    medium: threats.filter(t => t.severity === 'medium').length,
    low: threats.filter(t => t.severity === 'low').length,
  }), [threats])

  const statusCounts = useMemo(() => ({
    all: threats.length,
    active: threats.filter(t => t.status === 'active').length,
    contained: threats.filter(t => t.status === 'contained').length,
    mitigated: threats.filter(t => t.status === 'mitigated').length,
    investigating: threats.filter(t => t.status === 'investigating').length,
  }), [threats])

  const getConfidenceBar = (confidence) => {
    const pct = Math.round(confidence * 100)
    let color = '#22c55e'
    if (pct > 80) color = '#ef4444'
    else if (pct > 60) color = '#f59e0b'
    return (
      <div className="confidence-bar">
        <div className="confidence-bar__fill" style={{ width: `${pct}%`, backgroundColor: color }}></div>
        <span className="confidence-bar__label">{pct}%</span>
      </div>
    )
  }

  return (
    <div className="view-page">
      <div className="view-page__header">
        <h2 className="view-page__title"><i className="fa-solid fa-triangle-exclamation" style={{marginRight: '10px'}}></i>Threat Management</h2>
        <p className="view-page__subtitle">AI/ML-detected threats with confidence scoring and evidence</p>
      </div>

      {/* Severity chips */}
      <div className="threat-filters">
        <div className="threat-filters__row">
          {Object.entries(sevCounts).map(([sev, count]) => {
            const config = SEVERITY_CONFIG[sev]
            return (
              <button key={sev}
                className={`threat-chip ${severityFilter === sev ? 'threat-chip--active' : ''}`}
                style={config ? { '--chip-color': config.color, '--chip-bg': config.bg } : {}}
                onClick={() => setSeverityFilter(sev)}>
                {sev === 'all' ? 'All Threats' : config?.label || sev}
                <span className="threat-chip__count">{count}</span>
              </button>
            )
          })}
        </div>
        <div className="threat-filters__row">
          {Object.entries(statusCounts).map(([status, count]) => (
            <button key={status}
              className={`threat-chip threat-chip--small ${statusFilter === status ? 'threat-chip--active' : ''}`}
              onClick={() => setStatusFilter(status)}>
              {status === 'all' ? 'All Status' : status}
              <span className="threat-chip__count">{count}</span>
            </button>
          ))}
        </div>
        <input
          className="traffic-search"
          type="text"
          placeholder="Search threats by ID, type, IP, or country..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
        />
      </div>

      <div className="threats-layout">
        <div className="threats-table-wrap">
          <table className="traffic-table threats-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Type</th>
                <th>Severity</th>
                <th onClick={() => toggleSort('confidence')} className="sortable">
                  Confidence{sortIcon('confidence')}
                </th>
                <th onClick={() => toggleSort('riskScore')} className="sortable">
                  Risk{sortIcon('riskScore')}
                </th>
                <th>Source</th>
                <th>Destination</th>
                <th>Protocol</th>
                <th>Status</th>
                <th onClick={() => toggleSort('timestamp')} className="sortable">
                  Time{sortIcon('timestamp')}
                </th>
              </tr>
            </thead>
            <tbody>
              {filtered.map(threat => {
                const sev = SEVERITY_CONFIG[threat.severity] || SEVERITY_CONFIG.low
                const isSelected = selectedThreat?.id === threat.id
                return (
                  <tr key={threat.id}
                    className={`traffic-table__row ${isSelected ? 'traffic-table__row--selected' : ''}`}
                    onClick={() => onSelectThreat(threat)}>
                    <td className="traffic-table__mono">{threat.id}</td>
                    <td>{threat.icon} {threat.type}</td>
                    <td>
                      <span className="severity-badge" style={{ color: sev.color, backgroundColor: sev.bg }}>
                        {sev.label}
                      </span>
                    </td>
                    <td>{getConfidenceBar(threat.confidence)}</td>
                    <td className="traffic-table__mono">{threat.riskScore}/10</td>
                    <td>
                      <div className="traffic-table__ip-cell">
                        <span className="traffic-table__mono">{threat.sourceIP}</span>
                        <span className="traffic-table__sub">{threat.sourceCountry}</span>
                      </div>
                    </td>
                    <td className="traffic-table__mono">{threat.destIP}:{threat.destPort}</td>
                    <td>
                      <span className="traffic-table__proto">{threat.protocol}</span>
                    </td>
                    <td>
                      <span className={`status-badge status-badge--${threat.status}`}>
                        {threat.status}
                      </span>
                    </td>
                    <td className="traffic-table__mono">{threat.timestamp.split(' ')[1]}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
          {filtered.length === 0 && (
            <div className="traffic-empty">No threats match your filters</div>
          )}
        </div>

        {selectedThreat && (
          <div className="threats-evidence-sidebar">
            <EvidencePanel threat={selectedThreat} />
          </div>
        )}
      </div>
    </div>
  )
}
