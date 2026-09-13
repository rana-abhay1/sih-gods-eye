import { useState, useMemo, useEffect } from 'react'

const LOG_SOURCES = ['IDS', 'SIEM', 'FIREWALL', 'ML_ENGINE', 'SYSTEM']
const LOG_LEVELS = ['INFO', 'WARN', 'ERROR', 'CRIT']

const MOCK_LOG_TEMPLATES = [
  { src: 'IDS', level: 'INFO', msg: 'Packet inspection cycle completed — {n} packets analyzed' },
  { src: 'IDS', level: 'WARN', msg: 'Anomalous traffic pattern detected from {ip}' },
  { src: 'IDS', level: 'ERROR', msg: 'Failed to parse malformed TCP header from {ip}' },
  { src: 'IDS', level: 'CRIT', msg: 'High-confidence threat detected — {type} from {ip}' },
  { src: 'SIEM', level: 'INFO', msg: 'Correlation rule triggered: Rule-{n} — Suspicious activity cluster' },
  { src: 'SIEM', level: 'WARN', msg: 'Threshold exceeded: {n} alerts in last 5 minutes from {ip}' },
  { src: 'SIEM', level: 'INFO', msg: 'Event forwarded to analyst queue — Priority: {p}' },
  { src: 'FIREWALL', level: 'INFO', msg: 'Blocked inbound connection: {ip} → port {port}' },
  { src: 'FIREWALL', level: 'WARN', msg: 'Rate limit triggered for {ip} — {n} requests/sec' },
  { src: 'FIREWALL', level: 'ERROR', msg: 'Firewall rule update failed — manual intervention required' },
  { src: 'ML_ENGINE', level: 'INFO', msg: 'Model inference completed — confidence: {conf}%' },
  { src: 'ML_ENGINE', level: 'INFO', msg: 'Feature extraction pipeline processed {n} flows' },
  { src: 'ML_ENGINE', level: 'WARN', msg: 'Model latency spike: {n}ms (threshold: 500ms)' },
  { src: 'ML_ENGINE', level: 'INFO', msg: 'Ensemble prediction — RF: {rf}%, LSTM: {lstm}%' },
  { src: 'SYSTEM', level: 'INFO', msg: 'Dashboard heartbeat — uptime: {n}h' },
  { src: 'SYSTEM', level: 'WARN', msg: 'Memory usage at {n}% — consider scaling' },
  { src: 'SYSTEM', level: 'INFO', msg: 'Log rotation completed — archived {n}MB' },
  { src: 'SYSTEM', level: 'ERROR', msg: 'Database connection pool exhausted — retrying' },
]

function generateLog(id) {
  const template = MOCK_LOG_TEMPLATES[Math.floor(Math.random() * MOCK_LOG_TEMPLATES.length)]
  const ip = `${Math.floor(Math.random() * 200 + 10)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 254 + 1)}`
  const types = ['DDoS', 'Port Scan', 'Brute Force', 'Exfiltration', 'C2 Beacon']

  let msg = template.msg
    .replace('{ip}', ip)
    .replace('{n}', Math.floor(Math.random() * 5000 + 10))
    .replace('{port}', [22, 80, 443, 3306, 8080][Math.floor(Math.random() * 5)])
    .replace('{type}', types[Math.floor(Math.random() * types.length)])
    .replace('{p}', ['Low', 'Medium', 'High', 'Critical'][Math.floor(Math.random() * 4)])
    .replace('{conf}', Math.floor(Math.random() * 50 + 50))
    .replace('{rf}', Math.floor(Math.random() * 30 + 60))
    .replace('{lstm}', Math.floor(Math.random() * 30 + 60))

  return {
    id,
    timestamp: new Date(Date.now() - Math.random() * 3600000).toISOString().replace('T', ' ').slice(0, 23),
    source: template.src,
    level: template.level,
    message: msg,
  }
}

export default function LogsView() {
  const [logs, setLogs] = useState(() => Array.from({ length: 100 }, (_, i) => generateLog(i)))
  const [levelFilter, setLevelFilter] = useState('all')
  const [sourceFilter, setSourceFilter] = useState('all')
  const [searchQuery, setSearchQuery] = useState('')

  useEffect(() => {
    const timer = setInterval(() => {
      setLogs(prev => [generateLog(Date.now()), ...prev].slice(0, 500))
    }, 2000)
    return () => clearInterval(timer)
  }, [])

  const filtered = useMemo(() => {
    let result = logs
    if (levelFilter !== 'all') result = result.filter(l => l.level === levelFilter)
    if (sourceFilter !== 'all') result = result.filter(l => l.source === sourceFilter)
    if (searchQuery) result = result.filter(l => l.message.toLowerCase().includes(searchQuery.toLowerCase()))
    return result
  }, [logs, levelFilter, sourceFilter, searchQuery])

  const levelColors = {
    INFO: '#3b82f6', WARN: '#f59e0b', ERROR: '#f97316', CRIT: '#ef4444',
  }

  const logCounts = useMemo(() => {
    const counts = { all: logs.length, INFO: 0, WARN: 0, ERROR: 0, CRIT: 0 }
    logs.forEach(l => { counts[l.level] = (counts[l.level] || 0) + 1 })
    return counts
  }, [logs])

  return (
    <div className="view-page">
      <div className="view-page__header">
        <h2 className="view-page__title">📋 System Logs</h2>
        <p className="view-page__subtitle">Real-time log stream from IDS, SIEM, Firewall, ML Engine, and System</p>
      </div>

      {/* Log level filter chips */}
      <div className="logs-filters">
        <div className="logs-filter-chips">
          {['all', ...LOG_LEVELS].map(level => (
            <button key={level}
              className={`logs-chip ${levelFilter === level ? 'logs-chip--active' : ''}`}
              style={level !== 'all' ? { '--chip-color': levelColors[level] } : {}}
              onClick={() => setLevelFilter(level)}>
              {level === 'all' ? 'All Levels' : level}
              <span className="logs-chip__count">{logCounts[level] || 0}</span>
            </button>
          ))}
        </div>
        <div className="logs-filter-chips">
          <button className={`logs-chip logs-chip--small ${sourceFilter === 'all' ? 'logs-chip--active' : ''}`}
            onClick={() => setSourceFilter('all')}>All Sources</button>
          {LOG_SOURCES.map(src => (
            <button key={src}
              className={`logs-chip logs-chip--small ${sourceFilter === src ? 'logs-chip--active' : ''}`}
              onClick={() => setSourceFilter(src)}>
              {src}
            </button>
          ))}
        </div>
        <input className="traffic-search" type="text" placeholder="Search logs..."
          value={searchQuery} onChange={e => setSearchQuery(e.target.value)} />
      </div>

      {/* Log entries */}
      <div className="logs-list">
        {filtered.slice(0, 200).map(log => (
          <div key={log.id} className={`logs-entry logs-entry--${log.level.toLowerCase()}`}>
            <span className="logs-entry__time">{log.timestamp}</span>
            <span className="logs-entry__level" style={{ color: levelColors[log.level] }}>
              [{log.level}]
            </span>
            <span className="logs-entry__source">{log.source}</span>
            <span className="logs-entry__msg">{log.message}</span>
          </div>
        ))}
        {filtered.length === 0 && (
          <div className="traffic-empty">No logs match your filters</div>
        )}
      </div>
    </div>
  )
}
