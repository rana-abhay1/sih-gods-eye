import { useState, useRef, useEffect, useMemo } from 'react'


const PROTOCOL_COLORS = {
  TCP: '#3b82f6', UDP: '#06b6d4', ICMP: '#8b5cf6',
  HTTP: '#10b981', HTTPS: '#22c55e', DNS: '#f59e0b',
  SMTP: '#f97316', SSH: '#ec4899', FTP: '#6366f1',
}

export default function TrafficView({ packets, stats }) {
  const feedRef = useRef(null)
  const [filter, setFilter] = useState('all')
  const [protoFilter, setProtoFilter] = useState('all')
  const [searchIP, setSearchIP] = useState('')

  const filtered = useMemo(() => {
    let result = packets
    if (filter === 'suspicious') result = result.filter(p => p.isSuspicious)
    if (filter === 'normal') result = result.filter(p => !p.isSuspicious)
    if (protoFilter !== 'all') result = result.filter(p => p.protocol === protoFilter)
    if (searchIP) result = result.filter(p =>
      p.srcIP.includes(searchIP) || p.dstIP.includes(searchIP)
    )
    return result
  }, [packets, filter, protoFilter, searchIP])

  useEffect(() => {
    if (feedRef.current) feedRef.current.scrollTop = 0
  }, [filtered.length])

  const formatSize = (bytes) => bytes < 1024 ? `${bytes}B` : `${(bytes / 1024).toFixed(1)}KB`

  const protocolStats = useMemo(() => {
    const counts = {}
    packets.forEach(p => { counts[p.protocol] = (counts[p.protocol] || 0) + 1 })
    return Object.entries(counts).sort((a, b) => b[1] - a[1])
  }, [packets])

  const suspiciousRate = stats.totalPackets > 0
    ? ((stats.suspiciousPackets / stats.totalPackets) * 100).toFixed(1)
    : 0

  return (
    <div className="view-page">
      <div className="view-page__header">
        <h2 className="view-page__title"><i className="fa-solid fa-network-wired" style={{marginRight: '10px'}}></i>Live Traffic Monitor</h2>
        <p className="view-page__subtitle">Real-time one-directional IP traffic observation</p>
      </div>

      {/* Protocol Distribution Bar */}
      <div className="traffic-proto-bar">
        {protocolStats.map(([proto, count]) => (
          <div key={proto} className="traffic-proto-bar__segment" style={{
            flex: count,
            backgroundColor: PROTOCOL_COLORS[proto] || '#64748b'
          }} title={`${proto}: ${count}`}>
            {count > 2 && <span>{proto}</span>}
          </div>
        ))}
      </div>

      {/* Stats row */}
      <div className="traffic-stats-row">
        <div className="traffic-stat-pill">
          <span className="traffic-stat-pill__label">Total Packets</span>
          <span className="traffic-stat-pill__value">{stats.totalPackets.toLocaleString()}</span>
        </div>
        <div className="traffic-stat-pill traffic-stat-pill--warn">
          <span className="traffic-stat-pill__label">Suspicious</span>
          <span className="traffic-stat-pill__value">{stats.suspiciousPackets.toLocaleString()}</span>
        </div>
        <div className="traffic-stat-pill">
          <span className="traffic-stat-pill__label">Packets/sec</span>
          <span className="traffic-stat-pill__value">{stats.packetsPerSecond}</span>
        </div>
        <div className="traffic-stat-pill">
          <span className="traffic-stat-pill__label">Bandwidth</span>
          <span className="traffic-stat-pill__value">{stats.bandwidthMbps} Mbps</span>
        </div>
        <div className="traffic-stat-pill traffic-stat-pill--danger">
          <span className="traffic-stat-pill__label">Suspicious Rate</span>
          <span className="traffic-stat-pill__value">{suspiciousRate}%</span>
        </div>
        <div className="traffic-stat-pill">
          <span className="traffic-stat-pill__label">Active Connections</span>
          <span className="traffic-stat-pill__value">{stats.activeConnections}</span>
        </div>
      </div>

      {/* Filters */}
      <div className="traffic-filters">
        <div className="traffic-filters__group">
          <button className={`traffic-filter-btn ${filter === 'all' ? 'traffic-filter-btn--active' : ''}`}
            onClick={() => setFilter('all')}>All</button>
          <button className={`traffic-filter-btn ${filter === 'suspicious' ? 'traffic-filter-btn--active traffic-filter-btn--danger' : ''}`}
            onClick={() => setFilter('suspicious')}><i className="fa-solid fa-triangle-exclamation" style={{marginRight: '4px'}}></i>Suspicious</button>
          <button className={`traffic-filter-btn ${filter === 'normal' ? 'traffic-filter-btn--active traffic-filter-btn--ok' : ''}`}
            onClick={() => setFilter('normal')}><i className="fa-solid fa-circle-check" style={{marginRight: '4px'}}></i>Normal</button>
        </div>
        <div className="traffic-filters__group">
          {['all', ...Object.keys(PROTOCOL_COLORS)].map(p => (
            <button key={p} className={`traffic-proto-btn ${protoFilter === p ? 'traffic-proto-btn--active' : ''}`}
              onClick={() => setProtoFilter(p)}
              style={p !== 'all' ? { borderColor: PROTOCOL_COLORS[p] } : {}}>
              {p === 'all' ? 'All' : p}
            </button>
          ))}
        </div>
        <input
          className="traffic-search"
          type="text"
          placeholder="Search IP address..."
          value={searchIP}
          onChange={(e) => setSearchIP(e.target.value)}
        />
      </div>

      {/* Packet Feed Table */}
      <div className="traffic-table-wrap">
        <table className="traffic-table">
          <thead>
            <tr>
              <th>Status</th>
              <th>Time</th>
              <th>Protocol</th>
              <th>Source IP</th>
              <th>Src Port</th>
              <th>→</th>
              <th>Destination IP</th>
              <th>Dst Port</th>
              <th>Size</th>
            </tr>
          </thead>
          <tbody ref={feedRef}>
            {filtered.slice(0, 200).map((packet, i) => (
              <tr key={packet.id + i}
                className={`traffic-table__row ${packet.isSuspicious ? 'traffic-table__row--suspicious' : ''}`}>
                <td>
                  <span className={`traffic-table__flag ${packet.isSuspicious ? 'traffic-table__flag--danger' : 'traffic-table__flag--safe'}`}>
                    {packet.flag}
                  </span>
                </td>
                <td className="traffic-table__mono">{packet.timestamp.split(' ')[1]}</td>
                <td>
                  <span className="traffic-table__proto" style={{ color: PROTOCOL_COLORS[packet.protocol] || '#64748b' }}>
                    {packet.protocol}
                  </span>
                </td>
                <td className="traffic-table__mono">{packet.srcIP}</td>
                <td className="traffic-table__mono">{packet.srcPort}</td>
                <td className="traffic-table__arrow">→</td>
                <td className="traffic-table__mono">{packet.dstIP}</td>
                <td className="traffic-table__mono">{packet.dstPort}</td>
                <td className="traffic-table__mono traffic-table__size">{formatSize(packet.size)}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {filtered.length === 0 && (
          <div className="traffic-empty">No packets match your filters</div>
        )}
      </div>
    </div>
  )
}
