import { useState } from 'react'
import { NETWORK_NODES } from '../../data/threats'

const NODE_ICONS = {
  firewall: 'fa-solid fa-shield-halved', ids: 'fa-solid fa-magnifying-glass', siem: 'fa-solid fa-chart-line', webserver: 'fa-solid fa-globe',
  db: 'fa-solid fa-database', app: 'fa-solid fa-server', monitor: 'fa-solid fa-desktop',
}

const NODE_COLORS = {
  security: '#3b82f6',
  server: '#10b981',
  monitor: '#8b5cf6',
}

const CONNECTIONS = [
  { from: 'internet', to: 'firewall', label: 'Inbound Traffic' },
  { from: 'firewall', to: 'ids', label: 'Filtered Packets' },
  { from: 'ids', to: 'siem', label: 'Alerts & Logs' },
  { from: 'ids', to: 'webserver', label: 'Clean Traffic' },
  { from: 'ids', to: 'app', label: 'Clean Traffic' },
  { from: 'webserver', to: 'db', label: 'Queries' },
  { from: 'app', to: 'db', label: 'Queries' },
  { from: 'monitor', to: 'siem', label: 'Metrics' },
  { from: 'monitor', to: 'ids', label: 'Health Check' },
]

const ALL_NODES = [
  ...NETWORK_NODES,
  { id: 'internet', label: 'Internet', type: 'external', x: 50, y: 8 },
]

export default function TopologyView({ threats }) {
  const [hoveredNode, setHoveredNode] = useState(null)
  const [selectedNode, setSelectedNode] = useState(null)

  const activeThreats = threats.filter(t => t.status === 'active')
  const containedThreats = threats.filter(t => t.status === 'contained')
  const mitigatedThreats = threats.filter(t => t.status === 'mitigated')

  const svgW = 800
  const svgH = 500

  const getNodeCenter = (id) => {
    const node = ALL_NODES.find(n => n.id === id)
    return node ? { x: (node.x / 100) * svgW, y: (node.y / 100) * svgH } : { x: 0, y: 0 }
  }

  return (
    <div className="view-page">
      <div className="view-page__header">
        <h2 className="view-page__title"><i className="fa-solid fa-diagram-project" style={{marginRight: '10px'}}></i>Network Topology</h2>
        <p className="view-page__subtitle">Monitored network infrastructure and traffic flow</p>
      </div>

      {/* Status summary */}
      <div className="topology-status-row">
        <div className="topology-stat">
          <span className="topology-stat__dot topology-stat__dot--green"></span>
          <span className="topology-stat__label">Healthy Nodes</span>
          <span className="topology-stat__value">{ALL_NODES.length - (activeThreats.length > 0 ? 1 : 0)}</span>
        </div>
        <div className="topology-stat">
          <span className="topology-stat__dot topology-stat__dot--red"></span>
          <span className="topology-stat__label">Active Threats</span>
          <span className="topology-stat__value">{activeThreats.length}</span>
        </div>
        <div className="topology-stat">
          <span className="topology-stat__dot topology-stat__dot--orange"></span>
          <span className="topology-stat__label">Contained</span>
          <span className="topology-stat__value">{containedThreats.length}</span>
        </div>
        <div className="topology-stat">
          <span className="topology-stat__dot topology-stat__dot--green"></span>
          <span className="topology-stat__label">Mitigated</span>
          <span className="topology-stat__value">{mitigatedThreats.length}</span>
        </div>
      </div>

      {/* Interactive SVG Map */}
      <div className="topology-map">
        <svg viewBox={`0 0 ${svgW} ${svgH}`} className="topology-svg">
          <defs>
            <filter id="glow">
              <feGaussianBlur stdDeviation="4" result="coloredBlur"/>
              <feMerge><feMergeNode in="coloredBlur"/><feMergeNode in="SourceGraphic"/></feMerge>
            </filter>
            <marker id="arrowhead" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
              <polygon points="0 0, 8 3, 0 6" fill="rgba(59,130,246,0.5)" />
            </marker>
            <linearGradient id="connGrad" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="rgba(59,130,246,0.1)" />
              <stop offset="50%" stopColor="rgba(59,130,246,0.4)" />
              <stop offset="100%" stopColor="rgba(59,130,246,0.1)" />
            </linearGradient>
          </defs>

          {/* Connections */}
          {CONNECTIONS.map((conn, i) => {
            const from = getNodeCenter(conn.from)
            const to = getNodeCenter(conn.to)
            const midX = (from.x + to.x) / 2
            const midY = (from.y + to.y) / 2
            return (
              <g key={i}>
                <line x1={from.x} y1={from.y} x2={to.x} y2={to.y}
                  stroke="rgba(59,130,246,0.2)" strokeWidth={2}
                  markerEnd="url(#arrowhead)" />
                <text x={midX} y={midY - 8} fill="rgba(255,255,255,0.3)"
                  fontSize={9} textAnchor="middle">{conn.label}</text>
              </g>
            )
          })}

          {/* Nodes */}
          {ALL_NODES.map(node => {
            const center = getNodeCenter(node.id)
            const isHovered = hoveredNode === node.id
            const isSelected = selectedNode === node.id
            const color = NODE_COLORS[node.type] || '#64748b'
            return (
              <g key={node.id}
                onMouseEnter={() => setHoveredNode(node.id)}
                onMouseLeave={() => setHoveredNode(null)}
                onClick={() => setSelectedNode(selectedNode === node.id ? null : node.id)}
                style={{ cursor: 'pointer' }}>
                {/* Outer glow */}
                <circle cx={center.x} cy={center.y} r={isHovered || isSelected ? 45 : 35}
                  fill={color} opacity={isHovered || isSelected ? 0.12 : 0.06} />
                {/* Node circle */}
                <circle cx={center.x} cy={center.y} r={24}
                  fill={`${color}33`} stroke={color} strokeWidth={2}
                  filter={isHovered ? 'url(#glow)' : undefined} />
                {/* Icon */}
                <text x={center.x} y={center.y + 5} fontSize={18} textAnchor="middle" fill="white">
                  {NODE_ICONS[node.id] ? '●' : '●'}
                </text>
                {/* Label */}
                <text x={center.x} y={center.y + 42} fill="rgba(255,255,255,0.7)"
                  fontSize={11} textAnchor="middle" fontWeight="600">
                  {node.label}
                </text>
                {/* Type badge */}
                <text x={center.x} y={center.y + 55} fill="rgba(255,255,255,0.3)"
                  fontSize={8} textAnchor="middle" textTransform="uppercase">
                  {node.type}
                </text>
              </g>
            )
          })}
        </svg>

        {/* Node detail panel */}
        {selectedNode && (
          <div className="topology-detail">
            <h4><i className={NODE_ICONS[selectedNode] || 'fa-solid fa-circle'} style={{marginRight: '8px'}}></i>{ALL_NODES.find(n => n.id === selectedNode)?.label}</h4>
            <div className="topology-detail__stat">
              <span>Type</span>
              <span>{ALL_NODES.find(n => n.id === selectedNode)?.type}</span>
            </div>
            <div className="topology-detail__stat">
              <span>Connections</span>
              <span>{CONNECTIONS.filter(c => c.from === selectedNode || c.to === selectedNode).length}</span>
            </div>
            <div className="topology-detail__stat">
              <span>Active Threats</span>
              <span className={activeThreats.length > 0 ? 'text-red' : 'text-green'}>{activeThreats.length}</span>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
