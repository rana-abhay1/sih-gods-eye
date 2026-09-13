import { NETWORK_NODES } from '../data/threats'

export default function NetworkTopology({ threats }) {
  const svgWidth = 350
  const svgHeight = 250

  const nodeColors = {
    security: '#3b82f6',
    server: '#10b981',
    monitor: '#8b5cf6',
  }

  // Simple connections between nodes
  const connections = [
    { from: 'firewall', to: 'ids' },
    { from: 'ids', to: 'siem' },
    { from: 'ids', to: 'webserver' },
    { from: 'ids', to: 'app' },
    { from: 'webserver', to: 'db' },
    { from: 'monitor', to: 'siem' },
    { from: 'monitor', to: 'ids' },
  ]

  const getNodePos = (id) => {
    const node = NETWORK_NODES.find(n => n.id === id)
    return node ? { x: node.x, y: node.y } : { x: 50, y: 50 }
  }

  const activeThreatCount = threats.filter(t => t.status === 'active').length

  return (
    <div className="network-topology">
      <div className="network-topology__header">
        <span className="network-topology__title">🗺️ Network Topology</span>
        <span className="network-topology__status">
          {activeThreatCount > 0 ? (
            <span className="network-topology__status--alert">
              ⚠️ {activeThreatCount} active threats
            </span>
          ) : (
            <span className="network-topology__status--ok">✅ All clear</span>
          )}
        </span>
      </div>
      <svg
        viewBox={`0 0 ${svgWidth} ${svgHeight}`}
        className="network-topology__svg"
      >
        {/* Connections */}
        {connections.map((conn, i) => {
          const from = getNodePos(conn.from)
          const to = getNodePos(conn.to)
          return (
            <line
              key={i}
              x1={`${from.x}%`}
              y1={`${from.y}%`}
              x2={`${to.x}%`}
              y2={`${to.y}%`}
              stroke="rgba(59, 130, 246, 0.3)"
              strokeWidth={1.5}
              strokeDasharray="4 4"
            />
          )
        })}

        {/* Nodes */}
        {NETWORK_NODES.map(node => (
          <g key={node.id}>
            {/* Glow */}
            <circle
              cx={`${node.x}%`}
              cy={`${node.y}%`}
              r={18}
              fill={nodeColors[node.type]}
              opacity={0.15}
            />
            {/* Node circle */}
            <circle
              cx={`${node.x}%`}
              cy={`${node.y}%`}
              r={12}
              fill={nodeColors[node.type]}
              opacity={0.8}
              stroke={nodeColors[node.type]}
              strokeWidth={2}
            />
            {/* Label */}
            <text
              x={`${node.x}%`}
              y={`${node.y + 9}%`}
              fill="rgba(255,255,255,0.7)"
              fontSize={7}
              textAnchor="middle"
            >
              {node.label}
            </text>
          </g>
        ))}
      </svg>
    </div>
  )
}
