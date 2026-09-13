import { useState } from 'react'

const NAV_ITEMS = [
  { id: 'dashboard', label: 'Dashboard', icon: '📊' },
  { id: 'pcap', label: 'PCAP Analyzer', icon: '📁' },
  { id: 'live', label: 'Live Capture', icon: '🔴' },
  { id: 'traffic', label: 'Live Traffic', icon: '📡' },
  { id: 'threats', label: 'Threats', icon: '🚨' },
  { id: 'evidence', label: 'Evidence', icon: '🔬' },
  { id: 'topology', label: 'Network Map', icon: '🗺️' },
  { id: 'analytics', label: 'Analytics', icon: '📈' },
  { id: 'logs', label: 'Logs', icon: '📋' },
  { id: 'settings', label: 'Settings', icon: '⚙️' },
]

export default function Sidebar({ activeView, onViewChange, alertCount }) {
  const [collapsed, setCollapsed] = useState(false)

  return (
    <aside className={`sidebar ${collapsed ? 'sidebar--collapsed' : ''}`}>
      <div className="sidebar__logo">
        <div className="sidebar__logo-icon">🛡️</div>
        {!collapsed && (
          <div className="sidebar__logo-text">
            <span className="sidebar__logo-name">God's Eye</span>
            <span className="sidebar__logo-sub">CyberShield SIH</span>
          </div>
        )}
      </div>

      <button
        className="sidebar__toggle"
        onClick={() => setCollapsed(!collapsed)}
        title={collapsed ? 'Expand' : 'Collapse'}
      >
        {collapsed ? '»' : '«'}
      </button>

      <nav className="sidebar__nav">
        {NAV_ITEMS.map(item => (
          <button
            key={item.id}
            className={`sidebar__item ${activeView === item.id ? 'sidebar__item--active' : ''}`}
            onClick={() => onViewChange(item.id)}
            title={collapsed ? item.label : undefined}
          >
            <span className="sidebar__item-icon">{item.icon}</span>
            {!collapsed && <span className="sidebar__item-label">{item.label}</span>}
            {item.id === 'threats' && alertCount > 0 && (
              <span className="sidebar__badge">{alertCount > 99 ? '99+' : alertCount}</span>
            )}
          </button>
        ))}
      </nav>

      <div className="sidebar__footer">
        {!collapsed && (
          <div className="sidebar__status">
            <div className="sidebar__status-dot sidebar__status-dot--active"></div>
            <span>System Active</span>
          </div>
        )}
      </div>
    </aside>
  )
}
