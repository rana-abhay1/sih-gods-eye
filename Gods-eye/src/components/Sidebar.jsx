import { useState } from 'react'

const NAV_ITEMS = [
  { id: 'dashboard', label: 'Dashboard', icon: 'fa-solid fa-gauge-high' },
  { id: 'pcap', label: 'PCAP Analyzer', icon: 'fa-solid fa-file-lines' },
  { id: 'live', label: 'Live Capture', icon: 'fa-solid fa-satellite-dish' },
  { id: 'traffic', label: 'Live Traffic', icon: 'fa-solid fa-network-wired' },
  { id: 'threats', label: 'Threats', icon: 'fa-solid fa-triangle-exclamation' },
  { id: 'evidence', label: 'Evidence', icon: 'fa-solid fa-magnifying-glass' },
  { id: 'topology', label: 'Network Map', icon: 'fa-solid fa-diagram-project' },
  { id: 'analytics', label: 'Analytics', icon: 'fa-solid fa-chart-line' },
  { id: 'logs', label: 'Logs', icon: 'fa-solid fa-scroll' },
  { id: 'settings', label: 'Settings', icon: 'fa-solid fa-gear' },
]

export default function Sidebar({ activeView, onViewChange, alertCount }) {
  const [collapsed, setCollapsed] = useState(false)

  return (
    <aside className={`sidebar ${collapsed ? 'sidebar--collapsed' : ''}`}>
      <div className="sidebar__logo">
        <div className="sidebar__logo-icon"><i className="fa-solid fa-shield-halved"></i></div>
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
            <span className="sidebar__item-icon"><i className={item.icon}></i></span>
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
