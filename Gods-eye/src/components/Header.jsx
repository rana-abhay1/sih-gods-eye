import { useClock } from '../hooks/useBackend'

const VIEW_TITLES = {
  dashboard: 'Dashboard Overview',
  pcap: 'PCAP Analyzer',
  live: 'Live Network Capture',
  traffic: 'Live Traffic Monitor',
  threats: 'Threat Management',
  evidence: 'Evidence Chain',
  topology: 'Network Topology',
  analytics: 'Analytics & Insights',
  logs: 'System Logs',
  settings: 'Settings',
}

export default function Header({ activeView, connected, captureRunning }) {
  const time = useClock()

  const formatTime = (d) => d.toLocaleTimeString('en-US', { hour12: false })
  const formatDate = (d) => d.toLocaleDateString('en-US', { weekday: 'short', month: 'short', day: 'numeric', year: 'numeric' })

  return (
    <header className="header">
      <div className="header__left">
        <h1 className="header__title">God's Eye — {VIEW_TITLES[activeView] || 'Dashboard'}</h1>
        <span className="header__subtitle">AI/ML-Powered Passive Traffic Monitoring • SIH Project</span>
      </div>
      
      <div className="header__center">
        <div className="header__status-group">
          <div className={`header__status ${connected ? '' : 'header__status--offline'}`}>
            <span className={`header__status-dot ${connected ? 'header__status-dot--green' : ''}`}></span>
            <span>{connected ? 'BACKEND ONLINE' : 'BACKEND OFFLINE'}</span>
          </div>
          <div className={`header__status ${captureRunning ? 'header__status--active' : ''}`}>
            <span className={`header__status-dot ${captureRunning ? 'header__status-dot--green' : 'header__status-dot--blue'}`}></span>
            <span>{captureRunning ? 'CAPTURING' : 'PASSIVE MODE'}</span>
          </div>
          <div className="header__status">
            <span className="header__status-dot header__status-dot--blue"></span>
            <span>ML ENGINE v2.1</span>
          </div>
        </div>
      </div>

      <div className="header__right">
        <div className="header__clock">
          <span className="header__time">{formatTime(time)}</span>
          <span className="header__date">{formatDate(time)}</span>
        </div>
        <div className="header__user">
          <div className="header__avatar">SC</div>
          <div className="header__user-info">
            <span className="header__user-name">SOC Analyst</span>
            <span className="header__user-role">Security Ops</span>
          </div>
        </div>
      </div>
    </header>
  )
}
