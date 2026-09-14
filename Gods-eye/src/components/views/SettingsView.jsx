import { useState } from 'react'

export default function SettingsView({ stats }) {
  const [settings, setSettings] = useState({
    monitoringMode: 'passive',
    autoBlock: false,
    alertThreshold: 'medium',
    refreshRate: 'normal',
    mlModel: 'ensemble',
    logRetention: '30',
    notifications: true,
    soundAlerts: false,
    darkMode: true,
    trafficCapture: true,
    geoIP: true,
    packetCapture: true,
  })

  const toggleSetting = (key) => {
    setSettings(prev => ({ ...prev, [key]: !prev[key] }))
  }

  const updateSetting = (key, value) => {
    setSettings(prev => ({ ...prev, [key]: value }))
  }

  return (
    <div className="view-page">
      <div className="view-page__header">
        <h2 className="view-page__title"><i className="fa-solid fa-gear" style={{marginRight: '10px'}}></i>Settings</h2>
        <p className="view-page__subtitle">Configure monitoring parameters and system preferences</p>
      </div>

      <div className="settings-grid">
        {/* Monitoring Config */}
        <div className="settings-section">
          <h3 className="settings-section__title"><i className="fa-solid fa-magnifying-glass" style={{marginRight: '8px'}}></i>Monitoring Configuration</h3>

          <div className="settings-row">
            <div className="settings-row__info">
              <span className="settings-row__label">Monitoring Mode</span>
              <span className="settings-row__desc">Traffic observation mode (passive is recommended for SIH)</span>
            </div>
            <select className="settings-select" value={settings.monitoringMode}
              onChange={e => updateSetting('monitoringMode', e.target.value)}>
              <option value="passive">Passive (One-directional)</option>
              <option value="active">Active (Two-way)</option>
              <option value="hybrid">Hybrid</option>
            </select>
          </div>

          <div className="settings-row">
            <div className="settings-row__info">
              <span className="settings-row__label">Alert Severity Threshold</span>
              <span className="settings-row__desc">Only trigger alerts at or above this severity</span>
            </div>
            <select className="settings-select" value={settings.alertThreshold}
              onChange={e => updateSetting('alertThreshold', e.target.value)}>
              <option value="low">Low (All threats)</option>
              <option value="medium">Medium and above</option>
              <option value="high">High and above</option>
              <option value="critical">Critical only</option>
            </select>
          </div>

          <div className="settings-row">
            <div className="settings-row__info">
              <span className="settings-row__label">Auto-Block Threats</span>
              <span className="settings-row__desc">Automatically block IPs with high-confidence threats</span>
            </div>
            <button className={`settings-toggle ${settings.autoBlock ? 'settings-toggle--on' : ''}`}
              onClick={() => toggleSetting('autoBlock')}>
              <span className="settings-toggle__thumb"></span>
            </button>
          </div>

          <div className="settings-row">
            <div className="settings-row__info">
              <span className="settings-row__label">Traffic Capture</span>
              <span className="settings-row__desc">Enable full packet capture for evidence collection</span>
            </div>
            <button className={`settings-toggle ${settings.trafficCapture ? 'settings-toggle--on' : ''}`}
              onClick={() => toggleSetting('trafficCapture')}>
              <span className="settings-toggle__thumb"></span>
            </button>
          </div>

          <div className="settings-row">
            <div className="settings-row__info">
              <span className="settings-row__label">GeoIP Lookup</span>
              <span className="settings-row__desc">Resolve source IPs to geographic locations</span>
            </div>
            <button className={`settings-toggle ${settings.geoIP ? 'settings-toggle--on' : ''}`}
              onClick={() => toggleSetting('geoIP')}>
              <span className="settings-toggle__thumb"></span>
            </button>
          </div>
        </div>

        {/* ML Model Config */}
        <div className="settings-section">
          <h3 className="settings-section__title"><i className="fa-solid fa-brain" style={{marginRight: '8px'}}></i>ML Engine</h3>

          <div className="settings-row">
            <div className="settings-row__info">
              <span className="settings-row__label">Detection Model</span>
              <span className="settings-row__desc">Primary ML model for threat classification</span>
            </div>
            <select className="settings-select" value={settings.mlModel}
              onChange={e => updateSetting('mlModel', e.target.value)}>
              <option value="ensemble">RF + LSTM Ensemble</option>
              <option value="rf">Random Forest Only</option>
              <option value="lstm">LSTM Only</option>
              <option value="xgboost">XGBoost</option>
            </select>
          </div>

          <div className="settings-row">
            <div className="settings-row__info">
              <span className="settings-row__label">Data Refresh Rate</span>
              <span className="settings-row__desc">How often to re-analyze traffic patterns</span>
            </div>
            <select className="settings-select" value={settings.refreshRate}
              onChange={e => updateSetting('refreshRate', e.target.value)}>
              <option value="fast">Fast (100ms)</option>
              <option value="normal">Normal (500ms)</option>
              <option value="slow">Slow (2s)</option>
            </select>
          </div>

          <div className="settings-row">
            <div className="settings-row__info">
              <span className="settings-row__label">Log Retention</span>
              <span className="settings-row__desc">How long to keep analysis logs</span>
            </div>
            <select className="settings-select" value={settings.logRetention}
              onChange={e => updateSetting('logRetention', e.target.value)}>
              <option value="7">7 days</option>
              <option value="30">30 days</option>
              <option value="90">90 days</option>
              <option value="365">1 year</option>
            </select>
          </div>
        </div>

        {/* UI Preferences */}
        <div className="settings-section">
          <h3 className="settings-section__title"><i className="fa-solid fa-palette" style={{marginRight: '8px'}}></i>Interface</h3>

          <div className="settings-row">
            <div className="settings-row__info">
              <span className="settings-row__label">Dark Mode</span>
              <span className="settings-row__desc">Use dark theme for the dashboard</span>
            </div>
            <button className={`settings-toggle ${settings.darkMode ? 'settings-toggle--on' : ''}`}
              onClick={() => toggleSetting('darkMode')}>
              <span className="settings-toggle__thumb"></span>
            </button>
          </div>

          <div className="settings-row">
            <div className="settings-row__info">
              <span className="settings-row__label">Desktop Notifications</span>
              <span className="settings-row__desc">Show browser notifications for critical threats</span>
            </div>
            <button className={`settings-toggle ${settings.notifications ? 'settings-toggle--on' : ''}`}
              onClick={() => toggleSetting('notifications')}>
              <span className="settings-toggle__thumb"></span>
            </button>
          </div>

          <div className="settings-row">
            <div className="settings-row__info">
              <span className="settings-row__label">Sound Alerts</span>
              <span className="settings-row__desc">Play audio alert on critical threat detection</span>
            </div>
            <button className={`settings-toggle ${settings.soundAlerts ? 'settings-toggle--on' : ''}`}
              onClick={() => toggleSetting('soundAlerts')}>
              <span className="settings-toggle__thumb"></span>
            </button>
          </div>
        </div>

        {/* System Info */}
        <div className="settings-section">
          <h3 className="settings-section__title"><i className="fa-solid fa-circle-info" style={{marginRight: '8px'}}></i>System Information</h3>
          <div className="settings-info-grid">
            <div className="settings-info-item">
              <span className="settings-info-label">Dashboard Version</span>
              <span className="settings-info-value">1.0.0-beta</span>
            </div>
            <div className="settings-info-item">
              <span className="settings-info-label">ML Model Version</span>
              <span className="settings-info-value">v2.1.0</span>
            </div>
            <div className="settings-info-item">
              <span className="settings-info-label">Packets Processed</span>
              <span className="settings-info-value">{stats.totalPackets.toLocaleString()}</span>
            </div>
            <div className="settings-info-item">
              <span className="settings-info-label">Active Connections</span>
              <span className="settings-info-value">{stats.activeConnections}</span>
            </div>
            <div className="settings-info-item">
              <span className="settings-info-label">Training Dataset</span>
              <span className="settings-info-value">CICIDS2017 + UNSW-NB15</span>
            </div>
            <div className="settings-info-item">
              <span className="settings-info-label">Framework</span>
              <span className="settings-info-value">React + Vite</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
