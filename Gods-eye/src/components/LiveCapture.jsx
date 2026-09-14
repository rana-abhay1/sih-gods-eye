import { useState, useEffect, useRef, useCallback } from 'react'
import { SEVERITY_CONFIG } from '../data/threats'

export default function LiveCapture({ onThreatsDetected, API_URL = 'http://localhost:5000' }) {
  const [isRunning, setIsRunning] = useState(false)
  const [interfaces, setInterfaces] = useState([])
  const [selectedInterface, setSelectedInterface] = useState('')
  const [stats, setStats] = useState({})
  const [liveThreats, setLiveThreats] = useState([])
  const [events, setEvents] = useState([])
  const [error, setError] = useState('')
  const [connecting, setConnecting] = useState(false)
  const [simMode, setSimMode] = useState(false)
  const eventSourceRef = useRef(null)
  const eventsEndRef = useRef(null)
  const onThreatsDetectedRef = useRef(onThreatsDetected)
  useEffect(() => { onThreatsDetectedRef.current = onThreatsDetected })

  // Stable addEvent via ref to avoid initialization order issues
  const addEvent = useCallback((type, message) => {
    setEvents(prev => [...prev, {
      time: new Date().toLocaleTimeString('en-US', { hour12: false }),
      type,
      message,
    }].slice(-50))
  }, [])

  // Fetch available interfaces and check status on mount
  useEffect(() => {
    const init = async () => {
      try {
        const res = await fetch(`${API_URL}/api/capture/interfaces`)
        const data = await res.json()
        setInterfaces(data.interfaces || [])
        if (data.current) setSelectedInterface(data.current)
        else if (data.interfaces?.length > 0) setSelectedInterface(data.interfaces[0])
      } catch {
        setInterfaces(['eth0', 'wlan0', 'lo'])
      }
      try {
        const res = await fetch(`${API_URL}/api/capture/status`)
        const data = await res.json()
        setIsRunning(data.running)
        setSimMode(data.sim_mode || false)
        setStats(data.stats || {})
        if (data.interface) setSelectedInterface(data.interface)
        if (data.error) addEvent('error', data.error)
      } catch { /* ignore */ }
    }
    init()
    const timer = setInterval(async () => {
      try {
        const res = await fetch(`${API_URL}/api/capture/status`)
        const data = await res.json()
        setIsRunning(data.running)
        setSimMode(data.sim_mode || false)
        setStats(data.stats || {})
      } catch { /* ignore */ }
    }, 3000)
    return () => clearInterval(timer)
  }, [API_URL])

  // Auto-scroll events
  useEffect(() => {
    if (eventsEndRef.current) {
      eventsEndRef.current.scrollIntoView({ behavior: 'smooth' })
    }
  }, [events])

  // SSE connection
  const connectSSE = useCallback(() => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close()
    }

    const es = new EventSource(`${API_URL}/api/capture/stream`)
    eventSourceRef.current = es

    es.addEventListener('threats', (e) => {
      try {
        const data = JSON.parse(e.data)
        if (data.threats) {
          setLiveThreats(prev => [...data.threats, ...prev].slice(0, 100))
          addEvent('threat', `Detected ${data.threats.length} threat(s) in ${data.window_packets} packets`)
          if (onThreatsDetectedRef.current) onThreatsDetectedRef.current(data.threats)
        }
      } catch { /* parse error */ }
    })

    es.addEventListener('stats', (e) => {
      try {
        const data = JSON.parse(e.data)
        setStats(data)
      } catch { /* parse error */ }
    })

    es.addEventListener('error', (e) => {
      try {
        const data = JSON.parse(e.data)
        setError(data.message || 'Backend error')
        addEvent('error', data.message)
      } catch { /* ignore */ }
    })

    es.onerror = () => {
      if (es.readyState === EventSource.CLOSED) {
        setIsRunning(false)
        addEvent('info', 'SSE connection closed')
      }
    }
  }, [addEvent, API_URL])

  const disconnectSSE = useCallback(() => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close()
      eventSourceRef.current = null
    }
  }, [])

  useEffect(() => {
    return () => disconnectSSE()
  }, [disconnectSSE])

  // Reconnect if already running
  useEffect(() => {
    if (isRunning && !eventSourceRef.current) {
      connectSSE()
    }
  }, [isRunning, connectSSE])

  // Start capture
  const handleStart = async () => {
    setError('')
    setConnecting(true)
    try {
      const res = await fetch(`${API_URL}/api/capture/start`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ interface: selectedInterface || undefined }),
      })
      const data = await res.json()

      if (res.status === 409) {
        setIsRunning(true)
        setConnecting(false)
        connectSSE()
        return
      }

      if (!res.ok) {
        setError(data.error || data.message || 'Failed to start capture')
        setConnecting(false)
        return
      }

      setIsRunning(true)
      setConnecting(false)
      if (data.sim_mode) {
        addEvent('info', `Simulation mode active on ${data.interface || 'default'}. No root access — generating simulated traffic.`)
      } else {
        addEvent('info', `Real capture started on ${data.interface || 'default interface'}`)
      }
      if (data.error) addEvent('error', data.error)
      connectSSE()
    } catch {
      setError('Could not connect to backend. Is the Python server running?')
      setConnecting(false)
    }
  }

  // Stop capture
  const handleStop = async () => {
    try {
      const res = await fetch(`${API_URL}/api/capture/stop`, { method: 'POST' })
      const data = await res.json()
      setIsRunning(false)
      disconnectSSE()
      addEvent('info', `Capture stopped. ${data.final_stats?.total_packets || 0} packets analyzed.`)
    } catch {
      setError('Failed to stop capture')
    }
  }

  return (
    <div className="view-page">
      <div className="view-page__header">
        <h2 className="view-page__title"><i className="fa-solid fa-satellite-dish" style={{marginRight: '10px'}}></i>Live Capture</h2>
        <p className="view-page__subtitle">
          Real-time network interface capture with AI/ML threat detection
        </p>
      </div>

      {/* Status Bar */}
      <div className="lc-status-bar">
        <div className={`lc-status-indicator ${isRunning ? 'lc-status-indicator--active' : ''}`}>
          <span className="lc-status-indicator__dot"></span>
          <span className="lc-status-indicator__text">
            {isRunning ? (simMode ? 'SIMULATING' : 'CAPTURING') : 'IDLE'}
          </span>
        </div>
        {isRunning && (
          <div className="lc-status-stats">
            <span className="lc-status-stat">
              <span className="lc-status-stat__label">Packets</span>
              <span className="lc-status-stat__value">{(stats.total_packets || 0).toLocaleString()}</span>
            </span>
            <span className="lc-status-stat">
              <span className="lc-status-stat__label">PPS</span>
              <span className="lc-status-stat__value lc-status-stat__value--cyan">{stats.pps || 0}</span>
            </span>
            <span className="lc-status-stat">
              <span className="lc-status-stat__label">Src IPs</span>
              <span className="lc-status-stat__value">{stats.unique_src_ips || 0}</span>
            </span>
            <span className="lc-status-stat">
              <span className="lc-status-stat__label">Ports</span>
              <span className="lc-status-stat__value">{stats.unique_dst_ports || 0}</span>
            </span>
            <span className="lc-status-stat">
              <span className="lc-status-stat__label">Buffer</span>
              <span className="lc-status-stat__value">{stats.buffer_size || 0}</span>
            </span>
            <span className="lc-status-stat">
              <span className="lc-status-stat__label">Uptime</span>
              <span className="lc-status-stat__value lc-status-stat__value--green">{stats.uptime || 0}s</span>
            </span>
          </div>
        )}
      </div>

      {/* Controls */}
      <div className="lc-controls">
        <div className="lc-controls__left">
          <label className="lc-label">Network Interface</label>
          <select
            className="lc-select"
            value={selectedInterface}
            onChange={(e) => setSelectedInterface(e.target.value)}
            disabled={isRunning}
          >
            {interfaces.length === 0 && <option value="">Default</option>}
            {interfaces.map(iface => (
              <option key={iface} value={iface}>{iface}</option>
            ))}
          </select>
        </div>
        <div className="lc-controls__right">
          {!isRunning ? (
            <button
              className={`lc-btn lc-btn--start ${connecting ? 'lc-btn--loading' : ''}`}
              onClick={handleStart}
              disabled={connecting}
            >
              {connecting ? (
                <><span className="lc-spinner"></span> Starting...</>
              ) : (
                <><i className="fa-solid fa-play" style={{marginRight: '6px'}}></i>Start Capture</>
              )}
            </button>
          ) : (
            <button className="lc-btn lc-btn--stop" onClick={handleStop}>
              <i className="fa-solid fa-stop" style={{marginRight: '6px'}}></i>Stop Capture
            </button>
          )}
        </div>
      </div>

      {error && <div className="lc-error">{error}</div>}
      {simMode && isRunning && (
        <div className="lc-sim-notice">
          ⚡ <strong>Simulation Mode</strong> — No root access for real capture. Generating realistic simulated traffic.
          Run backend with <code>sudo</code> for live packet capture.
        </div>
      )}

      {/* Protocol Distribution */}
      {isRunning && stats.protocols && Object.keys(stats.protocols).length > 0 && (
        <div className="lc-protocols">
          <span className="lc-protocols__label">Protocol Distribution:</span>
          {Object.entries(stats.protocols).sort((a, b) => b[1] - a[1]).map(([proto, count]) => (
            <span key={proto} className="lc-protocols__tag">
              {proto}: {count}
            </span>
          ))}
        </div>
      )}

      <div className="lc-grid">
        {/* Live Threats */}
        <div className="lc-threats">
          <h3 className="lc-section-title">
            🚨 Live Threats ({liveThreats.length})
          </h3>
          <div className="lc-threats__list">
            {liveThreats.length === 0 && isRunning && (
              <div className="lc-empty">
                <span className="lc-empty__spinner"></span>
                Waiting for threats... Analyzing traffic in 10s windows
              </div>
            )}
            {liveThreats.length === 0 && !isRunning && (
              <div className="lc-empty">Start capture to detect threats in real time</div>
            )}
            {liveThreats.map((threat, i) => {
              const sev = SEVERITY_CONFIG[threat.severity] || SEVERITY_CONFIG.low
              return (
                <div key={threat.id + i} className="lc-threat-card">
                  <div className="lc-threat-card__header">
                    <span className="lc-threat-card__id">{threat.id}</span>
                    <span className="severity-badge" style={{ color: sev.color, backgroundColor: sev.bg }}>
                      {sev.label}
                    </span>
                    <span className="lc-threat-card__type">{threat.type}</span>
                    <span className="lc-threat-card__conf">
                      {Math.round(threat.confidence * 100)}%
                    </span>
                  </div>
                  <div className="lc-threat-card__details">
                    <span><strong>Src:</strong> {threat.source_ip}</span>
                    <span><strong>Dst:</strong> {threat.dest_ip}:{threat.dest_port}</span>
                    <span><strong>Proto:</strong> {threat.protocol}</span>
                    <span><strong>Risk:</strong> {threat.risk_score}/10</span>
                  </div>
                  {threat.evidence?.[0] && (
                    <pre className="lc-threat-card__evidence">{threat.evidence[0].detail}</pre>
                  )}
                </div>
              )
            })}
          </div>
        </div>

        {/* Event Log */}
        <div className="lc-events">
          <h3 className="lc-section-title"><i className="fa-solid fa-scroll" style={{marginRight: '8px'}}></i>Capture Events</h3>
          <div className="lc-events__list">
            {events.map((ev, i) => (
              <div key={i} className={`lc-event lc-event--${ev.type}`}>
                <span className="lc-event__time">{ev.time}</span>
                <span className="lc-event__type">[{ev.type.toUpperCase()}]</span>
                <span className="lc-event__msg">{ev.message}</span>
              </div>
            ))}
            <div ref={eventsEndRef} />
          </div>
        </div>
      </div>
    </div>
  )
}
