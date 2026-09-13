import { useState, useEffect, useRef, useCallback } from 'react'

const API_URL = 'http://localhost:5000'

// ─── Normalize backend threat fields to match component expectations ───
function normalizeThreat(t) {
  return {
    ...t,
    sourceIP: t.source_ip || t.sourceIP || 'unknown',
    destIP: t.dest_ip || t.destIP || 'unknown',
    destPort: t.dest_port || t.destPort || 0,
    sourcePort: t.source_port || 0,
    packetsAnalyzed: t.packets_analyzed || 0,
    bytesTransferred: t.bytes_transferred || 0,
    riskScore: t.risk_score || 0,
    timestamp: t.timestamp || new Date().toISOString().replace('T', ' ').slice(0, 19),
  }
}

// ─── Compute backend stats from raw capture stats ───
function computeStats(s, threatCount) {
  return {
    totalPackets: s.total_packets || 0,
    suspiciousPackets: s.suspicious_packets || 0,
    normalPackets: s.normal_packets || 0,
    packetsPerSecond: s.pps || 0,
    bandwidthMbps: s.bytes_per_sec ? Math.round((s.bytes_per_sec * 8 / 1000000) * 10) / 10 : 0,
    activeConnections: s.unique_src_ips || 0,
    threatsDetected: threatCount,
    avgConfidence: s.total_packets > 0 ? Math.round((s.suspicious_packets / s.total_packets) * 100) : 0,
  }
}

function makeHistoryPoint(s) {
  return {
    timestamp: new Date().toISOString().replace('T', ' ').slice(0, 19),
    totalPackets: s.pps || 0,
    suspiciousPackets: s.suspicious_packets || 0,
    normalPackets: Math.max(0, (s.total_packets || 0) - (s.suspicious_packets || 0)),
  }
}

// ─── Main backend hook ───
export function useBackend() {
  const [connected, setConnected] = useState(false)
  const [captureRunning, setCaptureRunning] = useState(false)
  const [captureStats, setCaptureStats] = useState({})
  const [threats, setThreats] = useState([])
  const [packets] = useState([])
  const [history, setHistory] = useState([])
  const [selectedThreat, setSelectedThreat] = useState(null)
  const [backendStats, setBackendStats] = useState({
    totalPackets: 0, suspiciousPackets: 0, normalPackets: 0,
    packetsPerSecond: 0, bandwidthMbps: 0, activeConnections: 0,
    threatsDetected: 0, avgConfidence: 0,
  })
  const eventSourceRef = useRef(null)
  const threatCountRef = useRef(0)

  // Keep threat count ref updated
  useEffect(() => { threatCountRef.current = threats.length }, [threats.length])

  // ── Health check ──
  const checkHealth = useCallback(async () => {
    try {
      const res = await fetch(API_URL + '/api/health')
      const data = await res.json()
      setConnected(data.status === 'ok')
      setCaptureRunning(data.live_capture || false)
    } catch {
      setConnected(false)
    }
  }, [])

  // ── Poll capture status ──
  const pollStatus = useCallback(async () => {
    try {
      const res = await fetch(API_URL + '/api/capture/status')
      const data = await res.json()
      setCaptureRunning(data.running)
      setCaptureStats(data.stats || {})
      setBackendStats(computeStats(data.stats || {}, threatCountRef.current))

      if (data.running && data.stats?.total_packets > 0) {
        setHistory(prev => [...prev, makeHistoryPoint(data.stats)].slice(-60))
      }
    } catch { /* backend offline */ }
  }, [])

  // ── SSE connection for live threats ──
  const connectSSE = useCallback(() => {
    if (eventSourceRef.current) eventSourceRef.current.close()

    const es = new EventSource(API_URL + '/api/capture/stream')
    eventSourceRef.current = es

    es.addEventListener('threats', (e) => {
      try {
        const data = JSON.parse(e.data)
        if (data.threats) {
          const normalized = data.threats.map(normalizeThreat)
          setThreats(prev => [...normalized, ...prev].slice(0, 200))
        }
      } catch { /* parse error */ }
    })

    es.addEventListener('stats', (e) => {
      try {
        const data = JSON.parse(e.data)
        setCaptureStats(data)
        setBackendStats(computeStats(data, threatCountRef.current))
        if (data.total_packets > 0) {
          setHistory(prev => [...prev, makeHistoryPoint(data)].slice(-60))
        }
      } catch { /* parse error */ }
    })

    es.onerror = () => {
      if (es.readyState === EventSource.CLOSED) setCaptureRunning(false)
    }
  }, [])

  const disconnectSSE = useCallback(() => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close()
      eventSourceRef.current = null
    }
  }, [])

  // ── Add threats from PCAP analysis ──
  const addThreats = useCallback((newThreats) => {
    const normalized = newThreats.map(normalizeThreat)
    setThreats(prev => [...normalized, ...prev].slice(0, 200))
  }, [])

  // ── Initialize on mount ──
  useEffect(() => {
    let mounted = true
    const init = async () => {
      try {
        const res = await fetch(API_URL + '/api/health')
        const data = await res.json()
        if (mounted) {
          setConnected(data.status === 'ok')
          setCaptureRunning(data.live_capture || false)
        }
      } catch { if (mounted) setConnected(false) }

      try {
        const res = await fetch(API_URL + '/api/capture/status')
        const data = await res.json()
        if (mounted) {
          setCaptureRunning(data.running)
          setCaptureStats(data.stats || {})
          setBackendStats(computeStats(data.stats || {}, 0))
        }
      } catch { /* ignore */ }
    }
    init()
    const timer = setInterval(() => {
      checkHealth()
      pollStatus()
    }, 3000)
    return () => { mounted = false; clearInterval(timer); disconnectSSE() }
  }, [checkHealth, pollStatus, disconnectSSE])

  // ── Reconnect SSE when capture starts ──
  useEffect(() => {
    if (captureRunning && !eventSourceRef.current) connectSSE()
    if (!captureRunning && eventSourceRef.current) disconnectSSE()
  }, [captureRunning, connectSSE, disconnectSSE])

  return {
    connected, captureRunning, captureStats, stats: backendStats,
    threats, packets, history, selectedThreat, setSelectedThreat,
    addThreats, API_URL,
  }
}

// ─── Clock hook ───
export function useClock() {
  const [time, setTime] = useState(new Date())
  useEffect(() => {
    const timer = setInterval(() => setTime(new Date()), 1000)
    return () => clearInterval(timer)
  }, [])
  return time
}
