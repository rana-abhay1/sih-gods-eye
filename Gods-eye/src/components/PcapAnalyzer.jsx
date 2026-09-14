import { useState, useRef } from 'react'
import { SEVERITY_CONFIG } from '../data/threats'

export default function PcapAnalyzer({ onThreatsDetected, API_URL = 'http://localhost:5000' }) {
  const [file, setFile] = useState(null)
  const [analyzing, setAnalyzing] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')
  const [dragOver, setDragOver] = useState(false)
  const fileRef = useRef(null)

  const handleFile = (f) => {
    if (f && (f.name.endsWith('.pcap') || f.name.endsWith('.pcapng') || f.name.endsWith('.cap'))) {
      setFile(f)
      setError('')
      setResult(null)
    } else {
      setError('Please select a .pcap, .pcapng, or .cap file')
    }
  }

  const handleDrop = (e) => {
    e.preventDefault()
    setDragOver(false)
    const f = e.dataTransfer.files[0]
    handleFile(f)
  }

  const handleAnalyze = async () => {
    if (!file) return
    setAnalyzing(true)
    setError('')
    setResult(null)

    const formData = new FormData()
    formData.append('file', file)

    try {
      const res = await fetch(`${API_URL}/api/analyze`, {
        method: 'POST',
        body: formData,
      })
      const data = await res.json()

      if (!res.ok) {
        setError(data.error || 'Analysis failed')
        return
      }

      setResult(data)

      // Feed detected threats into the dashboard
      if (data.threats && data.threats.length > 0 && onThreatsDetected) {
        onThreatsDetected(data.threats)
      }
    } catch {
      setError(`Could not connect to backend (${API_URL}). Make sure the Python server is running.`)
    } finally {
      setAnalyzing(false)
    }
  }

  const formatBytes = (b) => {
    if (b < 1024) return `${b} B`
    if (b < 1048576) return `${(b / 1024).toFixed(1)} KB`
    return `${(b / 1048576).toFixed(1)} MB`
  }

  return (
    <div className="view-page">
      <div className="view-page__header">
        <h2 className="view-page__title"><i className="fa-solid fa-file-lines" style={{marginRight: '10px'}}></i>PCAP Analyzer</h2>
        <p className="view-page__subtitle">Upload a pcap/pcapng file for AI/ML-powered threat detection</p>
      </div>

      {/* Upload Zone */}
      <div
        className={`pcap-dropzone ${dragOver ? 'pcap-dropzone--active' : ''} ${file ? 'pcap-dropzone--has-file' : ''}`}
        onDragOver={(e) => { e.preventDefault(); setDragOver(true) }}
        onDragLeave={() => setDragOver(false)}
        onDrop={handleDrop}
        onClick={() => fileRef.current?.click()}
      >
        <input
          ref={fileRef}
          type="file"
          accept=".pcap,.pcapng,.cap"
          hidden
          onChange={(e) => handleFile(e.target.files[0])}
        />
        <div className="pcap-dropzone__icon"><i className={`fa-solid ${file ? 'fa-file-circle-check' : 'fa-cloud-arrow-up'}`}></i></div>
        {file ? (
          <div className="pcap-dropzone__info">
            <span className="pcap-dropzone__filename">{file.name}</span>
            <span className="pcap-dropzone__size">{formatBytes(file.size)}</span>
          </div>
        ) : (
          <div className="pcap-dropzone__info">
            <span className="pcap-dropzone__hint">Drop a .pcap / .pcapng file here</span>
            <span className="pcap-dropzone__sub">or click to browse</span>
          </div>
        )}
      </div>

      {/* Analyze Button */}
      <button
        className={`pcap-analyze-btn ${analyzing ? 'pcap-analyze-btn--loading' : ''}`}
        disabled={!file || analyzing}
        onClick={handleAnalyze}
      >
        {analyzing ? (
          <><span className="pcap-spinner"></span> Analyzing Traffic...</>
        ) : (
          <><i className="fa-solid fa-magnifying-glass-chart" style={{marginRight: '8px'}}></i>Analyze for Threats</>
        )}
      </button>

      {error && <div className="pcap-error">{error}</div>}

      {/* Results */}
      {result && (
        <div className="pcap-results">
          {/* Summary */}
          <div className="pcap-summary">
            <h3 className="pcap-summary__title">Analysis Complete — {result.filename}</h3>
            <div className="pcap-summary__grid">
              <div className="pcap-summary__stat">
                <span className="pcap-summary__value">{result.packet_count.toLocaleString()}</span>
                <span className="pcap-summary__label">Packets</span>
              </div>
              <div className="pcap-summary__stat">
                <span className="pcap-summary__value">{formatBytes(result.features.total_bytes)}</span>
                <span className="pcap-summary__label">Data</span>
              </div>
              <div className="pcap-summary__stat">
                <span className="pcap-summary__value">{result.features.duration}s</span>
                <span className="pcap-summary__label">Duration</span>
              </div>
              <div className="pcap-summary__stat">
                <span className="pcap-summary__value">{result.features.pps}</span>
                <span className="pcap-summary__label">Packets/sec</span>
              </div>
              <div className="pcap-summary__stat">
                <span className="pcap-summary__value">{result.features.unique_src_ips}</span>
                <span className="pcap-summary__label">Source IPs</span>
              </div>
              <div className="pcap-summary__stat">
                <span className="pcap-summary__value">{result.features.unique_dst_ports}</span>
                <span className="pcap-summary__label">Ports Targeted</span>
              </div>
              <div className="pcap-summary__stat pcap-summary__stat--accent">
                <span className="pcap-summary__value">{result.elapsed_seconds}s</span>
                <span className="pcap-summary__label">Analysis Time</span>
              </div>
            </div>

            {/* Protocol Breakdown */}
            <div className="pcap-proto-breakdown">
              <span className="pcap-proto-breakdown__label">Protocols:</span>
              {Object.entries(result.features.protocols).map(([proto, count]) => (
                <span key={proto} className="pcap-proto-tag">{proto}: {count}</span>
              ))}
            </div>
          </div>

          {/* Threats */}
          {result.threats.length > 0 ? (
            <div className="pcap-threats">
              <h3 className="pcap-threats__title">
                <i className="fa-solid fa-skull-crossbones" style={{marginRight: '8px'}}></i>Detected {result.threats.length} Threat{result.threats.length !== 1 ? 's' : ''}
              </h3>
              {result.threats.map(threat => {
                const sev = SEVERITY_CONFIG[threat.severity] || SEVERITY_CONFIG.low
                return (
                  <div key={threat.id} className="pcap-threat-card">
                    <div className="pcap-threat-card__header">
                      <div className="pcap-threat-card__meta">
                        <span className="pcap-threat-card__id">{threat.id}</span>
                        <span className="severity-badge" style={{ color: sev.color, backgroundColor: sev.bg }}>
                          {sev.label}
                        </span>
                        <span className="pcap-threat-card__type">{threat.type}</span>
                      </div>
                      <div className="pcap-threat-card__confidence">
                        <span className="pcap-threat-card__conf-label">Confidence</span>
                        <div className="confidence-bar" style={{ width: 100 }}>
                          <div className="confidence-bar__fill" style={{
                            width: `${Math.round(threat.confidence * 100)}%`,
                            backgroundColor: threat.confidence > 0.8 ? '#ef4444' : threat.confidence > 0.6 ? '#f59e0b' : '#22c55e',
                          }}></div>
                          <span className="confidence-bar__label">{Math.round(threat.confidence * 100)}%</span>
                        </div>
                      </div>
                    </div>

                    <div className="pcap-threat-card__details">
                      <span><strong>Source:</strong> {threat.source_ip}</span>
                      <span><strong>Dest:</strong> {threat.dest_ip}:{threat.dest_port}</span>
                      <span><strong>Protocol:</strong> {threat.protocol}</span>
                      <span><strong>Risk:</strong> {threat.risk_score}/10</span>
                    </div>

                    {threat.evidence && threat.evidence.length > 0 && (
                      <div className="pcap-threat-card__evidence">
                        <strong>Supporting Evidence:</strong>
                        {threat.evidence.map((ev, i) => (
                          <pre key={i} className="pcap-threat-card__detail">{ev.detail}</pre>
                        ))}
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          ) : (
            <div className="pcap-clean">
              <span className="pcap-clean__icon"><i className="fa-solid fa-circle-check"></i></span>
              <span className="pcap-clean__text">No threats detected — traffic appears clean</span>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
