import { useEffect, useRef } from 'react'

export default function LiveTrafficFeed({ packets, captureRunning }) {
  const feedRef = useRef(null)

  useEffect(() => {
    if (feedRef.current) {
      feedRef.current.scrollTop = 0
    }
  }, [packets.length])

  const formatSize = (bytes) => {
    if (!bytes) return '0B'
    if (bytes < 1024) return `${bytes}B`
    return `${(bytes / 1024).toFixed(1)}KB`
  }

  // Normalize packet fields (backend uses snake_case)
  const getPacket = (p) => ({
    id: p.id || p.src_ip + '-' + p.dst_port,
    srcIP: p.src_ip || p.srcIP || '0.0.0.0',
    dstIP: p.dst_ip || p.dstIP || '0.0.0.0',
    srcPort: p.src_port || p.srcPort || 0,
    dstPort: p.dst_port || p.dstPort || 0,
    protocol: p.protocol || 'TCP',
    size: p.size || 0,
    timestamp: p.timestamp || new Date().toISOString().replace('T', ' ').slice(0, 19),
    isSuspicious: p.isSuspicious || false,
    flag: p.flag || '[NORMAL]',
  })

  return (
    <div className="traffic-feed">
      <div className="traffic-feed__header">
        <span className="traffic-feed__title">
          <span className={`traffic-feed__live-dot ${captureRunning ? '' : 'traffic-feed__live-dot--off'}`}></span>
          {captureRunning ? 'Live Traffic Feed' : 'Traffic Feed (No Capture)'}
        </span>
        <span className="traffic-feed__count">{packets.length} packets</span>
      </div>
      <div className="traffic-feed__body" ref={feedRef}>
        {packets.length === 0 && (
          <div className="traffic-empty" style={{ padding: '24px' }}>
            {captureRunning
              ? 'Waiting for packets... Start analyzing PCAP files or check capture status.'
              : 'No packet data. Start a live capture or upload a PCAP file to see traffic here.'
            }
          </div>
        )}
        {packets.map((raw, i) => {
          const p = getPacket(raw)
          return (
            <div
              key={p.id + i}
              className={`traffic-feed__row ${p.isSuspicious ? 'traffic-feed__row--suspicious' : ''}`}
            >
              <span className={`traffic-feed__flag ${p.isSuspicious ? 'traffic-feed__flag--danger' : 'traffic-feed__flag--safe'}`}>
                {p.flag}
              </span>
              <span className="traffic-feed__time">
                {typeof p.timestamp === 'string' ? (p.timestamp.split(' ')[1] || p.timestamp.slice(11, 19)) : ''}
              </span>
              <span className="traffic-feed__proto">{p.protocol}</span>
              <span className="traffic-feed__ip">{p.srcIP}</span>
              <span className="traffic-feed__arrow">→</span>
              <span className="traffic-feed__ip">{p.dstIP}</span>
              <span className="traffic-feed__port">:{p.dstPort}</span>
              <span className="traffic-feed__size">{formatSize(p.size)}</span>
            </div>
          )
        })}
      </div>
    </div>
  )
}
