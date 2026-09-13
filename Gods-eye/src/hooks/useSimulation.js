import { useState, useEffect, useCallback } from 'react'
import { generateTrafficPacket, generateThreat, generateInitialThreats, generateTrafficHistory } from '../data/threats'

export function useTrafficSimulation(interval = 800) {
  const [packets, setPackets] = useState([])
  const [stats, setStats] = useState({
    totalPackets: 0,
    suspiciousPackets: 0,
    normalPackets: 0,
    packetsPerSecond: 0,
    bandwidthMbps: 0,
    activeConnections: 0,
    threatsDetected: 0,
    avgConfidence: 0,
  })
  
  useEffect(() => {
    const timer = setInterval(() => {
      const packet = generateTrafficPacket()
      
      setPackets(prev => {
        const next = [packet, ...prev]
        return next.slice(0, 100)
      })
      
      setStats(prev => {
        const newTotal = prev.totalPackets + 1
        const newSuspicious = prev.suspiciousPackets + (packet.isSuspicious ? 1 : 0)
        return {
          totalPackets: newTotal,
          suspiciousPackets: newSuspicious,
          normalPackets: newTotal - newSuspicious,
          packetsPerSecond: Math.round(50 + Math.random() * 30),
          bandwidthMbps: Math.round((2.5 + Math.random() * 1.5) * 10) / 10,
          activeConnections: Math.round(40 + Math.random() * 60),
          threatsDetected: prev.threatsDetected + (packet.isSuspicious ? 1 : 0),
          avgConfidence: newSuspicious > 0 ? Math.round((newSuspicious / newTotal) * 100) / 100 : 0,
        }
      })
    }, interval)
    
    return () => clearInterval(timer)
  }, [interval])
  
  return { packets, stats }
}

export function useThreatSimulation(existingThreats = []) {
  const [threats, setThreats] = useState(() => 
    existingThreats.length > 0 ? existingThreats : generateInitialThreats(25)
  )
  const [selectedThreat, setSelectedThreat] = useState(null)
  
  useEffect(() => {
    const timer = setInterval(() => {
      const newThreat = generateThreat()
      setThreats(prev => [newThreat, ...prev].slice(0, 100))
    }, 5000 + Math.random() * 10000)
    
    return () => clearInterval(timer)
  }, [])
  
  const getThreatsBySeverity = useCallback((severity) => {
    return threats.filter(t => t.severity === severity)
  }, [threats])
  
  const getThreatsByType = useCallback(() => {
    const types = {}
    threats.forEach(t => {
      types[t.type] = (types[t.type] || 0) + 1
    })
    return Object.entries(types).map(([type, count]) => ({ type, count }))
      .sort((a, b) => b.count - a.count)
  }, [threats])
  
  const addThreats = useCallback((newThreats) => {
    setThreats(prev => {
      // Merge PCAP-detected threats with existing, prepend them
      const merged = [...newThreats, ...prev].slice(0, 200)
      return merged
    })
  }, [])

  return { threats, selectedThreat, setSelectedThreat, getThreatsBySeverity, getThreatsByType, addThreats }
}

export function useTrafficHistory() {
  const [history, setHistory] = useState(() => generateTrafficHistory(24, 48))
  
  useEffect(() => {
    const timer = setInterval(() => {
      setHistory(prev => {
        const next = [...prev.slice(1)]
        next.push({
          timestamp: new Date().toISOString().replace('T', ' ').slice(0, 19),
          totalPackets: Math.round(500 + Math.sin(Date.now() / 10000) * 200 + Math.random() * 100),
          suspiciousPackets: Math.round(Math.random() * 30),
          normalPackets: Math.round(400 + Math.random() * 200),
        })
        return next
      })
    }, 3000)
    
    return () => clearInterval(timer)
  }, [])
  
  return history
}

export function useClock() {
  const [time, setTime] = useState(new Date())
  
  useEffect(() => {
    const timer = setInterval(() => setTime(new Date()), 1000)
    return () => clearInterval(timer)
  }, [])
  
  return time
}
