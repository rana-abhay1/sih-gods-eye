import { useState } from 'react'
import Sidebar from './components/Sidebar'
import Header from './components/Header'
import StatsCards from './components/StatsCards'
import LiveTrafficFeed from './components/LiveTrafficFeed'
import ThreatAlerts from './components/ThreatAlerts'
import EvidencePanel from './components/EvidencePanel'
import TrafficChart from './components/TrafficChart'
import NetworkTopology from './components/NetworkTopology'
import ThreatBreakdown from './components/ThreatBreakdown'

import TrafficView from './components/views/TrafficView'
import ThreatsView from './components/views/ThreatsView'
import EvidenceView from './components/views/EvidenceView'
import TopologyView from './components/views/TopologyView'
import AnalyticsView from './components/views/AnalyticsView'
import LogsView from './components/views/LogsView'
import SettingsView from './components/views/SettingsView'
import PcapAnalyzer from './components/PcapAnalyzer'
import LiveCapture from './components/LiveCapture'

import { useBackend } from './hooks/useBackend'
import './App.css'

function DashboardView({ packets, stats, threats, selectedThreat, setSelectedThreat, history, captureRunning }) {
  return (
    <>
      <StatsCards stats={stats} threats={threats} captureRunning={captureRunning} />
      <div className="dashboard__grid">
        <div className="dashboard__grid-main">
          <TrafficChart history={history} />
          <LiveTrafficFeed packets={packets} captureRunning={captureRunning} />
        </div>
        <div className="dashboard__grid-side">
          <ThreatBreakdown threats={threats} />
          <NetworkTopology threats={threats} />
        </div>
      </div>
      <div className="dashboard__bottom">
        <ThreatAlerts
          threats={threats}
          selectedThreat={selectedThreat}
          onSelectThreat={setSelectedThreat}
        />
        <EvidencePanel threat={selectedThreat} />
      </div>
    </>
  )
}

function App() {
  const [activeView, setActiveView] = useState('dashboard')
  const {
    connected, captureRunning, stats, threats, packets, history,
    selectedThreat, setSelectedThreat, addThreats, API_URL,
  } = useBackend()

  const criticalThreats = threats.filter(t => t.severity === 'critical')

  const renderView = () => {
    switch (activeView) {
      case 'dashboard':
        return <DashboardView packets={packets} stats={stats} threats={threats}
          selectedThreat={selectedThreat} setSelectedThreat={setSelectedThreat}
          history={history} captureRunning={captureRunning} />
      case 'traffic':
        return <TrafficView packets={packets} stats={stats} captureRunning={captureRunning} />
      case 'threats':
        return <ThreatsView threats={threats} selectedThreat={selectedThreat} onSelectThreat={setSelectedThreat} />
      case 'evidence':
        return <EvidenceView threats={threats} />
      case 'topology':
        return <TopologyView threats={threats} />
      case 'analytics':
        return <AnalyticsView threats={threats} history={history} stats={stats} />
      case 'pcap':
        return <PcapAnalyzer onThreatsDetected={addThreats} API_URL={API_URL} />
      case 'live':
        return <LiveCapture onThreatsDetected={addThreats} API_URL={API_URL} />
      case 'logs':
        return <LogsView />
      case 'settings':
        return <SettingsView stats={stats} />
      default:
        return <DashboardView packets={packets} stats={stats} threats={threats}
          selectedThreat={selectedThreat} setSelectedThreat={setSelectedThreat}
          history={history} captureRunning={captureRunning} />
    }
  }

  return (
    <div className="dashboard">
      <Sidebar
        activeView={activeView}
        onViewChange={setActiveView}
        alertCount={criticalThreats.length}
      />
      <div className="dashboard__main">
        <Header stats={stats} activeView={activeView} connected={connected} captureRunning={captureRunning} />
        <main className="dashboard__content" key={activeView}>
          {renderView()}
        </main>
      </div>
    </div>
  )
}

export default App
