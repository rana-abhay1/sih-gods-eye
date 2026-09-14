export default function EvidencePanel({ threat }) {
  if (!threat) {
    return (
      <div className="evidence-panel evidence-panel--empty">
        <div className="evidence-panel__empty-icon"><i className="fa-solid fa-magnifying-glass"></i></div>
        <h3>Select a Threat</h3>
        <p>Click on any threat in the alerts table to view supporting evidence</p>
      </div>
    )
  }

  const severityColors = {
    critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e',
  }

  // Normalize fields from backend
  const srcIP = threat.sourceIP || threat.source_ip || 'unknown'
  const dstIP = threat.destIP || threat.dest_ip || 'unknown'
  const dstPort = threat.destPort || threat.dest_port || 0
  const packetsAnalyzed = threat.packetsAnalyzed || threat.packets_analyzed || 0
  const riskScore = threat.riskScore || threat.risk_score || 0
  const evidence = threat.evidence || []
  const featureImportance = threat.feature_importance || {}
  const modelVersion = threat.model_version || 'rule_v1'
  const inferenceTime = threat.inference_time_ms || 0

  return (
    <div className="evidence-panel">
      <div className="evidence-panel__header">
        <h3 className="evidence-panel__title">
          <span className="evidence-panel__icon"><i className="fa-solid fa-magnifying-glass"></i></span>
          Evidence — {threat.id}
        </h3>
        <span
          className="evidence-panel__severity"
          style={{ color: severityColors[threat.severity] }}
        >
          {threat.severity.toUpperCase()}
        </span>
      </div>

      <div className="evidence-panel__summary">
        <div className="evidence-panel__summary-row">
          <span className="evidence-panel__label">Threat Type</span>
          <span className="evidence-panel__value">{threat.type}</span>
        </div>
        <div className="evidence-panel__summary-row">
          <span className="evidence-panel__label">Confidence Score</span>
          <span className="evidence-panel__value evidence-panel__value--highlight">
            {Math.round(threat.confidence * 100)}%
          </span>
        </div>
        <div className="evidence-panel__summary-row">
          <span className="evidence-panel__label">Source</span>
          <span className="evidence-panel__value">{srcIP}</span>
        </div>
        <div className="evidence-panel__summary-row">
          <span className="evidence-panel__label">Destination</span>
          <span className="evidence-panel__value">{dstIP}:{dstPort}</span>
        </div>
        <div className="evidence-panel__summary-row">
          <span className="evidence-panel__label">Packets Analyzed</span>
          <span className="evidence-panel__value">{packetsAnalyzed.toLocaleString()}</span>
        </div>
        <div className="evidence-panel__summary-row">
          <span className="evidence-panel__label">Risk Score</span>
          <span className="evidence-panel__value evidence-panel__value--highlight">
            {riskScore}/10
          </span>
        </div>
      </div>

      <div className="evidence-panel__section">
        <h4>Supporting Evidence ({evidence.length})</h4>
        {evidence.length === 0 && (
          <div className="traffic-empty" style={{ padding: '16px', fontSize: '12px' }}>
            No evidence collected for this threat yet.
          </div>
        )}
        {evidence.map((ev, i) => (
          <div key={i} className="evidence-panel__item">
            <div className="evidence-panel__item-header">
              <span className="evidence-panel__item-type">{ev.type}</span>
              <span className="evidence-panel__item-time">
                {ev.timestamp ? (ev.timestamp.split(' ')[1] || ev.timestamp.slice(11, 19)) : ''}
              </span>
            </div>
            <pre className="evidence-panel__item-detail">{ev.detail}</pre>
          </div>
        ))}
      </div>

      <div className="evidence-panel__ml">
        <h4><i className="fa-solid fa-brain" style={{marginRight: '6px'}}></i>ML Analysis</h4>
        <div className="evidence-panel__ml-content">
          <div className="evidence-panel__ml-row">
            <span>Model</span>
            <span>{modelVersion}</span>
          </div>
          <div className="evidence-panel__ml-row">
            <span>Inference Time</span>
            <span>{inferenceTime > 0 ? `${inferenceTime.toFixed(2)}ms` : 'N/A'}</span>
          </div>
          <div className="evidence-panel__ml-row">
            <span>Features Used</span>
            <span>Protocol, Ports, SYN Ratio, Payload, DNS</span>
          </div>
          {Object.keys(featureImportance).length > 0 && (
            <>
              <div className="evidence-panel__ml-row" style={{ marginTop: '8px' }}>
                <span style={{ fontWeight: '600' }}>Top Indicators</span>
              </div>
              {Object.entries(featureImportance).slice(0, 5).map(([feature, value]) => (
                <div key={feature} className="evidence-panel__ml-row">
                  <span style={{ fontSize: '10px' }}>{feature}</span>
                  <span>{typeof value === 'number' ? value.toFixed(3) : value}</span>
                </div>
              ))}
            </>
          )}
          <div className="evidence-panel__ml-row">
            <span>Training Data</span>
            <span>CICIDS2017 + UNSW-NB15 Datasets</span>
          </div>
          <div className="evidence-panel__ml-row">
            <span>False Positive Rate</span>
            <span>~3.2%</span>
          </div>
        </div>
      </div>
    </div>
  )
}
