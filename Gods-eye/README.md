# God's Eye — AI-Powered Threat Detection Dashboard

A real-time cybersecurity dashboard for passive network traffic monitoring, PCAP analysis, and AI/ML-powered threat detection. Built as an SIH (Smart India Hackathon) project.

![Status](https://img.shields.io/badge/status-active-success)
![React](https://img.shields.io/badge/react-19-blue)
![Flask](https://img.shields.io/badge/flask-3.1-purple)
![License](https://img.shields.io/badge/license-MIT-green)

---

## Overview

God's Eye is a full-stack threat detection system that combines:

- **Frontend Dashboard** — React + Vite SPA with real-time stats, threat alerts, traffic feeds, evidence panels, network topology, analytics, and more.
- **Flask API Backend** — REST endpoints for PCAP file analysis, live capture control, and Server-Sent Events (SSE) streaming.
- **AI/ML Threat Engine** — Rule-based + statistical anomaly detection over parsed pcap/pcapng files using Scapy, with confidence scoring, evidence generation, and risk scoring.
- **Live Capture** — Real-time packet sniffing via Scapy with automatic fallback to a realistic simulation mode when root/sudo access is unavailable.

---

## Features

### Dashboard
- Real-time stats cards (packet counts, threat counts, PPS, uptime)
- Live traffic feed with suspicious packet flagging
- Traffic chart with 24-hour history
- Threat breakdown and network topology visualization
- Threat alerts panel with severity-based coloring
- Evidence panel showing packet captures, log entries, NetFlow records, DNS queries, HTTP requests, and SSL certificates

### PCAP Analyzer
- Upload `.pcap` / `.pcapng` / `.cap` files for analysis
- Parsed packet features: protocol distribution, port scanning patterns, SYN ratios, payload analysis
- Multi-threat detection: Port Scanning, SYN Flood, DDoS, Brute Force, Data Exfiltration, DNS Tunneling, Malware C2, Reconnaissance
- Per-threat evidence chains with timestamps
- Analysis history and re-view capability

### Live Capture
- Select network interface for real sniffing
- Automatic fallback to simulation mode
- SSE stream delivering live threats and stats to the dashboard
- Start/stop control with status monitoring
- Real-time threat detection on sliding 10-second windows

### Threat Detection Engine
Detects the following threat types with confidence scores and evidence:

| Threat Type | Severity | Detection Method |
|---|---|---|
| Port Scanning | High/Medium | Unique port count + PPS thresholds |
| SYN Flood Attack | Critical | SYN ratio + SYN count |
| DDoS Attack | Critical | Volume-based: PPS + unique sources |
| Brute Force Attack | High/Medium | Repeated connections to auth ports (22, 23, 3389, 21, 3306, 5432) |
| Data Exfiltration | Critical | High payload ratio + large total bytes |
| DNS Tunneling | High | Excessive DNS packet ratio |
| Malware C2 Beacon | Critical | Periodic low-entropy communication patterns |
| Reconnaissance | Medium | ICMP volume + broad port probing |

---

## Project Structure

```
.
├── src/                       # React frontend
│   ├── App.jsx                # Main app with view routing
│   ├── App.css                # Global styles
│   ├── components/            # UI components
│   │   ├── Header.jsx
│   │   ├── Sidebar.jsx
│   │   ├── StatsCards.jsx
│   │   ├── LiveTrafficFeed.jsx
│   │   ├── ThreatAlerts.jsx
│   │   ├── EvidencePanel.jsx
│   │   ├── TrafficChart.jsx
│   │   ├── NetworkTopology.jsx
│   │   ├── ThreatBreakdown.jsx
│   │   ├── PcapAnalyzer.jsx
│   │   └── LiveCapture.jsx
│   ├── components/views/      # Page-level views
│   │   ├── DashboardView.jsx
│   │   ├── TrafficView.jsx
│   │   ├── ThreatsView.jsx
│   │   ├── EvidenceView.jsx
│   │   ├── TopologyView.jsx
│   │   ├── AnalyticsView.jsx
│   │   ├── LogsView.jsx
│   │   ├── SettingsView.jsx
│   │   └── ...
│   ├── hooks/
│   │   ├── useBackend.js      # API communication + SSE
│   │   └── useSimulation.js
│   └── data/
│       └── threats.js          # Mock threat data generators
├── backend/                   # Flask API server
│   ├── app.py                 # REST API + SSE endpoints
│   ├── threat_detector.py     # PCAP parsing + threat classification
│   ├── live_capture.py        # Live sniffing engine + simulation
│   └── requirements.txt
├── package.json
├── vite.config.js
├── .oxlintrc.json
└── README.md
```

---

## Getting Started

### Prerequisites

- **Node.js** 18+ (for the React frontend)
- **Python** 3.9+ (for the Flask backend)
- **pip** for Python package installation

### 1. Install Backend Dependencies

```bash
cd backend
pip install -r requirements.txt
```

> **Note on Scapy:** Live packet capture requires root/sudo privileges. Without them, the engine automatically falls back to simulation mode, so the app still works fully for demo purposes.

### 2. Install Frontend Dependencies

```bash
npm install
```

### 3. Run the Backend

```bash
cd backend
python app.py
```

The API server starts on **http://localhost:5000**.

### 4. Run the Frontend (in a separate terminal)

```bash
npm run dev
```

Vite's dev server typically starts on **http://localhost:5173**.

### 5. Open the Dashboard

Navigate to the Vite dev URL in your browser. The frontend connects to the backend automatically.

If the backend is on a different host/port, set the `VITE_API_URL` environment variable:

```bash
VITE_API_URL=http://localhost:5000 npm run dev
```

---

## API Endpoints

### Health

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/health` | Service health, version, live capture status |

### PCAP Analysis

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/analyze` | Upload a pcap/pcapng file for threat analysis (multipart `file` field) |
| `GET` | `/api/analysis/:id` | Fetch a previously completed analysis by ID |
| `GET` | `/api/analysis` | List all completed analyses (id, filename, threat count, packet count, elapsed time) |

**Analyze response** includes: `analysis_id`, `filename`, `status`, `elapsed_seconds`, `packet_count`, `features` (total packets, unique IPs, ports, bytes, duration, PPS, protocol breakdown, SYN/DNS counts), `threats` array, and `threat_count`.

### Live Capture

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/capture/interfaces` | List available network interfaces + current interface |
| `POST` | `/api/capture/start` | Start capture (JSON body: `{ "interface": "eth0" }`). Returns status, interface, mode. |
| `POST` | `/api/capture/stop` | Stop capture. Returns final stats. |
| `GET` | `/api/capture/status` | Current running state, interface, sim mode, error message, stats |
| `GET` | `/api/capture/stream` | **SSE endpoint** — streams `threats` and `stats` events in real time |

**SSE Events:**

- `event: threats` — batch of detected threats for the current analysis window
- `event: stats` — current capture statistics (packet counts, PPS, unique IPs, protocols)

---

## Threat Detection Details

The engine works in two modes:

### File Analysis (`/api/analyze`)
1. Parse the pcap with Scapy → structured `PacketInfo` list
2. Extract statistical features (counters, ratios, rates, distributions)
3. Run 8 heuristic classifiers with confidence weighting
4. Return threats with evidence details and risk scores

### Live Capture (`/api/capture/stream`)
1. Sniff packets in real time (or generate simulated packets)
2. Buffer packets in a sliding 10-second window
3. On each window expiration, extract features and run lightweight threat detection
4. Push threats and stats to all connected SSE clients

**Confidence scoring** combines a base weight per threat type with indicator bonuses (packet rate > 100 pps, unique ports > 10, etc.), capped at 0.99.

---

## Frontend Architecture

- **React 19** with functional components and hooks
- **Vite** for fast HMR dev server and optimized builds
- **Custom hook** `useBackend` handles API calls, SSE connection lifecycle, threat state, and packet history
- **Views** are swapped via a `activeView` state string; the sidebar drives navigation
- **Mock data generators** in `src/data/threats.js` provide realistic initial state and traffic simulation when the backend is offline

---

## Views

| View | Description |
|---|---|
| **Dashboard** | Overview grid: stats, traffic chart, live feed, threat breakdown, topology, alerts, evidence |
| **Traffic** | Focused live traffic monitor |
| **Threats** | Threat management list with selection and detail |
| **Evidence** | Evidence chain viewer |
| **Topology** | Network topology visualization |
| **Analytics** | Analytics & insights across threats and history |
| **PCAP Analyzer** | File upload and analysis interface |
| **Live Capture** | Interface selection and capture control |
| **Logs** | System logs view |
| **Settings** | Settings panel |

---

## Demo Mode

If the backend is unreachable, the frontend falls back to simulated traffic and mock threats generated from `src/data/threats.js`. This lets you explore the full UI without running the Flask server.

To run live capture without root, the backend automatically uses simulation mode — packets are generated with realistic distributions and the same detection pipeline runs over them.

---

## Configuration

### Backend (`backend/app.py`)

- `UPLOAD_DIR` — temporary directory for uploaded pcap files (auto-created, cleaned up after analysis)
- `analysis_store` — in-memory store for analysis results (lost on restart)
- Flask runs on `0.0.0.0:5000` by default

### Live Capture (`backend/live_capture.py`)

- `WINDOW_SECONDS = 10` — analysis window duration
- `MAX_BUFFER_SIZE = 50000` — max buffered packets per window
- `SIM_PACKETS_PER_SEC = 80` — simulated packet generation rate

### Threat Detector (`backend/threat_detector.py`)

- `KNOWN_PORTS` — port-to-service mapping
- `SUSPICIOUS_PORTS` — well-known bad ports
- `ML_CONFIDENCE_WEIGHTS` — base confidence per threat type

---

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | React 19, Vite, Oxlint |
| Styling | Custom CSS (App.css) |
| Backend | Flask 3.1, Flask-CORS |
| Packet Parsing | Scapy 2.5 |
| Numeric | NumPy 2.2, scikit-learn 1.6 |
| Model Persistence | joblib 1.5 |

---

## Scripts

```bash
# Frontend
npm run dev      # Start Vite dev server
npm run build    # Production build
npm run preview  # Preview production build
npm run lint     # Run Oxlint

# Backend
python app.py                    # Run Flask dev server
python threat_detector.py file.pcap   # Standalone pcap analysis
```

---

## Standalone PCAP Analysis

You can run the threat detector directly from the command line without the Flask server:

```bash
cd backend
python threat_detector.py path/to/capture.pcap
```

Output is a JSON array of detected threats with full evidence.

---

## Threat Types & Severity Levels

| Severity | Color | Description |
|---|---|---|
| Critical | Red | Immediate response required (DDoS, exfiltration, C2, ransomware) |
| High | Orange | Significant threat (port scanning, brute force, DNS tunneling) |
| Medium | Yellow | Suspicious activity (recon, SQL injection, XSS) |
| Low | Green | Informational / normal |

---

## Limitations

- **No GeoIP:** Country mapping is a placeholder. Integrate GeoIP2 for real geo-lookups.
- **In-memory store:** Analysis results are not persisted across backend restarts.
- **Simulation mode:** Without root, live capture uses generated packets — useful for demo but not real traffic.
- **Heuristic-based:** The detector uses rule-based heuristics with statistical boosts, not a trained neural network. Confidence weights are tunable constants.
- **No authentication:** The API has no auth layer. Add one for production use.

---

## Future Improvements

- Integrate a trained ML model (scikit-learn / TensorFlow) for classification
- Add GeoIP2 for source country detection
- Persist analysis results to a database (SQLite/PostgreSQL)
- Add user authentication and role-based access
- Support for pcapNG metadata and TLS handshakes
- Real-time collaboration / multi-user SOC dashboards
- Alert export (CSV, PDF) and scheduled reporting
- Integration with SIEM systems via syslog or webhook

---

## Development

### Running the linter

```bash
npm run lint
```

Oxlint is configured via `.oxlintrc.json` at the project root.

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `VITE_API_URL` | `http://localhost:5000` | Frontend API base URL |

---

## License

MIT — see the project root for the license file.

---

Built as part of the **Smart India Hackathon (SIH)** — a cybersecurity operations dashboard for passive traffic monitoring and AI-assisted threat detection.
