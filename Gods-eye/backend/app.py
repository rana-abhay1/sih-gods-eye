"""
God's Eye — Flask API Server
Provides endpoints for pcap analysis, live capture, and threat detection.
"""

import os
import time
import uuid
import json
import queue

from flask import Flask, request, jsonify, Response
from flask_cors import CORS

from threat_detector import detect_threats, parse_pcap, extract_features
from live_capture import engine as capture_engine

app = Flask(__name__)
CORS(app)

UPLOAD_DIR = os.path.join(os.path.dirname(__file__), 'uploads')
os.makedirs(UPLOAD_DIR, exist_ok=True)

# In-memory store for analysis results
analysis_store = {}


# ──────────────────────────── Health ────────────────────────────

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'ok',
        'service': 'God\'s Eye Threat Detector',
        'version': '1.0.0',
        'live_capture': capture_engine.is_running,
    })


# ──────────────────────────── PCAP File Analysis ────────────────────────────

@app.route('/api/analyze', methods=['POST'])
def analyze_pcap():
    """Upload a pcap/pcapng file for threat analysis."""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided. Send a .pcap or .pcapng file as "file".'}), 400

    file = request.files['file']
    if not file.filename:
        return jsonify({'error': 'No file selected.'}), 400

    allowed = ('.pcap', '.pcapng', '.cap')
    if not file.filename.lower().endswith(allowed):
        return jsonify({'error': f'Unsupported file type. Allowed: {", ".join(allowed)}'}), 400

    analysis_id = str(uuid.uuid4())[:8]
    safe_name = f"{analysis_id}_{file.filename}"
    file_path = os.path.join(UPLOAD_DIR, safe_name)
    file.save(file_path)

    try:
        start = time.time()
        packets = parse_pcap(file_path)
        features = extract_features(packets)
        threats = detect_threats(file_path)
        elapsed = round(time.time() - start, 3)

        result = {
            'analysis_id': analysis_id,
            'filename': file.filename,
            'status': 'completed',
            'elapsed_seconds': elapsed,
            'packet_count': len(packets),
            'features': {
                'total_packets': features.get('total_packets', 0),
                'unique_src_ips': features.get('unique_src_ips', 0),
                'unique_dst_ips': features.get('unique_dst_ips', 0),
                'unique_dst_ports': features.get('unique_dst_ports', 0),
                'total_bytes': features.get('total_bytes', 0),
                'duration': round(features.get('duration', 0), 2),
                'pps': round(features.get('pps', 0), 1),
                'protocols': features.get('protocols', {}),
                'syn_count': features.get('syn_count', 0),
                'dns_count': features.get('dns_count', 0),
            },
            'threats': threats,
            'threat_count': len(threats),
        }

        analysis_store[analysis_id] = result
        return jsonify(result)

    except Exception as e:
        return jsonify({'error': f'Analysis failed: {str(e)}', 'status': 'failed', 'analysis_id': analysis_id}), 500
    finally:
        if os.path.exists(file_path):
            os.remove(file_path)


@app.route('/api/analysis/<analysis_id>', methods=['GET'])
def get_analysis(analysis_id):
    result = analysis_store.get(analysis_id)
    if not result:
        return jsonify({'error': 'Analysis not found'}), 404
    return jsonify(result)


@app.route('/api/analysis', methods=['GET'])
def list_analyses():
    summaries = []
    for aid, result in analysis_store.items():
        summaries.append({
            'analysis_id': aid, 'filename': result['filename'],
            'threat_count': result['threat_count'], 'packet_count': result['packet_count'],
            'elapsed_seconds': result['elapsed_seconds'],
        })
    return jsonify(summaries)


# ──────────────────────────── Live Capture ────────────────────────────

@app.route('/api/capture/interfaces', methods=['GET'])
def get_interfaces():
    """List available network interfaces for capture."""
    ifaces = capture_engine.get_available_interfaces()
    return jsonify({'interfaces': ifaces, 'current': capture_engine.interface})


@app.route('/api/capture/start', methods=['POST'])
def start_capture():
    """Start live packet capture on a network interface."""
    if capture_engine.is_running:
        return jsonify({'status': 'already_running', 'interface': capture_engine.interface}), 409

    data = request.get_json(silent=True) or {}
    interface = data.get('interface')

    result = capture_engine.start(interface=interface)
    # Give the capture thread a moment to determine mode
    import time; time.sleep(0.5)
    result['sim_mode'] = capture_engine.sim_mode
    result['error'] = capture_engine.error_message
    return jsonify(result)


@app.route('/api/capture/stop', methods=['POST'])
def stop_capture():
    """Stop live packet capture."""
    result = capture_engine.stop()
    return jsonify(result)


@app.route('/api/capture/status', methods=['GET'])
def capture_status():
    """Get current capture status and stats."""
    return jsonify({
        'running': capture_engine.is_running,
        'interface': capture_engine.interface,
        'sim_mode': capture_engine.sim_mode,
        'error': capture_engine.error_message,
        'stats': capture_engine.stats,
    })


@app.route('/api/capture/stream', methods=['GET'])
def capture_stream():
    """
    SSE endpoint that streams live threats and stats.
    Connect via EventSource from the frontend.
    """
    if not capture_engine.is_running:
        return jsonify({'error': 'Capture not running. Start capture first.'}), 400

    # Create a queue for this client
    client_queue = queue.Queue(maxsize=200)

    def on_threat(data):
        """Callback invoked by the capture engine for each analysis window."""
        try:
            client_queue.put_nowait(data)
        except queue.Full:
            pass  # Drop if client is too slow

    # Register the callback
    original_callback = capture_engine._callback
    def combined_callback(data):
        if original_callback:
            original_callback(data)
        on_threat(data)
    capture_engine._callback = combined_callback

    def event_stream():
        """Generator that yields SSE events."""
        try:
            while capture_engine.is_running:
                try:
                    data = client_queue.get(timeout=2)
                    event_type = data.get('type', 'message')
                    payload = json.dumps(data)
                    yield f"event: {event_type}\ndata: {payload}\n\n"
                except queue.Empty:
                    # Send heartbeat to keep connection alive
                    yield f": heartbeat\n\n"

                # Also send periodic stats
                stats = capture_engine.stats
                yield f"event: stats\ndata: {json.dumps(stats)}\n\n"

        except GeneratorExit:
            pass
        finally:
            # Restore original callback
            capture_engine._callback = original_callback

    return Response(
        event_stream(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'X-Accel-Buffering': 'no',
            'Access-Control-Allow-Origin': '*',
        },
    )


# ──────────────────────────── Main ────────────────────────────

if __name__ == '__main__':
    print("=" * 50)
    print("  God's Eye — Threat Detection API")
    print("  Running on http://localhost:5000")
    print("  Live capture: POST /api/capture/start")
    print("=" * 50)
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
