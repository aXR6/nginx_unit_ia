from flask import Flask, render_template, jsonify, request, Response, stream_with_context
import requests
import json
import time
import queue
from collections import defaultdict, deque

from . import db, firewall, config
from .detection import Detector

BACKEND_URL = config.BACKEND_URL

detector = Detector()

app = Flask(__name__)

db.init_db()

# Streaming listeners and DoS tracking
log_listeners = []
REQUEST_COUNTS = defaultdict(deque)
REQUEST_WINDOW = 10  # seconds
DOS_THRESHOLD = 20


def notify_log(entry: dict) -> None:
    """Send log entry to all active listeners."""
    for q in list(log_listeners):
        try:
            q.put_nowait(entry)
        except Exception:
            pass


@app.before_request
def _analyze():
    if request.path.startswith('/logs') or request.path.startswith('/blocked') or request.path.startswith('/api/'):
        return
    result = analyze_request()
    if isinstance(result, dict) and result.get('blocked'):
        return Response('Bloqueado', status=403)


def analyze_request() -> dict:
    """Analyze the current HTTP request using the ML models."""
    payload = request.get_data(as_text=True) or ""
    full_text = f"{request.method} {request.full_path}\n{payload}"
    result = detector.analyze(full_text)
    db.save_log(
        'unit',
        full_text,
        result['severity'],
        result['anomaly'],
        result['nids'],
    )
    notify_log({
        'created_at': time.strftime('%Y-%m-%d %H:%M:%S'),
        'iface': 'unit',
        'log': full_text,
        'severity': result['severity'],
        'anomaly': result['anomaly'],
        'nids': result['nids'],
    })
    sev = str(result['severity']['label']).lower()
    anom = str(result['anomaly']['label']).lower()
    ip = request.remote_addr
    if ip:
        now = time.time()
        dq = REQUEST_COUNTS[ip]
        dq.append(now)
        while dq and dq[0] < now - REQUEST_WINDOW:
            dq.popleft()
        if len(dq) > DOS_THRESHOLD:
            if firewall.block_ip(ip):
                db.save_blocked_ip(ip, 'dos')
                return {'blocked': True}

        if sev == 'high' or anom not in ('normal', 'none'):
            if firewall.block_ip(ip):
                reason = f"{result['anomaly']['label']} / {result['severity']['label']}"
                db.save_blocked_ip(ip, reason)
                return {'blocked': True}
    return result


@app.route('/')
def index():
    return 'Nginx Unit running'

@app.route('/logs')
def logs():
    logs = db.get_logs(limit=200)
    return render_template('logs.html', title='Logs', logs=logs)


@app.route('/blocked')
def blocked():
    firewall.sync_blocked_ips_with_ufw()
    blocked = db.get_blocked_ips(limit=200)
    return render_template('blocked.html', title='IPs Bloqueados', blocked=blocked)

@app.route('/api/logs')
def api_logs():
    logs = db.get_logs(limit=200)
    serialized = [
        {
            'created_at': str(log['created_at']),
            'iface': log['iface'],
            'log': log['log'],
            'severity': log['severity'],
            'anomaly': log['anomaly'],
            'nids': log['nids'],
        }
        for log in logs
    ]
    return jsonify(serialized)


@app.route('/stream/logs')
def stream_logs():
    def generator():
        q = queue.Queue()
        log_listeners.append(q)
        try:
            while True:
                entry = q.get()
                yield f"data: {json.dumps(entry)}\n\n"
        finally:
            log_listeners.remove(q)

    return Response(stream_with_context(generator()), mimetype='text/event-stream')


@app.route('/api/blocked')
def api_blocked():
    firewall.sync_blocked_ips_with_ufw()
    blocked = db.get_blocked_ips(limit=200)
    serialized = [
        {
            'ip': item['ip'],
            'reason': item['reason'],
            'status': item['status'],
            'blocked_at': str(item['blocked_at']),
        }
        for item in blocked
    ]
    return jsonify(serialized)


def _forward(path: str):
    url = f"{BACKEND_URL}/{path}" if path else BACKEND_URL
    try:
        resp = requests.request(
            method=request.method,
            url=url,
            headers={k: v for k, v in request.headers if k.lower() != 'host'},
            params=request.args,
            data=request.get_data(),
            allow_redirects=False,
        )
    except Exception as exc:
        return Response(f"Erro ao encaminhar: {exc}", status=502)
    excluded = {'content-encoding', 'content-length', 'transfer-encoding', 'connection'}
    headers = [(k, v) for k, v in resp.headers.items() if k.lower() not in excluded]
    return Response(resp.content, resp.status_code, headers)


@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
def catch_all(path: str):
    return _forward(path)

application = app
