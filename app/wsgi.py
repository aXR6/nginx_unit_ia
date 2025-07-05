from flask import Flask, render_template, jsonify, request, Response, stream_with_context
import requests
import json
import time
from collections import defaultdict, deque
import logging

from .logging_setup import configure_logging

configure_logging()
logger = logging.getLogger(__name__)

from . import db, firewall, config, events
from .detection import Detector

BACKEND_URL = config.BACKEND_URL

detector = Detector()

app = Flask(__name__)

db.init_db()

# Streaming listeners and DoS tracking
REQUEST_COUNTS = defaultdict(deque)
REQUEST_WINDOW = 10  # seconds
DOS_THRESHOLD = 20


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
    ip = request.remote_addr
    logger.info("Analyzing request from %s", ip or "unknown")
    ip_info = None
    if ip:
        from .ipinfo import fetch_ip_info
        ip_info = fetch_ip_info(ip)
    result = detector.analyze(full_text)
    logger.info(
        "Detection result - severity: %s, anomaly: %s, nids: %s",
        result['severity']['label'],
        result['anomaly']['label'],
        result['nids']['label'],
    )
    db.save_log(
        'unit',
        full_text,
        result['severity'],
        result['anomaly'],
        result['nids'],
        result['semantic'],
        ip=ip,
        ip_info=ip_info,
    )
    events.notify_log({
        'created_at': time.strftime('%Y-%m-%d %H:%M:%S'),
        'iface': 'unit',
        'log': full_text,
        'ip': ip,
        'ip_info': ip_info,
        'severity': result['severity'],
        'anomaly': result['anomaly'],
        'nids': result['nids'],
        'semantic': result['semantic'],
    })
    sev = str(result['severity']['label']).lower()
    anom = str(result['anomaly']['label']).lower()
    sem_outlier = bool(result.get('semantic', {}).get('outlier'))
    if ip:
        now = time.time()
        dq = REQUEST_COUNTS[ip]
        dq.append(now)
        while dq and dq[0] < now - REQUEST_WINDOW:
            dq.popleft()
        if len(dq) > DOS_THRESHOLD:
            if firewall.block_ip(ip):
                logger.warning("IP %s blocked due to DoS detection", ip)
                db.save_blocked_ip(ip, 'dos')
                events.notify_blocked({
                    'ip': ip,
                    'reason': 'dos',
                    'status': 'blocked',
                    'blocked_at': time.strftime('%Y-%m-%d %H:%M:%S')
                })
                return {'blocked': True}

        if sev in ('error', 'high') or (anom not in ('normal', 'none') and sem_outlier):
            if firewall.block_ip(ip):
                reason = f"{result['anomaly']['label']} / {result['severity']['label']}"
                logger.warning("IP %s blocked: %s", ip, reason)
                db.save_blocked_ip(ip, reason)
                events.notify_blocked({
                    'ip': ip,
                    'reason': reason,
                    'status': 'blocked',
                    'blocked_at': time.strftime('%Y-%m-%d %H:%M:%S')
                })
                return {'blocked': True}
    return result


@app.route('/')
def index():
    return 'Nginx Unit running'

@app.route('/logs')
def logs():
    page = int(request.args.get('page', '1'))
    logs = db.get_logs(limit=100, offset=(page - 1) * 100)
    models = {
        'severity': config.SEVERITY_MODEL,
        'anomaly': config.ANOMALY_MODEL,
        'nids': config.NIDS_MODEL,
        'semantic': config.SEMANTIC_MODEL,
    }
    return render_template('logs.html', title='Logs', logs=logs, page=page, models=models)


@app.route('/blocked')
def blocked():
    page = int(request.args.get('page', '1'))
    firewall.sync_blocked_ips_with_ufw()
    blocked = db.get_blocked_ips(limit=100, offset=(page - 1) * 100)
    models = {
        'severity': config.SEVERITY_MODEL,
        'anomaly': config.ANOMALY_MODEL,
        'nids': config.NIDS_MODEL,
        'semantic': config.SEMANTIC_MODEL,
    }
    return render_template('blocked.html', title='IPs Bloqueados', blocked=blocked, page=page, models=models)

@app.route('/api/logs')
def api_logs():
    page = int(request.args.get('page', '1'))
    logs = db.get_logs(limit=100, offset=(page - 1) * 100)
    serialized = [
        {
            'created_at': str(log['created_at']),
            'iface': log['iface'],
            'log': log['log'],
            'ip': log.get('ip'),
            'ip_info': log.get('ip_info'),
            'severity': log['severity'],
            'anomaly': log['anomaly'],
            'nids': log['nids'],
            'semantic': log.get('semantic'),
        }
        for log in logs
    ]
    return jsonify(serialized)


@app.route('/stream/logs')
def stream_logs():
    def generator():
        q = events.register_log_listener()
        try:
            while True:
                entry = q.get()
                yield f"data: {json.dumps(entry)}\n\n"
        finally:
            events.unregister_log_listener(q)

    return Response(stream_with_context(generator()), mimetype='text/event-stream')


@app.route('/stream/blocked')
def stream_blocked():
    def generator():
        q = events.register_blocked_listener()
        try:
            while True:
                entry = q.get()
                yield f"data: {json.dumps(entry)}\n\n"
        finally:
            events.unregister_blocked_listener(q)

    return Response(stream_with_context(generator()), mimetype='text/event-stream')


@app.route('/api/blocked')
def api_blocked():
    page = int(request.args.get('page', '1'))
    firewall.sync_blocked_ips_with_ufw()
    blocked = db.get_blocked_ips(limit=100, offset=(page - 1) * 100)
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
