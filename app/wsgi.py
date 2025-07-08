from flask import Flask, render_template, jsonify, request, Response, stream_with_context
import requests
import json
import time
from collections import defaultdict, deque
import logging

from .logging_setup import configure_logging

configure_logging()
logger = logging.getLogger(__name__)

from . import db, firewall, config, events, es
from .detection import Detector
from . import detection

BACKEND_URL = config.BACKEND_URL

detector = Detector()

app = Flask(__name__)

db.init_db()


def _sync_initial_blocked() -> None:
    """Ensure database reflects current UFW state on startup."""
    firewall.sync_blocked_ips_with_ufw()

# ``before_first_request`` was removed in Flask 3.x. Call the function once
# during startup instead of registering it as a hook.
_sync_initial_blocked()

# Streaming listeners and DoS tracking
REQUEST_COUNTS = defaultdict(deque)
REQUEST_WINDOW = 10  # seconds
DOS_THRESHOLD = 20


def _is_attack(label: str) -> bool:
    """Return True if the given label indicates an attack."""
    return str(label).lower() not in ("normal", "benign", "none")


@app.before_request
def _analyze():
    if (
        request.path.startswith('/logs')
        or request.path.startswith('/blocked')
        or request.path.startswith('/api/')
        or request.path.startswith('/stream/')
    ):
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
    category = result['nids'].get('majority', result['nids']['label'])
    logger.info(
        "Detection result - severity: %s, anomaly: %s, nids: %s",
        result['severity']['label'],
        result['anomaly']['label'],
        result['nids']['label'],
    )
    saved = db.save_log(
        'unit',
        full_text,
        result['severity'],
        result['anomaly'],
        result['nids'],
        result['semantic'],
        ip=ip,
        ip_info=ip_info,
    )
    created_at = time.strftime('%Y-%m-%d %H:%M:%S')
    log_id = None
    if saved:
        log_id, created_at_dt = saved
        if hasattr(created_at_dt, "strftime"):
            created_at = created_at_dt.strftime("%Y-%m-%d %H:%M:%S")
        else:
            created_at = str(created_at_dt)
    events.notify_log({
        'id': log_id,
        'created_at': created_at,
        'iface': 'unit',
        'log': full_text,
        'ip': ip,
        'ip_info': ip_info,
        'severity': result['severity'],
        'anomaly': result['anomaly'],
        'nids': result['nids'],
        'category': category,
        'is_attack': _is_attack(category),
        'semantic': result['semantic'],
        'intensity': result['intensity'],
    })
    es.index_log({
        'id': log_id,
        'created_at': created_at,
        'iface': 'unit',
        'log': full_text,
        'ip': ip,
        'ip_info': ip_info,
        'severity': result['severity'],
        'anomaly': result['anomaly'],
        'nids': result['nids'],
        'category': category,
        'is_attack': _is_attack(category),
        'semantic': result['semantic'],
        'intensity': result['intensity'],
    })
    sev = str(result['severity']['label']).lower()
    anom = str(result['anomaly']['label']).lower()
    anom_score = max(result['anomaly']['score']) if result['anomaly']['score'] else 0.0
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
                db.save_blocked_ip(ip, 'dos', ip_info=ip_info)
                events.notify_blocked({
                    'ip': ip,
                    'reason': 'dos',
                    'status': 'blocked',
                    'blocked_at': time.strftime('%Y-%m-%d %H:%M:%S')
                    ,'ip_info': ip_info,
                })
                es.index_blocked_ip({
                    'ip': ip,
                    'reason': 'dos',
                    'status': 'blocked',
                    'blocked_at': time.strftime('%Y-%m-%d %H:%M:%S'),
                    'ip_info': ip_info,
                })
                return {'blocked': True}

        block_by_sev = sev in config.BLOCK_SEVERITY_LEVELS
        block_by_anom = (
            anom not in ('normal', 'none')
            and sem_outlier
            and anom_score >= config.BLOCK_ANOMALY_THRESHOLD
        )
        if block_by_sev or block_by_anom:
            if firewall.block_ip(ip):
                reason = f"{result['anomaly']['label']} / {result['severity']['label']}"
                logger.warning("IP %s blocked: %s", ip, reason)
                db.save_blocked_ip(ip, reason, ip_info=ip_info)
                events.notify_blocked({
                    'ip': ip,
                    'reason': reason,
                    'status': 'blocked',
                    'blocked_at': time.strftime('%Y-%m-%d %H:%M:%S'),
                    'ip_info': ip_info,
                })
                es.index_blocked_ip({
                    'ip': ip,
                    'reason': reason,
                    'status': 'blocked',
                    'blocked_at': time.strftime('%Y-%m-%d %H:%M:%S'),
                    'ip_info': ip_info,
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
    filtered = []
    for item in logs:
        item['category'] = item['nids'].get('majority', item['nids']['label'])
        item['is_attack'] = _is_attack(item['category'])
        item['intensity'] = detection.calculate_intensity(
            item['severity']['label'],
            item['anomaly']['score'],
            item.get('semantic', {}).get('similarity', 1.0),
        )
        if item['is_attack']:
            filtered.append(item)
    models = {
        'severity': config.SEVERITY_MODEL,
        'anomaly': config.ANOMALY_MODEL,
        'nids': ', '.join(config.NIDS_MODELS),
        'semantic': config.SEMANTIC_MODEL,
    }
    return render_template('logs.html', title='Logs de Ameaças', logs=filtered, page=page, models=models)


@app.route('/common-logs')
def common_logs():
    page = int(request.args.get('page', '1'))
    logs = db.get_logs(limit=100, offset=(page - 1) * 100)
    filtered = []
    for item in logs:
        item['category'] = item['nids'].get('majority', item['nids']['label'])
        item['is_attack'] = _is_attack(item['category'])
        item['intensity'] = detection.calculate_intensity(
            item['severity']['label'],
            item['anomaly']['score'],
            item.get('semantic', {}).get('similarity', 1.0),
        )
        if not item['is_attack']:
            filtered.append(item)
    models = {
        'severity': config.SEVERITY_MODEL,
        'anomaly': config.ANOMALY_MODEL,
        'nids': ', '.join(config.NIDS_MODELS),
        'semantic': config.SEMANTIC_MODEL,
    }
    return render_template('logs.html', title='Logs Comuns', logs=filtered, page=page, models=models)


@app.route('/log/<int:log_id>')
def log_detail(log_id: int):
    log = db.get_log(log_id)
    if not log:
        return 'Log não encontrado', 404
    log['category'] = log['nids'].get('majority', log['nids']['label'])
    log['is_attack'] = _is_attack(log['category'])
    intensity = detection.calculate_intensity(
        log['severity']['label'],
        log['anomaly']['score'],
        log.get('semantic', {}).get('similarity', 1.0),
    )
    if log.get('ip') and not log.get('ip_info'):
        from .ipinfo import fetch_ip_info
        ip_info = fetch_ip_info(log['ip'])
        if ip_info:
            log['ip_info'] = ip_info
    return render_template('log_detail.html', title='Detalhes do Log', log=log, intensity=intensity)


@app.route('/blocked')
def blocked():
    page = int(request.args.get('page', '1'))
    firewall.sync_blocked_ips_with_ufw()
    blocked = db.get_blocked_ips(limit=100, offset=(page - 1) * 100)
    models = {
        'severity': config.SEVERITY_MODEL,
        'anomaly': config.ANOMALY_MODEL,
        'nids': ', '.join(config.NIDS_MODELS),
        'semantic': config.SEMANTIC_MODEL,
    }
    return render_template('blocked.html', title='Quarentena de IPs', blocked=blocked, page=page, models=models)


@app.route('/blocked/<ip>')
def blocked_detail(ip: str):
    item = db.get_blocked_ip(ip)
    if not item:
        return 'IP não encontrado', 404
    logs = db.get_logs_by_ip(ip)
    ip_info = item.get('ip_info')
    if not ip_info:
        from .ipinfo import fetch_ip_info
        ip_info = fetch_ip_info(ip)
    models = {
        'severity': config.SEVERITY_MODEL,
        'anomaly': config.ANOMALY_MODEL,
        'nids': ', '.join(config.NIDS_MODELS),
        'semantic': config.SEMANTIC_MODEL,
    }
    return render_template(
        'blocked_detail.html',
        title='IP Quarentenado',
        item=item,
        logs=logs,
        ip_info=ip_info,
        models=models,
    )


@app.route('/unblock/<ip>', methods=['POST'])
def unblock_ip_route(ip: str):
    if firewall.unblock_ip(ip):
        db.unblock_ip(ip)
        events.notify_blocked({
            'ip': ip,
            'reason': 'manual',
            'status': 'unblocked',
            'blocked_at': time.strftime('%Y-%m-%d %H:%M:%S')
        })
        es.index_blocked_ip({
            'ip': ip,
            'reason': 'manual',
            'status': 'unblocked',
            'blocked_at': time.strftime('%Y-%m-%d %H:%M:%S')
        })
    return ('', 204)


@app.route('/api/unblock/<ip>', methods=['POST'])
def api_unblock(ip: str):
    if firewall.unblock_ip(ip):
        db.unblock_ip(ip)
        events.notify_blocked({
            'ip': ip,
            'reason': 'manual',
            'status': 'unblocked',
            'blocked_at': time.strftime('%Y-%m-%d %H:%M:%S')
        })
        es.index_blocked_ip({
            'ip': ip,
            'reason': 'manual',
            'status': 'unblocked',
            'blocked_at': time.strftime('%Y-%m-%d %H:%M:%S')
        })
    return ('', 204)

@app.route('/api/logs')
def api_logs():
    page = int(request.args.get('page', '1'))
    logs = db.get_logs(limit=100, offset=(page - 1) * 100)
    serialized = []
    for log in logs:
        intensity = detection.calculate_intensity(
            log['severity']['label'],
            log['anomaly']['score'],
            log.get('semantic', {}).get('similarity', 1.0),
        )
        serialized.append({
            'id': log.get('id'),
            'created_at': str(log['created_at']),
            'iface': log['iface'],
            'log': log['log'],
            'ip': log.get('ip'),
            'ip_info': log.get('ip_info'),
            'severity': log['severity'],
            'anomaly': log['anomaly'],
            'nids': log['nids'],
            'category': log['nids'].get('majority', log['nids']['label']),
            'is_attack': _is_attack(log['nids'].get('majority', log['nids']['label'])),
            'semantic': log.get('semantic'),
            'intensity': intensity,
        })
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
            'ip_info': item.get('ip_info'),
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
            timeout=5,
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
