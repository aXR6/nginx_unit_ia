from flask import Flask, render_template, jsonify
from . import db, firewall

app = Flask(__name__)

db.init_db()

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

application = app
