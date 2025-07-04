from flask import Flask, render_template, jsonify
from . import db

app = Flask(__name__)

db.init_db()

@app.route('/')
def index():
    return 'Nginx Unit running'

@app.route('/logs')
def logs():
    logs = db.get_logs(limit=200)
    return render_template('logs.html', logs=logs)

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

application = app
