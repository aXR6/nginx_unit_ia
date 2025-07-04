from flask import Flask, render_template
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

application = app
