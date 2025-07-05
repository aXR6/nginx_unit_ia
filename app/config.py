import os
from dotenv import load_dotenv

load_dotenv()

POSTGRES_USER = os.getenv('POSTGRES_USER')
POSTGRES_PASSWORD = os.getenv('POSTGRES_PASSWORD')
POSTGRES_DB = os.getenv('POSTGRES_DB')
POSTGRES_HOST = os.getenv('POSTGRES_HOST')
POSTGRES_PORT = int(os.getenv('POSTGRES_PORT', 5432))

SEMANTIC_MODEL = os.getenv('SEMANTIC_MODEL')
SEVERITY_MODEL = os.getenv('SEVERITY_MODEL')
ANOMALY_MODEL = os.getenv('ANOMALY_MODEL')
NIDS_MODEL = os.getenv('NIDS_MODEL')

SEMANTIC_THRESHOLD = float(os.getenv('SEMANTIC_THRESHOLD', '0.5'))

DEVICE = os.getenv('DEVICE', 'cpu')
WEB_PANEL_PORT = int(os.getenv('WEB_PANEL_PORT', '8080'))
UNIT_PORT = int(os.getenv('UNIT_PORT', '8090'))
BACKEND_URL = os.getenv('BACKEND_URL', 'http://hello:8000')
LOG_FILE = os.getenv('LOG_FILE', 'app.log')
