import os
from dotenv import load_dotenv

load_dotenv()

POSTGRES_USER = os.getenv('POSTGRES_USER')
POSTGRES_PASSWORD = os.getenv('POSTGRES_PASSWORD')
POSTGRES_DB = os.getenv('POSTGRES_DB')
POSTGRES_HOST = os.getenv('POSTGRES_HOST')
POSTGRES_PORT = int(os.getenv('POSTGRES_PORT', 5432))

# Model identifiers are defined only via environment variables
SEMANTIC_MODEL = os.getenv('SEMANTIC_MODEL')
SEVERITY_MODEL = os.getenv('SEVERITY_MODEL')
ANOMALY_MODEL = os.getenv('ANOMALY_MODEL')
# Allow a list of NIDS models to be configured. If ``NIDS_MODELS`` is not
# provided, fall back to ``NIDS_MODEL`` or a sensible default.
NIDS_MODELS = [
    s.strip() for s in os.getenv('NIDS_MODELS', '').split(',') if s.strip()
]

# Backwards compatibility with the old ``NIDS_MODEL`` variable. The first model
# in ``NIDS_MODELS`` is treated as the primary one.
NIDS_MODEL = os.getenv('NIDS_MODEL', NIDS_MODELS[0] if NIDS_MODELS else None)

# Base model to use when a NIDS entry provides only LoRA adapters
NIDS_BASE_MODEL = os.getenv('NIDS_BASE_MODEL')

SEMANTIC_THRESHOLD = float(os.getenv('SEMANTIC_THRESHOLD', '0.5'))
BLOCK_SEVERITY_LEVELS = [s.strip().lower() for s in os.getenv('BLOCK_SEVERITY_LEVELS', 'error,high').split(',')]
BLOCK_ANOMALY_THRESHOLD = float(os.getenv('BLOCK_ANOMALY_THRESHOLD', '0.5'))

DEVICE = os.getenv('DEVICE', 'cpu')
WEB_PANEL_PORT = int(os.getenv('WEB_PANEL_PORT', '8080'))
UNIT_PORT = int(os.getenv('UNIT_PORT', '8090'))
BACKEND_URL = os.getenv('BACKEND_URL', 'http://hello:8000')
LOG_FILE = os.getenv('LOG_FILE', 'app.log')
UNIT_BACKEND_PORT = int(os.getenv('UNIT_BACKEND_PORT', '18080'))
