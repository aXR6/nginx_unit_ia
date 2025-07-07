import os
from dotenv import load_dotenv

load_dotenv()

POSTGRES_USER = os.getenv('POSTGRES_USER')
POSTGRES_PASSWORD = os.getenv('POSTGRES_PASSWORD')
POSTGRES_DB = os.getenv('POSTGRES_DB')
POSTGRES_HOST = os.getenv('POSTGRES_HOST')
POSTGRES_PORT = int(os.getenv('POSTGRES_PORT', 5432))

# Optional Elasticsearch settings
ES_HOST = os.getenv('ES_HOST')
ES_USER = os.getenv('ES_USER')
ES_PASSWORD = os.getenv('ES_PASSWORD')

# Model identifiers are defined only via environment variables
# Provide sensible defaults so the application can start even when the
# environment file is missing. These match the values defined in
# ``.env.example`` and allow running the container without additional
# configuration.
SEMANTIC_MODEL = os.getenv(
    'SEMANTIC_MODEL', 'sentence-transformers/all-MiniLM-L6-v2'
)
SEVERITY_MODEL = os.getenv(
    'SEVERITY_MODEL', 'byviz/bylastic_classification_logs'
)
ANOMALY_MODEL = os.getenv(
    'ANOMALY_MODEL', 'teoogherghi/Log-Analysis-Model-DistilBert'
)
# Allow a list of NIDS models to be configured. If ``NIDS_MODELS`` is not
# provided, fall back to ``NIDS_MODEL`` or a sensible default.
NIDS_MODELS = [
    s.strip()
    for s in os.getenv(
        'NIDS_MODELS',
        'maleke01/RoBERTa-WebAttack,Canstralian/CyberAttackDetection,maheshj01/sql-injection-classifier,Dumi2025/log-anomaly-detection-model-roberta',
    ).split(',')
    if s.strip()
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

# If ``LOG_FILE`` is a relative path, place it inside the application
# directory so the Unit process has permission to write the file. When the
# application runs inside the official ``nginx/unit`` container, the current
# working directory is ``/`` which would place the log file at the root where
# the unprivileged ``unit`` user lacks write permissions.  Prefixing the path
# with the directory of this configuration file ensures it resolves to a
# writable location (``/www/app`` when using docker-compose).
if LOG_FILE and not os.path.isabs(LOG_FILE):
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    LOG_FILE = os.path.join(BASE_DIR, LOG_FILE)
UNIT_BACKEND_PORT = int(os.getenv('UNIT_BACKEND_PORT', '18080'))
