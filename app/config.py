import os
from dotenv import load_dotenv

load_dotenv()

POSTGRES_USER = os.getenv('POSTGRES_USER')
POSTGRES_PASSWORD = os.getenv('POSTGRES_PASSWORD')
POSTGRES_DB = os.getenv('POSTGRES_DB')
POSTGRES_HOST = os.getenv('POSTGRES_HOST')
POSTGRES_PORT = int(os.getenv('POSTGRES_PORT', 5432))

# Provide sensible defaults for the HuggingFace model identifiers so the
# application can run even if environment variables are missing.
SEMANTIC_MODEL = os.getenv(
    'SEMANTIC_MODEL', 'sentence-transformers/all-MiniLM-L6-v2'
)
SEVERITY_MODEL = os.getenv(
    'SEVERITY_MODEL', 'byviz/bylastic_classification_logs'
)
ANOMALY_MODEL = os.getenv(
    'ANOMALY_MODEL', 'teoogherghi/Log-Analysis-Model-DistilBert'
)
NIDS_MODEL = os.getenv(
    'NIDS_MODEL', 'Dumi2025/log-anomaly-detection-model-roberta'
)

SEMANTIC_THRESHOLD = float(os.getenv('SEMANTIC_THRESHOLD', '0.5'))
BLOCK_SEVERITY_LEVELS = [s.strip().lower() for s in os.getenv('BLOCK_SEVERITY_LEVELS', 'error,high').split(',')]
BLOCK_ANOMALY_THRESHOLD = float(os.getenv('BLOCK_ANOMALY_THRESHOLD', '0.5'))

DEVICE = os.getenv('DEVICE', 'cpu')
WEB_PANEL_PORT = int(os.getenv('WEB_PANEL_PORT', '8080'))
UNIT_PORT = int(os.getenv('UNIT_PORT', '8090'))
BACKEND_URL = os.getenv('BACKEND_URL', 'http://hello:8000')
LOG_FILE = os.getenv('LOG_FILE', 'app.log')
UNIT_BACKEND_PORT = int(os.getenv('UNIT_BACKEND_PORT', '18080'))
