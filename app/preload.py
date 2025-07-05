import logging
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from sentence_transformers import SentenceTransformer

from . import config

logger = logging.getLogger(__name__)


def download_models() -> None:
    """Download all HuggingFace models used by the application."""
    logger.info("Baixando modelos para o cache se necessario")
    models = [
        (config.SEVERITY_MODEL, True),
        (config.ANOMALY_MODEL, True),
        *[(model, True) for model in config.NIDS_MODELS],
    ]
    for model_name, is_classifier in models:
        try:
            AutoTokenizer.from_pretrained(model_name)
            if is_classifier:
                AutoModelForSequenceClassification.from_pretrained(model_name)
        except Exception as exc:
            logger.error("Erro ao baixar %s: %s", model_name, exc)
    try:
        SentenceTransformer(config.SEMANTIC_MODEL)
    except Exception as exc:
        logger.error("Erro ao baixar modelo semantico %s: %s", config.SEMANTIC_MODEL, exc)
    logger.info("Modelos verificados")
