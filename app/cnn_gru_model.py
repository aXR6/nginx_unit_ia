import os
from typing import Tuple

# Reduce TensorFlow verbosity and avoid GPU initialization messages when
# running on systems without the necessary CUDA libraries.  The environment
# variables must be set before importing TensorFlow.
os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")
os.environ.setdefault("CUDA_VISIBLE_DEVICES", "")

from tensorflow.keras.models import load_model
from sentence_transformers import SentenceTransformer
from huggingface_hub import hf_hub_download
import numpy as np

class CNNGRUModel:
    """Wrapper for the YangYang-Research/web-attack-detection model."""

    def __init__(self, repo_id: str = "YangYang-Research/web-attack-detection", filename: str = "model.h5") -> None:
        local_model = hf_hub_download(repo_id=repo_id, filename=filename)
        self.model = load_model(local_model)
        enc_name = os.environ.get("CNN_GRU_ENCODER", "sentence-transformers/all-MiniLM-L6-v2")
        self.encoder = SentenceTransformer(enc_name)
        self.repo_id = repo_id

    def predict_from_text(self, text: str) -> Tuple[str, list]:
        """Return label and probability for the given text."""
        emb = self.encoder.encode(text).reshape((1, -1))
        prob = float(self.model.predict(emb)[0][0])
        label = "webattack" if prob >= 0.5 else "normal"
        return label, [1 - prob, prob]
