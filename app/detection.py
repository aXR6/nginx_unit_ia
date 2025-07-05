from transformers import AutoTokenizer, AutoModelForSequenceClassification
from sentence_transformers import SentenceTransformer, util
import torch
import logging
from collections import deque

logger = logging.getLogger(__name__)
from . import config

# Default label mapping for anomaly model if config lacks id2label
ANOMALY_LABELS = {
    0: "normal",
    1: "anomaly",
}

class Detector:
    def __init__(self):
        device = config.DEVICE
        if device == "cuda" and not torch.cuda.is_available():
            logger.warning("CUDA não disponível, usando CPU")
            device = "cpu"
        logger.info("Carregando modelos em %s", device)
        self.device = torch.device(device)

        self.severity_tokenizer = AutoTokenizer.from_pretrained(config.SEVERITY_MODEL)
        self.severity_model = AutoModelForSequenceClassification.from_pretrained(config.SEVERITY_MODEL).to(self.device)
        self.anomaly_tokenizer = AutoTokenizer.from_pretrained(config.ANOMALY_MODEL)
        self.anomaly_model = AutoModelForSequenceClassification.from_pretrained(config.ANOMALY_MODEL).to(self.device)
        self.nids_tokenizer = AutoTokenizer.from_pretrained(config.NIDS_MODEL)
        self.nids_model = AutoModelForSequenceClassification.from_pretrained(config.NIDS_MODEL).to(self.device)
        self.semantic_model = SentenceTransformer(config.SEMANTIC_MODEL, device=str(self.device))
        self.recent_embeddings = deque(maxlen=100)
        self.semantic_threshold = float(getattr(config, 'SEMANTIC_THRESHOLD', 0.5))
        logger.info("Modelos carregados com sucesso")

    def analyze(self, text: str):
        logger.debug("Analise de texto")
        embedding = self.semantic_model.encode(
            text,
            convert_to_tensor=True,
            normalize_embeddings=True,
        )
        similarity = 1.0
        if self.recent_embeddings:
            sims = util.cos_sim(embedding, torch.stack(list(self.recent_embeddings)))[0]
            similarity = float(torch.max(sims).item())
        outlier = similarity < self.semantic_threshold
        self.recent_embeddings.append(embedding.cpu())
        inputs = self.anomaly_tokenizer(
            text,
            return_tensors="pt",
            truncation=True,
            max_length=self.anomaly_tokenizer.model_max_length,
        )
        inputs = {k: v.to(self.device) for k, v in inputs.items()}
        anomaly_output = self.anomaly_model(**inputs)
        anomaly_probs = torch.softmax(anomaly_output.logits, dim=-1)[0]
        anomaly_score = anomaly_probs.tolist()
        anomaly_label_idx = int(torch.argmax(anomaly_probs).item())
        anomaly_label = self.anomaly_model.config.id2label.get(
            anomaly_label_idx, str(anomaly_label_idx)
        )
        if isinstance(anomaly_label, str) and anomaly_label.startswith("LABEL_"):
            anomaly_label = ANOMALY_LABELS.get(anomaly_label_idx, anomaly_label)

        sev_inputs = self.severity_tokenizer(
            text,
            return_tensors="pt",
            truncation=True,
            max_length=self.severity_tokenizer.model_max_length,
        )
        sev_inputs = {k: v.to(self.device) for k, v in sev_inputs.items()}
        sev_output = self.severity_model(**sev_inputs)
        sev_probs = torch.softmax(sev_output.logits, dim=-1)[0]
        severity_score = sev_probs.tolist()
        severity_label_idx = int(torch.argmax(sev_probs).item())
        severity_label = self.severity_model.config.id2label.get(severity_label_idx, str(severity_label_idx))

        nids_inputs = self.nids_tokenizer(
            text,
            return_tensors="pt",
            truncation=True,
            max_length=self.nids_tokenizer.model_max_length,
        )
        nids_inputs = {k: v.to(self.device) for k, v in nids_inputs.items()}
        nids_output = self.nids_model(**nids_inputs)
        nids_probs = torch.softmax(nids_output.logits, dim=-1)[0]
        nids_score = nids_probs.tolist()
        nids_label_idx = int(torch.argmax(nids_probs).item())
        nids_label = self.nids_model.config.id2label.get(nids_label_idx, str(nids_label_idx))

        return {
            'anomaly': {'label': anomaly_label, 'score': anomaly_score},
            'severity': {'label': severity_label, 'score': severity_score},
            'nids': {'label': nids_label, 'score': nids_score},
            'semantic': {
                'embedding': embedding.cpu().tolist(),
                'similarity': similarity,
                'outlier': outlier,
            },
        }
