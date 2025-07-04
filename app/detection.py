from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch
from . import config

class Detector:
    def __init__(self):
        self.semantic_tokenizer = AutoTokenizer.from_pretrained(config.SEMANTIC_MODEL)
        self.semantic_model = AutoModelForSequenceClassification.from_pretrained(config.SEMANTIC_MODEL)
        self.severity_tokenizer = AutoTokenizer.from_pretrained(config.SEVERITY_MODEL)
        self.severity_model = AutoModelForSequenceClassification.from_pretrained(config.SEVERITY_MODEL)
        self.anomaly_tokenizer = AutoTokenizer.from_pretrained(config.ANOMALY_MODEL)
        self.anomaly_model = AutoModelForSequenceClassification.from_pretrained(config.ANOMALY_MODEL)
        self.nids_tokenizer = AutoTokenizer.from_pretrained(config.NIDS_MODEL)
        self.nids_model = AutoModelForSequenceClassification.from_pretrained(config.NIDS_MODEL)

    def analyze(self, text: str):
        inputs = self.anomaly_tokenizer(text, return_tensors='pt')
        anomaly_output = self.anomaly_model(**inputs)
        anomaly_probs = torch.softmax(anomaly_output.logits, dim=-1)[0]
        anomaly_score = anomaly_probs.tolist()
        anomaly_label_idx = int(torch.argmax(anomaly_probs).item())
        anomaly_label = self.anomaly_model.config.id2label.get(anomaly_label_idx, str(anomaly_label_idx))

        sev_inputs = self.severity_tokenizer(text, return_tensors='pt')
        sev_output = self.severity_model(**sev_inputs)
        sev_probs = torch.softmax(sev_output.logits, dim=-1)[0]
        severity_score = sev_probs.tolist()
        severity_label_idx = int(torch.argmax(sev_probs).item())
        severity_label = self.severity_model.config.id2label.get(severity_label_idx, str(severity_label_idx))

        nids_inputs = self.nids_tokenizer(text, return_tensors='pt')
        nids_output = self.nids_model(**nids_inputs)
        nids_probs = torch.softmax(nids_output.logits, dim=-1)[0]
        nids_score = nids_probs.tolist()
        nids_label_idx = int(torch.argmax(nids_probs).item())
        nids_label = self.nids_model.config.id2label.get(nids_label_idx, str(nids_label_idx))

        return {
            'anomaly': {'label': anomaly_label, 'score': anomaly_score},
            'severity': {'label': severity_label, 'score': severity_score},
            'nids': {'label': nids_label, 'score': nids_score},
        }
