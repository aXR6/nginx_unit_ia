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
        anomaly_score = torch.softmax(anomaly_output.logits, dim=-1)[0].tolist()

        sev_inputs = self.severity_tokenizer(text, return_tensors='pt')
        sev_output = self.severity_model(**sev_inputs)
        severity_score = torch.softmax(sev_output.logits, dim=-1)[0].tolist()

        nids_inputs = self.nids_tokenizer(text, return_tensors='pt')
        nids_output = self.nids_model(**nids_inputs)
        nids_score = torch.softmax(nids_output.logits, dim=-1)[0].tolist()

        return anomaly_score, severity_score, nids_score
