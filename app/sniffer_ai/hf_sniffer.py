from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch


class HFTextSniffer:
    """Wrapper for the Hugging Face Sniffer.AI model using Transformers."""

    LABELS = [
        "Normal",
        "Backdoor",
        "DDoS",
        "Injection",
        "Password Attack",
        "Ransomware",
        "Scanning",
        "XSS",
    ]

    def __init__(self, repo: str = "SilverDragon9/Sniffer.AI") -> None:
        self.repo = repo
        self.tokenizer = AutoTokenizer.from_pretrained(
            repo,
            trust_remote_code=True,
        )
        self.model = AutoModelForSequenceClassification.from_pretrained(
            repo,
            trust_remote_code=True,
        )

    def predict_from_text(self, text: str):
        inputs = self.tokenizer(text, truncation=True, padding=True, return_tensors="pt")
        outputs = self.model(**inputs)
        probs = torch.softmax(outputs.logits, dim=-1)[0].detach().cpu().tolist()
        idx = int(torch.argmax(outputs.logits, dim=-1).item())
        return self.LABELS[idx], probs
