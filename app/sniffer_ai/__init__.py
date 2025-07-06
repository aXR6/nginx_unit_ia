import os
import json
import time
from typing import Dict, Iterable

import pandas as pd
import joblib
import warnings
import sklearn
from huggingface_hub import hf_hub_download


class Sniffer:
    """Wrapper to load and use Sniffer.AI IDS models."""

    CLASS_LABELS = {
        0: "Normal",
        1: "Backdoor",
        2: "DDoS",
        3: "Injection",
        4: "Password Attack",
        5: "Ransomware",
        6: "Scanning",
        7: "XSS",
    }

    FEATURE_COLUMNS = [
        "date_numeric",
        "time_numeric",
        "door_state",
        "sphone_signal",
        "label",
    ]

    def __init__(self, model_dir: str | None = None):
        self.model_dir = model_dir or os.path.join(os.path.dirname(__file__), "models")
        os.makedirs(self.model_dir, exist_ok=True)
        self._ensure_models()
        self.models: Dict[str, object] = {}
        for name in ("fridge", "garage_door", "gps_tracker", "thermostat", "weather"):
            path = os.path.join(self.model_dir, f"{name}_model.pkl")
            if os.path.exists(path):
                with warnings.catch_warnings():
                    warnings.filterwarnings(
                        "ignore",
                        category=sklearn.exceptions.InconsistentVersionWarning,
                    )
                    model = joblib.load(path)
                self.models[name] = model
                try:
                    joblib.dump(model, path)
                except Exception:
                    pass

    def _ensure_models(self) -> None:
        required = [
            "fridge_model.pkl",
            "garage_door_model.pkl",
            "gps_tracker_model.pkl",
            "thermostat_model.pkl",
            "weather_model.pkl",
        ]
        for fname in required:
            path = os.path.join(self.model_dir, fname)
            if not os.path.exists(path):
                try:
                    hf_hub_download(
                        "SilverDragon9/Sniffer.AI",
                        fname,
                        repo_type="model",
                        local_dir=self.model_dir,
                        local_dir_use_symlinks=False,
                    )
                except Exception as exc:
                    # Download failures are not fatal; model will simply be skipped
                    print(f"Sniffer.AI: falha ao baixar {fname}: {exc}")

    def parse_line(self, line: str) -> Dict[str, str]:
        """Parse a log line in JSON or key=value format."""
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            data = {}
            tokens = line.replace(",", " ").split()
            for tok in tokens:
                if "=" in tok:
                    k, v = tok.split("=", 1)
                    data[k.strip()] = v.strip()
            if not data and len(tokens) >= 5:
                keys = ["date", "time", "door_state", "sphone_signal", "label"]
                data = dict(zip(keys, tokens[:5]))
        return {
            "date": data.get("date", ""),
            "time": data.get("time", ""),
            "door_state": data.get("door_state", data.get("state", "")),
            "sphone_signal": data.get("sphone_signal", data.get("signal", "")),
            "label": data.get("label", ""),
        }

    def _prepare_features(self, feats: Dict[str, str]) -> pd.DataFrame:
        """Return a dataframe with the features expected by the models."""
        df = pd.DataFrame([feats])
        df["door_state"] = (
            df["door_state"]
            .map({"closed": 0, "open": 1})
            .fillna(pd.to_numeric(df["door_state"], errors="coerce"))
            .fillna(0)
        )
        df["sphone_signal"] = pd.to_numeric(
            df["sphone_signal"], errors="coerce"
        ).fillna(0)
        df["date_numeric"] = (
            pd.to_datetime(df["date"], errors="coerce").astype("int64") // 10**9
        )
        t = pd.to_datetime(df["time"], errors="coerce")
        df["time_numeric"] = t.dt.hour * 3600 + t.dt.minute * 60 + t.dt.second
        df["label"] = pd.to_numeric(df.get("label", 0), errors="coerce").fillna(0)
        return df[self.FEATURE_COLUMNS].astype(float)

    def predict(self, feats: Dict[str, str]) -> str:
        model = self.models.get("garage_door")
        if model is None:
            return "Normal"
        features = self._prepare_features(feats)
        pred = int(model.predict(features)[0])
        return self.CLASS_LABELS.get(pred, str(pred))

    def predict_from_text(self, line: str) -> str:
        try:
            feats = self.parse_line(line)
        except Exception:
            return "Normal"
        return self.predict(feats)

    def stream_file(self, path: str, delay: float = 1.0) -> Iterable[str]:
        """Yield new log lines from ``path`` in real time."""
        with open(path, "r") as f:
            while True:
                line = f.readline()
                if not line:
                    time.sleep(delay)
                    continue
                yield line.strip()
