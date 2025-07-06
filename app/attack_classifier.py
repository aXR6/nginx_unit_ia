import os


THRESHOLD = int(os.getenv("ATTACK_SIZE_THRESHOLD", "1000"))


def ml_multiclass_predict(text: str) -> str:
    """Placeholder ML classification returning ``normal`` by default."""
    return "normal"




def classify(text: str) -> str:
    """Classify the text into an attack category."""
    if len(text) > THRESHOLD:
        return "dos"
    return ml_multiclass_predict(text)
