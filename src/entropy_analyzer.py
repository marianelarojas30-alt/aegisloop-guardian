from pathlib import Path
import math
from typing import Dict, Any

def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0

    frequencies = {}
    for byte in data:
        frequencies[byte] = frequencies.get(byte, 0) + 1

    entropy = 0.0
    length = len(data)
    for count in frequencies.values():
        p = count / length
        entropy -= p * math.log2(p)

    return entropy

def analyze_entropy(path: Path, max_bytes: int = 1024 * 1024) -> Dict[str, Any]:
    """
    High entropy may indicate packed, compressed, encrypted, or obfuscated content.
    It is not proof of malware.
    """
    try:
        data = path.read_bytes()[:max_bytes]
    except Exception as exc:
        return {
            "entropy": None,
            "high_entropy": False,
            "reason": f"Could not read bytes for entropy: {exc}"
        }

    entropy = calculate_entropy(data)
    return {
        "entropy": round(entropy, 3),
        "high_entropy": entropy >= 7.2,
        "reason": "High entropy can indicate compression, encryption, packing, or obfuscation." if entropy >= 7.2 else "Entropy not unusually high."
    }
