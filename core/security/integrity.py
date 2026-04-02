import hashlib
import math
import os
from collections import Counter


class IntegrityInspector:
    @staticmethod
    def _entropy(data: bytes) -> float:
        if not data:
            return 0.0
        counts = Counter(data)
        total = len(data)
        return -sum((count / total) * math.log2(count / total) for count in counts.values())

    @staticmethod
    def inspect_file(path: str) -> dict:
        with open(path, "rb") as handle:
            data = handle.read()

        entropy = IntegrityInspector._entropy(data[: min(len(data), 4096)])
        sha256 = hashlib.sha256(data).hexdigest()
        blake2b = hashlib.blake2b(data).hexdigest()
        size = os.path.getsize(path)

        level = "LOW"
        if entropy > 7.7:
            level = "HIGH"
        if path.endswith((".exe", ".dll", ".bin")) and entropy > 7.9:
            level = "CRITICAL"

        return {
            "success": True,
            "path": path,
            "size": size,
            "hashes": {"sha256": sha256, "blake2b": blake2b},
            "risk_analysis": {
                "level": level,
                "entropy": round(entropy, 4),
                "notes": "Dev integrity scanner based on file hashes and Shannon entropy.",
            },
        }
