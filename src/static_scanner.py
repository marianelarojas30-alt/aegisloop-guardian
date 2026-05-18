from pathlib import Path
from typing import Dict, Any, List
from ioc_extractor import ioc_findings

def scan_text(path: Path, text: str, rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings = []
    lower_text = text.lower()

    for rule in rules:
        pattern = rule["pattern"].lower()
        if pattern in lower_text:
            findings.append({
                "file": str(path),
                "rule_id": rule["id"],
                "label": rule["label"],
                "severity": rule["severity"],
                "category": rule["category"],
                "reason": rule["reason"],
                "matched_pattern": rule["pattern"]
            })

    return findings

def scan_file(path: Path, rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception as exc:
        return [{
            "file": str(path),
            "rule_id": "READ-ERROR",
            "label": "Could not read file",
            "severity": "low",
            "category": "read_error",
            "reason": f"File could not be read safely as text: {exc}",
            "matched_pattern": ""
        }]

    return scan_text(path, text, rules) + ioc_findings(path, text)
