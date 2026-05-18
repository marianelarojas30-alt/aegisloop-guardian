from pathlib import Path
from typing import Dict, Any, List
import json

from hash_utils import hash_file
from entropy_analyzer import analyze_entropy
from file_type_analyzer import analyze_file_type
from clamav_adapter import scan_with_clamav

ROOT = Path(__file__).resolve().parents[1]
HASH_DENYLIST = ROOT / "hashes" / "known_bad_hashes.json"

def _load_hash_denylist() -> Dict[str, Any]:
    try:
        return json.loads(HASH_DENYLIST.read_text(encoding="utf-8"))
    except Exception:
        return {"sha256": [], "sha1": [], "md5": []}

def _hash_findings(path: Path, hashes: Dict[str, str], denylist: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings = []

    for hash_type in ["sha256", "sha1", "md5"]:
        local_hash = hashes.get(hash_type)
        known = denylist.get(hash_type, [])
        for item in known:
            if isinstance(item, dict) and item.get("hash", "").lower() == local_hash:
                findings.append({
                    "file": str(path),
                    "rule_id": f"HASH-{hash_type.upper()}",
                    "label": "Known-bad hash match",
                    "severity": item.get("severity", "critical"),
                    "category": "known_bad_hash",
                    "reason": f"File hash matched local denylist entry: {item.get('label', 'unknown')}",
                    "matched_pattern": local_hash
                })

    return findings

def av_style_scan_file(path: Path, use_clamav: bool = False) -> List[Dict[str, Any]]:
    """
    Antivirus-style static checks.
    Does not execute the file.
    """
    findings = []
    denylist = _load_hash_denylist()

    try:
        hashes = hash_file(path)
        findings.extend(_hash_findings(path, hashes, denylist))
    except Exception as exc:
        findings.append({
            "file": str(path),
            "rule_id": "HASH-ERROR",
            "label": "Hash calculation error",
            "severity": "low",
            "category": "scan_error",
            "reason": f"Could not hash file: {exc}",
            "matched_pattern": ""
        })

    type_info = analyze_file_type(path)
    if type_info.get("extension_mismatch"):
        findings.append({
            "file": str(path),
            "rule_id": "TYPE-001",
            "label": "Executable content with document-like extension",
            "severity": "high",
            "category": "file_type_mismatch",
            "reason": type_info.get("reason"),
            "matched_pattern": f"{type_info.get('detected_type')} as {type_info.get('extension')}"
        })

    entropy_info = analyze_entropy(path)
    if entropy_info.get("high_entropy"):
        findings.append({
            "file": str(path),
            "rule_id": "ENTROPY-001",
            "label": "High file entropy",
            "severity": "medium",
            "category": "obfuscation",
            "reason": entropy_info.get("reason"),
            "matched_pattern": str(entropy_info.get("entropy"))
        })

    if use_clamav:
        clam = scan_with_clamav(path)
        if clam.get("infected"):
            findings.append({
                "file": str(path),
                "rule_id": "CLAMAV-FOUND",
                "label": "ClamAV signature match",
                "severity": "critical",
                "category": "clamav_detection",
                "reason": f"ClamAV detected: {clam.get('signature')}",
                "matched_pattern": clam.get("signature") or "FOUND"
            })

    return findings
