from pathlib import Path
from typing import List, Dict, Any
import json
from datetime import datetime
from hash_utils import hash_file

ROOT = Path(__file__).resolve().parents[1]
BASELINE_PATH = ROOT / "baselines" / "baseline.json"

def build_baseline(files: List[Path], output_path: Path = BASELINE_PATH) -> Dict[str, Any]:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    records = []
    for path in files:
        try:
            hashes = hash_file(path)
            stat = path.stat()
            records.append({
                "path": str(path),
                "size": stat.st_size,
                "mtime": stat.st_mtime,
                "sha256": hashes["sha256"]
            })
        except Exception:
            continue

    baseline = {
        "created_at": datetime.utcnow().isoformat() + "Z",
        "files": records
    }

    output_path.write_text(json.dumps(baseline, indent=2), encoding="utf-8")
    return baseline

def compare_to_baseline(files: List[Path], baseline_path: Path = BASELINE_PATH) -> List[Dict[str, Any]]:
    if not baseline_path.exists():
        return []

    try:
        baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    except Exception:
        return []

    old = {item["path"]: item for item in baseline.get("files", [])}
    findings = []

    current_paths = set()
    for path in files:
        current_paths.add(str(path))
        try:
            hashes = hash_file(path)
            stat = path.stat()
        except Exception:
            continue

        old_item = old.get(str(path))
        if not old_item:
            findings.append({
                "file": str(path),
                "rule_id": "BASELINE-NEW",
                "label": "New file since baseline",
                "severity": "low",
                "category": "baseline_change",
                "reason": "File was not present in the previous baseline.",
                "matched_pattern": str(path)
            })
        elif old_item.get("sha256") != hashes.get("sha256"):
            findings.append({
                "file": str(path),
                "rule_id": "BASELINE-MODIFIED",
                "label": "File changed since baseline",
                "severity": "medium",
                "category": "baseline_change",
                "reason": "File hash changed since the previous baseline.",
                "matched_pattern": str(path)
            })

    for old_path in old.keys():
        if old_path not in current_paths:
            findings.append({
                "file": old_path,
                "rule_id": "BASELINE-DELETED",
                "label": "File missing since baseline",
                "severity": "low",
                "category": "baseline_change",
                "reason": "File existed in baseline but is missing now.",
                "matched_pattern": old_path
            })

    return findings
