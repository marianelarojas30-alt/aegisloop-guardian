from pathlib import Path
from typing import List, Dict, Any
import json
import re
from tempfile import NamedTemporaryFile
from datetime import datetime, timezone
from hash_utils import hash_file

ROOT = Path(__file__).resolve().parents[1]
BASELINE_PATH = ROOT / "baselines" / "baseline.json"

class BaselineError(ValueError):
    """A requested reference inventory could not be used."""


def build_baseline(files: List[Path], output_path: Path = BASELINE_PATH) -> Dict[str, Any]:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    records = []
    for path in files:
        hashes = hash_file(path)
        stat = path.stat()
        records.append({
            "path": str(path),
            "size": stat.st_size,
            "mtime": stat.st_mtime,
            "sha256": hashes["sha256"]
        })

    baseline = {
        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "files": records
    }

    tmp = NamedTemporaryFile(mode="w", encoding="utf-8", dir=output_path.parent, delete=False)
    pending = Path(tmp.name)
    try:
        with tmp:
            json.dump(baseline, tmp, indent=2)
        pending.replace(output_path)
    finally:
        pending.unlink(missing_ok=True)
    return baseline

def compare_to_baseline(files: List[Path], baseline_path: Path = BASELINE_PATH) -> List[Dict[str, Any]]:
    try:
        baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise BaselineError(f"No baseline at {baseline_path}. Create one with --build-baseline first.") from exc
    except (ValueError, OSError) as exc:
        raise BaselineError(f"Cannot read baseline {baseline_path}: {exc}") from exc

    if not isinstance(baseline, dict) or not isinstance(baseline.get("files"), list):
        raise BaselineError(f"Invalid baseline {baseline_path}: expected a files list.")
    old = {}
    for item in baseline["files"]:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str) or not item["path"]:
            raise BaselineError(f"Invalid file path in baseline {baseline_path}.")
        checksum = item.get("sha256")
        if not isinstance(checksum, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", checksum):
            raise BaselineError(f"Invalid SHA-256 for {item['path']} in baseline {baseline_path}.")
        if item["path"] in old:
            raise BaselineError(f"Duplicate path in baseline {baseline_path}: {item['path']}.")
        old[item["path"]] = checksum.lower()
    findings = []

    current_paths = set()
    for path in files:
        current_paths.add(str(path))
        hashes = hash_file(path)
        old_hash = old.get(str(path))
        if old_hash is None:
            findings.append({
                "file": str(path),
                "rule_id": "BASELINE-NEW",
                "label": "New file since baseline",
                "severity": "low",
                "category": "baseline_change",
                "reason": "File was not present in the previous baseline.",
                "matched_pattern": str(path)
            })
        elif old_hash != hashes["sha256"]:
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
