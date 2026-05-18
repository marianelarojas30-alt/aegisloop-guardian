from pathlib import Path
from typing import List, Dict, Any
import shutil
import time
import json

def quarantine_flagged_files(findings: List[Dict[str, Any]], quarantine_dir: Path) -> List[Dict[str, Any]]:
    """
    Safe quarantine-by-copy.

    This does not delete or move the original file.
    It copies flagged files into quarantine for manual review.
    """
    quarantine_dir.mkdir(parents=True, exist_ok=True)

    copied = []
    seen = set()

    for finding in findings:
        file_path = Path(finding.get("file", ""))
        if not file_path.exists() or file_path in seen:
            continue

        seen.add(file_path)
        stamp = int(time.time())
        safe_name = f"{stamp}_{file_path.name}"
        dest = quarantine_dir / safe_name

        try:
            shutil.copy2(file_path, dest)
            copied.append({
                "source": str(file_path),
                "quarantine_copy": str(dest),
                "status": "copied"
            })
        except Exception as exc:
            copied.append({
                "source": str(file_path),
                "quarantine_copy": None,
                "status": f"copy_failed: {exc}"
            })

    manifest_path = quarantine_dir / "quarantine_manifest.json"
    try:
        if manifest_path.exists():
            existing = json.loads(manifest_path.read_text(encoding="utf-8"))
            if not isinstance(existing, list):
                existing = []
        else:
            existing = []
        existing.extend(copied)
        manifest_path.write_text(json.dumps(existing, indent=2), encoding="utf-8")
    except Exception:
        pass

    return copied
