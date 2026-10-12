from pathlib import Path
from typing import List, Dict, Any
import json
import os
import shutil
import stat
import tempfile


def quarantine_flagged_files(findings: List[Dict[str, Any]], quarantine_dir: Path) -> List[Dict[str, Any]]:
    """Copy evidence into private, exclusive files; never replace the source.

    Random destination names prevent same-name collisions and planted destination
    symlinks. The manifest is atomically replaced, never opened for writing through
    an existing link. Quarantine is for a trusted user-controlled local directory.
    """
    if quarantine_dir.is_symlink():
        raise ValueError("quarantine directory must not be a symlink")
    quarantine_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    copied = []
    seen = set()
    for finding in findings:
        file_path = Path(finding.get("file", ""))
        if file_path in seen:
            continue
        seen.add(file_path)
        record = {"source": str(file_path), "quarantine_copy": None}
        if file_path.is_symlink():
            copied.append({**record, "status": "skipped_symlink"})
            continue
        dest = None
        try:
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
            with os.fdopen(os.open(file_path, flags), "rb") as source:
                if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                    copied.append({**record, "status": "skipped_not_regular_file"})
                    continue
                fd, name = tempfile.mkstemp(prefix="evidence-", suffix=".quarantine", dir=quarantine_dir)
                dest = Path(name)
                with os.fdopen(fd, "wb") as target:
                    shutil.copyfileobj(source, target)
                    target.flush()
                    os.fsync(target.fileno())
            copied.append({**record, "quarantine_copy": str(dest), "status": "copied"})
        except OSError as exc:
            if dest is not None:
                dest.unlink(missing_ok=True)
            copied.append({**record, "status": f"copy_failed: {exc}"})

    manifest_path = quarantine_dir / "quarantine_manifest.json"
    existing = []
    if not manifest_path.is_symlink() and manifest_path.is_file():
        try:
            loaded = json.loads(manifest_path.read_text(encoding="utf-8"))
            if isinstance(loaded, list):
                existing = loaded
        except (OSError, ValueError):
            pass
    fd, name = tempfile.mkstemp(prefix=".manifest-", suffix=".tmp", dir=quarantine_dir)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as manifest:
            json.dump(existing + copied, manifest, indent=2)
            manifest.flush()
            os.fsync(manifest.fileno())
        os.replace(name, manifest_path)
    finally:
        Path(name).unlink(missing_ok=True)
    return copied
