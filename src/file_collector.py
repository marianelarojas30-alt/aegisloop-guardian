from pathlib import Path
from typing import List

DEFAULT_EXTENSIONS = {
    ".txt", ".md", ".py", ".sh", ".json", ".yaml", ".yml", ".csv", ".log"
}

def collect_files(root_path: Path, max_size_kb: int = 512) -> List[Path]:
    """
    Collects local files for defensive static scanning.

    This function does not execute files.
    """
    if not root_path.exists():
        raise FileNotFoundError(f"Path does not exist: {root_path}")

    if root_path.is_file():
        candidates = [root_path]
    else:
        candidates = [p for p in root_path.rglob("*") if p.is_file()]

    files = []
    for path in candidates:
        if ".git" in path.parts or ".venv" in path.parts:
            continue
        if path.suffix.lower() not in DEFAULT_EXTENSIONS:
            continue
        try:
            size_kb = path.stat().st_size / 1024
        except OSError:
            continue
        if size_kb <= max_size_kb:
            files.append(path)
    return files

def folder_fingerprint(files: List[Path]) -> str:
    """
    Creates a simple fingerprint from file path, size, and modified time.
    Used by watch mode to detect changes without reading every file constantly.
    """
    parts = []
    for path in sorted(files):
        try:
            stat = path.stat()
            parts.append(f"{path}:{stat.st_size}:{stat.st_mtime}")
        except OSError:
            continue
    return "|".join(parts)
