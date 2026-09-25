from pathlib import Path
from typing import List
import hashlib

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

    if root_path.is_symlink():
        raise ValueError(f"Refusing to scan symlink root: {root_path}")

    candidates = (
        (root_path,)
        if root_path.is_file()
        else (p for p in root_path.rglob("*") if not p.is_symlink() and p.is_file())
    )

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
    digest = hashlib.blake2b(digest_size=16)
    for path in sorted(files):
        try:
            stat = path.stat()
        except OSError:
            continue
        digest.update(str(path).encode("utf-8", errors="surrogatepass"))
        digest.update(b"\0")
        digest.update(str(stat.st_size).encode())
        digest.update(b":")
        digest.update(str(stat.st_mtime_ns).encode())
        digest.update(b"\n")
    return digest.hexdigest()
