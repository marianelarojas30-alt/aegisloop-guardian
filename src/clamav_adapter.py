from pathlib import Path
from typing import Dict, Any
import shutil
import subprocess

def scan_with_clamav(path: Path) -> Dict[str, Any]:
    """
    Optional integration with ClamAV if clamscan is installed.

    This does not install ClamAV.
    """
    clamscan = shutil.which("clamscan")
    if not clamscan:
        return {
            "available": False,
            "infected": False,
            "signature": None,
            "raw_output": "clamscan not found"
        }

    try:
        proc = subprocess.run(
            [clamscan, "--no-summary", str(path)],
            capture_output=True,
            text=True,
            timeout=120
        )
        output = (proc.stdout or "") + (proc.stderr or "")
        infected = "FOUND" in output
        signature = None
        if infected:
            parts = output.strip().split(":")
            if len(parts) >= 2:
                signature = parts[-1].replace("FOUND", "").strip()

        return {
            "available": True,
            "infected": infected,
            "signature": signature,
            "raw_output": output.strip()
        }
    except Exception as exc:
        return {
            "available": True,
            "infected": False,
            "signature": None,
            "raw_output": f"ClamAV scan error: {exc}"
        }
