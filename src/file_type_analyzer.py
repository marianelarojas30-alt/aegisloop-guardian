from pathlib import Path
from typing import Dict, Any

MAGIC_SIGNATURES = {
    b"MZ": "windows_pe_executable",
    b"\\x7fELF": "linux_elf_executable",
    b"\\xca\\xfe\\xba\\xbe": "java_or_mach_o_fat",
    b"\\xfe\\xed\\xfa": "mach_o_binary",
    b"PK\\x03\\x04": "zip_or_office_archive",
    b"%PDF": "pdf_document",
    b"#!": "script_shebang",
}

EXECUTABLE_TYPES = {
    "windows_pe_executable",
    "linux_elf_executable",
    "java_or_mach_o_fat",
    "mach_o_binary",
    "script_shebang"
}

def analyze_file_type(path: Path) -> Dict[str, Any]:
    """
    Basic magic-byte file type inspection.
    """
    try:
        header = path.read_bytes()[:16]
    except Exception as exc:
        return {
            "detected_type": "unknown",
            "extension": path.suffix.lower(),
            "extension_mismatch": False,
            "reason": f"Could not read file header: {exc}"
        }

    detected = "unknown"
    for sig, label in MAGIC_SIGNATURES.items():
        if header.startswith(sig):
            detected = label
            break

    ext = path.suffix.lower()
    mismatch = False

    if detected in EXECUTABLE_TYPES and ext in {".txt", ".md", ".csv", ".json", ".yaml", ".yml", ".log"}:
        mismatch = True

    return {
        "detected_type": detected,
        "extension": ext,
        "extension_mismatch": mismatch,
        "reason": "Executable-like file content has a text/document extension." if mismatch else "No obvious extension mismatch."
    }
