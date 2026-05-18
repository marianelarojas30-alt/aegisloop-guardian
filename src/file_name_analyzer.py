from pathlib import Path
from typing import Dict, Any, List

DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".msi", ".app", ".dmg", ".sh"
}

DOCUMENT_EXTENSIONS = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".csv", ".txt", ".md", ".jpg", ".png"
}

def analyze_filename(path: Path) -> List[Dict[str, Any]]:
    findings = []
    name = path.name.lower()
    suffixes = [s.lower() for s in path.suffixes]

    if len(suffixes) >= 2:
        previous = suffixes[-2]
        final = suffixes[-1]
        if previous in DOCUMENT_EXTENSIONS and final in DANGEROUS_EXTENSIONS:
            findings.append({
                "file": str(path),
                "rule_id": "NAME-001",
                "label": "Double-extension executable lure",
                "severity": "critical",
                "category": "file_name_deception",
                "reason": "File name appears to disguise an executable as a document.",
                "matched_pattern": path.name
            })

    lure_terms = ["invoice", "payment", "urgent", "resume", "statement", "refund", "tax"]
    if any(term in name for term in lure_terms) and path.suffix.lower() in DANGEROUS_EXTENSIONS:
        findings.append({
            "file": str(path),
            "rule_id": "NAME-002",
            "label": "Executable file with social-engineering lure name",
            "severity": "high",
            "category": "file_name_deception",
            "reason": "Executable/script file name uses common phishing or fraud lure terms.",
            "matched_pattern": path.name
        })

    return findings
