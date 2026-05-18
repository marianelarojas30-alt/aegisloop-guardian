from pathlib import Path
from typing import List, Dict, Any
import csv

def export_findings_csv(findings: List[Dict[str, Any]], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = ["file", "rule_id", "label", "severity", "category", "reason", "matched_pattern"]

    with output_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for item in findings:
            writer.writerow({key: item.get(key, "") for key in fieldnames})
