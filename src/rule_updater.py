from pathlib import Path
from typing import Dict, Any, List
import json
from datetime import datetime
from collections import Counter

def save_regression_case(findings: List[Dict[str, Any]], score: Dict[str, Any], output_path: Path) -> None:
    """
    Saves findings as defensive regression intelligence.

    This is the safe self-updating loop:
    it updates detection memory, not executable code.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)

    case = {
        "created_at": datetime.utcnow().isoformat() + "Z",
        "purpose": "Defensive regression case generated from scanner findings.",
        "score": score,
        "findings": findings
    }

    if output_path.exists():
        try:
            existing = json.loads(output_path.read_text(encoding="utf-8"))
            if not isinstance(existing, list):
                existing = []
        except Exception:
            existing = []
    else:
        existing = []

    existing.append(case)
    output_path.write_text(json.dumps(existing, indent=2), encoding="utf-8")

def propose_rules_from_repeated_findings(findings: List[Dict[str, Any]], proposal_path: Path) -> None:
    """
    Creates human-review rule proposals from repeated findings.

    This does not modify active rules automatically.
    """
    proposal_path.parent.mkdir(parents=True, exist_ok=True)

    pattern_counts = Counter((f.get("matched_pattern", ""), f.get("category", "")) for f in findings)
    proposals = []

    for (pattern, category), count in pattern_counts.items():
        if not pattern or count < 2:
            continue
        proposals.append({
            "created_at": datetime.utcnow().isoformat() + "Z",
            "status": "requires_human_review",
            "suggested_pattern": pattern,
            "category": category,
            "observed_count": count,
            "reason": "Repeated finding observed during local defensive scan. Review before adding to active rules."
        })

    if not proposals:
        return

    if proposal_path.exists():
        try:
            existing = json.loads(proposal_path.read_text(encoding="utf-8"))
            if not isinstance(existing, list):
                existing = []
        except Exception:
            existing = []
    else:
        existing = []

    existing.extend(proposals)
    proposal_path.write_text(json.dumps(existing, indent=2), encoding="utf-8")
