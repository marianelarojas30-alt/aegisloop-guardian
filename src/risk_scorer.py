from typing import Dict, Any, List

DEFAULT_WEIGHTS = {
    "low": 1,
    "medium": 3,
    "high": 7,
    "critical": 12
}

def score_findings(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    score = 0
    categories = {}

    for finding in findings:
        severity = finding.get("severity", "low")
        score += DEFAULT_WEIGHTS.get(severity, 1)
        category = finding.get("category", "unknown")
        categories[category] = categories.get(category, 0) + 1

    if score >= 22:
        risk_level = "CRITICAL"
    elif score >= 12:
        risk_level = "HIGH"
    elif score >= 5:
        risk_level = "MEDIUM"
    elif score >= 1:
        risk_level = "LOW"
    else:
        risk_level = "NONE"

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "category_counts": categories,
        "finding_count": len(findings)
    }
