from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime
from alert_manager import build_recommendations

def generate_report(
    findings: List[Dict[str, Any]],
    score: Dict[str, Any],
    markdown_path: Path,
    json_path: Path,
    llm_explanation: Optional[str] = None
) -> None:
    markdown_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.parent.mkdir(parents=True, exist_ok=True)

    recommendations = build_recommendations(score.get("category_counts", {}))

    lines = []
    lines.append("# AegisLoop Guardian Report")
    lines.append("")
    lines.append(f"Generated: {datetime.utcnow().isoformat()}Z")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Risk level: {score['risk_level']}")
    lines.append(f"- Risk score: {score['risk_score']}")
    lines.append(f"- Findings: {score['finding_count']}")
    lines.append("")
    lines.append("## Category Counts")
    lines.append("")
    if score.get("category_counts"):
        for category, count in sorted(score["category_counts"].items()):
            lines.append(f"- {category}: {count}")
    else:
        lines.append("- No findings.")
    lines.append("")
    lines.append("## Findings")
    lines.append("")
    if findings:
        for item in findings:
            lines.append(f"### {item['rule_id']} - {item['label']}")
            lines.append("")
            lines.append(f"- File: `{item['file']}`")
            lines.append(f"- Severity: {item['severity']}")
            lines.append(f"- Category: {item['category']}")
            lines.append(f"- Matched pattern: `{item['matched_pattern']}`")
            lines.append(f"- Reason: {item['reason']}")
            lines.append("")
    else:
        lines.append("No suspicious patterns were detected.")
        lines.append("")
    lines.append("## Defensive Recommendations")
    lines.append("")
    if recommendations:
        for rec in recommendations:
            lines.append(f"- **{rec['category']}**: {rec['recommendation']}")
    else:
        lines.append("- No action needed based on current rules.")
    lines.append("")

    if llm_explanation:
        lines.append("## Optional LLM Explanation")
        lines.append("")
        lines.append(llm_explanation)
        lines.append("")

    lines.append("## Safety Note")
    lines.append("")
    lines.append("AegisLoop Guardian is a defensive scanner. It does not execute or delete scanned files. External LLM providers are contacted only when the user explicitly enables remote explanation.")

    markdown_path.write_text("\n".join(lines), encoding="utf-8")

    import json
    json_path.write_text(json.dumps({
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "score": score,
        "findings": findings,
        "recommendations": recommendations,
        "llm_explanation": llm_explanation
    }, indent=2), encoding="utf-8")
