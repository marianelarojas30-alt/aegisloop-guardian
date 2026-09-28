from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime
import html
from alert_manager import build_recommendations

def _md_text(value: Any) -> str:
    return html.escape(str(value), quote=False).replace("`", "\\`")

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
            lines.append(f"### {_md_text(item['rule_id'])} - {_md_text(item['label'])}")
            lines.append("")
            lines.append(f"- File: `{_md_text(item['file'])}`")
            lines.append(f"- Severity: {_md_text(item['severity'])}")
            lines.append(f"- Category: {_md_text(item['category'])}")
            lines.append(f"- Matched pattern: `{_md_text(item['matched_pattern'])}`")
            lines.append(f"- Reason: {_md_text(item['reason'])}")
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
        lines.append("> Security note: model-generated explanation is untrusted advisory text. Do not execute commands from it automatically.")
        lines.append("")
        lines.append(_md_text(llm_explanation))
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
