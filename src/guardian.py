import argparse
import json
from pathlib import Path

from file_collector import collect_files
from static_scanner import scan_file
from av_scanner import av_style_scan_file
from quarantine_manager import quarantine_flagged_files
from file_name_analyzer import analyze_filename
from baseline_manager import build_baseline, compare_to_baseline
from csv_exporter import export_findings_csv
from risk_scorer import score_findings
from rule_updater import save_regression_case, propose_rules_from_repeated_findings
from report_generator import generate_report
from llm_explainer import explain_findings

ROOT = Path(__file__).resolve().parents[1]
RULES_DIR = ROOT / "rules"
REPORTS_DIR = ROOT / "reports"
REGRESSION_PATH = ROOT / "regression_memory" / "findings_memory.json"
PROPOSALS_PATH = ROOT / "regression_memory" / "rule_proposals.json"

def load_rules():
    all_rules = []
    for path in [
        RULES_DIR / "suspicious_code_patterns.json",
        RULES_DIR / "worm_like_patterns.json",
        RULES_DIR / "financial_fraud_patterns.json",
        RULES_DIR / "llm_agent_risk_patterns.json",
        RULES_DIR / "document_risk_patterns.json",
    ]:
        data = json.loads(path.read_text(encoding="utf-8"))
        all_rules.extend(data.get("patterns", []))
    return all_rules

def run_scan(path: str, max_size_kb: int = 512, explain_provider: str = "none", model: str = "qwen2.5:7b", openai_base_url: str = None, enable_av_checks: bool = False, use_clamav: bool = False, quarantine: bool = False, build_baseline_flag: bool = False, compare_baseline: bool = False):
    target = Path(path)
    if not target.is_absolute():
        target = ROOT / target

    rules = load_rules()
    files = collect_files(target, max_size_kb=max_size_kb)

    findings = []
    for file_path in files:
        findings.extend(analyze_filename(file_path))
        findings.extend(scan_file(file_path, rules))
        if enable_av_checks:
            findings.extend(av_style_scan_file(file_path, use_clamav=use_clamav))

    if build_baseline_flag:
        build_baseline(files)

    if compare_baseline:
        findings.extend(compare_to_baseline(files))

    score = score_findings(findings)

    quarantine_results = []
    if quarantine and findings:
        quarantine_results = quarantine_flagged_files(findings, ROOT / "quarantine")

    llm_explanation = None
    if explain_provider and explain_provider != "none" and findings:
        llm_explanation = explain_findings(
            findings,
            provider=explain_provider,
            model=model,
            openai_base_url=openai_base_url
        )

    markdown_path = REPORTS_DIR / "latest_guardian_report.md"
    json_path = REPORTS_DIR / "latest_guardian_results.json"

    generate_report(findings, score, markdown_path, json_path, llm_explanation=llm_explanation)
    export_findings_csv(findings, REPORTS_DIR / "latest_guardian_findings.csv")

    if findings:
        save_regression_case(findings, score, REGRESSION_PATH)
        propose_rules_from_repeated_findings(findings, PROPOSALS_PATH)

    return {
        "files_scanned": len(files),
        "findings": findings,
        "score": score,
        "markdown_path": markdown_path,
        "json_path": json_path,
        "quarantine_results": quarantine_results
    }

def main():
    parser = argparse.ArgumentParser(description="Run AegisLoop Guardian defensive scan.")
    parser.add_argument("--path", default="watched_folder", help="File or folder to scan.")
    parser.add_argument("--max-size-kb", type=int, default=512, help="Maximum file size to scan.")
    parser.add_argument("--explain-provider", default="none", choices=["none", "ollama", "anthropic", "openai", "gemini"], help="Optional LLM provider for explaining findings.")
    parser.add_argument("--model", default="qwen2.5:7b", help="Model name for optional explanation provider.")
    parser.add_argument("--openai-base-url", default=None, help="Optional OpenAI-compatible chat completions endpoint.")
    parser.add_argument("--enable-av-checks", action="store_true", help="Enable antivirus-style static checks: hashes, entropy, file type, optional ClamAV.")
    parser.add_argument("--use-clamav", action="store_true", help="Use ClamAV if clamscan is installed.")
    parser.add_argument("--quarantine", action="store_true", help="Copy flagged files into quarantine/ for manual review. Does not delete originals.")
    parser.add_argument("--build-baseline", action="store_true", help="Create a file integrity baseline for the scanned path.")
    parser.add_argument("--compare-baseline", action="store_true", help="Compare current files against the existing baseline.")
    args = parser.parse_args()

    result = run_scan(
        path=args.path,
        max_size_kb=args.max_size_kb,
        explain_provider=args.explain_provider,
        model=args.model,
        openai_base_url=args.openai_base_url,
        enable_av_checks=args.enable_av_checks,
        use_clamav=args.use_clamav,
        quarantine=args.quarantine,
        build_baseline_flag=args.build_baseline,
        compare_baseline=args.compare_baseline
    )

    print("AegisLoop Guardian scan complete.")
    print(f"Files scanned: {result['files_scanned']}")
    print(f"Findings: {result['score']['finding_count']}")
    print(f"Risk level: {result['score']['risk_level']}")
    print(f"Markdown report: {result['markdown_path']}")
    print(f"JSON results: {result['json_path']}")
    print(f"CSV findings: {REPORTS_DIR / 'latest_guardian_findings.csv'}")
    if result.get("quarantine_results"):
        print(f"Quarantine copies: {len(result['quarantine_results'])}")

if __name__ == "__main__":
    main()
