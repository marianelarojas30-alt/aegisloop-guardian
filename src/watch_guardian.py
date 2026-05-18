import argparse
import time
from pathlib import Path

from file_collector import collect_files, folder_fingerprint
from guardian import run_scan, ROOT

def main():
    parser = argparse.ArgumentParser(description="Continuously watch a folder and run AegisLoop Guardian when files change.")
    parser.add_argument("--path", default="watched_folder", help="Folder to watch.")
    parser.add_argument("--interval", type=int, default=5, help="Seconds between checks.")
    parser.add_argument("--max-size-kb", type=int, default=512)
    parser.add_argument("--explain-provider", default="none", choices=["none", "ollama", "anthropic", "openai", "gemini"])
    parser.add_argument("--model", default="qwen2.5:7b")
    parser.add_argument("--openai-base-url", default=None)
    parser.add_argument("--enable-av-checks", action="store_true")
    parser.add_argument("--use-clamav", action="store_true")
    parser.add_argument("--quarantine", action="store_true")
    parser.add_argument("--compare-baseline", action="store_true")
    args = parser.parse_args()

    target = Path(args.path)
    if not target.is_absolute():
        target = ROOT / target

    print(f"AegisLoop Guardian watch mode started: {target}")
    print("Press Ctrl+C to stop.")

    previous = None

    try:
        while True:
            try:
                files = collect_files(target, max_size_kb=args.max_size_kb)
                current = folder_fingerprint(files)

                if current != previous:
                    print("Change detected. Running scan...")
                    result = run_scan(
                        path=str(target),
                        max_size_kb=args.max_size_kb,
                        explain_provider=args.explain_provider,
                        model=args.model,
                        openai_base_url=args.openai_base_url,
                        enable_av_checks=args.enable_av_checks,
                        use_clamav=args.use_clamav,
                        quarantine=args.quarantine,
                        compare_baseline=args.compare_baseline
                    )
                    print(f"Risk level: {result['score']['risk_level']} | Findings: {result['score']['finding_count']}")
                    previous = current

                time.sleep(args.interval)
            except Exception as exc:
                print(f"Watch error: {exc}")
                time.sleep(args.interval)
    except KeyboardInterrupt:
        print("Watch mode stopped.")

if __name__ == "__main__":
    main()
