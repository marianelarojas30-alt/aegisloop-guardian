# AegisLoop Guardian

AegisLoop Guardian is a model-agnostic defensive security scanner and AI-safety monitoring prototype.

It combines antivirus-style local file inspection with AI-agent workspace scanning.

## Important truth

AegisLoop Guardian is **not a replacement for a commercial antivirus, EDR, or incident-response platform**.

A real enterprise antivirus needs large malware-signature databases, behavior telemetry, sandboxing, kernel/process monitoring, cloud reputation, and professional threat-intelligence feeds.

AegisLoop Guardian is a defensive prototype that implements practical antivirus-style components in a transparent local tool.

## What it can do

AegisLoop Guardian v5 includes:

- static file scanning
- IOC extraction: URLs, domains, IPs, emails, crypto wallets
- local IOC denylist checks
- SHA256 / SHA1 / MD5 hashing
- local malicious-hash denylist checks
- suspicious-code pattern detection
- worm-like behavior indicators
- entropy / obfuscation scoring
- file-type and extension mismatch checks
- double-extension and deceptive filename detection
- macro/document lure indicators
- baseline inventory and file integrity comparison
- financial-fraud and phishing pattern checks
- prompt-injection and unsafe LLM-agent behavior checks
- optional ClamAV integration if `clamscan` is installed
- continuous folder watching
- safe quarantine-by-copy
- regression memory
- human-reviewed rule proposals
- optional LLM explanations from Ollama, Claude, OpenAI-compatible models, or Gemini

## What it never does

AegisLoop Guardian does **not**:

- execute suspicious files
- detonate malware
- attack systems
- steal credentials
- delete user files automatically
- upload private files
- scan devices without authorization
- bypass security controls

## Model-agnostic AI explanation layer

The scanner works with no LLM:

```bash
python src/guardian.py --path tests/safe_test_files
```

Optional explanation providers:

```text
none
ollama
anthropic
openai
gemini
```

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python src/guardian.py --path tests/safe_test_files
```

## Stronger antivirus-style scan

```bash
python src/guardian.py --path tests/safe_test_files --enable-av-checks
```

## Build a baseline

```bash
python src/guardian.py --path watched_folder --enable-av-checks --build-baseline
```

## Compare against baseline

```bash
python src/guardian.py --path watched_folder --enable-av-checks --compare-baseline
```

## Optional ClamAV scan

Install ClamAV separately, then run:

```bash
python src/guardian.py --path tests/safe_test_files --enable-av-checks --use-clamav
```

If ClamAV is not installed, AegisLoop will continue with its own local checks.

## Safe quarantine-by-copy

This does **not delete** the original file. It copies flagged files into `quarantine/` for review.

```bash
python src/guardian.py --path tests/safe_test_files --enable-av-checks --quarantine
```

## Continuous watch mode

```bash
python src/watch_guardian.py --path watched_folder --interval 5 --enable-av-checks
```

## Optional local Ollama explanation

```bash
ollama pull qwen2.5:7b
python src/guardian.py --path tests/safe_test_files --enable-av-checks --explain-provider ollama --model qwen2.5:7b
```

## Optional Claude explanation

```bash
export ANTHROPIC_API_KEY="your_key_here"
python src/guardian.py --path tests/safe_test_files --enable-av-checks --explain-provider anthropic --model claude-3-5-haiku-latest
```

## Reports

Markdown report:

```text
reports/latest_guardian_report.md
```

JSON results:

```text
reports/latest_guardian_results.json
```

CSV findings:

```text
reports/latest_guardian_findings.csv
```

Quarantine folder:

```text
quarantine/
```

Regression memory:

```text
regression_memory/findings_memory.json
```

## Repository structure

```text
aegisloop-guardian/
├── README.md
├── VERSION
├── hashes/
│   └── known_bad_hashes.json
├── quarantine/
├── rules/
│   ├── suspicious_code_patterns.json
│   ├── worm_like_patterns.json
│   ├── financial_fraud_patterns.json
│   └── llm_agent_risk_patterns.json
├── src/
│   ├── guardian.py
│   ├── watch_guardian.py
│   ├── av_scanner.py
│   ├── ioc_extractor.py
│   ├── file_name_analyzer.py
│   ├── baseline_manager.py
│   ├── csv_exporter.py
│   ├── hash_utils.py
│   ├── entropy_analyzer.py
│   ├── file_type_analyzer.py
│   ├── clamav_adapter.py
│   ├── quarantine_manager.py
│   ├── static_scanner.py
│   ├── risk_scorer.py
│   ├── rule_updater.py
│   ├── llm_explainer.py
│   └── report_generator.py
└── tests/
    └── safe_test_files/
```

## Research direction

AegisLoop Guardian explores whether a transparent local defensive agent can combine:

1. antivirus-style static file inspection
2. social-engineering and fraud detection
3. prompt-injection and LLM-agent risk detection
4. continuous monitoring
5. safe human-reviewed improvement loops

## Status

Stronger defensive prototype. Use only on files and folders you own or are authorized to inspect.
