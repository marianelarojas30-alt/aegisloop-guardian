from pathlib import Path
from typing import Dict, Any, List
import re
import json

ROOT = Path(__file__).resolve().parents[1]
IOC_DENYLIST = ROOT / "rules" / "iocs" / "local_ioc_denylist.json"

URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
BTC_RE = re.compile(r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}\b")
ETH_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")

def extract_iocs_from_text(text: str) -> Dict[str, List[str]]:
    urls = sorted(set(URL_RE.findall(text)))
    emails = sorted(set(EMAIL_RE.findall(text)))
    ips = sorted(set(IP_RE.findall(text)))
    domains = sorted(set(DOMAIN_RE.findall(text)))
    btc = sorted(set(BTC_RE.findall(text)))
    eth = sorted(set(ETH_RE.findall(text)))

    # remove domains already contained in email local extraction? keep simple for transparency
    return {
        "urls": urls,
        "emails": emails,
        "ips": ips,
        "domains": domains,
        "crypto_wallets": btc + eth,
    }

def load_local_ioc_denylist() -> Dict[str, Any]:
    try:
        return json.loads(IOC_DENYLIST.read_text(encoding="utf-8"))
    except Exception:
        return {"domains": [], "urls": [], "ips": [], "emails": [], "crypto_wallets": []}

def ioc_findings(path: Path, text: str) -> List[Dict[str, Any]]:
    extracted = extract_iocs_from_text(text)
    denylist = load_local_ioc_denylist()
    findings = []

    for key in ["urls", "domains", "ips", "emails", "crypto_wallets"]:
        found_values = {v.lower(): v for v in extracted.get(key, [])}
        for item in denylist.get(key, []):
            value = str(item.get("value", "")).lower()
            if value and value in found_values:
                findings.append({
                    "file": str(path),
                    "rule_id": f"IOC-{key.upper()}",
                    "label": f"Local IOC match: {key}",
                    "severity": item.get("severity", "high"),
                    "category": "ioc_match",
                    "reason": f"Matched local IOC denylist entry: {item.get('label', value)}",
                    "matched_pattern": found_values[value]
                })

    # Report suspicious presence of crypto wallets even if not in denylist
    for wallet in extracted.get("crypto_wallets", []):
        findings.append({
            "file": str(path),
            "rule_id": "IOC-CRYPTO-WALLET",
            "label": "Crypto wallet indicator",
            "severity": "medium",
            "category": "crypto_payment_indicator",
            "reason": "Crypto wallet strings can be legitimate but may indicate extortion, scam, or payment-redirection risk.",
            "matched_pattern": wallet
        })

    return findings
