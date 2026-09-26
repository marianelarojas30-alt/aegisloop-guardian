from typing import List, Dict, Any, Optional
from pathlib import Path
from urllib.parse import urlparse
import json
import os
import requests

DEFAULT_MODELS = {
    "ollama": "qwen3.5:4b",
    "anthropic": "claude-haiku-4-5-20251001",
    "openai": "gpt-6-luna",
    "gemini": "gemini-3.8-flash",
}

def _build_prompt(findings: List[Dict[str, Any]]) -> str:
    compact = [
        {
            "rule_id": f.get("rule_id"),
            "label": f.get("label"),
            "severity": f.get("severity"),
            "category": f.get("category"),
            "reason": f.get("reason"),
            "matched_pattern": f.get("matched_pattern"),
            "file": Path(str(f.get("file") or "")).name
        }
        for f in findings[:25]
    ]

    return f"""
You are a defensive cybersecurity assistant.

Explain the following local scanner findings in plain English.
Do not provide offensive instructions.
Do not provide exploit steps.
Focus on:
1. What was detected
2. Why it may matter
3. What a safe user should do next
4. What should be verified manually

Findings:
{json.dumps(compact, indent=2)}
""".strip()


def explain_findings(
    findings: List[Dict[str, Any]],
    provider: str = "none",
    model: Optional[str] = None,
    openai_base_url: Optional[str] = None,
) -> str:
    """
    Provider-agnostic optional explanation layer.

    The scanner does not require an LLM.
    Use provider='none' for pure local rule-based scanning.

    Supported providers:
    - none
    - ollama
    - anthropic
    - openai
    - gemini
    """
    provider = (provider or "none").lower().strip()

    if not findings:
        return "No findings to explain."

    if provider == "none":
        return ""

    prompt = _build_prompt(findings)

    if provider == "ollama":
        return _explain_with_ollama(prompt, model or DEFAULT_MODELS["ollama"])

    if provider == "anthropic":
        return _explain_with_anthropic(prompt, model or DEFAULT_MODELS["anthropic"])

    if provider == "openai":
        return _explain_with_openai_compatible(
            prompt,
            model or DEFAULT_MODELS["openai"],
            openai_base_url or "https://api.openai.com/v1/chat/completions"
        )

    if provider == "gemini":
        return _explain_with_gemini(prompt, model or DEFAULT_MODELS["gemini"])

    return f"Unsupported explanation provider: {provider}"


def _explain_with_ollama(prompt: str, model: str) -> str:
    try:
        session = requests.Session()
        session.trust_env = False
        response = session.post(
            "http://127.0.0.1:11434/api/generate",
            json={
                "model": model,
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0.0}
            },
            timeout=180
        )
        response.raise_for_status()
        return response.json().get("response", "")
    except Exception as exc:
        return f"Ollama explanation unavailable: {exc}"


def _explain_with_anthropic(prompt: str, model: str) -> str:
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        return "Anthropic explanation unavailable: ANTHROPIC_API_KEY is not set."

    try:
        response = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": model,
                "max_tokens": 800,
                "temperature": 0,
                "messages": [
                    {"role": "user", "content": prompt}
                ],
            },
            timeout=180
        )
        response.raise_for_status()
        data = response.json()
        parts = data.get("content", [])
        text_parts = [p.get("text", "") for p in parts if p.get("type") == "text"]
        return "\n".join(text_parts).strip()
    except Exception as exc:
        return f"Anthropic explanation unavailable: {exc}"


def _explain_with_openai_compatible(prompt: str, model: str, base_url: str) -> str:
    api_key = os.getenv("OPENAI_API_KEY", "")
    headers = {"content-type": "application/json"}
    if api_key:
        headers["authorization"] = f"Bearer {api_key}"

    try:
        session = requests.Session()
        try:
            host = (urlparse(base_url).hostname or "").lower()
        except ValueError:
            host = ""
        if host in {"127.0.0.1", "localhost", "::1"}:
            session.trust_env = False
        payload = {
            "model": model,
            "messages": [
                {
                    "role": "system",
                    "content": "You are a defensive cybersecurity assistant. Do not provide offensive instructions."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
        }
        if model.lower().startswith("gpt-6"):
            payload["reasoning_effort"] = "none"
        else:
            payload["temperature"] = 0

        response = session.post(
            base_url,
            headers=headers,
            json=payload,
            timeout=180
        )
        response.raise_for_status()
        data = response.json()
        return data["choices"][0]["message"]["content"].strip()
    except Exception as exc:
        return f"OpenAI-compatible explanation unavailable: {exc}"


def _explain_with_gemini(prompt: str, model: str) -> str:
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        return "Gemini explanation unavailable: GEMINI_API_KEY is not set."

    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"

    try:
        response = requests.post(
            url,
            headers={
                "content-type": "application/json",
                "x-goog-api-key": api_key,
            },
            json={
                "contents": [
                    {
                        "parts": [
                            {"text": prompt}
                        ]
                    }
                ],
                "generationConfig": {
                    "temperature": 0
                }
            },
            timeout=180
        )
        response.raise_for_status()
        data = response.json()
        candidates = data.get("candidates", [])
        if not candidates:
            return ""
        parts = candidates[0].get("content", {}).get("parts", [])
        return "\n".join(p.get("text", "") for p in parts).strip()
    except Exception as exc:
        return f"Gemini explanation unavailable: {exc}"
