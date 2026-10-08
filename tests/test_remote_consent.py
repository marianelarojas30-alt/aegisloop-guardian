import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import guardian  # noqa: E402
import llm_explainer  # noqa: E402
from llm_explainer import explain_findings, is_remote_provider  # noqa: E402

FINDING = [{"rule_id": "R1", "label": "x", "severity": "high", "category": "c", "reason": "r", "matched_pattern": "p", "file": "/a/b.txt"}]


class IsRemoteProviderTests(unittest.TestCase):
    def test_classification(self):
        cases = [
            ("none", None, False), ("ollama", None, False),
            ("anthropic", None, True), ("gemini", None, True),
            ("openai", None, True),
            ("openai", "http://127.0.0.1:1234/v1/chat/completions", False),
            ("openai", "http://localhost:8080/v1", False),
            ("openai", "http://[::1]:8080/v1", False),
            ("openai", "http://127.0.0.1@evil.example/v1", True),
            ("openai", "http://localhost.evil.example/v1", True),
        ]
        for provider, url, expected in cases:
            with self.subTest(provider=provider, url=url):
                self.assertEqual(is_remote_provider(provider, url), expected)


class ExplainerConsentTests(unittest.TestCase):
    def test_remote_provider_refused_without_consent_before_any_network_call(self):
        with mock.patch.object(llm_explainer, "requests") as fake_requests:
            for provider in ("anthropic", "gemini", "openai"):
                with self.subTest(provider=provider):
                    with self.assertRaises(ValueError):
                        explain_findings(FINDING, provider=provider)
            fake_requests.post.assert_not_called()
            fake_requests.Session.assert_not_called()

    def test_local_provider_needs_no_consent(self):
        with mock.patch.object(llm_explainer, "_explain_with_ollama", return_value="ok") as fake:
            self.assertEqual(explain_findings(FINDING, provider="ollama"), "ok")
            fake.assert_called_once()

    def test_remote_provider_runs_with_consent(self):
        with mock.patch.object(llm_explainer, "_explain_with_anthropic", return_value="ok") as fake:
            self.assertEqual(explain_findings(FINDING, provider="anthropic", allow_remote=True), "ok")
            fake.assert_called_once()


class RunScanConsentTests(unittest.TestCase):
    def test_refuses_before_scanning_or_writing(self):
        with tempfile.TemporaryDirectory() as d:
            with mock.patch.object(guardian, "collect_files") as collect, \
                 mock.patch.object(guardian, "quarantine_flagged_files") as quarantine, \
                 mock.patch.object(guardian, "generate_report") as report:
                with self.assertRaises(ValueError):
                    guardian.run_scan(d, explain_provider="anthropic", quarantine=True)
                collect.assert_not_called()
                quarantine.assert_not_called()
                report.assert_not_called()


if __name__ == "__main__":
    unittest.main()
