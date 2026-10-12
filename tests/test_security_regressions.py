import csv
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock
import requests
from requests.adapters import BaseAdapter
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import llm_explainer
from quarantine_manager import quarantine_flagged_files
from csv_exporter import export_findings_csv


class Trap(BaseAdapter):
    def __init__(self):
        self.sent = []
    def send(self, request, **kwargs):
        self.sent.append(request)
        r = requests.Response()
        r.request = request
        r.url = request.url
        r.status_code = 307 if len(self.sent) == 1 else 200
        r._content = b'{"choices":[{"message":{"content":"fixture"}}],"response":"fixture"}'
        if len(self.sent) == 1:
            r.headers["Location"] = "https://outside.invalid/collect"
        return r
    def close(self):
        pass


class GuardianSecurityTests(unittest.TestCase):
    def test_local_explanations_do_not_follow_redirects(self):
        for provider in ("openai", "ollama"):
            with self.subTest(provider=provider):
                session = requests.Session()
                trap = Trap()
                session.mount("http://", trap)
                session.mount("https://", trap)
                with mock.patch.object(llm_explainer.requests, "Session", return_value=session):
                    result = llm_explainer.explain_findings([{"file":"synthetic.txt"}], provider=provider,
                        openai_base_url="http://127.0.0.1:1234/v1/chat/completions")
                self.assertEqual(len(trap.sent), 1, "Findings left local endpoint without consent")
                self.assertIn("unavailable", result.lower())
                session.close()

    def test_cloud_key_not_sent_to_local_compatible_server(self):
        with mock.patch.dict(os.environ, {"OPENAI_API_KEY": "synthetic-key"}):
            with mock.patch.object(llm_explainer.requests, "Session") as factory:
                llm_explainer.explain_findings([{"file":"synthetic"}], provider="openai",
                    openai_base_url="http://127.0.0.1:1234/v1/chat/completions")
                headers = factory.return_value.post.call_args.kwargs["headers"]
                self.assertNotIn("authorization", headers)

    def test_csv_untrusted_fields_do_not_become_formulas(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.csv"
            for value in ('=1+1', '+1+1', '-1+1', '@SUM(1)', '\t=1+1', '\r=1+1', '  =1+1'):
                export_findings_csv([{"file": value}], path)
                with path.open(newline="") as f:
                    actual = next(csv.DictReader(f))["file"]
                self.assertTrue(actual.startswith("'"), repr(actual))

    def test_quarantine_preserves_same_name_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files = []
            for name, content in (("a", "first"), ("b", "second")):
                (root / name).mkdir()
                path = root / name / "sample.txt"
                path.write_text(content)
                files.append({"file": str(path)})
            with mock.patch("time.time", return_value=1234):
                copies = quarantine_flagged_files(files, root / "quarantine")
            self.assertEqual(len({c["quarantine_copy"] for c in copies}), 2)
            self.assertEqual([Path(c["quarantine_copy"]).read_text() for c in copies], ["first", "second"])

    @unittest.skipUnless(os.name == "posix", "symlink fixture")
    def test_quarantine_does_not_overwrite_symlink_target(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            src = root / "sample.txt"
            src.write_text("synthetic evidence")
            victim = root / "sentinel.txt"
            victim.write_text("must remain")
            quarantine = root / "quarantine"
            quarantine.mkdir()
            (quarantine / "1234_sample.txt").symlink_to(victim)
            (quarantine / "quarantine_manifest.json").symlink_to(victim)
            with mock.patch("time.time", return_value=1234):
                quarantine_flagged_files([{"file":str(src)}], quarantine)
            self.assertEqual(victim.read_text(), "must remain")

    def test_cloud_key_stays_scoped_to_official_origin(self):
        for url, expected in (("https://api.openai.com/v1/chat/completions", "Bearer synthetic-cloud"),
                              ("https://compatible.invalid/v1/chat/completions", "Bearer synthetic-compatible"),
                              ("http://api.openai.com/v1/chat/completions", "Bearer synthetic-compatible")):
            with self.subTest(url=url), mock.patch.dict(os.environ, {
                "OPENAI_API_KEY": "synthetic-cloud", "OPENAI_COMPATIBLE_API_KEY": "synthetic-compatible"
            }), mock.patch.object(llm_explainer.requests, "Session") as factory:
                llm_explainer.explain_findings([{"file":"synthetic"}], provider="openai",
                                              openai_base_url=url, allow_remote=True)
                self.assertEqual(factory.return_value.post.call_args.kwargs["headers"]["authorization"], expected)

    def test_normal_csv_text_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.csv"
            export_findings_csv([{"file": "normal.txt", "reason": "ordinary text"}], path)
            with path.open(newline="") as f:
                row = next(csv.DictReader(f))
            self.assertEqual(row["file"], "normal.txt")
            self.assertEqual(row["reason"], "ordinary text")
