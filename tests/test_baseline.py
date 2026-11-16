import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from baseline_manager import build_baseline, compare_to_baseline
from guardian import run_scan


class BaselineTests(unittest.TestCase):
    def test_unavailable_inventory_does_not_report_no_changes(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "baseline.json"
            with self.assertRaisesRegex(ValueError, "--build-baseline"):
                compare_to_baseline([], path)
            for raw in ("{", "{}", '{"files":[{}]}', '{"files":[{"path":"a","sha256":"bad"}]}'):
                with self.subTest(raw=raw):
                    path.write_text(raw)
                    with self.assertRaises(ValueError):
                        compare_to_baseline([], path)
            path.write_text('{"files":[]}')
            self.assertEqual(compare_to_baseline([], path), [])

    def test_failed_build_preserves_prior_inventory(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "baseline.json"
            old = build_baseline([], path)
            with self.assertRaises(FileNotFoundError):
                build_baseline([Path(folder) / "missing.txt"], path)
            self.assertEqual(json.loads(path.read_text()), old)

    def test_combined_flags_compare_before_refreshing(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / "note.txt"
            inventory = root / "baseline.json"
            source.write_text("original")
            build_baseline([source], inventory)
            source.write_text("changed")
            with (patch("guardian.build_baseline", side_effect=lambda files: build_baseline(files, inventory)),
                  patch("guardian.compare_to_baseline", side_effect=lambda files: compare_to_baseline(files, inventory)),
                  patch("guardian.REPORTS_DIR", root), patch("guardian.REGRESSION_PATH", root / "memory.json"),
                  patch("guardian.PROPOSALS_PATH", root / "proposals.json")):
                result = run_scan(str(source), build_baseline_flag=True, compare_baseline=True)
            self.assertIn("BASELINE-MODIFIED", [finding["rule_id"] for finding in result["findings"]])
            self.assertEqual(compare_to_baseline([source], inventory), [])
