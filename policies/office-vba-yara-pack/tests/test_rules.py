"""Compile the pack and check the behavior of every rule without running macros."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import yara


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from scan import KINDS, compile_kind  # noqa: E402


FIXTURES = json.loads((ROOT / "tests" / "fixtures.json").read_text(encoding="utf-8"))
BENIGN = {
    "vba": 'Attribute VB_Name = "Formatting"\nSub FormatReport()\n Range("A1").Value = "Report"\nEnd Sub',
    "pcode": 'FuncDefn (Sub FormatReport())\nLitStr 0x0006 "Report"\nEndSub',
    "xlm": 'NAME ReportStart = MacroSheet!A1\n=SET.VALUE(A1, 42)\n=HALT()',
    "office_xml": '<Relationship Type="https://schemas.example.invalid/hyperlink" TargetMode="External" Target="https://example.invalid/" />',
    "payload": "Illustrative embedded text asset",
    "parser_evidence": "VBA_ANALYSIS_COMPLETE",
}
REQUIRED_META = {
    "id", "description", "version", "updated", "artifact", "category",
    "subcategory", "severity", "confidence", "false_positive",
}


def fixture_bytes(value):
    return bytes.fromhex(value["hex"]) if isinstance(value, dict) else value.encode("utf-8")


class RulePackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.packs = {kind: compile_kind(kind) for kind in KINDS}

    def test_every_rule_metadata_and_fixtures(self):
        seen_ids = set()
        seen_names = set()
        for path in sorted((ROOT / "rules").rglob("*.yar")):
            with self.subTest(file=path.relative_to(ROOT)):
                standalone = yara.compile(filepath=str(path), includes=False, error_on_warning=True)
                [rule] = list(standalone)
                meta = rule.meta
                kind, category, subcategory, _ = path.relative_to(ROOT / "rules").parts
                self.assertTrue(REQUIRED_META.issubset(meta))
                self.assertEqual((meta["artifact"], meta["category"], meta["subcategory"]), (kind, category, subcategory))
                self.assertEqual(set(rule.tags), {kind, category})
                self.assertIn(meta["severity"], {"info", "medium", "high"})
                self.assertIn(meta["confidence"], {"medium", "high"})
                self.assertNotIn(meta["id"], seen_ids)
                self.assertNotIn(rule.identifier, seen_names)
                seen_ids.add(meta["id"])
                seen_names.add(rule.identifier)

                case = FIXTURES[meta["id"]]
                self.assertEqual(case["artifact"], kind)
                positive = fixture_bytes(case["positive"])
                self.assertTrue(standalone.match(data=positive, timeout=2))
                matches = self.packs[kind].match(data=positive, timeout=2)
                self.assertIn(rule.identifier, {match.rule for match in matches})
                self.assertFalse(standalone.match(data=fixture_bytes(BENIGN[kind]), timeout=2))
                if case["negative"] is not None:
                    self.assertFalse(standalone.match(data=fixture_bytes(case["negative"]), timeout=2))
        self.assertEqual(seen_ids, set(FIXTURES))

    def test_wide_source_and_case_insensitivity(self):
        data = 'PRIVATE SUB WORKBOOK_OPEN()'.encode("utf-16le")
        hits = self.packs["vba"].match(data=data, timeout=2)
        self.assertIn("Office_VBA_AutoOpenEvents", {hit.rule for hit in hits})

    def test_cli_routing_and_status(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "sample.bas"
            path.write_text('Shell "cmd.exe /c echo fixture"', encoding="utf-8")
            missing = Path(temp) / "missing.bas"
            cli = [sys.executable, str(ROOT / "tools" / "scan.py")]
            for kind, expected_count in (("vba", 2), ("xlm", 0)):
                with self.subTest(kind=kind):
                    proc = subprocess.run(
                        [*cli, "--kind", kind, str(path)],
                        capture_output=True, text=True, check=True,
                    )
                    output = json.loads(proc.stdout)
                    self.assertEqual(output["status"], "completed")
                    self.assertEqual(len(output["artifacts"][0]["matches"]), expected_count)
            proc = subprocess.run(
                [*cli, "--kind", "vba", str(path), str(missing)],
                capture_output=True, text=True, check=False,
            )
            output = json.loads(proc.stdout)
            self.assertEqual(proc.returncode, 2)
            self.assertEqual(output["status"], "incomplete")
            self.assertEqual([item["status"] for item in output["artifacts"]], ["scanned", "incomplete"])

    def test_cli_rejects_unknown_evidence_and_oversized_inputs(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "evidence.txt"
            path.write_bytes(b"VBA_STOMPING_SUSPECTED\n")
            cli = [sys.executable, str(ROOT / "tools" / "scan.py")]
            proc = subprocess.run(
                [*cli, "--kind", "parser_evidence", str(path)],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(proc.returncode, 2)
            path.write_bytes(b"VBA_STOMPING_SUSPECTED")
            proc = subprocess.run(
                [*cli, "--kind", "parser_evidence", str(path)],
                capture_output=True, text=True, check=True,
            )
            self.assertEqual(json.loads(proc.stdout)["artifacts"][0]["matches"][0]["meta"]["id"], "OFM-EVD-1801")
            with path.open("wb") as stream:
                stream.truncate(16 * 1024 * 1024 + 1)
            proc = subprocess.run(
                [*cli, "--kind", "vba", str(path)],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(proc.returncode, 2)
            self.assertIn("exceeds 16 MiB", json.loads(proc.stdout)["artifacts"][0]["error"])


if __name__ == "__main__":
    unittest.main()
