"""Registro de reglas, overrides por proyecto y casos reales (tests/cases/*.json)."""
import glob
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import rules  # noqa: E402
from copilot import analyze  # noqa: E402
from security import CONTROLS  # noqa: E402

CASES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cases")


def rule_ids(a):
    return {f["rule"] for f in a["findings"]}


class RegistryTest(unittest.TestCase):
    def test_registry_has_rules(self):
        reg = {r["id"]: r for r in rules.registry()}
        self.assertGreater(len(reg), 200)
        for rid in ("NET-NEEDS-NAT", "SG-OPEN-ADMIN", "ACC-ROOT-MFA", "GLUE-PII-NO-LF", "RTB-TARGET-NAT", "TAG-MISSING"):
            self.assertIn(rid, reg)
        self.assertTrue(all(r["severity"] in rules.SEVERITIES for r in reg.values()))

    def test_security_controls_reference_existing_rules(self):
        known = {r["id"] for r in rules.registry()}
        missing = sorted({r for *_, rs in CONTROLS for r in rs} - known)
        self.assertEqual(missing, [], "controles de seguridad que apuntan a reglas inexistentes")


class OverridesTest(unittest.TestCase):
    def project(self, overrides=None):
        nodes = [{"id": "q", "type": "sqs", "label": "q", "x": 0, "y": 0, "w": 150, "h": 56, "config": {"dlq": False}},
                 {"id": "k", "type": "kms", "label": "k", "x": 0, "y": 100, "w": 150, "h": 56, "config": {"rotation": False, "key_spec": "Simétrica (SYMMETRIC_DEFAULT)"}}]
        return {"settings": {"rules": overrides or {}}, "nodes": nodes, "edges": []}

    def test_disable_and_change_severity(self):
        base = analyze(self.project())
        self.assertIn("SQS-DLQ", rule_ids(base))
        a = analyze(self.project({"SQS-DLQ": {"enabled": False}, "KMS-ROT": {"severity": "high"}}))
        self.assertNotIn("SQS-DLQ", rule_ids(a))
        kms = next(f for f in a["findings"] if f["rule"] == "KMS-ROT")
        self.assertEqual((kms["severity"], kms["default_severity"]), ("high", "low"))
        ctrl = {c["id"]: c for d in a["posture"]["domains"] for c in d["controls"]}
        self.assertEqual(ctrl["DAT-KMS"]["worst"], "high")

    def test_clean_and_csv_roundtrip(self):
        clean = rules.clean_overrides({"NO-EXISTE": {"enabled": False}, "SQS-DLQ": {"enabled": False, "comment": "dev"},
                                       "KMS-ROT": {"severity": "low"}})  # severidad igual a la de defecto: se ignora
        self.assertEqual(clean, {"SQS-DLQ": {"enabled": False, "comment": "dev"}})
        text = rules.to_csv(clean, {"SQS-DLQ": 3})
        self.assertIn("SQS-DLQ", text)
        edited = text.replace("KMS-ROT,Seguridad,low", "KMS-ROT,Seguridad,low", 1)
        lines = [l for l in edited.splitlines()]
        idx = next(i for i, l in enumerate(lines) if l.startswith("KMS-ROT,"))
        cols = lines[idx].split(",")
        cols[5] = "Alto"  # severidad_proyecto en español
        lines[idx] = ",".join(cols)
        back = rules.from_csv("\n".join(lines))
        self.assertEqual(back["SQS-DLQ"]["enabled"], False)
        self.assertEqual(back["KMS-ROT"]["severity"], "high")
        with self.assertRaises(ValueError):
            rules.from_csv("a,b\n1,2")


class RealCasesTest(unittest.TestCase):
    """Cada archivo de tests/cases describe un escenario real y las reglas que deben (o no) aparecer."""

    def test_cases(self):
        files = sorted(glob.glob(os.path.join(CASES, "*.json")))
        self.assertTrue(files)
        known = {r["id"] for r in rules.registry()}
        for path in files:
            with self.subTest(case=os.path.basename(path)):
                with open(path, encoding="utf-8") as fh:
                    case = json.load(fh)
                got = rule_ids(analyze(case["project"]))
                for rid in case.get("expect", []) + case.get("not_expect", []):
                    self.assertIn(rid, known, f"regla desconocida en el caso: {rid}")
                for rid in case.get("expect", []):
                    self.assertIn(rid, got, case["description"])
                for rid in case.get("not_expect", []):
                    self.assertNotIn(rid, got, case["description"])


if __name__ == "__main__":
    unittest.main()
