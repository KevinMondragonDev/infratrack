"""Pruebas del motor de reglas del Copilot (sólo librería estándar)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from catalog import COMPONENTS, missing_required  # noqa: E402
from copilot import analyze  # noqa: E402
from report import build_markdown  # noqa: E402
from samples import sample_project  # noqa: E402


def N(id, type, x, y, w=150, h=56, **cfg):
    return {"id": id, "type": type, "label": id, "x": x, "y": y, "w": w, "h": h, "config": cfg}


def E(id, s, t, access=None, **kw):
    return {"id": id, "source": s, "target": t, "access": access, **kw}


def rules(a):
    return {f["rule"] for f in a["findings"]}


class CatalogTest(unittest.TestCase):
    def test_ids_unique_and_fields_valid(self):
        ids = [c["id"] for c in COMPONENTS]
        self.assertEqual(len(ids), len(set(ids)))
        for c in COMPONENTS:
            keys = [f["key"] for f in c["fields"]]
            self.assertEqual(len(keys), len(set(keys)), c["id"])
            for f in c["fields"]:
                if f["type"] in ("select", "multiselect"):
                    self.assertTrue(f.get("options"), f"{c['id']}.{f['key']}")
                for k in (f.get("show_if") or {}):
                    self.assertIn(k, keys, f"{c['id']}.{f['key']} show_if")

    def test_missing_required(self):
        s3 = next(c for c in COMPONENTS if c["id"] == "s3")
        self.assertIn("Uso del bucket", missing_required(s3, {}))


class SampleTest(unittest.TestCase):
    def test_sample_analyzes_and_reports(self):
        p = sample_project()
        a = analyze(p)
        self.assertIn("EMR-ICEBERG", rules(a))
        self.assertTrue(a["roles"])
        self.assertTrue(a["security_groups"])
        md = build_markdown(p)
        self.assertIn("## Hallazgos del Copilot", md)


class NetworkRulesTest(unittest.TestCase):
    def base(self):
        return [
            N("vpc", "vpc", 0, 0, 900, 600, cidr="10.0.0.0/16"),
            N("pub", "subnet", 20, 50, 400, 200, tier="public", cidr="10.0.0.0/24", az="a"),
            N("priv", "subnet", 20, 300, 400, 250, tier="private", cidr="10.0.1.0/24", az="a"),
        ]

    def test_subnet_outside_vpc_and_overlap(self):
        nodes = self.base() + [N("bad", "subnet", 450, 50, 400, 200, tier="private", cidr="10.1.0.0/24", az="b"),
                               N("dup", "subnet", 450, 300, 400, 250, tier="private", cidr="10.0.1.0/25", az="b")]
        r = rules(analyze({"nodes": nodes, "edges": []}))
        self.assertIn("NET-SUBNET-OUT", r)
        self.assertIn("NET-SUBNET-OVERLAP", r)
        self.assertIn("NET-NO-IGW", r)

    def test_private_lambda_to_s3_without_route(self):
        nodes = self.base() + [N("fn", "lambda", 40, 350), N("b", "s3", 1000, 100)]
        a = analyze({"nodes": nodes, "edges": [E("e", "fn", "b", "read")]})
        self.assertIn("NET-NEEDS-ENDPOINT", rules(a))
        actions = {x for s in a["plans"]["e"]["identity"] for x in s["Action"]}
        self.assertIn("s3:GetObject", actions)
        self.assertNotIn("s3:PutObject", actions)

    def test_gateway_endpoint_satisfies_route(self):
        nodes = self.base() + [N("fn", "lambda", 40, 350), N("b", "s3", 1000, 100),
                               N("ep", "vpce", 250, 350, endpoint_type="Gateway", services=["s3"])]
        a = analyze({"nodes": nodes, "edges": [E("e", "fn", "b", "write")]})
        self.assertNotIn("NET-NEEDS-ENDPOINT", rules(a))

    def test_users_to_private_ec2_unreachable(self):
        nodes = self.base() + [N("u", "users", -300, 0), N("ec2", "ec2", 40, 350, count=2)]
        r = rules(analyze({"nodes": nodes, "edges": [E("e", "u", "ec2")]}))
        self.assertIn("NET-UNREACHABLE", r)
        self.assertIn("LB-NEEDED", r)

    def test_lambda_outside_vpc_to_rds(self):
        nodes = self.base() + [N("fn", "lambda", 1000, 100), N("db", "rds", 40, 350, engine="PostgreSQL")]
        a = analyze({"nodes": nodes, "edges": [E("e", "fn", "db", "network")]})
        self.assertIn("NET-OUTSIDE-TO-PRIVATE", rules(a))
        self.assertIn("HA-MULTI-AZ-REQ", rules(a))

    def test_sqs_to_lambda_puts_permissions_on_lambda(self):
        a = analyze({"nodes": [N("q", "sqs", 0, 0), N("fn", "lambda", 300, 0)],
                     "edges": [E("e", "q", "fn", "invoke")]})
        plan = a["plans"]["e"]
        self.assertEqual(plan["principal"]["node_id"], "fn")
        actions = {x for s in plan["identity"] for x in s["Action"]}
        self.assertIn("sqs:ReceiveMessage", actions)

    def test_dismissed_finding_marked(self):
        p = {"nodes": [N("q", "sqs", 0, 0, dlq=False)], "edges": []}
        fid = next(f["id"] for f in analyze(p)["findings"] if f["rule"] == "SQS-DLQ")
        p["dismissed"] = {fid: {"reason": "dev", "by": "test"}}
        f = next(f for f in analyze(p)["findings"] if f["id"] == fid)
        self.assertTrue(f["dismissed"])


if __name__ == "__main__":
    unittest.main()
