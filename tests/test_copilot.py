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



class NetworkControlsTest(unittest.TestCase):
    def vpc(self):
        return [
            N("vpc", "vpc", 0, 0, 1000, 700, cidr="10.0.0.0/16"),
            N("pub", "subnet", 20, 50, 450, 250, tier="public", cidr="10.0.0.0/24", az="a"),
            N("app", "subnet", 20, 350, 450, 300, tier="private", cidr="10.0.1.0/24", az="a"),
            N("data", "subnet", 500, 350, 450, 300, tier="private", cidr="10.0.2.0/24", az="b"),
            N("igw", "igw", 480, 10, 100, 40), N("nat", "nat", 40, 100),
            N("fn", "lambda", 40, 400), N("db", "rds", 520, 400, engine="PostgreSQL"),
        ]

    def test_sg_missing_and_open_rules(self):
        nodes = self.vpc() + [N("sg", "sg", 520, 600, group_name="sg-db", rules=[
            {"direction": "ingress", "protocol": "tcp", "from_port": 22, "to_port": 22, "peer": "0.0.0.0/0"}])]
        a = analyze({"nodes": nodes, "edges": [E("e", "fn", "db", "network"), E("s", "sg", "db")]})
        r = rules(a)
        self.assertIn("SG-OPEN-ADMIN", r)
        self.assertIn("SG-MISSING-RULES", r)
        sug = a["sg_suggestions"]["sg"][0]
        self.assertEqual((sug["direction"], sug["from_port"], sug["peer"]), ("ingress", 5432, "sg-fn"))
        # La regla del Copilot usa el nombre del SG real
        self.assertEqual(a["plans"]["e"]["network"][0]["sg"], "sg-db")

    def test_sg_rule_by_cidr_covers_requirement(self):
        nodes = self.vpc() + [N("sg", "sg", 520, 600, group_name="sg-db", rules=[
            {"direction": "ingress", "protocol": "tcp", "from_port": 5432, "to_port": 5432, "peer": "10.0.0.0/16"}])]
        a = analyze({"nodes": nodes, "edges": [E("e", "fn", "db", "network"), E("s", "sg", "db")]})
        self.assertNotIn("SG-MISSING-RULES", rules(a))

    def test_nacl_needs_ephemeral_ports(self):
        nacl = N("acl", "nacl", 750, 400, rules=[
            {"rule_no": 100, "direction": "ingress", "action": "allow", "protocol": "tcp",
             "from_port": 5432, "to_port": 5432, "cidr": "10.0.1.0/24"}])
        a = analyze({"nodes": self.vpc() + [nacl], "edges": [E("e", "fn", "db", "network")]})
        self.assertIn("NACL-BLOCK", rules(a))
        nacl["config"]["rules"].append({"rule_no": 100, "direction": "egress", "action": "allow", "protocol": "tcp",
                                        "from_port": 1024, "to_port": 65535, "cidr": "10.0.1.0/24"})
        a = analyze({"nodes": self.vpc() + [nacl], "edges": [E("e", "fn", "db", "network")]})
        self.assertNotIn("NACL-BLOCK", rules(a))

    def test_nacl_deny_before_allow(self):
        nacl = N("acl", "nacl", 750, 400, rules=[
            {"rule_no": 90, "direction": "ingress", "action": "deny", "protocol": "all", "cidr": "10.0.1.0/24"},
            {"rule_no": 100, "direction": "ingress", "action": "allow", "protocol": "all", "cidr": "0.0.0.0/0"},
            {"rule_no": 100, "direction": "egress", "action": "allow", "protocol": "all", "cidr": "0.0.0.0/0"}])
        a = analyze({"nodes": self.vpc() + [nacl], "edges": [E("e", "fn", "db", "network")]})
        self.assertIn("NACL-BLOCK", rules(a))

    def test_route_tables(self):
        nodes = self.vpc() + [
            N("rpub", "rtb", 250, 100, routes=[]),
            N("rapp", "rtb", 250, 400, routes=[{"destination": "0.0.0.0/0", "target_type": "igw"}]),
            N("b", "s3", 1200, 100)]
        a = analyze({"nodes": nodes, "edges": [E("e", "fn", "b", "read")]})
        r = rules(a)
        self.assertIn("RTB-PUBLIC-NO-IGW", r)
        self.assertIn("RTB-PRIVATE-IGW", r)
        self.assertIn("NET-PUBLIC-NO-IP", r)

    def test_gateway_endpoint_without_route(self):
        nodes = self.vpc() + [
            N("rapp", "rtb", 250, 400, routes=[{"destination": "0.0.0.0/0", "target_type": "nat"}]),
            N("ep", "vpce", 300, 500, endpoint_type="Gateway", services=["s3"]), N("b", "s3", 1200, 100)]
        a = analyze({"nodes": nodes, "edges": [E("e", "fn", "b", "read")]})
        self.assertIn("RTB-GW-ASSOC", rules(a))
        nodes[-3]["config"]["routes"].append({"destination": "pl-s3", "target_type": "vpce"})
        a = analyze({"nodes": nodes, "edges": [E("e", "fn", "b", "read")]})
        self.assertNotIn("RTB-GW-ASSOC", rules(a))
        self.assertTrue(any("VPC endpoint" in x for x in a["plans"]["e"]["path"]))


class NewServicesTest(unittest.TestCase):
    def test_new_services(self):
        nodes = [
            N("vpc", "vpc", 0, 0, 900, 600, cidr="10.0.0.0/16"),
            N("priv", "subnet", 20, 50, 400, 500, tier="private", cidr="10.0.1.0/24", az="a"),
            N("db", "rds", 40, 100, engine="MySQL"), N("ar", "apprunner", 1000, 100),
            N("mq", "mq", 40, 250, engine="RabbitMQ", deployment="Single-instance", public=True),
            N("dx", "dx", 1000, 400, redundancy="Una conexión (sin SLA)"),
            N("eb", "beanstalk", 220, 100, deploy_policy="All at once", env_type="Single instance"),
            N("bt", "batch", 220, 250, compute="Fargate Spot"), N("ga", "globalaccel", -300, 100),
        ]
        a = analyze({"settings": {"environment": "prod"}, "nodes": nodes,
                     "edges": [E("e1", "ar", "db", "network"), E("e2", "ga", "db")]})
        r = rules(a)
        for rule in ("NET-APPRUNNER-CONNECTOR", "SEC-DATA-PUBLIC", "MQ-SINGLE", "DX-SINGLE", "EB-DEPLOY", "EB-SINGLE",
                     "BATCH-SPOT-RETRY", "GA-ENDPOINT"):
            self.assertIn(rule, r)
        self.assertEqual(analyze({"nodes": [N("x", "lambda", 0, 0), N("b", "batch", 300, 0)],
                                  "edges": [E("e", "x", "b", "invoke")]})["plans"]["e"]["identity"][0]["Action"][-1],
                         "batch:TerminateJob")

if __name__ == "__main__":
    unittest.main()
