"""Importación de la red existente desde la salida de la AWS CLI."""
import glob
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import awsimport  # noqa: E402
from copilot import analyze  # noqa: E402

FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "aws")


def texts():
    return [open(f, encoding="utf-8").read() for f in sorted(glob.glob(os.path.join(FIX, "*.json")))]


class AwsImportTest(unittest.TestCase):
    def setUp(self):
        self.r = awsimport.build(texts())
        self.by_label = {}
        for n in self.r["nodes"]:
            self.by_label.setdefault(n["label"], []).append(n)

    def node(self, label):
        return self.by_label[label][0]

    def test_counts_region_and_tiers(self):
        self.assertEqual(self.r["region"], "us-east-1")
        self.assertEqual(self.r["counts"]["Subnets"], 5)
        tiers = {self.node(x)["config"]["tier"] for x in ("pub-a", "app-a", "data-a")}
        self.assertEqual(tiers, {"public", "private", "isolated"})
        self.assertEqual(self.node("app-a")["config"]["az"], "a")

    def test_routes_rules_and_endpoints(self):
        routes = self.by_label["rt-app"][0]["config"]["routes"]
        self.assertIn({"destination": "0.0.0.0/0", "target_type": "nat", "target": "nat-1"}, routes)
        self.assertIn("pl-s3", [r["destination"] for r in routes])
        self.assertEqual(len(self.by_label["rt-app"]), 2)  # una por subnet asociada
        db = self.node("sg-db")["config"]["rules"]
        self.assertEqual(db, [{"direction": "ingress", "protocol": "tcp", "from_port": 5432, "to_port": 5432, "peer": "sg-app",
                               "description": ""}])
        acl = self.node("acl-data")["config"]["rules"]
        self.assertEqual([r["rule_no"] for r in acl], [100])
        self.assertTrue(all(r["rule_no"] != 32767 for r in self.node("NACL por defecto")["config"]["rules"]))
        sm = self.node("Endpoint secretsmanager")
        self.assertEqual(len([e for e in self.r["edges"] if e["source"] == sm["id"]]), 1)  # también en app-b

    def test_nodes_land_inside_their_containers(self):
        a = analyze({"nodes": self.r["nodes"], "edges": self.r["edges"]})
        par = a["parents"]
        ids = {n["id"]: n for n in self.r["nodes"]}
        self.assertEqual(ids[par[self.node("nat-1")["id"]]]["label"], "pub-a")
        self.assertEqual(ids[par[self.node("Endpoint secretsmanager")["id"]]]["label"], "app-a")
        self.assertEqual(ids[par[self.node("pub-a")["id"]]]["type"], "vpc")
        rules = {f["rule"] for f in a["findings"]}
        self.assertIn("SG-OPEN-ADMIN", rules)          # 22 abierto a internet en sg-app
        self.assertNotIn("RTB-GW-ASSOC", rules)         # el Gateway de S3 sí está en la tabla
        self.assertNotIn("NET-NEEDS-SUBNET", rules)     # todo quedó dentro de su subnet
        self.assertNotIn("RTB-PUBLIC-NO-IGW", rules)

    def test_concatenated_and_invalid(self):
        joined = "\n".join(texts())
        self.assertEqual(len(awsimport.build([joined])["nodes"]), len(self.r["nodes"]))
        with self.assertRaises(ValueError):
            awsimport.build(['{"Foo": []}'])
        with self.assertRaises(ValueError):
            awsimport.build(["{no json"])
        self.assertEqual(awsimport.safe_region("us-east-1"), "us-east-1")
        self.assertEqual(awsimport.safe_region("<script>"), "")


if __name__ == "__main__":
    unittest.main()
