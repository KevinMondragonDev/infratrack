"""Importación de estado y plan de Terraform."""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tfstate  # noqa: E402
from copilot import analyze  # noqa: E402
from samples import sample_project  # noqa: E402

SHOW = {"format_version": "1.0", "values": {"root_module": {
    "resources": [
        {"address": "aws_s3_bucket.raw", "mode": "managed", "type": "aws_s3_bucket", "name": "raw",
         "values": {"bucket": "pedidos-data-lake-raw", "arn": "arn:aws:s3:::pedidos-data-lake-raw"}},
        {"address": "aws_db_instance.db", "mode": "managed", "type": "aws_db_instance", "name": "db",
         "values": {"name": "BD pedidos", "password": "supersecreto", "arn": "arn:aws:rds:us-east-1:1:db:bd"},
         "sensitive_values": {"password": True}},
        {"address": "data.aws_caller_identity.me", "mode": "data", "type": "aws_caller_identity", "name": "me", "values": {}}],
    "child_modules": [{"resources": [
        {"address": "module.net.aws_vpc.main", "mode": "managed", "type": "aws_vpc", "name": "main",
         "values": {"cidr_block": "10.20.0.0/16", "tags": {"Name": "VPC principal"}}},
        {"address": "module.net.aws_cloudwatch_log_group.x", "mode": "managed", "type": "aws_cloudwatch_log_group", "name": "x", "values": {}},
        {"address": "module.net.aws_sqs_queue.extra", "mode": "managed", "type": "aws_sqs_queue", "name": "extra",
         "values": {"name": "cola-extra"}}]}]}}}

V4 = {"version": 4, "resources": [
    {"module": "module.app", "mode": "managed", "type": "aws_lambda_function", "name": "fn",
     "instances": [{"index_key": "a", "attributes": {"function_name": "procesa-pedidos", "arn": "arn:aws:lambda:x"}},
                   {"index_key": 1, "attributes": {"function_name": "otra"}}]},
    {"mode": "managed", "type": "aws_lb", "name": "nlb", "instances": [{"attributes": {"name": "edge", "load_balancer_type": "network"}}]}]}

PLAN = {"format_version": "1.2", "resource_changes": [
    {"address": "aws_db_instance.db", "mode": "managed", "type": "aws_db_instance", "name": "db",
     "change": {"actions": ["delete", "create"], "after": {"name": "BD pedidos"}}},
    {"address": "aws_sqs_queue.q", "mode": "managed", "type": "aws_sqs_queue", "name": "q",
     "change": {"actions": ["update"], "after": {"name": "pedidos-cola-pedidos"}}},
    {"address": "aws_s3_bucket.old", "mode": "managed", "type": "aws_s3_bucket", "name": "old",
     "change": {"actions": ["delete"], "before": {"bucket": "bucket-viejo"}}},
    {"address": "aws_iam_role.r", "mode": "managed", "type": "aws_iam_role", "name": "r", "change": {"actions": ["no-op"]}}]}


def rules(a):
    return {f["rule"] for f in a["findings"]}


class TfStateTest(unittest.TestCase):
    def test_show_json_matching_and_secrets(self):
        r = tfstate.analyze_text(sample_project(), json.dumps(SHOW))
        self.assertEqual(r["kind"], "state")
        self.assertEqual({(m["node_id"], m["address"]) for m in r["matched"]},
                         {("raw", "aws_s3_bucket.raw"), ("rds", "aws_db_instance.db"), ("vpc1", "module.net.aws_vpc.main")})
        self.assertEqual([x["name"] for x in r["only_tf"]], ["cola-extra"])
        self.assertEqual(r["unmapped_types"], ["aws_cloudwatch_log_group"])
        self.assertNotIn("supersecreto", json.dumps(r))
        self.assertNotIn("data.aws_caller_identity.me", json.dumps(r))

    def test_tfstate_v4(self):
        r = tfstate.parse(json.dumps(V4))
        addrs = {x["address"]: x["component"] for x in r["resources"]}
        self.assertEqual(addrs, {'module.app.aws_lambda_function.fn["a"]': "lambda", "module.app.aws_lambda_function.fn[1]": "lambda",
                                 "aws_lb.nlb": "nlb"})

    def test_match_by_tf_address_first(self):
        p = sample_project()
        next(n for n in p["nodes"] if n["id"] == "curated")["tf_address"] = "aws_s3_bucket.raw"
        r = tfstate.analyze_text(p, json.dumps(SHOW))
        self.assertIn(("curated", "aws_s3_bucket.raw"), {(m["node_id"], m["address"]) for m in r["matched"]})

    def test_plan_and_copilot(self):
        p = sample_project()
        r = tfstate.analyze_text(p, json.dumps(PLAN))
        self.assertEqual(r["kind"], "plan")
        actions = {m["node_id"]: m["action"] for m in r["matched"]}
        self.assertEqual(actions, {"rds": "replace", "sqs": "update"})
        p["tf_plan"] = {"changes": actions, "unmatched": r["only_tf"]}
        a = analyze(p)
        destroy = [f for f in a["findings"] if f["rule"] == "TF-PLAN-DESTROY"]
        self.assertEqual(len(destroy), 2)  # RDS reemplazado + bucket viejo destruido
        self.assertIn("TF-PLAN", rules(a))

    def test_state_findings(self):
        p = sample_project()
        r = tfstate.analyze_text(p, json.dumps(SHOW))
        p["tf_import"] = {"only_tf": r["only_tf"], "only_diagram_ids": [x["node_id"] for x in r["only_diagram"]]}
        a = analyze(p)
        self.assertIn("TF-ONLY-IN-STATE", rules(a))
        self.assertIn("TF-NOT-IN-STATE", rules(a))  # p. ej. la VPC 'Privada A' está terraformada pero no en este estado

    def test_invalid(self):
        for bad in ("no json", "[]", json.dumps({"hola": 1})):
            with self.assertRaises(ValueError):
                tfstate.parse(bad)


if __name__ == "__main__":
    unittest.main()
