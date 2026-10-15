"""Pruebas del detalle del Glue Data Catalog."""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import glue_catalog as gc  # noqa: E402
from copilot import analyze  # noqa: E402

GET_TABLES = {"TableList": [
    {"Name": "clientes", "DatabaseName": "cip_curated", "Owner": "hadoop", "TableType": "EXTERNAL_TABLE",
     "Parameters": {"table_type": "ICEBERG", "metadata_location": "s3://dlz-curated/clientes/metadata/00001.json"},
     "StorageDescriptor": {"Location": "s3://dlz-curated/clientes", "Columns": [
         {"Name": "id_cliente", "Type": "bigint"}, {"Name": "rfc", "Type": "string", "Comment": "RFC del cliente"},
         {"Name": "email", "Type": "string"}]},
     "PartitionKeys": []},
    {"Name": "eventos", "DatabaseName": "cip_raw", "TableType": "EXTERNAL_TABLE",
     "Parameters": {"classification": "json"},
     "StorageDescriptor": {"Location": "s3://dlz-raw/eventos/", "InputFormat": "org.apache.hadoop.mapred.TextInputFormat",
                           "Columns": [{"Name": "payload", "Type": "string"}]},
     "PartitionKeys": [{"Name": "dt", "Type": "string"}]},
]}
GET_DATABASES = {"DatabaseList": [{"Name": "cip_curated", "Description": "Capa curated", "LocationUri": "s3://dlz-curated/"}]}
CSV = """database,table,column,type,partition,comment,format,location,pii
cip_gold,ventas,id_venta,bigint,,,parquet,s3://dlz-gold/ventas/,
cip_gold,ventas,telefono,string,,Celular,,,
cip_gold,ventas,anio,int,yes,,,,
"""


class GlueCatalogTest(unittest.TestCase):
    def test_parse_cli_json(self):
        text = json.dumps(GET_TABLES) + "\n" + json.dumps(GET_DATABASES)  # dos respuestas concatenadas
        cat = gc.parse_import(text, "tablas.json")
        dbs = {d["name"]: d for d in cat["databases"]}
        self.assertEqual(dbs["cip_curated"]["description"], "Capa curated")
        cl = dbs["cip_curated"]["tables"][0]
        self.assertEqual(cl["format"], "Apache Iceberg")
        self.assertTrue(next(c for c in cl["columns"] if c["name"] == "rfc")["pii"])
        self.assertFalse(next(c for c in cl["columns"] if c["name"] == "id_cliente")["pii"])
        ev = dbs["cip_raw"]["tables"][0]
        self.assertEqual(ev["format"], "Hive - JSON")
        self.assertEqual(ev["partition_keys"][0]["name"], "dt")

    def test_parse_csv(self):
        cat = gc.parse_import(CSV, "catalogo.csv")
        t = cat["databases"][0]["tables"][0]
        self.assertEqual((t["name"], t["format"], t["location"]), ("ventas", "Hive - Parquet", "s3://dlz-gold/ventas/"))
        self.assertEqual([p["name"] for p in t["partition_keys"]], ["anio"])
        self.assertTrue(next(c for c in t["columns"] if c["name"] == "telefono")["pii"])

    def test_merge_keeps_manual_data(self):
        old = gc.parse_import(json.dumps(GET_TABLES))
        t = old["databases"][0]["tables"][0]
        t["description"], t["sensitivity"] = "Clientes únicos", "Restringida (PII / financiera)"
        t["columns"][0]["pii"] = True
        merged = gc.merge(old, gc.parse_import(json.dumps(GET_TABLES)))
        t2 = merged["databases"][0]["tables"][0]
        self.assertEqual(t2["description"], "Clientes únicos")
        self.assertEqual(t2["sensitivity"], "Restringida (PII / financiera)")
        self.assertTrue(t2["columns"][0]["pii"])

    def test_invalid_inputs(self):
        with self.assertRaises(ValueError):
            gc.parse_import("{}", "x.json")
        with self.assertRaises(ValueError):
            gc.parse_import("a,b\n1,2", "x.csv")

    def test_terraform(self):
        tf = gc.terraform(gc.parse_import(json.dumps(GET_TABLES)), "111111111111")
        self.assertIn('resource "aws_glue_catalog_database" "cip_curated"', tf)
        self.assertIn('resource "aws_glue_catalog_table" "cip_curated_clientes"', tf)
        self.assertIn("iceberg_input", tf)
        self.assertIn('name = "dt"', tf)

    def test_copilot_rules_and_iam(self):
        cat = gc.parse_import(json.dumps(GET_TABLES))
        nodes = [{"id": "gdc", "type": "glue_catalog", "label": "Catálogo", "x": 0, "y": 0, "w": 150, "h": 56,
                  "config": {"catalog": cat, "governance": "Sólo IAM", "encryption": "No"}},
                 {"id": "fn", "type": "lambda", "label": "fn", "x": 300, "y": 0, "w": 150, "h": 56, "config": {}}]
        a = analyze({"nodes": nodes, "edges": [{"id": "e", "source": "fn", "target": "gdc", "access": "read"}]})
        rules = {f["rule"] for f in a["findings"]}
        for r in ("GLUE-CAT-ENC", "GLUE-PII-NO-LF", "GLUE-SENSITIVITY", "GLUE-DOC"):
            self.assertIn(r, rules)
        self.assertNotIn("GLUE-NO-PARTITION", rules)  # 'eventos' es JSON pero está particionada por dt
        cat["databases"][1]["tables"][0]["partition_keys"] = []
        self.assertIn("GLUE-NO-PARTITION", {f["rule"] for f in analyze({"nodes": nodes, "edges": []})["findings"]})
        res = a["plans"]["e"]["identity"][0]["Resource"]
        self.assertTrue(any(r.endswith(":table/cip_curated/*") for r in res))
        self.assertIn("aws_glue_catalog_table", a["glue_catalogs"]["gdc"]["terraform"])


if __name__ == "__main__":
    unittest.main()
