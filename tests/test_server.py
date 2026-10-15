"""Prueba de humo del servidor HTTP y del almacenamiento JSON."""
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app  # noqa: E402
from storage import Store  # noqa: E402


class ServerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        app.STORE = Store(cls.tmp.name)
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
        cls.base = f"http://127.0.0.1:{cls.srv.server_address[1]}"
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        cls.tmp.cleanup()

    def call(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method,
                                     headers={"Content-Type": "application/json"} if data else {})
        with urllib.request.urlopen(req, timeout=10) as r:
            raw = r.read().decode()
            return r.status, (json.loads(raw) if "json" in r.headers.get("Content-Type", "") else raw)

    def test_flow(self):
        status, html = self.call("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn("InfraTrack", html)
        _, cat = self.call("GET", "/api/catalog")
        self.assertTrue(cat["components"])

        status, p = self.call("POST", "/api/projects", {"sample": True})
        self.assertEqual(status, 201)
        pid = p["id"]
        _, full = self.call("GET", f"/api/projects/{pid}")
        full["nodes"][0]["terraformed"] = True
        _, saved = self.call("PUT", f"/api/projects/{pid}", full)
        self.assertEqual(saved["rev"], full["rev"] + 1)

        # Guardar con una revisión vieja produce conflicto
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.call("PUT", f"/api/projects/{pid}", full)
        self.assertEqual(ctx.exception.code, 409)

        _, a = self.call("POST", "/api/analyze", full)
        self.assertIn("findings", a)
        _, md = self.call("GET", f"/api/projects/{pid}/export.md")
        self.assertIn("# ", md)
        _, lst = self.call("GET", "/api/projects")
        self.assertEqual(lst[0]["id"], pid)

        # Duplicar para otro ambiente y comparar
        status, pre = self.call("POST", f"/api/projects/{pid}/duplicate",
                                {"environment": "pre", "account_map": {"123456789012": "954066442156"}})
        self.assertEqual(status, 201)
        _, pre_full = self.call("GET", f"/api/projects/{pre['id']}")
        acct = next(n for n in pre_full["nodes"] if n["type"] == "account")
        self.assertEqual(acct["config"]["account_id"], "954066442156")
        self.assertEqual(acct["config"]["root_mfa"], "Sin confirmar")
        self.assertFalse(any(n.get("terraformed") for n in pre_full["nodes"]))
        _, diff = self.call("GET", f"/api/compare/{pid}/{pre['id']}")
        self.assertTrue(diff["changed"])  # cambia el estado de terraform
        self.assertEqual(diff["only_a"], [])
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.call("POST", f"/api/projects/{pid}/duplicate", {"environment": "pro", "account_map": {"1": "abc"}})
        self.assertEqual(ctx.exception.code, 400)

    def test_glue_import(self):
        text = '{"TableList": [{"Name": "t1", "DatabaseName": "db1", "StorageDescriptor": {"Columns": [{"Name": "email", "Type": "string"}]}}]}'
        _, r = self.call("POST", "/api/glue/import", {"text": text, "filename": "t.json", "existing": {}})
        self.assertEqual(r["stats"]["tables"], 1)
        self.assertTrue(r["catalog"]["databases"][0]["tables"][0]["columns"][0]["pii"])
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.call("POST", "/api/glue/import", {"text": "nada", "filename": "x.json"})
        self.assertEqual(ctx.exception.code, 400)

    def test_path_traversal_blocked(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.call("GET", "/../app.py")
        self.assertEqual(ctx.exception.code, 404)
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.call("GET", "/api/projects/..%2F..%2Fetc")
        self.assertEqual(ctx.exception.code, 404)


if __name__ == "__main__":
    unittest.main()
