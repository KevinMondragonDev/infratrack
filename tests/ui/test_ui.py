"""Pruebas de interfaz con Playwright (se omiten si Playwright no está instalado).

    pip install playwright && python -m playwright install chromium
    python -m unittest discover -s tests
"""
import json
import os
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

try:
    from playwright.sync_api import sync_playwright
except ImportError:  # pragma: no cover
    sync_playwright = None

import app  # noqa: E402
from samples import sample_project  # noqa: E402
from storage import Store  # noqa: E402

GET_TABLES = {"TableList": [
    {"Name": "clientes", "DatabaseName": "cip_curated", "Parameters": {"table_type": "ICEBERG"},
     "StorageDescriptor": {"Location": "s3://dlz/clientes", "Columns": [{"Name": "rfc", "Type": "string"}]}},
    {"Name": "eventos", "DatabaseName": "cip_raw", "Parameters": {"classification": "json"},
     "StorageDescriptor": {"Location": "s3://dlz/eventos", "Columns": [{"Name": "payload", "Type": "string"}]}}]}


@unittest.skipIf(sync_playwright is None, "Playwright no está instalado")
class UiTest(unittest.TestCase):
    demo = False

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.prev_demo, cls.prev_store = app.DEMO, app.STORE
        app.DEMO = cls.demo
        app.STORE = Store(cls.tmp.name)
        if not cls.demo:
            app.STORE.create(None, sample_project())
        cls.srv = app.Server(("127.0.0.1", 0), app.Handler)
        cls.base = f"http://127.0.0.1:{cls.srv.server_address[1]}"
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.pw = sync_playwright().start()
        cls.browser = cls.pw.chromium.launch()

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls.pw.stop()
        cls.srv.shutdown()
        cls.srv.server_close()
        app.DEMO, app.STORE = cls.prev_demo, cls.prev_store
        cls.tmp.cleanup()

    def setUp(self):
        self.ctx = self.browser.new_context(viewport={"width": 1440, "height": 900})
        self.page = self.ctx.new_page()
        self.errors = []
        self.page.on("pageerror", lambda e: self.errors.append(str(e)))
        self.page.goto(self.base)
        self.page.wait_for_function("window.InfraTrack && window.InfraTrack.S.analysis")

    def tearDown(self):
        self.ctx.close()
        self.assertEqual(self.errors, [], "errores de JavaScript en la página")

    def js(self, expr):
        return self.page.evaluate(expr)

    def node_count(self):
        return self.js("window.InfraTrack.P().nodes.length")


class AppUiTest(UiTest):
    def test_loads_sample_and_renders(self):
        self.assertIn("Ejemplo", self.page.locator("#projectSelect").inner_text())
        self.assertGreater(self.page.locator("#world [data-node]").count(), 10)
        self.assertGreater(self.page.locator(".pal-item").count(), 50)

    def test_add_component_from_palette(self):
        before = self.node_count()
        self.page.locator(".pal-item[data-type='sqs']").click()
        self.assertEqual(self.node_count(), before + 1)
        self.assertIn("SQS", self.page.locator(".ins-head h3").inner_text())

    def test_connect_nodes_shows_permissions(self):
        before = self.js("window.InfraTrack.P().edges.length")
        self.js("window.InfraTrack.select('node', 'lambda')")
        port = self.page.locator("[data-port='lambda'] .port-hit").bounding_box()
        target = self.page.locator("[data-node='secret'] .body").bounding_box()
        self.page.mouse.move(port["x"] + port["width"] / 2, port["y"] + port["height"] / 2)
        self.page.mouse.down()
        self.page.mouse.move(target["x"] + 20, target["y"] + 20, steps=8)
        self.page.mouse.up()
        self.assertEqual(self.js("window.InfraTrack.P().edges.length"), before + 1)
        self.page.wait_for_function("document.querySelector('#edgePlan') && document.querySelector('#edgePlan').innerText.includes('IAM')")

    def test_toggle_terraformed(self):
        before = self.page.locator("#progressLabel").inner_text()
        self.page.locator("[data-check='rds']").click()
        self.assertTrue(self.js("window.InfraTrack.nodeById('rds').terraformed"))
        self.assertNotEqual(self.page.locator("#progressLabel").inner_text(), before)

    def test_copilot_tabs(self):
        self.page.locator("#btnCopilot").click()
        for tab in ("Seguridad", "Roles IAM", "Security Groups", "Tags y Terraform"):
            self.page.locator(".mtabs .tab", has_text=tab).click()
            self.assertTrue(self.page.locator(".mcontent").inner_text().strip(), tab)
        self.page.keyboard.press("Escape")
        self.assertTrue(self.page.locator("#modal").is_hidden())

    def test_glue_catalog_upload(self):
        self.js("window.InfraTrack.addNode('glue_catalog', {x: 1500, y: 700})")
        self.page.locator(".tab[data-tab='catalog']").click()
        self.page.locator("#catFile").set_input_files(
            files=[{"name": "tablas.json", "mimeType": "application/json", "buffer": json.dumps(GET_TABLES).encode()}])
        self.page.wait_for_function("document.querySelectorAll('details.cat-tb').length === 2")
        self.assertIn("2 tablas", self.page.locator("#insBody").inner_text())

    def test_flows_filter(self):
        self.js("window.InfraTrack.select(null)")
        self.page.locator("[data-padd='flows']").click()
        self.assertTrue(self.page.locator("#flowFilter").is_visible())
        self.assertIn("FL-01", self.page.locator("#flowFilter").inner_text())

    def test_delete_and_undo(self):
        before = self.node_count()
        self.js("window.InfraTrack.select('node', 'sqs')")
        self.page.locator("#canvas").focus()
        self.page.keyboard.press("Delete")
        self.assertEqual(self.node_count(), before - 1)
        self.page.locator("#btnUndo").click()
        self.assertEqual(self.node_count(), before)


class RulesUiTest(UiTest):
    def test_disable_rule_from_rules_tab(self):
        self.assertTrue(self.js("window.InfraTrack.S.analysis.findings.some(f => f.rule === 'EMR-ICEBERG')"))
        self.page.locator("#btnCopilot").click()
        self.page.locator(".mtabs .tab", has_text="Reglas").click()
        self.page.locator("#rulesSearch").fill("EMR-ICEBERG")
        self.page.locator("input[data-ren='EMR-ICEBERG']").uncheck()
        self.page.wait_for_function("!window.InfraTrack.S.analysis.findings.some(f => f.rule === 'EMR-ICEBERG')")
        self.assertEqual(self.js("window.InfraTrack.P().settings.rules['EMR-ICEBERG'].enabled"), False)
        self.assertTrue(self.page.locator("tr:not(.hidden) input[data-ren='EMR-ICEBERG']").is_visible())


class DemoUiTest(UiTest):
    demo = True

    def test_demo_saves_in_browser(self):
        self.assertTrue(self.page.locator("#demoBanner").is_visible())
        self.page.locator("[data-check='rds']").click()
        self.page.wait_for_function("document.querySelector('#saveStatus').textContent.includes('Guardado')")
        self.page.wait_for_timeout(900)
        self.page.reload()
        self.page.wait_for_function("window.InfraTrack && window.InfraTrack.S.analysis")
        self.assertTrue(self.js("window.InfraTrack.nodeById('rds').terraformed"))


del UiTest  # la clase base no se ejecuta sola

if __name__ == "__main__":
    unittest.main()
