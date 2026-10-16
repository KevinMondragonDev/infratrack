#!/usr/bin/env python3
"""InfraTrack — seguimiento de infraestructura AWS con Copilot de arquitectura.

Uso:
    python3 app.py                    # http://127.0.0.1:8765
    python3 app.py --port 9000 --data ./mis-datos
    python3 app.py --host 0.0.0.0     # compartir en la red local (sin autenticación)
    python3 app.py --setup-icons      # descarga los iconos oficiales de AWS (una vez)

Sólo usa la librería estándar de Python (3.9+). La IA es opcional (pip install anthropic).
"""
import argparse
import base64
import json
import mimetypes
import os
import re
import sys
import traceback
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import quote, urlparse

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)

import ai  # noqa: E402
import compare as comparer  # noqa: E402
import glue_catalog  # noqa: E402
import icons  # noqa: E402
from catalog import catalog  # noqa: E402
from copilot import analyze  # noqa: E402
from report import build_markdown  # noqa: E402
from samples import sample_project  # noqa: E402
from storage import Conflict, Store  # noqa: E402

STATIC = os.path.join(BASE, "static")
MAX_BODY = 20 * 1024 * 1024
STORE = None


class Server(ThreadingHTTPServer):
    """Servidor con cola de conexiones amplia: la interfaz pide ~100 archivos (módulos e iconos) al cargar."""
    request_queue_size = 128
    daemon_threads = True
# Demo pública (p. ej. Vercel): sin almacenamiento en servidor; los proyectos viven en el navegador.
DEMO = os.environ.get("INFRATRACK_DEMO") == "1"


class Handler(BaseHTTPRequestHandler):
    server_version = "InfraTrack/1.0"

    def log_message(self, fmt, *args):
        if os.environ.get("INFRATRACK_VERBOSE"):
            super().log_message(fmt, *args)

    # ───── respuestas ─────
    def send_json(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def send_text(self, text, ctype, filename=None):
        body = text.encode()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        if filename:
            self.send_header("Content-Disposition", f"attachment; filename*=UTF-8''{quote(filename)}")
        self.end_headers()
        self.wfile.write(body)

    def error(self, status, msg):
        self.send_json({"error": msg}, status)

    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > MAX_BODY:
            raise ValueError("Payload demasiado grande")
        raw = self.rfile.read(n) if n else b"{}"
        return json.loads(raw or b"{}")

    def _same_origin(self):
        origin = self.headers.get("Origin")
        if not origin:
            return True
        return urlparse(origin).netloc == self.headers.get("Host")

    # ───── ruteo ─────
    def do_GET(self):
        self.route("GET")

    def do_POST(self):
        self.route("POST")

    def do_PUT(self):
        self.route("PUT")

    def do_DELETE(self):
        self.route("DELETE")

    @staticmethod
    def find_route(method, path):
        for m, pattern, fn in ROUTES:
            match = re.fullmatch(pattern, path) if m == method else None
            if match:
                return fn, match.groups()
        return None, ()

    def dispatch(self, method, path):
        if method != "GET" and not self._same_origin():
            return self.error(403, "Origen no permitido")
        if not path.startswith("/api/"):
            return self.static(path) if method == "GET" else self.error(405, "Método no permitido")
        fn, args = self.find_route(method, path)
        if fn is None:
            return self.error(404, "No encontrado")
        if DEMO and fn not in DEMO_ROUTES:
            return self.error(404, "No disponible en la demo")
        return fn(self, *args)

    def route(self, method):
        try:
            self.dispatch(method, urlparse(self.path).path)
        except KeyError:
            self.error(404, "Proyecto no encontrado")
        except Conflict as c:
            self.error(409, f"El proyecto cambió en otra pestaña (rev {c.args[0]}). Recarga para no sobrescribir.")
        except (ValueError, json.JSONDecodeError) as exc:
            self.error(400, str(exc))
        except Exception as exc:  # noqa: BLE001
            traceback.print_exc()
            self.error(500, f"{type(exc).__name__}: {exc}")

    def static(self, path):
        if path in ("", "/"):
            path = "/index.html"
        full = os.path.normpath(os.path.join(STATIC, path.lstrip("/")))
        if not full.startswith(STATIC) or not os.path.isfile(full):
            return self.error(404, "No encontrado")
        ctype = mimetypes.guess_type(full)[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype in ("application/javascript",):
            ctype += "; charset=utf-8"
        with open(full, "rb") as fh:
            data = fh.read()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache")
        if full.endswith(".svg"):
            self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
        self.end_headers()
        self.wfile.write(data)

    # ───── API ─────
    def api_catalog(self):
        self.send_json(catalog())

    def api_list(self):
        self.send_json(STORE.list())

    def api_create(self):
        b = self.body()
        tpl = sample_project() if b.get("sample") else None
        self.send_json(STORE.create(b.get("name") or (tpl or {}).get("name") or "Nuevo proyecto", tpl), 201)

    def api_get(self, pid):
        self.send_json(STORE.get(pid))

    def api_save(self, pid):
        b = self.body()
        if not isinstance(b.get("nodes"), list) or not isinstance(b.get("edges"), list):
            raise ValueError("Formato inválido: se esperan 'nodes' y 'edges'")
        saved = STORE.save(pid, b, force=bool(b.pop("_force", False)))
        self.send_json({"rev": saved["rev"], "updated": saved["updated"]})

    def api_delete(self, pid):
        STORE.delete(pid)
        self.send_json({"ok": True})

    def api_duplicate(self, pid):
        p = STORE.get(pid)
        b = self.body()
        env = (b.get("environment") or "").strip()
        if env:
            amap = {str(k): str(v) for k, v in (b.get("account_map") or {}).items() if str(v).strip()}
            for v in amap.values():
                if not re.fullmatch(r"\d{12}", v):
                    raise ValueError(f"ID de cuenta inválido: {v}")
            new = comparer.for_environment(p, env, amap, b.get("name"))
            return self.send_json(STORE.create(new["name"], new), 201)
        p.pop("id", None)
        self.send_json(STORE.create(b.get("name") or f"{p.get('name')} (copia)", p), 201)

    def api_glue_import(self):
        b = self.body()
        parsed = glue_catalog.parse_import(b.get("text") or "", b.get("filename") or "")
        merged = parsed if b.get("replace") else glue_catalog.merge(b.get("existing") or {}, parsed)
        self.send_json({"catalog": merged, "imported": glue_catalog.stats(parsed), "stats": glue_catalog.stats(merged)})

    def api_compare(self, a, b):
        self.send_json(comparer.compare(STORE.get(a), STORE.get(b)))

    def api_import(self):
        b = self.body()
        if not isinstance(b.get("nodes"), list):
            raise ValueError("El archivo no parece un proyecto de InfraTrack")
        b.pop("id", None)
        self.send_json(STORE.create(b.get("name") or "Importado", b), 201)

    def api_analyze(self):
        self.send_json(analyze(self.body()))

    def api_export_md(self, pid):
        p = STORE.get(pid)
        self.send_text(build_markdown(p), "text/markdown; charset=utf-8", f"{p.get('name', pid)}.md")

    def api_export_json(self, pid):
        p = STORE.get(pid)
        self.send_text(json.dumps(p, ensure_ascii=False, indent=2), "application/json; charset=utf-8",
                       f"{p.get('name', pid)}.infratrack.json")

    def api_backups(self, pid):
        self.send_json(STORE.list_backups(pid))

    def api_restore(self, pid, bid):
        p = STORE.restore_backup(pid, bid)
        self.send_json({"rev": p["rev"]})

    def api_icons(self):
        self.send_json(icons.available(BASE))

    def api_icons_setup(self):
        try:
            res = icons.setup_icons(BASE)
        # Cualquier falla (red, proxy, ZIP inválido) se informa al usuario con una alternativa.
        except Exception as exc:  # noqa: BLE001
            return self.error(502, f"No se pudieron descargar los iconos: {exc}. "
                                   "Puedes descargarlo a mano y usar: python3 app.py --setup-icons --icons-zip archivo.zip")
        self.send_json({**res, **icons.available(BASE)})

    def api_ai_status(self):
        if DEMO:
            return self.send_json({"available": False, "reason": "El Copilot IA no está disponible en la demo pública."})
        self.send_json(ai.status())

    # ───── sin estado (los usa la demo; reciben el proyecto en el cuerpo) ─────
    def api_config(self):
        self.send_json({"storage": "browser" if DEMO else "server", "demo": DEMO})

    def api_sample(self):
        self.send_json(sample_project())

    def api_export_md_post(self):
        # El reporte viaja en base64 (la respuesta no contiene marcado reflejado); el navegador arma la descarga.
        md = build_markdown(self.body()).encode("utf-8")
        self.send_json({"markdown_b64": base64.b64encode(md).decode("ascii")})

    def api_compare_projects(self):
        b = self.body()
        self.send_json(comparer.compare(b.get("a") or {}, b.get("b") or {}))

    def api_duplicate_env(self):
        b = self.body()
        env = (b.get("environment") or "").strip()
        if not env:
            raise ValueError("Falta el ambiente destino")
        amap = {str(k): str(v) for k, v in (b.get("account_map") or {}).items() if str(v).strip()}
        for v in amap.values():
            if not re.fullmatch(r"\d{12}", v):
                raise ValueError(f"ID de cuenta inválido: {v}")
        self.send_json(comparer.for_environment(b.get("project") or {}, env, amap, b.get("name")))

    def api_ai_ask(self):
        b = self.body()
        project = b.get("project") or {}
        try:
            res = ai.ask(project, analyze(project), b.get("question"), b.get("node_id"))
        except RuntimeError as exc:
            return self.error(400, str(exc))
        self.send_json(res)


P = r"([a-zA-Z0-9_-]{1,64})"
ROUTES = [
    ("GET", r"/api/catalog", Handler.api_catalog),
    ("GET", r"/api/config", Handler.api_config),
    ("GET", r"/api/sample", Handler.api_sample),
    ("POST", r"/api/export-md", Handler.api_export_md_post),
    ("POST", r"/api/compare-projects", Handler.api_compare_projects),
    ("POST", r"/api/duplicate-env", Handler.api_duplicate_env),
    ("GET", r"/api/projects", Handler.api_list),
    ("POST", r"/api/projects", Handler.api_create),
    ("POST", r"/api/import", Handler.api_import),
    ("POST", r"/api/analyze", Handler.api_analyze),
    ("POST", r"/api/glue/import", Handler.api_glue_import),
    ("GET", r"/api/icons", Handler.api_icons),
    ("POST", r"/api/icons/setup", Handler.api_icons_setup),
    ("GET", r"/api/ai/status", Handler.api_ai_status),
    ("POST", r"/api/ai/ask", Handler.api_ai_ask),
    ("GET", rf"/api/projects/{P}", Handler.api_get),
    ("PUT", rf"/api/projects/{P}", Handler.api_save),
    ("DELETE", rf"/api/projects/{P}", Handler.api_delete),
    ("POST", rf"/api/projects/{P}/duplicate", Handler.api_duplicate),
    ("GET", rf"/api/projects/{P}/export\.md", Handler.api_export_md),
    ("GET", rf"/api/projects/{P}/export\.json", Handler.api_export_json),
    ("GET", rf"/api/projects/{P}/backups", Handler.api_backups),
    ("GET", rf"/api/compare/{P}/{P}", Handler.api_compare),
    ("POST", rf"/api/projects/{P}/backups/(\d{{8}}-\d{{6}})/restore", Handler.api_restore),
]


DEMO_ROUTES = {Handler.api_catalog, Handler.api_config, Handler.api_sample, Handler.api_analyze, Handler.api_glue_import,
               Handler.api_export_md_post, Handler.api_compare_projects, Handler.api_duplicate_env, Handler.api_icons,
               Handler.api_ai_status}


def main():
    global STORE
    ap = argparse.ArgumentParser(description="InfraTrack")
    ap.add_argument("--host", default=os.environ.get("INFRATRACK_HOST", "127.0.0.1"))
    ap.add_argument("--port", type=int, default=int(os.environ.get("INFRATRACK_PORT", 8765)))
    ap.add_argument("--data", default=os.environ.get("INFRATRACK_DATA", os.path.join(BASE, "data")))
    ap.add_argument("--open", action="store_true", help="Abrir el navegador al iniciar")
    ap.add_argument("--setup-icons", action="store_true", help="Descargar los iconos oficiales de AWS y salir")
    ap.add_argument("--icons-zip", help="Usar un paquete de iconos ya descargado (ZIP) en lugar de descargarlo")
    args = ap.parse_args()
    if args.setup_icons or args.icons_zip:
        icons.setup_icons(BASE, zip_path=args.icons_zip)
        return
    STORE = Store(args.data)
    if not DEMO and not STORE.list():
        STORE.create(None, sample_project())
    srv = Server((args.host, args.port), Handler)
    url = f"http://{'127.0.0.1' if args.host in ('0.0.0.0', '') else args.host}:{args.port}"
    print(f"InfraTrack en {url}  (datos: {STORE.root})  Ctrl+C para salir")
    if args.host not in ("127.0.0.1", "localhost"):
        print("⚠  Escuchando en la red sin autenticación: compártelo sólo en redes de confianza.")
    if args.open:
        webbrowser.open(url)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nHasta luego.")


if __name__ == "__main__":
    main()
