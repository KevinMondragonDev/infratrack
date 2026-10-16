"""Punto de entrada para Vercel (función Python). Corre InfraTrack en modo demo:
sin almacenamiento en el servidor; los proyectos se guardan en el navegador de cada visitante."""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ["INFRATRACK_DEMO"] = "1"

import app as infratrack  # noqa: E402

infratrack.DEMO = True


class handler(infratrack.Handler):  # noqa: N801 — Vercel busca una clase llamada "handler"
    pass
