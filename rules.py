"""Registro de reglas del Copilot y overrides por proyecto.

El registro se obtiene leyendo el código de las reglas (copilot.py, security.py, extensions.py) con `ast`,
así nunca se desfasa: cada llamada `self.add(severidad, categoría, "REGLA", título, …)` es una regla.

Overrides por proyecto (settings.rules):
    {"SG-OPEN-WIDE": {"enabled": false}, "COST-GW-ENDPOINT": {"severity": "info"}}
"""
import ast
import csv
import io
import os
from functools import lru_cache

BASE = os.path.dirname(os.path.abspath(__file__))
SOURCES = ("copilot.py", "security.py", "extensions.py")
SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEVERITY_LABEL = {"critical": "Crítico", "high": "Alto", "medium": "Medio", "low": "Bajo", "info": "Info"}
RTB_TARGETS = ["IGW", "NAT", "VPCE", "TGW", "PCX", "VGW", "NFW"]


def _text(node):
    """Texto de una constante o f-string (los valores dinámicos se muestran como …)."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(v.value if isinstance(v, ast.Constant) else "…" for v in node.values)
    return None


def _severity(node):
    if isinstance(node, ast.Constant) and node.value in SEVERITIES:
        return node.value
    if isinstance(node, ast.IfExp):  # "high" if prod else "medium" → la más alta
        options = [s for s in (_severity(node.body), _severity(node.orelse)) if s]
        return min(options, key=SEVERITIES.index) if options else None
    return None


def _from_calls(tree, source):
    out = {}
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "add"
                and len(node.args) >= 4):
            continue
        rule = _text(node.args[2])
        if not rule:
            continue
        entry = {"id": rule, "severity": _severity(node.args[0]) or "medium",
                 "category": _text(node.args[1]) or "—", "title": _text(node.args[3]) or rule, "source": source}
        if rule.startswith("RTB-TARGET-"):
            for t in RTB_TARGETS:
                out[f"RTB-TARGET-{t}"] = {**entry, "id": f"RTB-TARGET-{t}", "title": f"Tabla de rutas apunta a {t.lower()} inexistente"}
            continue
        if "…" not in rule:
            out.setdefault(rule, entry)
    return out


def _from_tables():
    """Reglas declaradas en tablas (línea base de cuenta y reglas del catálogo de Glue)."""
    from security import ACCOUNT_BASELINE
    out = {}
    for _field, rule, sev, title, _rec in ACCOUNT_BASELINE:
        out[rule] = {"id": rule, "severity": sev, "category": "Seguridad", "title": f"Cuenta: {title}", "source": "security.py"}
    for rule, sev, cat, title in (
            ("GLUE-PII-NO-LF", "medium", "Seguridad", "Tablas con datos personales sin Lake Formation"),
            ("GLUE-SENSITIVITY", "low", "Datos", "Tablas con datos personales sin clasificar"),
            ("GLUE-DOC", "low", "Seguimiento", "Tablas sin descripción o dueño"),
            ("GLUE-NO-PARTITION", "low", "Costo", "Tablas de texto sin particiones")):
        out[rule] = {"id": rule, "severity": sev, "category": cat, "title": title, "source": "extensions.py"}
    return out


@lru_cache(maxsize=1)
def registry():
    rules = {}
    for name in SOURCES:
        with open(os.path.join(BASE, name), encoding="utf-8") as fh:
            rules.update(_from_calls(ast.parse(fh.read()), name))
    for rule, entry in _from_tables().items():
        rules.setdefault(rule, entry)
    return sorted(rules.values(), key=lambda r: (r["category"], r["id"]))


def apply_overrides(findings, overrides):
    """Quita los hallazgos de reglas desactivadas y cambia severidades. Devuelve la lista nueva."""
    if not overrides:
        return findings
    out = []
    for f in findings:
        ov = overrides.get(f["rule"]) or {}
        if ov.get("enabled") is False:
            continue
        sev = ov.get("severity")
        if sev in SEVERITIES and sev != f["severity"]:
            f = {**f, "severity": sev, "default_severity": f["severity"]}
        out.append(f)
    return out


def clean_overrides(raw):
    """Normaliza overrides (de la interfaz o importados): sólo reglas conocidas y valores válidos."""
    known = {r["id"]: r for r in registry()}
    out = {}
    for rule, ov in (raw or {}).items():
        if rule not in known or not isinstance(ov, dict):
            continue
        item = {}
        if ov.get("enabled") is False:
            item["enabled"] = False
        if ov.get("severity") in SEVERITIES and ov["severity"] != known[rule]["severity"]:
            item["severity"] = ov["severity"]
        if ov.get("comment"):
            item["comment"] = str(ov["comment"])[:500]
        if item:
            out[rule] = item
    return out


def to_csv(overrides, counts=None):
    """Lista para revisar con el arquitecto (se abre en Excel)."""
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "categoria", "severidad_por_defecto", "descripcion", "activa", "severidad_proyecto",
                "hallazgos_actuales", "comentario"])
    for r in registry():
        ov = (overrides or {}).get(r["id"], {})
        w.writerow([r["id"], r["category"], r["severity"], r["title"], "no" if ov.get("enabled") is False else "sí",
                    ov.get("severity", ""), (counts or {}).get(r["id"], 0), ov.get("comment", "")])
    return buf.getvalue()


def from_csv(text):
    """Lee la lista revisada (columnas id, activa, severidad_proyecto, comentario)."""
    rows = csv.DictReader(io.StringIO(text.lstrip("﻿")))
    if not rows.fieldnames or "id" not in [f.strip() for f in rows.fieldnames]:
        raise ValueError("El CSV debe tener al menos la columna 'id' (y activa, severidad_proyecto, comentario).")
    raw = {}
    for row in rows:
        row = {k.strip(): (v or "").strip() for k, v in row.items() if k}
        sev = row.get("severidad_proyecto", "").lower()
        sev = {v.lower(): k for k, v in SEVERITY_LABEL.items()}.get(sev, sev)
        raw[row["id"]] = {"enabled": row.get("activa", "sí").lower() not in ("no", "false", "0", "n"),
                          "severity": sev or None, "comment": row.get("comentario", "")}
    return clean_overrides(raw)
