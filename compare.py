"""Duplicar un proyecto para otro ambiente y comparar dos proyectos (p. ej. DEV vs PRE vs PRO)."""
import copy
import re

from catalog import COMPONENTS_BY_ID

IGNORED_CONFIG = {"account_id", "environment", "_extra"}


def _key(n):
    return (n.get("type"), re.sub(r"\s+", " ", (n.get("label") or "").strip().lower()))


def for_environment(project, environment, account_map=None, name=None):
    """Copia el proyecto para otro ambiente: cambia cuentas/ambiente y reinicia el avance de terraform."""
    p = copy.deepcopy(project)
    account_map = account_map or {}
    p.pop("id", None)
    p["name"] = name or f"{project.get('name')} ({environment.upper()})"
    p.setdefault("settings", {})
    p["settings"]["environment"] = environment
    p["settings"]["base_project"] = project.get("id")
    if p["settings"].get("account_id") in account_map:
        p["settings"]["account_id"] = account_map[p["settings"]["account_id"]]
    for n in p.get("nodes", []):
        n["terraformed"] = False
        n["terraformed_at"] = None
        n["questions"] = [q for q in n.get("questions") or [] if q.get("status") != "closed"]
        if n.get("type") == "account":
            cfg = n.setdefault("config", {})
            old = str(cfg.get("account_id") or "")
            if old in account_map:
                cfg["account_id"] = account_map[old]
            cfg["environment"] = environment
            # La línea base se debe confirmar de nuevo en la cuenta nueva
            for f in COMPONENTS_BY_ID["account"]["fields"]:
                if f.get("tri"):
                    cfg[f["key"]] = "Sin confirmar"
    for e in p.get("edges", []):
        e["terraformed"] = False
    p["dismissed"] = {}
    return p


def compare(a, b):
    """Diferencias por componente (tipo + nombre), configuración y conexiones."""
    na = {_key(n): n for n in a.get("nodes", []) if n.get("type") in COMPONENTS_BY_ID and n.get("type") != "note"}
    nb = {_key(n): n for n in b.get("nodes", []) if n.get("type") in COMPONENTS_BY_ID and n.get("type") != "note"}
    only_a = [_brief(na[k]) for k in sorted(set(na) - set(nb))]
    only_b = [_brief(nb[k]) for k in sorted(set(nb) - set(na))]
    changed, same = [], 0
    for k in sorted(set(na) & set(nb)):
        x, y = na[k], nb[k]
        cx, cy = x.get("config") or {}, y.get("config") or {}
        labels = {f["key"]: f["label"] for f in COMPONENTS_BY_ID[x["type"]]["fields"]}
        diffs = []
        for key in sorted(set(cx) | set(cy)):
            if key in IGNORED_CONFIG:
                continue
            if _norm(cx.get(key)) != _norm(cy.get(key)):
                diffs.append({"field": labels.get(key, key), "a": cx.get(key), "b": cy.get(key)})
        tf = (bool(x.get("terraformed")), bool(y.get("terraformed")))
        if diffs or tf[0] != tf[1]:
            changed.append({**_brief(x), "diffs": diffs, "terraformed_a": tf[0], "terraformed_b": tf[1]})
        else:
            same += 1

    def edge_keys(p, nodes_by_id):
        out = {}
        for e in p.get("edges", []):
            s, t = nodes_by_id.get(e.get("source")), nodes_by_id.get(e.get("target"))
            if s and t:
                out[(_key(s), _key(t))] = e
        return out

    ea = edge_keys(a, {n["id"]: n for n in a.get("nodes", [])})
    eb = edge_keys(b, {n["id"]: n for n in b.get("nodes", [])})
    edges_only_a = [_edge(k) for k in sorted(set(ea) - set(eb))]
    edges_only_b = [_edge(k) for k in sorted(set(eb) - set(ea))]
    edges_changed = [{**_edge(k), "a": ea[k].get("access"), "b": eb[k].get("access"), "port_a": ea[k].get("port"),
                      "port_b": eb[k].get("port")}
                     for k in sorted(set(ea) & set(eb))
                     if (ea[k].get("access"), ea[k].get("port")) != (eb[k].get("access"), eb[k].get("port"))]
    return {"a": {"id": a.get("id"), "name": a.get("name")}, "b": {"id": b.get("id"), "name": b.get("name")},
            "only_a": only_a, "only_b": only_b, "changed": changed, "same": same,
            "edges_only_a": edges_only_a, "edges_only_b": edges_only_b, "edges_changed": edges_changed}


def _norm(v):
    if isinstance(v, list):
        return sorted(str(x) for x in v)
    if v in (None, "", []):
        return None
    return v


def _brief(n):
    return {"type": n["type"], "type_name": COMPONENTS_BY_ID[n["type"]]["name"], "label": n.get("label") or ""}


def _edge(k):
    (ts, ls), (tt, lt) = k
    return {"source": ls, "target": lt, "source_type": ts, "target_type": tt}
