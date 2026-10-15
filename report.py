"""Reporte Markdown para revisar el diseño con el arquitecto."""
import json

from catalog import CATEGORIES, COMPONENTS_BY_ID, visible_fields
from copilot import analyze

SEV_ICON = {"critical": "🟥 Crítico", "high": "🟧 Alto", "medium": "🟨 Medio", "low": "🟦 Bajo", "info": "⬜ Info"}


def _fmt(v):
    if isinstance(v, bool):
        return "Sí" if v else "No"
    if isinstance(v, list):
        return ", ".join(str(x) for x in v) or "—"
    if v in (None, ""):
        return "—"
    return str(v).replace("\n", "<br>").replace("|", "\\|")


def build_markdown(project):
    a = analyze(project)
    s = a["summary"]
    nodes = {n["id"]: n for n in project.get("nodes", []) if n.get("type") in COMPONENTS_BY_ID}
    label = lambda nid: nodes[nid].get("label") or COMPONENTS_BY_ID[nodes[nid]["type"]]["name"] if nid in nodes else nid
    st = project.get("settings") or {}
    L = [f"# {project.get('name')}", ""]
    if project.get("description"):
        L += [project["description"], ""]
    L += [f"- **Región:** {st.get('region') or '—'} · **Cuenta:** {st.get('account_id') or '—'} · "
          f"**Ambiente:** {st.get('environment') or '—'}",
          f"- **Actualizado:** {project.get('updated')} (rev {project.get('rev')})",
          f"- **Terraformado:** {s['terraformed']}/{s['components']} componentes ({s['terraform_pct']}%) · "
          f"{s['edges_terraformed']}/{s['edges']} conexiones",
          f"- **Configuración completa:** {s['config_pct']}%",
          f"- **Preguntas abiertas:** {s['open_questions']} · respondidas sin cerrar: {s['answered_questions']}",
          "- **Hallazgos:** " + " · ".join(f"{SEV_ICON[k]}: {v}" for k, v in s["findings"].items() if v), ""]

    # Preguntas para el arquitecto
    qs = [(n, q) for n in nodes.values() for q in n.get("questions") or [] if q.get("status") != "closed"]
    if qs:
        L += ["## Preguntas para el arquitecto", "", "| Componente | Pregunta | Respuesta | Estado |", "|---|---|---|---|"]
        for n, q in qs:
            L.append(f"| {_fmt(label(n['id']))} | {_fmt(q.get('text'))} | {_fmt(q.get('answer'))} | "
                     f"{'Respondida' if q.get('answer') else 'Abierta'} |")
        L.append("")

    # Hallazgos
    active = [f for f in a["findings"] if not f.get("dismissed")]
    if active:
        L += ["## Hallazgos del Copilot", ""]
        for f in active:
            where = ", ".join(label(i) for i in f["node_ids"])
            L += [f"### {SEV_ICON[f['severity']]} · {f['category']} · {f['title']}",
                  f"{f['detail']}", "", f"**Recomendación:** {f['recommendation']}" + (f"  \n_Componentes: {where}_" if where else ""), ""]
    dism = [f for f in a["findings"] if f.get("dismissed")]
    if dism:
        L += ["## Riesgos aceptados / descartados", "", "| Hallazgo | Motivo | Por |", "|---|---|---|"]
        for f in dism:
            d = f["dismissed"]
            L.append(f"| {_fmt(f['title'])} | {_fmt(d.get('reason'))} | {_fmt(d.get('by'))} {d.get('at', '')} |")
        L.append("")

    # Componentes
    L += ["## Componentes", ""]
    for cat in CATEGORIES:
        items = [n for n in nodes.values() if COMPONENTS_BY_ID[n["type"]]["category"] == cat["id"] and n["type"] != "note"]
        if not items:
            continue
        L += [f"### {cat['name']}", ""]
        for n in sorted(items, key=lambda x: x.get("label") or ""):
            comp = COMPONENTS_BY_ID[n["type"]]
            parent = a["parents"].get(n["id"])
            tf = "✅ Terraformado" if n.get("terraformed") else ("⬜ Pendiente" if comp["terraformable"] else "—")
            L += [f"#### {label(n['id'])} · _{comp['name']}_",
                  f"{tf} · Estado: **{n.get('status') or 'Borrador'}**"
                  + (f" · Responsable: {n['owner']}" if n.get("owner") else "")
                  + (f" · Ubicación: {label(parent)}" if parent else "")
                  + (f" · TF: `{n['tf_address']}`" if n.get("tf_address") else ""), ""]
            if n.get("description"):
                L += [n["description"], ""]
            cfg = n.get("config") or {}
            rows = [(f["label"], cfg.get(f["key"])) for f in visible_fields(comp, cfg) if cfg.get(f["key"]) not in (None, "", [])]
            if rows:
                L += ["| Configuración | Valor |", "|---|---|"] + [f"| {k} | {_fmt(v)} |" for k, v in rows] + [""]
            notes = n.get("notes") or []
            if notes:
                L.append("**Notas:**")
                for nt in notes:
                    L.append(f"- _{nt.get('at', '')[:16]} {nt.get('author') or ''}_: {nt.get('text', '')}")
                L.append("")
    # Conexiones
    edges = [e for e in project.get("edges", []) if e["id"] in a["plans"]]
    if edges:
        L += ["## Conexiones y permisos", ""]
        for e in edges:
            p = a["plans"][e["id"]]
            L += [f"### {p['summary']}" + (" ✅" if e.get("terraformed") else ""), ""]
            if e.get("notes"):
                L += [e["notes"], ""]
            if p.get("principal"):
                pr = p["principal"]
                L += [f"**Rol:** `{pr['role']}` ({pr['desc']})", "", "```json",
                      json.dumps({"Version": "2012-10-17", "Statement": p["identity"]}, indent=2, ensure_ascii=False), "```", ""]
            for rp in p["resource_policies"]:
                L += [f"**{rp['type']} en {rp['on']}:**", "", "```json", json.dumps(rp["statement"], indent=2, ensure_ascii=False), "```", ""]
            for r in p["network"]:
                L.append(f"- SG `{r['sg']}` {r['direction']} {r['protocol']}/{r['port']} ↔ `{r['peer']}` — {r['description']}")
            for x in p["path"] + p["notes"]:
                L.append(f"- {x}")
            L.append("")
    return "\n".join(L)
