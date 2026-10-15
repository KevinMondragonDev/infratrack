"""Copilot IA opcional (Claude). Sólo se activa si está instalado el SDK `anthropic`
y hay credenciales (ANTHROPIC_API_KEY o un perfil de `ant auth login`).

El motor de reglas (copilot.py) funciona siempre sin esto; la IA agrega una
revisión en lenguaje natural y responde preguntas libres sobre el diagrama.
"""
import json
import os

from catalog import COMPONENTS_BY_ID

MODEL = os.environ.get("INFRATRACK_MODEL", "claude-opus-5-5")

try:
    import anthropic  # type: ignore
except ImportError:  # pragma: no cover
    anthropic = None

SYSTEM = """Eres un arquitecto de soluciones AWS senior que revisa diseños de infraestructura
de un equipo que los implementa con Terraform. Respondes en español, de forma concreta y accionable.
Recibes el diagrama (componentes, configuración, conexiones, ubicación en VPC/subnets) y los
hallazgos de un motor de reglas determinista. No repitas esos hallazgos: complétalos con lo que
el motor no puede ver (diseño, costos, límites de servicio, alternativas, riesgos operativos,
seguridad, permisos IAM de mínimo privilegio, preguntas que el equipo debería llevar al arquitecto).
Cuando falte información, dilo y formula la pregunta. Usa Markdown con encabezados cortos y listas."""


def status():
    if anthropic is None:
        return {"available": False, "reason": "Instala el SDK: pip install anthropic"}
    if not (os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN")
            or os.path.isdir(os.path.expanduser("~/.config/anthropic"))):
        return {"available": False, "reason": "Configura ANTHROPIC_API_KEY (o ejecuta `ant auth login`)."}
    return {"available": True, "model": MODEL}


def _compact(project, analysis):
    parents = analysis["parents"]
    nodes = {n["id"]: n for n in project.get("nodes", []) if n.get("type") in COMPONENTS_BY_ID}
    lbl = lambda i: nodes[i].get("label") or nodes[i]["type"] if i in nodes else i
    comps = []
    for n in nodes.values():
        if n["type"] == "note":
            continue
        comps.append({
            "id": n["id"], "nombre": lbl(n["id"]), "tipo": COMPONENTS_BY_ID[n["type"]]["name"],
            "dentro_de": lbl(parents[n["id"]]) if parents.get(n["id"]) else None,
            "terraformado": bool(n.get("terraformed")), "estado": n.get("status") or "Borrador",
            "config": n.get("config") or {}, "descripcion": n.get("description") or "",
            "notas": [x.get("text") for x in n.get("notes") or []][-5:],
            "preguntas_abiertas": [q.get("text") for q in n.get("questions") or [] if q.get("status") != "closed"],
        })
    conns = [{"de": lbl(e["source"]), "a": lbl(e["target"]), "acceso": e.get("access") or "sin definir",
              "puerto": e.get("port"), "notas": e.get("notes") or ""} for e in project.get("edges", [])
             if e.get("source") in nodes and e.get("target") in nodes]
    finds = [{"sev": f["severity"], "cat": f["category"], "titulo": f["title"]} for f in analysis["findings"]
             if not f.get("dismissed")]
    return {"proyecto": project.get("name"), "ajustes": project.get("settings"), "componentes": comps,
            "conexiones": conns, "hallazgos_motor_reglas": finds}


def ask(project, analysis, question=None, node_id=None):
    st = status()
    if not st["available"]:
        raise RuntimeError(st["reason"])
    ctx = _compact(project, analysis)
    if node_id:
        focus = next((c for c in ctx["componentes"] if c["id"] == node_id), None)
        if focus:
            question = (question or "") + f"\n\nEnfócate en el componente '{focus['nombre']}' ({focus['tipo']})."
    prompt = ("Diagrama actual (JSON):\n```json\n" + json.dumps(ctx, ensure_ascii=False, indent=1) + "\n```\n\n"
              + (question or "Haz una revisión de arquitectura completa: qué falta, qué cambiarías, qué preguntar al arquitecto."))
    client = anthropic.Anthropic()
    with client.beta.messages.stream(
        model=MODEL,
        max_tokens=16000,
        system=SYSTEM,
        output_config={"effort": "high"},
        betas=["server-side-fallback-2026-07-01"],
        fallbacks="default",
        messages=[{"role": "user", "content": prompt}],
    ) as stream:
        msg = stream.get_final_message()
    if msg.stop_reason == "refusal":
        raise RuntimeError("El modelo declinó la solicitud.")
    text = "".join(b.text for b in msg.content if getattr(b, "type", "") == "text")
    if msg.stop_reason == "max_tokens":
        text += "\n\n_(respuesta truncada)_"
    return {"answer": text, "model": msg.model}
