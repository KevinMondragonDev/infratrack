/* InfraTrack — interaction */
import { toast } from './api.js';
import { renderCanvas } from './canvas.js';
import { $, S, isAssoc, isAssocPair, nowIso, snap, uid } from './core.js';
import { renderInspector } from './inspector-common.js';
import { P, center, changed, containerAt, descendants, isContainer, labelOf, nodeById, snapshot } from './model.js';
import { applyView, saveView, svg, toWorld, zoomAt } from './view.js';

/* ───── interacción ───── */
export function onPointerDown(ev) {
  if (ev.button !== 0 || !P()) return;
  const t = ev.target;
  svg().focus({ preventScroll: true });
  const chk = t.closest('[data-check]');
  if (chk) { toggleTerraformed(nodeById(chk.dataset.check)); return; }
  const port = t.closest('[data-port]');
  if (port) {
    const n = nodeById(port.dataset.port);
    const c = { x: n.x + n.w, y: n.y + n.h / 2 };
    S.drag = { kind: 'connect', from: n.id };
    S.temp = { x1: c.x, y1: c.y, x2: c.x, y2: c.y };
    return;
  }
  const rz = t.closest('[data-resize]');
  if (rz) {
    const n = nodeById(rz.dataset.resize);
    S.drag = { kind: 'resize', id: n.id, p0: toWorld(ev.clientX, ev.clientY), w0: n.w, h0: n.h, snap: false };
    return;
  }
  const ed = t.closest('[data-edge]');
  if (ed) { select('edge', ed.dataset.edge); return; }
  const nd = t.closest('[data-node]');
  if (nd) {
    const n = nodeById(nd.dataset.node);
    if (!(S.sel && S.sel.kind === 'node' && S.sel.id === n.id)) select('node', n.id);
    const ids = [n.id, ...(isContainer(n) ? descendants(n).map((d) => d.id) : [])];
    S.drag = { kind: 'move', ids, starts: Object.fromEntries(ids.map((id) => { const x = nodeById(id); return [id, { x: x.x, y: x.y }]; })),
      p0: toWorld(ev.clientX, ev.clientY), moved: false, main: n.id };
    return;
  }
  if (S.sel) select(null);
  S.drag = { kind: 'pan', x0: ev.clientX, y0: ev.clientY, vx: S.view.x, vy: S.view.y };
  svg().classList.add('panning');
}

export function onPointerMove(ev) {
  const d = S.drag;
  if (!d) return;
  if (d.kind === 'pan') {
    S.view.x = d.vx + ev.clientX - d.x0; S.view.y = d.vy + ev.clientY - d.y0; applyView(); return;
  }
  const p = toWorld(ev.clientX, ev.clientY);
  if (d.kind === 'move') {
    const dx = p.x - d.p0.x, dy = p.y - d.p0.y;
    if (!d.moved && Math.hypot(dx, dy) * S.view.k < 4) return;
    if (!d.moved) { snapshot(); d.moved = true; }
    const m = d.starts[d.main];
    const ddx = snap(m.x + dx) - m.x, ddy = snap(m.y + dy) - m.y;
    for (const id of d.ids) { const n = nodeById(id); n.x = d.starts[id].x + ddx; n.y = d.starts[id].y + ddy; }
    const main = nodeById(d.main);
    const c = containerAt(center(main), new Set(d.ids));
    S.hover = c ? c.id : null;
    renderCanvas();
  } else if (d.kind === 'resize') {
    if (!d.snap) { snapshot(); d.snap = true; }
    const n = nodeById(d.id);
    const minW = isContainer(n) ? 160 : n.type === 'note' ? 100 : 110;
    const minH = isContainer(n) ? 90 : n.type === 'note' ? 40 : 48;
    n.w = Math.max(minW, snap(d.w0 + p.x - d.p0.x));
    n.h = Math.max(minH, snap(d.h0 + p.y - d.p0.y));
    renderCanvas();
  } else if (d.kind === 'connect') {
    S.temp.x2 = p.x; S.temp.y2 = p.y;
    const el = document.elementFromPoint(ev.clientX, ev.clientY);
    const nd = el && el.closest('[data-node]');
    S.hover = nd && nd.dataset.node !== d.from ? nd.dataset.node : null;
    renderCanvas();
  }
}

export function onPointerUp(ev) {
  const d = S.drag;
  if (!d) return;
  S.drag = null;
  svg().classList.remove('panning');
  if (d.kind === 'pan') { saveView(); return; }
  if (d.kind === 'move') { S.hover = null; if (d.moved) changed({ inspector: false }); else renderCanvas(); return; }
  if (d.kind === 'resize') { if (d.snap) changed(); return; }
  if (d.kind === 'connect') {
    const target = S.hover;
    S.temp = null; S.hover = null;
    if (target && target !== d.from) {
      const dup = P().edges.find((e) => e.source === d.from && e.target === target);
      if (dup) { select('edge', dup.id); renderCanvas(); toast('Esa conexión ya existe'); return; }
      snapshot();
      const e = { id: uid('e'), source: d.from, target, access: guessAccess(nodeById(d.from), nodeById(target)), port: null, protocol: 'tcp', label: '', notes: '', terraformed: false };
      P().edges.push(e);
      select('edge', e.id);
      changed();
      toast(isAssoc(e) ? 'Asignación creada' : 'Conexión creada: revisa los permisos que necesita en el panel derecho');
    } else renderCanvas();
  }
}

export function guessAccess(a, b) {
  if (isAssocPair(a, b)) return null;
  if (['users', 'onprem', 'alb', 'nlb', 'cloudfront'].includes(a.type)) return 'network';
  if (['rds', 'aurora', 'elasticache', 'documentdb', 'efs', 'redshift', 'msk', 'ec2', 'asg', 'ecs', 'eks'].includes(b.type)) return 'network';
  if (['lambda', 'stepfn', 'glue', 'emr', 'apigw', 'athena'].includes(b.type)) return 'invoke';
  if (['sqs', 'sns', 'eventbridge', 'firehose', 'cloudwatch'].includes(b.type)) return 'write';
  if (['secrets', 'ecr', 'glue_catalog'].includes(b.type)) return 'read';
  return null;
}

export function onWheel(ev) {
  ev.preventDefault();
  // Ctrl/Cmd + rueda (o pinch en trackpad) = zoom; rueda/dos dedos = desplazar.
  if (ev.ctrlKey || ev.metaKey || ev.deltaMode !== 0) {
    const dy = ev.deltaMode === 1 ? ev.deltaY * 30 : ev.deltaY;
    zoomAt(Math.exp(-dy * (ev.ctrlKey ? 0.01 : 0.0018)), ev.clientX, ev.clientY);
  } else {
    S.view.x -= ev.deltaX; S.view.y -= ev.deltaY; applyView(); clearTimeout(onWheel.t); onWheel.t = setTimeout(saveView, 300);
  }
}

export function toggleTerraformed(n) {
  snapshot();
  n.terraformed = !n.terraformed;
  n.terraformed_at = n.terraformed ? nowIso() : null;
  changed({ inspector: S.sel && S.sel.id === n.id });
  toast(n.terraformed ? `✓ ${labelOf(n)} terraformado` : `${labelOf(n)} marcado como pendiente`);
}

export function deleteSelection() {
  if (!S.sel) return;
  snapshot();
  if (S.sel.kind === 'node') {
    P().nodes = P().nodes.filter((n) => n.id !== S.sel.id);
    P().edges = P().edges.filter((e) => e.source !== S.sel.id && e.target !== S.sel.id);
  } else P().edges = P().edges.filter((e) => e.id !== S.sel.id);
  S.sel = null;
  changed({ inspector: true });
}

export function duplicateNode(n) {
  snapshot();
  const c = JSON.parse(JSON.stringify(n));
  c.id = uid('n'); c.x += 30; c.y += 30; c.label = n.label + ' (copia)'; c.terraformed = false; c.terraformed_at = null;
  c.questions = []; c.notes = [];
  P().nodes.push(c);
  select('node', c.id);
  changed();
}

export function select(kind, id, tab) {
  S.sel = kind ? { kind, id } : null;
  if (tab) S.tab = tab;
  else if (kind === 'edge') S.tab = 'edge';
  else if (kind === 'node' && (S.tab === 'edge' || !S.tab)) S.tab = 'general';
  renderCanvas(); renderInspector();
  $('#inspector').scrollTop = 0;
}
