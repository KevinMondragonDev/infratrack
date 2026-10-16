/* InfraTrack — model */
import { renderCanvas } from './canvas.js';
import { $, S } from './core.js';
import { renderInspector } from './inspector-common.js';
import { scheduleAnalyze, scheduleSave } from './persistence.js';
import { updateProgress } from './statusbar.js';

/* ───────────────────────── Modelo ───────────────────────── */
export const P = () => S.project;
export const nodeById = (id) => P().nodes.find((n) => n.id === id);
export const edgeById = (id) => P().edges.find((e) => e.id === id);
export const compOf = (n) => S.comp[n.type] || { name: n.type, abbr: '?', color: '#888', fields: [], category: 'external' };
export const isContainer = (n) => !!compOf(n).container;
export const center = (n) => ({ x: n.x + n.w / 2, y: n.y + n.h / 2 });
export const labelOf = (n) => (n ? n.label || compOf(n).name : '—');

export function showIf(f, cfg) {
  if (!f.show_if) return true;
  return Object.entries(f.show_if).every(([k, vals]) => {
    const v = cfg[k];
    if (Array.isArray(v)) return v.some((x) => vals.includes(x));
    return vals.includes(v === undefined ? null : v);
  });
}
export const isEmpty = (v, f) => (f.type === 'bool' ? v === undefined || v === null : v === undefined || v === null || v === '' || (Array.isArray(v) && !v.length));
export function configProgress(n) {
  const cfg = n.config || {};
  const req = compOf(n).fields.filter((f) => f.required && showIf(f, cfg));
  const done = req.filter((f) => !isEmpty(cfg[f.key], f)).length;
  return { done, total: req.length, pct: req.length ? Math.round((100 * done) / req.length) : 100 };
}

export function descendants(c) {
  const area = c.w * c.h;
  return P().nodes.filter((n) => {
    if (n.id === c.id) return false;
    const m = center(n);
    if (!(m.x >= c.x && m.x <= c.x + c.w && m.y >= c.y && m.y <= c.y + c.h)) return false;
    return !isContainer(n) || n.w * n.h < area;
  });
}

export function containerAt(pt, excludeIds = new Set()) {
  let best = null;
  for (const c of P().nodes) {
    if (!isContainer(c) || excludeIds.has(c.id)) continue;
    if (pt.x >= c.x && pt.x <= c.x + c.w && pt.y >= c.y && pt.y <= c.y + c.h) {
      if (!best || c.w * c.h < best.w * best.h) best = c;
    }
  }
  return best;
}

export function snapshot() {
  S.undo.push(JSON.stringify({ nodes: P().nodes, edges: P().edges, dismissed: P().dismissed || {} }));
  if (S.undo.length > 150) S.undo.shift();
  S.redo = [];
  updateUndoButtons();
}
export function restoreState(stack, other) {
  if (!stack.length) return;
  other.push(JSON.stringify({ nodes: P().nodes, edges: P().edges, dismissed: P().dismissed || {} }));
  const st = JSON.parse(stack.pop());
  Object.assign(P(), st);
  if (S.sel && !(S.sel.kind === 'node' ? nodeById(S.sel.id) : edgeById(S.sel.id))) S.sel = null;
  changed({ inspector: true });
  updateUndoButtons();
}
export const undo = () => restoreState(S.undo, S.redo);
export const redo = () => restoreState(S.redo, S.undo);
export function updateUndoButtons() { $('#btnUndo').disabled = !S.undo.length; $('#btnRedo').disabled = !S.redo.length; }

export function changed({ canvas = true, inspector = false } = {}) {
  scheduleSave();
  scheduleAnalyze();
  if (canvas) renderCanvas();
  if (inspector) renderInspector();
  updateProgress();
}
