/* InfraTrack — view */
import { $, S, lsSet } from './core.js';
import { P, center } from './model.js';

/* ───────────────────────── Canvas ───────────────────────── */
export const svg = () => $('#canvas');
export function toWorld(cx, cy) {
  const r = svg().getBoundingClientRect();
  return { x: (cx - r.left - S.view.x) / S.view.k, y: (cy - r.top - S.view.y) / S.view.k };
}
export function applyView() {
  const t = `translate(${S.view.x},${S.view.y}) scale(${S.view.k})`;
  $('#world').setAttribute('transform', t);
  $('#gridRect').setAttribute('transform', t);
  $('#zoomLabel').textContent = Math.round(S.view.k * 100) + '%';
}
export function saveView() { if (P()) lsSet(`it.view.${P().id}`, S.view); }
export function zoomAt(factor, cx, cy) {
  const r = svg().getBoundingClientRect();
  const px = cx ?? r.left + r.width / 2, py = cy ?? r.top + r.height / 2;
  const w = toWorld(px, py);
  const k = Math.min(2.5, Math.max(0.15, S.view.k * factor));
  S.view.k = k;
  S.view.x = px - r.left - w.x * k;
  S.view.y = py - r.top - w.y * k;
  applyView(); saveView();
}
export function fitView() {
  const nodes = P() ? P().nodes : [];
  const r = svg().getBoundingClientRect();
  if (!nodes.length || !r.width) { S.view = { x: 40, y: 60, k: 1 }; applyView(); return; }
  const minX = Math.min(...nodes.map((n) => n.x)), minY = Math.min(...nodes.map((n) => n.y));
  const maxX = Math.max(...nodes.map((n) => n.x + n.w)), maxY = Math.max(...nodes.map((n) => n.y + n.h));
  const pad = 60;
  const k = Math.min(1.4, Math.max(0.15, Math.min((r.width - pad * 2) / (maxX - minX || 1), (r.height - pad * 2 - 40) / (maxY - minY || 1))));
  S.view = { k, x: (r.width - (maxX - minX) * k) / 2 - minX * k, y: (r.height - (maxY - minY) * k) / 2 - minY * k + 15 };
  applyView(); saveView();
}
export function centerOn(n) {
  const r = svg().getBoundingClientRect();
  const c = center(n);
  S.view.x = r.width / 2 - c.x * S.view.k;
  S.view.y = r.height / 2 - c.y * S.view.k;
  applyView(); saveView();
}

export function clipToRect(n, toward) {
  const c = center(n);
  const dx = toward.x - c.x, dy = toward.y - c.y;
  if (!dx && !dy) return c;
  const sx = dx ? (n.w / 2 + 3) / Math.abs(dx) : Infinity;
  const sy = dy ? (n.h / 2 + 3) / Math.abs(dy) : Infinity;
  const s = Math.min(sx, sy, 1);
  return { x: c.x + dx * s, y: c.y + dy * s };
}

export function checkSvg(n, x, y) {
  return `<g class="check ${n.terraformed ? 'on' : ''}" data-check="${n.id}" transform="translate(${x},${y})">
    <title>${n.terraformed ? 'Terraformado — clic para desmarcar' : 'Marcar como terraformado'}</title>
    <circle r="9"/><path d="M-4,0 L-1,3.5 L4.5,-3.5"/></g>`;
}
