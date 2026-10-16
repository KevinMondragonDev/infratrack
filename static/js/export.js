/* InfraTrack — export: diagrama a SVG, PNG y draw.io (iconos incrustados, funciona fuera de la app) */
import { $, NAMED_COLORS, SUBNET_STYLE, ENV_COLOR, esc } from './core.js';
import { P, compOf, isContainer, labelOf } from './model.js';
import { iconUrl } from './icons.js';
import { download, fileSafe } from './storage.js';
import { reportError, toast } from './api.js';

const MARGIN = 40;
const TITLE_H = 46;
const iconCache = new Map();

/* Estilos con colores fijos (tema claro): el archivo exportado no depende de la hoja de estilos de la app. */
const EXPORT_CSS = `
text { font-family: -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; }
.node .body { fill: #fff; stroke: #c9d0d8; stroke-width: 1; }
.node .label { fill: #16191f; font-size: 12.5px; font-weight: 600; }
.node .type { fill: #5f6b7a; font-size: 10.5px; }
.node .abbr { fill: #fff; font-size: 11px; font-weight: 800; text-anchor: middle; }
.icon-tile { fill: #fff; stroke: #dfe3e8; }
.check circle { fill: #fff; stroke: #9aa5b1; stroke-width: 1.5; }
.check.on circle { fill: #1d8102; stroke: #1d8102; }
.check path { stroke: #fff; stroke-width: 2.2; fill: none; stroke-linecap: round; stroke-linejoin: round; }
.check:not(.on) path { stroke: transparent; }
.container .cbody { stroke-width: 1.5; stroke-dasharray: 7 4; }
.container .chead { font-size: 12px; font-weight: 700; }
.container .csub { font-size: 11px; }
.edge .line { stroke: #7d8998; stroke-width: 1.6; fill: none; }
.edge .line.undef { stroke-dasharray: 5 4; }
.edge .line.assoc { stroke-dasharray: 2 4; opacity: .7; }
.edge .line.ok { stroke: #1d8102; }
.edge .elabel rect { fill: #fff; stroke: #dfe3e8; }
.edge .elabel text { font-size: 10.5px; fill: #5f6b7a; text-anchor: middle; }
.sevring { fill: none; stroke-width: 2.5; }
.sev-critical { stroke: #b3261e; } .sev-high { stroke: #e0590b; } .sev-medium { stroke: #c99700; } .sev-low { stroke: #2f6fb3; } .sev-info { stroke: #7d8998; }
.sevdot.sev-critical { fill: #b3261e; } .sevdot.sev-high { fill: #e0590b; } .sevdot.sev-medium { fill: #c99700; } .sevdot.sev-low { fill: #2f6fb3; }
.nbadge { font-size: 10px; fill: #5f6b7a; }
.notecard rect { fill: #fff6c2; stroke: #e6cf62; }
.notecard text { fill: #5c4a00; font-size: 12px; }
.plan-badge circle { stroke: #fff; stroke-width: 2; } .plan-badge text { fill: #fff; font-size: 13px; font-weight: 800; text-anchor: middle; }
.plan-create circle { fill: #1d8102; } .plan-update circle { fill: #c99700; } .plan-delete circle { fill: #d13212; } .plan-replace circle { fill: #e0590b; }
.arrow-head { fill: #7d8998; } .arrow-head.ok { fill: #1d8102; }
.title { font-size: 18px; font-weight: 700; fill: #16191f; } .subtitle { font-size: 11.5px; fill: #5f6b7a; }`;

function b64(text) {
  const bytes = new TextEncoder().encode(text);
  let bin = '';
  bytes.forEach((b) => { bin += String.fromCharCode(b); });
  return btoa(bin);
}

async function iconData(url) {
  if (!iconCache.has(url)) {
    const r = await fetch(url);
    iconCache.set(url, r.ok ? `data:image/svg+xml;base64,${b64(await r.text())}` : '');
  }
  return iconCache.get(url);
}

function bounds() {
  const nodes = P().nodes;
  if (!nodes.length) return { x: 0, y: 0, w: 400, h: 200 };
  const x = Math.min(...nodes.map((n) => n.x)) - MARGIN;
  const y = Math.min(...nodes.map((n) => n.y)) - MARGIN - TITLE_H;
  const w = Math.max(...nodes.map((n) => n.x + n.w)) + MARGIN - x;
  const h = Math.max(...nodes.map((n) => n.y + n.h)) + MARGIN - y;
  return { x, y, w, h };
}

/* SVG autónomo: copia del lienzo sin controles de edición, con iconos en base64 y notas como texto plano. */
export async function buildSvg({ findings = true } = {}) {
  const g = $('#world').cloneNode(true);
  g.removeAttribute('transform');
  g.querySelectorAll('.port, .resize, .hit, .temp-line, .pending-ring').forEach((el) => el.remove());
  if (!findings) g.querySelectorAll('.sevring, .sevdot').forEach((el) => el.remove());
  g.querySelectorAll('.dim, .drop-target, .sel').forEach((el) => el.classList.remove('dim', 'drop-target', 'sel'));
  g.querySelectorAll('foreignObject').forEach((fo) => {
    const lines = (fo.textContent || '').split('\n').slice(0, 6);
    const t = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    t.setAttribute('x', fo.getAttribute('x')); t.setAttribute('y', Number(fo.getAttribute('y')) + 12);
    lines.forEach((l, i) => {
      const s = document.createElementNS('http://www.w3.org/2000/svg', 'tspan');
      s.setAttribute('x', fo.getAttribute('x')); s.setAttribute('dy', i ? '15' : '0'); s.textContent = l.slice(0, 40);
      t.appendChild(s);
    });
    fo.replaceWith(t);
  });
  await Promise.all([...g.querySelectorAll('image')].map(async (img) => {
    const href = img.getAttribute('href');
    if (href) img.setAttribute('href', await iconData(href));
  }));
  const b = bounds();
  const date = new Date().toLocaleString('es');
  const defs = $('#canvas defs').outerHTML.replace(/<pattern[\s\S]*?<\/pattern>/, '');
  return `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="${b.x} ${b.y} ${b.w} ${b.h}" width="${b.w}" height="${b.h}">
<style>${EXPORT_CSS}</style>${defs}
<rect x="${b.x}" y="${b.y}" width="${b.w}" height="${b.h}" fill="#ffffff"/>
<text class="title" x="${b.x + MARGIN}" y="${b.y + 28}">${esc(P().name)}</text>
<text class="subtitle" x="${b.x + MARGIN}" y="${b.y + 44}">InfraTrack · ${esc(date)}</text>
${g.innerHTML}
</svg>`;
}

async function exportSvg() {
  download(`${fileSafe(P().name)}.svg`, await buildSvg(), 'image/svg+xml');
}

async function exportPng() {
  const svg = await buildSvg();
  const b = bounds();
  const img = new Image();
  img.src = `data:image/svg+xml;base64,${b64(svg)}`;
  await img.decode();
  const scale = Math.min(2, 16000 / Math.max(b.w, b.h));
  const canvas = document.createElement('canvas');
  canvas.width = Math.round(b.w * scale); canvas.height = Math.round(b.h * scale);
  const ctx = canvas.getContext('2d');
  ctx.fillStyle = '#fff'; ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
  const blob = await new Promise((res) => canvas.toBlob(res, 'image/png'));
  download(`${fileSafe(P().name)}.png`, blob, 'image/png');
}

/* ───── draw.io (mxGraph) ───── */
const xml = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;' }[c]));

function containerColor(n) {
  const cfg = n.config || {};
  if (n.type === 'subnet') return SUBNET_STYLE[cfg.tier || 'private'].stroke;
  if (n.type === 'account') return ENV_COLOR[cfg.environment] || compOf(n).color;
  if (n.type === 'zone') return NAMED_COLORS[cfg.color] || NAMED_COLORS.Azul;
  return compOf(n).color;
}

async function nodeCell(n, id) {
  const comp = compOf(n);
  const label = `${labelOf(n)}${n.terraformed ? ' ✓' : ''}`;
  if (isContainer(n)) {
    const cfg = n.config || {};
    const sub = [cfg.cidr, cfg.az ? `AZ ${cfg.az}` : '', cfg.account_id, cfg.environment].filter(Boolean).join(' · ');
    const style = `rounded=1;arcSize=2;whiteSpace=wrap;html=1;fillColor=none;dashed=1;strokeColor=${containerColor(n)};fontColor=${containerColor(n)};verticalAlign=top;align=left;spacingLeft=10;spacingTop=4;fontStyle=1;`;
    return `<mxCell id="${id}" value="${xml(`${comp.name}: ${label}${sub ? `<br><span style="font-weight:normal">${xml(sub)}</span>` : ''}`)}" style="${style}" vertex="1" parent="1"><mxGeometry x="${n.x}" y="${n.y}" width="${n.w}" height="${n.h}" as="geometry"/></mxCell>`;
  }
  if (n.type === 'note') {
    return `<mxCell id="${id}" value="${xml(`${n.label}\n${n.description || ''}`)}" style="shape=note;whiteSpace=wrap;html=0;fillColor=#fff6c2;strokeColor=#e6cf62;align=left;verticalAlign=top;spacing=6;" vertex="1" parent="1"><mxGeometry x="${n.x}" y="${n.y}" width="${n.w}" height="${n.h}" as="geometry"/></mxCell>`;
  }
  const url = iconUrl(n.type, n.config);
  const data = url ? await iconData(url) : '';
  const icon = data ? `shape=image;aspect=fixed;image=${data.replace(';base64', '')};` : `rounded=1;fillColor=${comp.color};fontColor=#ffffff;`;
  const size = 48;
  return `<mxCell id="${id}" value="${xml(`${label}\n${comp.name}`)}" style="${icon}verticalLabelPosition=bottom;verticalAlign=top;labelBackgroundColor=#ffffff;html=0;whiteSpace=wrap;fontSize=11;" vertex="1" parent="1"><mxGeometry x="${n.x + (n.w - size) / 2}" y="${n.y}" width="${size}" height="${size}" as="geometry"/></mxCell>`;
}

function edgeCell(e, ids, id) {
  const flow = (P().settings?.flows || []).find((f) => (e.flows || []).includes(f.id));
  const color = flow ? (NAMED_COLORS[flow.color] || '#7d8998') : e.terraformed ? '#1d8102' : '#7d8998';
  const label = [e.access || '', e.port ? `:${e.port}` : '', e.label ? ` ${e.label}` : ''].join('');
  return `<mxCell id="${id}" value="${xml(label)}" style="endArrow=classic;html=0;rounded=0;strokeColor=${color};fontSize=10;${e.access ? '' : 'dashed=1;'}" edge="1" parent="1" source="${ids[e.source]}" target="${ids[e.target]}"><mxGeometry relative="1" as="geometry"/></mxCell>`;
}

export async function buildDrawio() {
  const nodes = [...P().nodes].sort((a, b) => Number(isContainer(b)) - Number(isContainer(a)) || b.w * b.h - a.w * a.h);
  const ids = Object.fromEntries(nodes.map((n, i) => [n.id, `n${i + 2}`]));
  const cells = await Promise.all(nodes.map((n) => nodeCell(n, ids[n.id])));
  const edges = P().edges.filter((e) => ids[e.source] && ids[e.target]).map((e, i) => edgeCell(e, ids, `e${i}`));
  return `<mxfile host="InfraTrack"><diagram name="${xml(P().name)}"><mxGraphModel grid="1" gridSize="10" page="0"><root>
<mxCell id="0"/><mxCell id="1" parent="0"/>
${cells.join('\n')}
${edges.join('\n')}
</root></mxGraphModel></diagram></mxfile>`;
}

async function exportDrawio() {
  download(`${fileSafe(P().name)}.drawio`, await buildDrawio(), 'application/xml');
}

export async function runExport(kind) {
  if (!P().nodes.length) { toast('El diagrama está vacío'); return; }
  const fn = { svg: exportSvg, png: exportPng, drawio: exportDrawio }[kind];
  try { await fn(); toast('Diagrama exportado'); } catch (e) { reportError(e); }
}

