/* InfraTrack — canvas */
import { planBadge } from './tf-import.js';
import { $, ACCESS_SHORT, CONTAINER_PREFIX, ENV_COLOR, NAMED_COLORS, S, SEV_LABEL, SUBNET_STYLE, esc, isAssoc, trunc } from './core.js';
import { envDim } from './filters.js';
import { iconUrl } from './icons.js';
import { P, center, compOf, isContainer, labelOf, nodeById } from './model.js';
import { checkSvg, clipToRect } from './view.js';

export function containerStyle(n, comp, cfg) {
  if (n.type === 'subnet') return SUBNET_STYLE[cfg.tier || 'private'];
  if (n.type === 'account') return { stroke: ENV_COLOR[cfg.environment] || comp.color, fill: 'rgba(127,127,127,.025)', name: '' };
  if (n.type === 'zone') { const c = NAMED_COLORS[cfg.color] || NAMED_COLORS.Azul; return { stroke: c, fill: c + '12', name: '' }; }
  return { stroke: comp.color, fill: 'rgba(140,79,255,.035)', name: '' };
}
export function containerSubtitle(n, st, cfg) {
  let parts;
  if (n.type === 'vpc') parts = [cfg.cidr, cfg.region];
  else if (n.type === 'account') parts = [cfg.account_id, cfg.environment, cfg.ou];
  else if (n.type === 'zone') parts = [cfg.owner, trunc(n.description || '', 80)];
  else parts = [st.name, cfg.cidr, cfg.az ? 'AZ ' + cfg.az : ''];
  return parts.filter(Boolean).join(' · ');
}

export const flows = () => P().settings?.flows || [];
export const flowById = (id) => flows().find((f) => f.id === id);
export const flowColor = (f) => NAMED_COLORS[f.color] || f.color || '#7D8998';
export function edgeInFilter(e) { return !S.flowFilter || (e.flows || []).includes(S.flowFilter); }
export function nodeInFlowFilter(n) {
  if (!S.flowFilter || isContainer(n)) return true;
  return P().edges.some((e) => (e.flows || []).includes(S.flowFilter) && (e.source === n.id || e.target === n.id));
}
export function renderFlowFilter() {
  const sel = $('#flowFilter');
  const fs = flows();
  if (S.flowFilter && !fs.some((f) => f.id === S.flowFilter)) S.flowFilter = '';
  sel.innerHTML = `<option value="">Todos los flujos</option>${fs.map((f) => `<option value="${esc(f.id)}" ${f.id === S.flowFilter ? 'selected' : ''}>${esc(f.id)} ${esc(f.name || '')}</option>`).join('')}`;
  sel.classList.toggle('hidden', !fs.length);
}
/* Parte un nombre en hasta 2 líneas respetando el ancho disponible. */
export function wrapLabel(text, chars) {
  const t = (text || '').trim();
  if (t.length <= chars) return [t];
  const words = t.split(/\s+/);
  let first = '';
  while (words.length && (first + ' ' + words[0]).trim().length <= chars) first = (first + ' ' + words.shift()).trim();
  if (!first) { first = t.slice(0, chars); return [first, trunc(t.slice(chars), chars)]; }
  return [first, trunc(words.join(' '), chars)];
}

export function portSvg(n) {
  return `<g class="port" data-port="${n.id}"><circle class="port-hit" cx="${n.w}" cy="${n.h / 2}" r="13"/>
    <circle class="port-dot" cx="${n.w}" cy="${n.h / 2}" r="6.5"/><title>Arrastra hacia otro componente para conectar</title></g>`;
}

export function renderCanvas() {
  if (!P()) return;
  const isSel = (k, id) => S.sel && S.sel.kind === k && S.sel.id === id;
  const sevOf = (id) => (S.showFindings && S.analysis ? S.analysis.node_severity[id] : null);
  const edgeSev = new Set();
  if (S.showFindings && S.analysis) {
    S.analysis.findings.forEach((f) => { if (!f.dismissed && ['critical', 'high'].includes(f.severity)) f.edge_ids.forEach((e) => edgeSev.add(e)); });
  }
  const containers = P().nodes.filter(isContainer).sort((a, b) => b.w * b.h - a.w * a.h);
  const regular = P().nodes.filter((n) => !isContainer(n));
  let out = '';

  for (const n of containers) {
    const comp = compOf(n), cfg = n.config || {};
    const st = containerStyle(n, comp, cfg);
    const sev = sevOf(n.id);
    const sub = containerSubtitle(n, st, cfg);
    const pending = S.highlightPending && !n.terraformed;
    const cicon = iconUrl(n.type, cfg);
    const cx = cicon ? 40 : 12;
    out += `<g class="container ${isSel('node', n.id) ? 'sel' : ''} ${S.hover === n.id ? 'drop-target' : ''} ${envDim(n) ? 'dim' : ''}" data-node="${n.id}" transform="translate(${n.x},${n.y})">
      <rect class="cbody" width="${n.w}" height="${n.h}" rx="10" fill="${st.fill}" stroke="${st.stroke}"/>
      ${planBadge(n)}
      ${pending ? `<rect class="pending-ring" x="-4" y="-4" width="${n.w + 8}" height="${n.h + 8}" rx="13"/>` : ''}
      ${sev ? `<circle class="sevdot sev-${sev}" cx="${n.w - 34}" cy="16" r="5"><title>Hallazgo ${SEV_LABEL[sev]}</title></circle>` : ''}
      ${cicon ? `<image href="${esc(cicon)}" x="8" y="7" width="26" height="26"/>` : ''}
      <text class="chead" x="${cx}" y="20" fill="${st.stroke}">${esc(CONTAINER_PREFIX[n.type] || '')}${esc(trunc(n.label, 40))}</text>
      <text class="csub" x="${cx}" y="35" fill="${st.stroke}">${esc(sub)}</text>
      ${checkSvg(n, n.w - 14, 15)}
      ${portSvg(n)}
      <rect class="resize" x="${n.w - 11}" y="${n.h - 11}" width="11" height="11" rx="2" data-resize="${n.id}"/>
    </g>`;
  }

  for (const e of P().edges) {
    const a = nodeById(e.source), b = nodeById(e.target);
    if (!a || !b) continue;
    const p1 = clipToRect(a, center(b)), p2 = clipToRect(b, center(a));
    const sel = isSel('edge', e.id);
    const marker = sel ? 'arrowSel' : e.terraformed ? 'arrowOk' : 'arrow';
    const assoc = isAssoc(e);
    const vpceAssoc = assoc && [a.type, b.type].includes('vpce') && [a.type, b.type].includes('subnet');
    const base = [e.access ? ACCESS_SHORT[e.access] : '¿acceso?', e.port ? ':' + e.port : ''].join('') + (e.label ? ' · ' + e.label : '');
    const txt = assoc ? (vpceAssoc ? 'desplegado en' : 'asignado') : base;
    const efl = (e.flows || []).map(flowById).filter(Boolean);
    const shown = trunc(txt, 60);
    const dots = efl.length * 10;
    const mx = (p1.x + p2.x) / 2, my = (p1.y + p2.y) / 2, tw = Math.min(400, shown.length * 6 + 12 + dots);
    const stroke = !sel && efl.length ? `style="stroke:${flowColor(efl[0])};stroke-width:2.2"` : '';
    const tip = `${labelOf(a)} → ${labelOf(b)}: ${txt}${efl.length ? '\nFlujos: ' + efl.map((f) => `${f.id} ${f.name || ''}`).join(', ') : ''}`;
    out += `<g class="edge ${sel ? 'sel' : ''} ${edgeSev.has(e.id) ? 'sev-edge' : ''} ${edgeInFilter(e) ? '' : 'dim'}" data-edge="${e.id}">
      <title>${esc(tip)}</title>
      <line class="hit" x1="${p1.x}" y1="${p1.y}" x2="${p2.x}" y2="${p2.y}"/>
      <line class="line ${assoc ? 'assoc' : e.access ? '' : 'undef'} ${e.terraformed ? 'ok' : ''}" ${stroke} x1="${p1.x}" y1="${p1.y}" x2="${p2.x}" y2="${p2.y}" marker-end="url(#${marker})"/>
      <g class="elabel" transform="translate(${mx},${my})"><rect x="${-tw / 2}" y="-9" width="${tw}" height="17" rx="8"/>
      ${efl.map((f, i) => `<circle cx="${-tw / 2 + 9 + i * 10}" cy="0" r="4" style="fill:${flowColor(f)}"/>`).join('')}
      <text x="${dots / 2}" y="3.5">${esc(shown)}</text></g></g>`;
  }

  for (const n of regular) {
    const comp = compOf(n);
    const sel = isSel('node', n.id);
    if (n.type === 'note') {
      out += `<g class="notecard ${sel ? 'sel' : ''}" data-node="${n.id}" transform="translate(${n.x},${n.y})">
        <rect width="${n.w}" height="${n.h}" rx="4"/>
        <foreignObject x="8" y="6" width="${n.w - 16}" height="${n.h - 12}"><div xmlns="http://www.w3.org/1999/xhtml" style="font:12px/1.35 var(--font);color:#5c4a00;overflow:hidden;height:100%;white-space:pre-wrap"><b>${esc(n.label)}</b>${n.description ? '\n' + esc(n.description) : ''}</div></foreignObject>
        <rect class="resize" x="${n.w - 10}" y="${n.h - 10}" width="10" height="10" data-resize="${n.id}" style="fill:transparent;stroke:none"/></g>`;
      continue;
    }
    const sev = sevOf(n.id);
    const pending = S.highlightPending && comp.terraformable && !n.terraformed;
    const dim = (S.highlightPending && n.terraformed) || envDim(n) || !nodeInFlowFilter(n);
    const openQ = (n.questions || []).filter((q) => q.status !== 'closed' && !q.answer).length;
    const nNotes = (n.notes || []).length;
    const h = n.h, w = n.w;
    const badges = [nNotes ? `📝${nNotes}` : '', openQ ? `❓${openQ}` : ''].filter(Boolean).join(' ');
    const cfg = n.config || {};
    const custom = n.type === 'custom_ext' && cfg.abbr;
    const icon = custom ? null : iconUrl(n.type, cfg);
    const color = n.type === 'custom_ext' ? (NAMED_COLORS[cfg.color] || comp.color) : comp.color;
    const abbr = custom ? String(cfg.abbr).slice(0, 6) : comp.abbr;
    const tx = icon ? 51 : 46;
    const chars = Math.max(8, Math.floor((w - tx - 16) / 6.8));
    const lines = wrapLabel(n.label, chars);
    const y0 = lines.length > 1 ? h / 2 - 9 : h / 2 - 3;
    out += `<g class="node ${sel ? 'sel' : ''} ${dim ? 'dim' : ''} ${S.hover === n.id ? 'drop-target' : ''}" data-node="${n.id}" transform="translate(${n.x},${n.y})">
      ${sev ? `<rect class="sevring sev-${sev}" x="-4" y="-4" width="${w + 8}" height="${h + 8}" rx="11"><title>Hallazgo ${SEV_LABEL[sev]}</title></rect>` : ''}
      ${pending ? `<rect class="pending-ring" x="-7" y="-7" width="${w + 14}" height="${h + 14}" rx="13"/>` : ''}
      <rect class="body" width="${w}" height="${h}" rx="8"/>
      ${planBadge(n)}
      ${icon ? `<rect class="icon-tile" x="5" y="${(h - 40) / 2}" width="40" height="40" rx="6"/>
      <image href="${esc(icon)}" x="9" y="${(h - 32) / 2}" width="32" height="32"/>`
    : `<path d="M8,0 H38 V${h} H8 A8,8 0 0 1 0,${h - 8} V8 A8,8 0 0 1 8,0 Z" fill="${color}"/>
      <text class="abbr" x="19" y="${h / 2 + 4}" style="font-size:${abbr.length > 4 ? 9 : 11}px">${esc(abbr)}</text>`}
      ${lines.map((l, i) => `<text class="label" x="${tx}" y="${y0 + i * 13}">${esc(l)}</text>`).join('')}
      <text class="type" x="${tx}" y="${y0 + lines.length * 13 + 2}">${esc(trunc(comp.name, chars + 4))}</text>
      ${comp.terraformable ? checkSvg(n, w - 1, 1) : ''}
      ${badges ? `<text class="nbadge" x="${w - 5}" y="${h - 5}" text-anchor="end">${badges}</text>` : ''}
      ${portSvg(n)}
      <rect class="resize nresize" x="${w - 9}" y="${h - 9}" width="9" height="9" rx="2" data-resize="${n.id}"/>
      <title>${esc(n.label)} — ${esc(comp.name)}${n.terraformed ? ' (terraformado)' : ''}${n.description ? '\n' + esc(trunc(n.description, 200)) : ''}</title>
    </g>`;
  }

  if (S.temp) out += `<line class="temp-line" x1="${S.temp.x1}" y1="${S.temp.y1}" x2="${S.temp.x2}" y2="${S.temp.y2}"/>`;
  $('#world').innerHTML = out;
  $('#emptyHint').classList.toggle('hidden', P().nodes.length > 0);
}
