/* InfraTrack — inspector-common */
import { copy } from './api.js';
import { $, S, SEV_LABEL, esc } from './core.js';
import { renderEdgeInspector } from './inspector-edge.js';
import { renderNodeInspector } from './inspector-node.js';
import { renderProjectInspector } from './inspector-project.js';
import { select } from './interaction.js';
import { P, edgeById, isEmpty, labelOf, nodeById } from './model.js';

/* ───────────────────────── Inspector ───────────────────────── */
export function fieldHtml(f, val, attr) {
  const req = f.required ? ' <span class="req">*</span>' : '';
  const help = f.help ? `<div class="help">${esc(f.help)}</div>` : '';
  const missing = f.required && isEmpty(val, f) ? 'missing' : '';
  const ph = f.placeholder ? `placeholder="${esc(f.placeholder)}"` : '';
  if (f.type === 'bool') {
    return `<div class="field"><label class="boolrow"><input type="checkbox" ${attr} ${val ? 'checked' : ''}> ${esc(f.label)}${req}</label>${help}</div>`;
  }
  let inner;
  if (f.type === 'select') {
    inner = `<select ${attr}><option value="">—</option>${f.options.map((o) => `<option ${o === val ? 'selected' : ''}>${esc(o)}</option>`).join('')}</select>`;
  } else if (f.type === 'multiselect') {
    const vs = Array.isArray(val) ? val : [];
    inner = `<div class="ms">${f.options.map((o) => `<label class="${vs.includes(o) ? 'on' : ''}"><input type="checkbox" data-ms="${esc(f.key)}" value="${esc(o)}" ${vs.includes(o) ? 'checked' : ''}>${esc(o)}</label>`).join('')}</div>`;
  } else if (f.type === 'rules') {
    inner = rulesTableHtml(f, Array.isArray(val) ? val : []);
  } else if (f.type === 'textarea') {
    inner = `<textarea ${attr} ${ph}>${esc(val)}</textarea>`;
  } else if (f.type === 'number') {
    inner = `<input type="number" ${attr} value="${val ?? ''}" ${ph}>`;
  } else {
    inner = `<input type="text" spellcheck="false" ${attr} value="${esc(val)}" ${ph}>`;
  }
  return `<div class="field ${missing}"><label>${esc(f.label)}${req}</label>${inner}${help}</div>`;
}

export function rulesTableHtml(f, rows) {
  // Cada fila: línea 1 con selects/números (con encabezado), línea 2 con los campos de texto.
  const isPort = (c) => c.key.endsWith('port');
  const short = f.columns.filter((c) => c.type !== 'text' && !isPort(c));
  const long = f.columns.filter((c) => c.type === 'text' || isPort(c));
  const grid = `grid-template-columns:${short.map((c) => (c.key === 'rule_no' ? '52px' : '1fr')).join(' ')} 26px`;
  const grid2 = `grid-template-columns:${long.map((c) => (isPort(c) ? '62px' : '1fr')).join(' ')}`;
  const cell = (c, v, i) => {
    const a = `data-rcell="${esc(f.key)}" data-row="${i}" data-col="${esc(c.key)}" data-ctype="${c.type}" title="${esc(c.label)}"`;
    if (c.type === 'select') return `<select ${a}><option value=""></option>${c.options.map((o) => `<option ${o === v ? 'selected' : ''}>${esc(o)}</option>`).join('')}</select>`;
    if (c.type === 'number') return `<input type="number" ${a} value="${v ?? ''}" placeholder="${isPort(c) ? c.label.toLowerCase() : ''}">`;
    return `<input type="text" spellcheck="false" ${a} value="${esc(v)}" placeholder="${esc(c.label + (c.placeholder ? ': ' + c.placeholder : ''))}">`;
  };
  return `<div class="rules">
    <div class="rhead" style="${grid}">${short.map((c) => `<span>${esc(c.label)}</span>`).join('')}<span></span></div>
    ${rows.map((r, i) => `<div class="rrow">
      <div class="rline" style="${grid}">${short.map((c) => cell(c, r[c.key], i)).join('')}
        <button class="btn sm ghost" data-delrow="${esc(f.key)}" data-row="${i}" title="Quitar">✕</button></div>
      ${long.length ? `<div class="rline long" style="${grid2}">${long.map((c) => cell(c, r[c.key], i)).join('')}</div>` : ''}
    </div>`).join('') || '<div class="muted" style="padding:6px">Sin filas.</div>'}
  </div><button class="btn sm" data-addrow="${esc(f.key)}" style="margin-top:6px">+ Agregar fila</button>`;
}

export function sgSuggestionsHtml(n) {
  const sug = S.analysis && S.analysis.sg_suggestions && S.analysis.sg_suggestions[n.id];
  if (!sug || !sug.length) return '';
  return `<div class="finding sev-medium"><h4>El Copilot sugiere ${sug.length} regla(s) para este SG</h4>
    <ul style="margin:4px 0 6px 16px;padding:0">${sug.map((r) => `<li><code>${esc(r.direction)} ${esc(r.protocol)}/${esc(r.from_port ?? 'todos')} ${r.direction === 'ingress' ? 'desde' : 'hacia'} ${esc(r.peer)}</code> <span class="muted">${esc(r.description)}</span></li>`).join('')}</ul>
    <button class="btn blue sm" data-act="applySg">Agregar reglas sugeridas</button></div>`;
}

export function findingHtml(f, { links = true } = {}) {
  const nodes = links ? f.node_ids.map((id) => nodeById(id)).filter(Boolean) : [];
  return `<div class="finding sev-${f.severity} ${f.dismissed ? 'dismissed' : ''}">
    <div><span class="chip sev-${f.severity}">${SEV_LABEL[f.severity]}</span> <span class="chip">${esc(f.category)}</span></div>
    <h4>${esc(f.title)}</h4>
    ${f.detail ? `<p class="muted">${esc(f.detail)}</p>` : ''}
    <p class="rec">${esc(f.recommendation)}</p>
    ${f.dismissed ? `<p class="muted">Aceptado/descartado por ${esc(f.dismissed.by || '—')}: “${esc(f.dismissed.reason)}”</p>` : ''}
    <div class="foot">
      ${nodes.map((n) => `<a class="link" data-goto="${n.id}">${esc(labelOf(n))}</a>`).join(' · ')}
      <span style="flex:1"></span>
      ${f.dismissed ? `<button class="btn sm" data-undismiss="${f.id}">Reactivar</button>` : `<button class="btn sm" data-dismiss="${f.id}" title="Registrar que se acepta el riesgo o no aplica">Aceptar riesgo / no aplica</button>`}
    </div></div>`;
}

export function codeBlock(text) {
  return `<div class="codewrap"><button class="copy" data-copy="${esc(text)}">Copiar</button><pre class="code">${esc(text)}</pre></div>`;
}

export function renderInspector() {
  const el = $('#inspector');
  if (!P()) { el.innerHTML = ''; return; }
  if (S.sel && S.sel.kind === 'node') { const n = nodeById(S.sel.id); if (n) return renderNodeInspector(el, n); }
  if (S.sel && S.sel.kind === 'edge') { const e = edgeById(S.sel.id); if (e) return renderEdgeInspector(el, e); }
  renderProjectInspector(el);
}

export function nodeFindings(id) {
  return S.analysis ? S.analysis.findings.filter((f) => f.node_ids.includes(id)) : [];
}
