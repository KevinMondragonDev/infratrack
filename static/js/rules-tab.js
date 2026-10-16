/* InfraTrack — rules-tab: reglas del Copilot configurables por proyecto */
import { api, reportError, toast } from './api.js';
import { $, $$, S, SEVS, SEV_LABEL, esc } from './core.js';
import { renderCopilotTab } from './copilot-modal.js';
import { P, changed, snapshot } from './model.js';
import { download } from './storage.js';

const overrides = () => { P().settings = P().settings || {}; P().settings.rules = P().settings.rules || {}; return P().settings.rules; };
const b64ToText = (b64) => new TextDecoder().decode(Uint8Array.from(atob(b64), (ch) => ch.charCodeAt(0)));

export async function loadRegistry() {
  if (!S.rulesRegistry) S.rulesRegistry = (await api('GET', '/api/rules')).rules;
  return S.rulesRegistry;
}

function ruleCounts(A) {
  const counts = {};
  for (const f of A.findings) if (!f.dismissed) counts[f.rule] = (counts[f.rule] || 0) + 1;
  return counts;
}

function ruleRow(r, ov, count) {
  const changedRow = ov.enabled === false || ov.severity;
  const sevOptions = [`<option value="">Por defecto (${SEV_LABEL[r.severity]})</option>`,
    ...SEVS.map((s) => `<option value="${s}" ${ov.severity === s ? 'selected' : ''}>${SEV_LABEL[s]}</option>`)].join('');
  const search = `${r.id} ${r.category} ${r.title}`.toLowerCase();
  return `<tr data-search="${esc(search)}" data-changed="${changedRow ? 1 : 0}" data-count="${count}" class="${ov.enabled === false ? 'rule-off' : ''}">
    <td><input type="checkbox" data-ren="${esc(r.id)}" ${ov.enabled === false ? '' : 'checked'} title="Activa"></td>
    <td><code>${esc(r.id)}</code><div class="muted">${esc(r.category)}</div></td>
    <td>${esc(r.title)}</td>
    <td>${count ? `<span class="chip sev-${r.severity}">${count}</span>` : '<span class="muted">0</span>'}</td>
    <td><select data-rsev="${esc(r.id)}" class="btn sm">${sevOptions}</select></td>
    <td><input type="text" data-rcom="${esc(r.id)}" value="${esc(ov.comment || '')}" placeholder="Motivo del ajuste" class="rule-comment"></td>
  </tr>`;
}

export function rulesTabHtml(A) {
  if (!S.rulesRegistry) {
    loadRegistry().then(() => { if (S.mtab === 'rules') renderCopilotTab(); }).catch(reportError);
    return '<p class="muted">Cargando reglas…</p>';
  }
  const ov = overrides();
  const counts = ruleCounts(A);
  const adjusted = Object.keys(ov).length;
  return `<p class="muted">${S.rulesRegistry.length} reglas · ${adjusted} ajustadas en este proyecto. Desactiva las que no apliquen a tu contexto
      o cambia su severidad: los ajustes se guardan con el proyecto y aparecen en el reporte.</p>
    <div class="filters">
      <input type="search" id="rulesSearch" placeholder="Buscar regla, categoría o descripción…" class="rules-search">
      <label class="tgl"><input type="checkbox" id="rulesOnlyChanged"> Sólo ajustadas</label>
      <label class="tgl"><input type="checkbox" id="rulesOnlyHits"> Sólo con hallazgos</label>
    </div>
    <div class="filters">
      <button class="btn sm" data-rules="export-csv">Exportar lista para revisión (CSV)</button>
      <label class="btn sm">Importar CSV revisado<input type="file" id="rulesCsv" accept=".csv,text/csv" hidden></label>
      <button class="btn sm" data-rules="export-json">Exportar configuración (JSON)</button>
      <label class="btn sm">Importar configuración<input type="file" id="rulesJson" accept=".json,application/json" hidden></label>
      ${adjusted ? '<button class="btn sm danger" data-rules="reset">Restablecer todo</button>' : ''}
    </div>
    <table class="tbl rules-table"><thead><tr><th></th><th>Regla</th><th>Descripción</th><th>Hallazgos</th><th>Severidad</th><th>Comentario</th></tr></thead>
    <tbody>${S.rulesRegistry.map((r) => ruleRow(r, ov[r.id] || {}, counts[r.id] || 0)).join('')}</tbody></table>`;
}

function setOverride(id, patch) {
  snapshot();
  const all = overrides();
  const cur = { ...(all[id] || {}), ...patch };
  if (cur.enabled !== false) delete cur.enabled;
  if (!cur.severity) delete cur.severity;
  if (!cur.comment) delete cur.comment;
  if (Object.keys(cur).length) all[id] = cur; else delete all[id];
  changed({ canvas: true });
}

export function filterRules() {
  const q = ($('#rulesSearch')?.value || '').trim().toLowerCase();
  const onlyChanged = $('#rulesOnlyChanged')?.checked;
  const onlyHits = $('#rulesOnlyHits')?.checked;
  $$('.rules-table tbody tr').forEach((tr) => {
    const hide = (q && !tr.dataset.search.includes(q)) || (onlyChanged && tr.dataset.changed !== '1') || (onlyHits && tr.dataset.count === '0');
    tr.classList.toggle('hidden', hide);
  });
}

async function importRules(file, kind) {
  const text = await file.text();
  const body = kind === 'csv' ? { csv: text } : { overrides: JSON.parse(text).rules || JSON.parse(text) };
  const r = await api('POST', '/api/rules/import', body);
  snapshot();
  P().settings.rules = r.overrides;
  changed({ canvas: true });
  toast(`${Object.keys(r.overrides).length} reglas ajustadas importadas`);
}

export function onRulesChange(t) {
  if (t.dataset.ren) setOverride(t.dataset.ren, { enabled: t.checked ? undefined : false });
  else if (t.dataset.rsev) setOverride(t.dataset.rsev, { severity: t.value || undefined });
  else if (t.dataset.rcom) setOverride(t.dataset.rcom, { comment: t.value.trim() || undefined });
  else if (t.id === 'rulesOnlyChanged' || t.id === 'rulesOnlyHits') filterRules();
  else if ((t.id === 'rulesCsv' || t.id === 'rulesJson') && t.files.length) {
    importRules(t.files[0], t.id === 'rulesCsv' ? 'csv' : 'json').catch(reportError);
  } else return false;
  return true;
}

export async function onRulesClick(t) {
  const act = t.dataset.rules;
  const name = (P().name || 'proyecto').replace(/[^\w\-. ]+/g, '_');
  if (act === 'export-csv') {
    const r = await api('POST', '/api/rules/export-csv', { overrides: overrides(), counts: ruleCounts(S.analysis) });
    download(`${name}-reglas.csv`, b64ToText(r.csv_b64), 'text/csv');
  } else if (act === 'export-json') {
    download(`${name}-reglas.json`, JSON.stringify({ rules: overrides() }, null, 2), 'application/json');
  } else if (act === 'reset' && confirm('¿Restablecer todas las reglas a su configuración por defecto?')) {
    snapshot(); P().settings.rules = {}; changed({ canvas: true });
  }
}
