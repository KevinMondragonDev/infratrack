/* InfraTrack — glue-catalog */
import { api, toast } from './api.js';
import { $, S, esc } from './core.js';
import { codeBlock } from './inspector-common.js';
import { select } from './interaction.js';
import { center, changed, snapshot } from './model.js';

/* ───── Glue Data Catalog ───── */
export const GLUE_FORMATS = ['Apache Iceberg', 'Delta Lake', 'Apache Hudi', 'Hive - Parquet', 'Hive - ORC', 'Hive - Avro', 'Hive - JSON',
  'Hive - CSV', 'Hive - otro', 'Vista'];
export const GLUE_SENSITIVITY = ['Pública', 'Interna', 'Confidencial', 'Restringida (PII / financiera)'];
export const catOf = (n) => { n.config = n.config || {}; n.config.catalog = n.config.catalog || { databases: [] }; return n.config.catalog; };
export const tableHasPii = (t) => [...(t.columns || []), ...(t.partition_keys || [])].some((c) => c.pii);

export function catalogTabHtml(n) {
  const cat = catOf(n);
  const tables = cat.databases.flatMap((d) => d.tables || []);
  const cols = tables.reduce((a, t) => a + (t.columns || []).length, 0);
  const pii = tables.filter(tableHasPii).length;
  const out = S.analysis?.glue_catalogs?.[n.id];
  S.catOpen = S.catOpen || new Set();
  return `<div class="cat-upload">
      <b>Subir el detalle del catálogo</b>
      <div class="help">JSON de <code>aws glue get-databases</code> y <code>aws glue get-tables --database-name &lt;base&gt;</code>
        (puedes subir varios archivos a la vez), o un CSV con columnas <code>database, table, column, type, partition, comment,
        format, location, pii, description, owner</code>. Se combina con lo que ya tienes y conserva lo capturado a mano.</div>
      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
        <input type="file" id="catFile" accept=".json,.csv,.txt" multiple>
        <label class="tgl"><input type="checkbox" id="catReplace"> Reemplazar todo</label></div>
    </div>
    <p class="muted">${cat.databases.length} bases · ${tables.length} tablas · ${cols} columnas · ${pii} con datos personales</p>
    <div style="display:flex;gap:6px;margin-bottom:8px">
      <input type="search" id="catSearch" placeholder="Buscar tabla o columna…" style="flex:1;padding:5px 8px;border:1px solid var(--border);border-radius:6px;background:var(--panel-2)">
      <button class="btn sm" data-catact="add-db">+ Base</button></div>
    ${cat.databases.map((d, di) => `<details class="cat-db" open><summary><b>${esc(d.name)}</b>
        <span class="muted">${(d.tables || []).length} tablas</span></summary>
      <div class="row2">${catInput('Nombre', d.name, `data-cat="db" data-di="${di}" data-field="name"`)}
        ${catInput('Ubicación', d.location, `data-cat="db" data-di="${di}" data-field="location"`, 's3://bucket/ruta/')}</div>
      ${catInput('Descripción', d.description, `data-cat="db" data-di="${di}" data-field="description"`)}
      ${(d.tables || []).map((t, ti) => catTableHtml(t, di, ti)).join('')}
      <div style="display:flex;gap:6px;margin:6px 0 4px"><button class="btn sm" data-catact="add-table" data-di="${di}">+ Tabla</button>
        <button class="btn sm danger" data-catact="del-db" data-di="${di}">Eliminar base</button></div>
    </details>`).join('') || '<p class="muted">Aún no hay bases. Sube un archivo o agrega una base.</p>'}
    ${cat.databases.length ? `<button class="btn sm danger" data-catact="clear" style="margin-top:8px">Vaciar catálogo</button>` : ''}
    ${out?.terraform ? `<details class="tf"><summary>Terraform del catálogo (aws_glue_catalog_database / aws_glue_catalog_table)</summary>${codeBlock(out.terraform)}</details>` : ''}`;
}

export function catInput(label, value, attr, ph = '') {
  return `<div class="field"><label>${esc(label)}</label><input type="text" spellcheck="false" ${attr} value="${esc(value)}" placeholder="${esc(ph)}"></div>`;
}

export function catTableHtml(t, di, ti) {
  const key = `${di}:${ti}`;
  const open = S.catOpen.has(key);
  const search = [t.name, ...(t.columns || []).map((c) => c.name), ...(t.partition_keys || []).map((c) => c.name)].join(' ').toLowerCase();
  const badges = [t.format ? `<span class="chip ref">${esc(t.format)}</span>` : '',
    tableHasPii(t) ? '<span class="chip st-open">datos personales</span>' : '',
    t.sensitivity ? `<span class="chip ref">${esc(t.sensitivity)}</span>` : ''].join(' ');
  return `<details class="cat-tb" data-di="${di}" data-ti="${ti}" data-search="${esc(search)}" ${open ? 'open' : ''}>
    <summary>${esc(t.name)} <span class="muted">${(t.columns || []).length} col.</span> ${badges}</summary>
    <div class="cat-tb-body">${open ? catTableBody(t, di, ti) : ''}</div></details>`;
}

export function catTableBody(t, di, ti) {
  const a = (field) => `data-cat="tb" data-di="${di}" data-ti="${ti}" data-field="${field}"`;
  const sel = (field, opts, v) => `<select ${a(field)}><option value="">—</option>${opts.map((o) => `<option ${o === v ? 'selected' : ''}>${esc(o)}</option>`).join('')}</select>`;
  const colRows = (kind) => (t[kind] || []).map((c, ci) => {
    const ca = (field) => `data-cat="col" data-di="${di}" data-ti="${ti}" data-ck="${kind}" data-ci="${ci}" data-field="${field}"`;
    return `<div class="rline" style="grid-template-columns:1fr 1fr 1fr 34px 26px">
      <input type="text" ${ca('name')} value="${esc(c.name)}" placeholder="columna">
      <input type="text" ${ca('type')} value="${esc(c.type)}" placeholder="string">
      <input type="text" ${ca('comment')} value="${esc(c.comment)}" placeholder="comentario">
      <label class="pii" title="Datos personales"><input type="checkbox" ${ca('pii')} ${c.pii ? 'checked' : ''}>PII</label>
      <button class="btn sm ghost" data-catact="del-col" data-di="${di}" data-ti="${ti}" data-ck="${kind}" data-ci="${ci}" title="Quitar">✕</button></div>`;
  }).join('');
  const params = Object.entries(t.parameters || {});
  return `<div class="row2">${catInput('Nombre', t.name, a('name'))}${catInput('Dueño', t.owner, a('owner'), 'equipo / persona')}</div>
    ${catInput('Descripción', t.description, a('description'), '¿Qué contiene esta tabla?')}
    <div class="row2"><div class="field"><label>Formato</label>${sel('format', GLUE_FORMATS, t.format)}</div>
      <div class="field"><label>Sensibilidad</label>${sel('sensitivity', GLUE_SENSITIVITY, t.sensitivity)}</div></div>
    <div class="row2">${catInput('Ubicación', t.location, a('location'), 's3://bucket/tabla/')}
      <div class="field"><label>Retención (días)</label><input type="number" ${a('retention_days')} value="${t.retention_days ?? ''}"></div></div>
    <div class="section-title">Particiones</div><div class="rules">${colRows('partition_keys') || '<div class="muted" style="padding:6px">Sin particiones.</div>'}</div>
    <button class="btn sm" data-catact="add-col" data-di="${di}" data-ti="${ti}" data-ck="partition_keys" style="margin:6px 0">+ Partición</button>
    <div class="section-title">Columnas</div><div class="rules">${colRows('columns') || '<div class="muted" style="padding:6px">Sin columnas.</div>'}</div>
    <div style="display:flex;gap:6px;margin:6px 0"><button class="btn sm" data-catact="add-col" data-di="${di}" data-ti="${ti}" data-ck="columns">+ Columna</button>
      <button class="btn sm danger" data-catact="del-table" data-di="${di}" data-ti="${ti}">Eliminar tabla</button></div>
    ${params.length ? `<details class="tf"><summary>Parámetros de la tabla (${params.length})</summary><pre class="code">${esc(params.map(([k, v]) => `${k} = ${v}`).join('\n'))}</pre></details>` : ''}`;
}

export async function importCatalogFiles(n, files) {
  const replace = $('#catReplace')?.checked;
  let first = true, imported = 0, errors = [];
  snapshot();
  for (const f of files) {
    try {
      const text = await f.text();
      const r = await api('POST', '/api/glue/import', { text, filename: f.name, existing: catOf(n), replace: replace && first });
      n.config.catalog = r.catalog; imported += r.imported.tables; first = false;
    } catch (e) { errors.push(`${f.name}: ${e.message}`); }
  }
  changed({ inspector: true });
  toast(errors.length ? `Importadas ${imported} tablas. Errores: ${errors.join(' · ')}` : `Importadas ${imported} tablas`, errors.length ? 9000 : 3500);
}

export function onCatalogAction(t, n) {
  const cat = catOf(n);
  const di = Number(t.dataset.di), ti = Number(t.dataset.ti);
  const act = t.dataset.catact;
  if (act === 'add-db') {
    const name = prompt('Nombre de la base de datos'); if (!name) return;
    snapshot(); cat.databases.push({ name: name.trim(), description: '', location: '', tables: [] });
  } else if (act === 'del-db') {
    if (!confirm(`¿Eliminar la base ${cat.databases[di].name} y sus tablas?`)) return;
    snapshot(); cat.databases.splice(di, 1); S.catOpen.clear();
  } else if (act === 'add-table') {
    const name = prompt('Nombre de la tabla'); if (!name) return;
    snapshot();
    cat.databases[di].tables = cat.databases[di].tables || [];
    cat.databases[di].tables.push({ name: name.trim(), description: '', owner: '', format: '', table_type: 'EXTERNAL_TABLE', location: '',
      classification: '', sensitivity: '', retention_days: null, partition_keys: [], columns: [], parameters: {} });
    S.catOpen.add(`${di}:${cat.databases[di].tables.length - 1}`);
  } else if (act === 'del-table') {
    if (!confirm(`¿Eliminar la tabla ${cat.databases[di].tables[ti].name}?`)) return;
    snapshot(); cat.databases[di].tables.splice(ti, 1); S.catOpen.clear();
  } else if (act === 'add-col') {
    snapshot(); const tb = cat.databases[di].tables[ti];
    tb[t.dataset.ck] = tb[t.dataset.ck] || [];
    tb[t.dataset.ck].push({ name: '', type: 'string', comment: '', pii: false });
  } else if (act === 'del-col') {
    snapshot(); cat.databases[di].tables[ti][t.dataset.ck].splice(Number(t.dataset.ci), 1);
  } else if (act === 'clear') {
    if (!confirm('¿Vaciar todo el catálogo de este componente?')) return;
    snapshot(); n.config.catalog = { databases: [] }; S.catOpen.clear();
  }
  const sc = $('#inspector').scrollTop; changed({ inspector: true }); $('#inspector').scrollTop = sc;
}

export function onCatalogInput(t, n) {
  const cat = catOf(n);
  const d = cat.databases[Number(t.dataset.di)];
  if (!d) return;
  let target = d;
  if (t.dataset.cat !== 'db') target = d.tables[Number(t.dataset.ti)];
  if (t.dataset.cat === 'col') target = target[t.dataset.ck][Number(t.dataset.ci)];
  if (!target) return;
  let v = t.type === 'checkbox' ? t.checked : t.value;
  if (t.type === 'number') v = t.value === '' ? null : Number(t.value);
  target[t.dataset.field] = v;
}
