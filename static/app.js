'use strict';
/* InfraTrack — frontend sin dependencias. */

const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const uid = (p = 'n') => p + Date.now().toString(36).slice(-4) + Math.random().toString(36).slice(2, 7);
const nowIso = () => new Date().toISOString();
const trunc = (s, n) => (s && s.length > n ? s.slice(0, n - 1) + '…' : s || '');
const snap = (v, g = 10) => Math.round(v / g) * g;
const fmtDate = (s) => { if (!s) return ''; const d = new Date(s); return isNaN(d) ? s : d.toLocaleString('es', { dateStyle: 'short', timeStyle: 'short' }); };
const lsGet = (k, d) => { try { const v = localStorage.getItem(k); return v === null ? d : JSON.parse(v); } catch { return d; } };
const lsSet = (k, v) => { try { localStorage.setItem(k, JSON.stringify(v)); } catch { /* sin almacenamiento */ } };

const SEVS = ['critical', 'high', 'medium', 'low', 'info'];
const SEV_LABEL = { critical: 'Crítico', high: 'Alto', medium: 'Medio', low: 'Bajo', info: 'Info' };
const STATUSES = ['Borrador', 'En revisión', 'Aprobado', 'Requiere cambios', 'Pendiente de definición', 'Descartado'];
const NAMED_COLORS = { Naranja: '#ED7100', Azul: '#0972D3', Verde: '#3F8624', Morado: '#8C4FFF', Rojo: '#D13212',
  Gris: '#7D8998', Rosa: '#E7157B', Turquesa: '#01A88D', Amarillo: '#C99700' };
const COLOR_NAMES = Object.keys(NAMED_COLORS);
const ACCESS = [['read', 'Lectura'], ['write', 'Escritura'], ['readwrite', 'Lectura y escritura'], ['invoke', 'Invocación / llamada'], ['network', 'Tráfico de red (puerto)']];
const ACCESS_SHORT = { read: 'lee', write: 'escribe', readwrite: 'lee/escribe', invoke: 'invoca', network: 'red' };
const ASSOC_TYPES = new Set(['sg', 'iam_role']);
const isAssocPair = (a, b) => !!(a && b && (ASSOC_TYPES.has(a.type) || ASSOC_TYPES.has(b.type)
  || (a.type === 'vpce' && b.type === 'subnet') || (a.type === 'subnet' && b.type === 'vpce')));
const isAssoc = (e) => isAssocPair(nodeById(e.source), nodeById(e.target));
const ENV_COLOR = { prod: '#D13212', staging: '#0972D3', qa: '#0972D3', dev: '#0972D3', sandbox: '#7D8998' };
const CONTAINER_PREFIX = { vpc: 'VPC · ', account: 'Cuenta · ', zone: 'Zona · ' };
const SUBNET_STYLE = {
  public: { stroke: '#3F8624', fill: 'rgba(63,134,36,.07)', name: 'Pública' },
  private: { stroke: '#147EBA', fill: 'rgba(20,126,186,.07)', name: 'Privada' },
  isolated: { stroke: '#687078', fill: 'rgba(104,112,120,.08)', name: 'Aislada' },
};

const S = {
  catalog: null, comp: {}, cats: {},
  projects: [], project: null, analysis: null,
  sel: null, tab: 'general', view: { x: 40, y: 40, k: 1 },
  undo: [], redo: [], drag: null, temp: null, hover: null,
  highlightPending: false, showFindings: true, envFilter: '', flowFilter: '',
  saving: false, saveAgain: false, saveT: null, anT: null, anSeq: 0,
  author: lsGet('it.author', ''), ai: { available: false }, icons: new Set(), iconsVersion: null,
  modal: null, mtab: 'findings', sevFilter: new Set(SEVS), showDismissed: false, catFilter: '',
};

/* ───────────────────────── API ───────────────────────── */
async function api(method, url, body) {
  const r = await fetch(url, {
    method, headers: body ? { 'Content-Type': 'application/json' } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  const ct = r.headers.get('content-type') || '';
  const data = ct.includes('json') ? await r.json() : await r.text();
  if (!r.ok) { const e = new Error((data && data.error) || r.statusText); e.status = r.status; throw e; }
  return data;
}

function toast(msg, ms = 2600) {
  const t = $('#toast'); t.textContent = msg; t.classList.remove('hidden');
  clearTimeout(toast.t); toast.t = setTimeout(() => t.classList.add('hidden'), ms);
}

async function copy(text) {
  try { await navigator.clipboard.writeText(text); toast('Copiado al portapapeles'); }
  catch {
    const ta = document.createElement('textarea'); ta.value = text; document.body.appendChild(ta); ta.select();
    document.execCommand('copy'); ta.remove(); toast('Copiado');
  }
}

/* ───────────────────────── Modelo ───────────────────────── */
const P = () => S.project;
const nodeById = (id) => P().nodes.find((n) => n.id === id);
const edgeById = (id) => P().edges.find((e) => e.id === id);
const compOf = (n) => S.comp[n.type] || { name: n.type, abbr: '?', color: '#888', fields: [], category: 'external' };
const isContainer = (n) => !!compOf(n).container;
const center = (n) => ({ x: n.x + n.w / 2, y: n.y + n.h / 2 });
const labelOf = (n) => (n ? n.label || compOf(n).name : '—');

function showIf(f, cfg) {
  if (!f.show_if) return true;
  return Object.entries(f.show_if).every(([k, vals]) => {
    const v = cfg[k];
    if (Array.isArray(v)) return v.some((x) => vals.includes(x));
    return vals.includes(v === undefined ? null : v);
  });
}
const isEmpty = (v, f) => (f.type === 'bool' ? v === undefined || v === null : v === undefined || v === null || v === '' || (Array.isArray(v) && !v.length));
function configProgress(n) {
  const cfg = n.config || {};
  const req = compOf(n).fields.filter((f) => f.required && showIf(f, cfg));
  const done = req.filter((f) => !isEmpty(cfg[f.key], f)).length;
  return { done, total: req.length, pct: req.length ? Math.round((100 * done) / req.length) : 100 };
}

function descendants(c) {
  const area = c.w * c.h;
  return P().nodes.filter((n) => {
    if (n.id === c.id) return false;
    const m = center(n);
    if (!(m.x >= c.x && m.x <= c.x + c.w && m.y >= c.y && m.y <= c.y + c.h)) return false;
    return !isContainer(n) || n.w * n.h < area;
  });
}

function containerAt(pt, excludeIds = new Set()) {
  let best = null;
  for (const c of P().nodes) {
    if (!isContainer(c) || excludeIds.has(c.id)) continue;
    if (pt.x >= c.x && pt.x <= c.x + c.w && pt.y >= c.y && pt.y <= c.y + c.h) {
      if (!best || c.w * c.h < best.w * best.h) best = c;
    }
  }
  return best;
}

function snapshot() {
  S.undo.push(JSON.stringify({ nodes: P().nodes, edges: P().edges, dismissed: P().dismissed || {} }));
  if (S.undo.length > 150) S.undo.shift();
  S.redo = [];
  updateUndoButtons();
}
function restoreState(stack, other) {
  if (!stack.length) return;
  other.push(JSON.stringify({ nodes: P().nodes, edges: P().edges, dismissed: P().dismissed || {} }));
  const st = JSON.parse(stack.pop());
  Object.assign(P(), st);
  if (S.sel && !(S.sel.kind === 'node' ? nodeById(S.sel.id) : edgeById(S.sel.id))) S.sel = null;
  changed({ inspector: true });
  updateUndoButtons();
}
const undo = () => restoreState(S.undo, S.redo);
const redo = () => restoreState(S.redo, S.undo);
function updateUndoButtons() { $('#btnUndo').disabled = !S.undo.length; $('#btnRedo').disabled = !S.redo.length; }

function changed({ canvas = true, inspector = false } = {}) {
  scheduleSave();
  scheduleAnalyze();
  if (canvas) renderCanvas();
  if (inspector) renderInspector();
  updateProgress();
}

/* ───────────────────────── Guardado y análisis ───────────────────────── */
function setSaveStatus(t) { $('#saveStatus').textContent = t; }
function scheduleSave() { setSaveStatus('Sin guardar…'); clearTimeout(S.saveT); S.saveT = setTimeout(() => save(), 700); }
async function save(force = false) {
  if (!P()) return;
  clearTimeout(S.saveT); S.saveT = null;
  if (S.saving) { S.saveAgain = true; return; }
  S.saving = true; setSaveStatus('Guardando…');
  try {
    const body = { ...P() };
    if (force) body._force = true;
    const r = await api('PUT', `/api/projects/${P().id}`, body);
    P().rev = r.rev; P().updated = r.updated;
    setSaveStatus('Guardado ✓');
    $('#conflict').classList.add('hidden');
  } catch (e) {
    if (e.status === 409) { $('#conflict').classList.remove('hidden'); setSaveStatus('Conflicto'); }
    else { setSaveStatus('Error al guardar'); toast(e.message, 5000); }
  } finally {
    S.saving = false;
    if (S.saveAgain) { S.saveAgain = false; save(); }
  }
}
async function flushSave() { if (S.saveT || S.saving) { await save(); while (S.saving) await new Promise((r) => setTimeout(r, 50)); } }

function scheduleAnalyze() { clearTimeout(S.anT); S.anT = setTimeout(analyzeNow, 350); }
async function analyzeNow() {
  if (!P()) return;
  const seq = ++S.anSeq;
  try {
    const a = await api('POST', '/api/analyze', P());
    if (seq !== S.anSeq) return;
    S.analysis = a;
  } catch (e) { console.error(e); return; }
  renderEnvFilter(); renderFlowFilter(); renderCanvas(); renderStatusbar(); refreshInspectorAnalysis(); updateCopilotBadge();
  if (S.modal === 'copilot' && S.mtab !== 'ai') renderCopilotTab();
}

/* ───────────────────────── Proyectos ───────────────────────── */
async function loadProjects(selectId) {
  S.projects = await api('GET', '/api/projects');
  const sel = $('#projectSelect');
  sel.innerHTML = S.projects.map((p) => `<option value="${p.id}">${esc(p.name)} (${p.terraformed}/${p.nodes})</option>`).join('');
  const id = selectId || lsGet('it.lastProject', null);
  const target = S.projects.find((p) => p.id === id) || S.projects[0];
  if (target) await openProject(target.id);
}

async function openProject(id) {
  if (P() && P().id !== id) await flushSave();
  const p = await api('GET', `/api/projects/${id}`);
  p.dismissed = p.dismissed || {};
  // Aplica defaults del catálogo para que el formulario muestre lo mismo que evalúa el Copilot.
  for (const n of p.nodes) {
    const comp = S.comp[n.type];
    if (!comp) continue;
    n.config = n.config || {};
    comp.fields.forEach((f) => {
      // Versiones previas guardaban true/false: false nunca distinguió "no" de "sin confirmar".
      if (f.tri && n.config[f.key] === true) n.config[f.key] = 'Sí';
      if (f.tri && n.config[f.key] === false) n.config[f.key] = 'Sin confirmar';
      if ('default' in f && n.config[f.key] === undefined) n.config[f.key] = f.default;
    });
  }
  S.project = p; S.sel = null; S.undo = []; S.redo = []; S.analysis = null;
  $('#projectSelect').value = id;
  lsSet('it.lastProject', id);
  updateUndoButtons();
  const v = lsGet(`it.view.${id}`, null);
  if (v) { S.view = v; applyView(); } else fitView();
  renderCanvas(); renderInspector(); updateProgress(); setSaveStatus('Guardado ✓');
  analyzeNow();
}

async function newProject(sample = false) {
  const name = sample ? null : prompt('Nombre del proyecto', 'Nueva arquitectura');
  if (!sample && name === null) return;
  await flushSave();
  const p = await api('POST', '/api/projects', { name, sample });
  await loadProjects(p.id);
}

/* ───────────────────────── Paleta ───────────────────────── */
function renderPalette() {
  const q = $('#paletteSearch').value.trim().toLowerCase();
  const html = S.catalog.categories.map((cat) => {
    const items = S.catalog.components.filter((c) => c.category === cat.id &&
      (!q || c.name.toLowerCase().includes(q) || c.abbr.toLowerCase().includes(q) || (c.desc || '').toLowerCase().includes(q)));
    if (!items.length) return '';
    return `<details class="pal-cat" open><summary><span class="dot" style="background:${cat.color}"></span>${esc(cat.name)}</summary>
      ${items.map((c) => `<div class="pal-item" draggable="true" data-type="${c.id}" title="${esc(c.desc || '')}">
        ${badgeHtml(c)}<span class="nm">${esc(c.name)}</span></div>`).join('')}
    </details>`;
  }).join('');
  $('#paletteList').innerHTML = html || '<p class="hint">Sin resultados.</p>';
}

function defaultSize(type) {
  if (type === 'account') return { w: 1200, h: 800 };
  if (type === 'zone') return { w: 620, h: 420 };
  if (type === 'vpc') return { w: 680, h: 440 };
  if (type === 'subnet') return { w: 320, h: 210 };
  if (type === 'note') return { w: 200, h: 90 };
  if (type === 'igw') return { w: 110, h: 50 };
  return { w: 150, h: 56 };
}

function addNode(type, pt) {
  const comp = S.comp[type];
  if (!comp) return;
  const cfg = {};
  comp.fields.forEach((f) => { if ('default' in f) cfg[f.key] = f.default; });
  const size = defaultSize(type);
  const count = P().nodes.filter((n) => n.type === type).length;
  const n = {
    id: uid('n'), type, label: type === 'note' ? 'Nota' : `${comp.name}${count ? ' ' + (count + 1) : ''}`,
    x: snap(pt.x - size.w / 2), y: snap(pt.y - size.h / 2), ...size, config: cfg,
    terraformed: false, status: 'Borrador', notes: [], questions: [],
  };
  if (type === 'subnet') {
    const vpc = containerAt(pt);
    const subs = P().nodes.filter((x) => x.type === 'subnet');
    n.config.az = ['a', 'b', 'c'][subs.length % 3];
    if (vpc && vpc.config && vpc.config.cidr) {
      const m = /^(\d+)\.(\d+)\./.exec(vpc.config.cidr);
      if (m) n.config.cidr = `${m[1]}.${m[2]}.${subs.length}.0/24`;
    }
  }
  snapshot();
  P().nodes.push(n);
  select('node', n.id, 'general');
  changed();
}

/* ───────────────────────── Canvas ───────────────────────── */
const svg = () => $('#canvas');
function toWorld(cx, cy) {
  const r = svg().getBoundingClientRect();
  return { x: (cx - r.left - S.view.x) / S.view.k, y: (cy - r.top - S.view.y) / S.view.k };
}
function applyView() {
  const t = `translate(${S.view.x},${S.view.y}) scale(${S.view.k})`;
  $('#world').setAttribute('transform', t);
  $('#gridRect').setAttribute('transform', t);
  $('#zoomLabel').textContent = Math.round(S.view.k * 100) + '%';
}
function saveView() { if (P()) lsSet(`it.view.${P().id}`, S.view); }
function zoomAt(factor, cx, cy) {
  const r = svg().getBoundingClientRect();
  const px = cx ?? r.left + r.width / 2, py = cy ?? r.top + r.height / 2;
  const w = toWorld(px, py);
  const k = Math.min(2.5, Math.max(0.15, S.view.k * factor));
  S.view.k = k;
  S.view.x = px - r.left - w.x * k;
  S.view.y = py - r.top - w.y * k;
  applyView(); saveView();
}
function fitView() {
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
function centerOn(n) {
  const r = svg().getBoundingClientRect();
  const c = center(n);
  S.view.x = r.width / 2 - c.x * S.view.k;
  S.view.y = r.height / 2 - c.y * S.view.k;
  applyView(); saveView();
}

function clipToRect(n, toward) {
  const c = center(n);
  const dx = toward.x - c.x, dy = toward.y - c.y;
  if (!dx && !dy) return c;
  const sx = dx ? (n.w / 2 + 3) / Math.abs(dx) : Infinity;
  const sy = dy ? (n.h / 2 + 3) / Math.abs(dy) : Infinity;
  const s = Math.min(sx, sy, 1);
  return { x: c.x + dx * s, y: c.y + dy * s };
}

function checkSvg(n, x, y) {
  return `<g class="check ${n.terraformed ? 'on' : ''}" data-check="${n.id}" transform="translate(${x},${y})">
    <title>${n.terraformed ? 'Terraformado — clic para desmarcar' : 'Marcar como terraformado'}</title>
    <circle r="9"/><path d="M-4,0 L-1,3.5 L4.5,-3.5"/></g>`;
}

function accountOf(n) {
  const parents = S.analysis ? S.analysis.parents : {};
  let id = n.type === 'account' ? n.id : parents[n.id];
  while (id) { const p = nodeById(id); if (!p) return null; if (p.type === 'account') return p; id = parents[id]; }
  return null;
}
function envDim(n) {
  if (!S.envFilter) return false;
  const a = accountOf(n);
  return !a || ((a.config || {}).environment || '') !== S.envFilter;
}
function renderEnvFilter() {
  const sel = $('#envFilter');
  const envs = [...new Set(P().nodes.filter((n) => n.type === 'account').map((n) => (n.config || {}).environment).filter(Boolean))].sort();
  if (S.envFilter && !envs.includes(S.envFilter)) S.envFilter = '';
  sel.innerHTML = `<option value="">Todos los ambientes</option>${envs.map((e) => `<option ${e === S.envFilter ? 'selected' : ''}>${esc(e)}</option>`).join('')}`;
  sel.classList.toggle('hidden', !envs.length);
}

/* Iconos oficiales de AWS (si se instalaron con --setup-icons) */
function iconKey(type, cfg) {
  if (type === 'subnet') return cfg?.tier === 'public' ? 'subnet-public' : 'subnet-private';
  return type;
}
function iconUrl(type, cfg) {
  const k = iconKey(type, cfg);
  // La clave viene del catálogo y la versión del servidor: ambas se codifican antes de usarse en HTML.
  if (!S.icons.has(k)) return null;
  return `/icons/aws/${encodeURIComponent(k)}.svg?v=${encodeURIComponent(S.iconsVersion || '')}`;
}
function badgeHtml(c, cfg, cls = 'ab') {
  const url = iconUrl(c.id, cfg);
  return url ? `<img class="${cls} icon" src="${esc(url)}" alt="" draggable="false">`
    : `<span class="${cls}" style="background:${c.color}">${esc(c.abbr)}</span>`;
}
async function loadIcons() {
  try {
    const r = await api('GET', '/api/icons');
    S.icons = new Set(r.available); S.iconsVersion = r.version; S.iconsOutdated = !!r.outdated;
  } catch { S.icons = new Set(); S.iconsOutdated = false; }
  const hint = $('#iconsHint');
  hint.classList.toggle('hidden', S.icons.size > 0 && !S.iconsOutdated);
  if (S.iconsOutdated) {
    hint.querySelector('span').textContent = 'Hay componentes nuevos sin icono. Vuelve a descargar el paquete oficial para actualizarlos.';
    $('#btnIcons').textContent = 'Actualizar iconos';
  }
}
async function installIcons(btn) {
  btn.disabled = true; btn.textContent = 'Descargando iconos oficiales (~14 MB)…';
  try {
    const r = await api('POST', '/api/icons/setup');
    S.icons = new Set(r.available); S.iconsVersion = r.version; S.iconsOutdated = false;
    $('#iconsHint').classList.add('hidden');
    renderPalette(); renderCanvas(); renderInspector();
    toast(`${r.installed} iconos de AWS instalados`);
  } catch (e) {
    toast(e.message, 9000); btn.disabled = false; btn.textContent = 'Reintentar descarga de iconos';
  }
}

function containerStyle(n, comp, cfg) {
  if (n.type === 'subnet') return SUBNET_STYLE[cfg.tier || 'private'];
  if (n.type === 'account') return { stroke: ENV_COLOR[cfg.environment] || comp.color, fill: 'rgba(127,127,127,.025)', name: '' };
  if (n.type === 'zone') { const c = NAMED_COLORS[cfg.color] || NAMED_COLORS.Azul; return { stroke: c, fill: c + '12', name: '' }; }
  return { stroke: comp.color, fill: 'rgba(140,79,255,.035)', name: '' };
}
function containerSubtitle(n, st, cfg) {
  let parts;
  if (n.type === 'vpc') parts = [cfg.cidr, cfg.region];
  else if (n.type === 'account') parts = [cfg.account_id, cfg.environment, cfg.ou];
  else if (n.type === 'zone') parts = [cfg.owner, trunc(n.description || '', 80)];
  else parts = [st.name, cfg.cidr, cfg.az ? 'AZ ' + cfg.az : ''];
  return parts.filter(Boolean).join(' · ');
}

const flows = () => P().settings?.flows || [];
const flowById = (id) => flows().find((f) => f.id === id);
const flowColor = (f) => NAMED_COLORS[f.color] || f.color || '#7D8998';
function edgeInFilter(e) { return !S.flowFilter || (e.flows || []).includes(S.flowFilter); }
function nodeInFlowFilter(n) {
  if (!S.flowFilter || isContainer(n)) return true;
  return P().edges.some((e) => (e.flows || []).includes(S.flowFilter) && (e.source === n.id || e.target === n.id));
}
function renderFlowFilter() {
  const sel = $('#flowFilter');
  const fs = flows();
  if (S.flowFilter && !fs.some((f) => f.id === S.flowFilter)) S.flowFilter = '';
  sel.innerHTML = `<option value="">Todos los flujos</option>${fs.map((f) => `<option value="${esc(f.id)}" ${f.id === S.flowFilter ? 'selected' : ''}>${esc(f.id)} ${esc(f.name || '')}</option>`).join('')}`;
  sel.classList.toggle('hidden', !fs.length);
}
/* Parte un nombre en hasta 2 líneas respetando el ancho disponible. */
function wrapLabel(text, chars) {
  const t = (text || '').trim();
  if (t.length <= chars) return [t];
  const words = t.split(/\s+/);
  let first = '';
  while (words.length && (first + ' ' + words[0]).trim().length <= chars) first = (first + ' ' + words.shift()).trim();
  if (!first) { first = t.slice(0, chars); return [first, trunc(t.slice(chars), chars)]; }
  return [first, trunc(words.join(' '), chars)];
}

function portSvg(n) {
  return `<g class="port" data-port="${n.id}"><circle class="port-hit" cx="${n.w}" cy="${n.h / 2}" r="13"/>
    <circle class="port-dot" cx="${n.w}" cy="${n.h / 2}" r="6.5"/><title>Arrastra hacia otro componente para conectar</title></g>`;
}

function renderCanvas() {
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

/* ───── interacción ───── */
function onPointerDown(ev) {
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

function onPointerMove(ev) {
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

function onPointerUp(ev) {
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

function guessAccess(a, b) {
  if (isAssocPair(a, b)) return null;
  if (['users', 'onprem', 'alb', 'nlb', 'cloudfront'].includes(a.type)) return 'network';
  if (['rds', 'aurora', 'elasticache', 'documentdb', 'efs', 'redshift', 'msk', 'ec2', 'asg', 'ecs', 'eks'].includes(b.type)) return 'network';
  if (['lambda', 'stepfn', 'glue', 'emr', 'apigw', 'athena'].includes(b.type)) return 'invoke';
  if (['sqs', 'sns', 'eventbridge', 'firehose', 'cloudwatch'].includes(b.type)) return 'write';
  if (['secrets', 'ecr'].includes(b.type)) return 'read';
  return null;
}

function onWheel(ev) {
  ev.preventDefault();
  // Ctrl/Cmd + rueda (o pinch en trackpad) = zoom; rueda/dos dedos = desplazar.
  if (ev.ctrlKey || ev.metaKey || ev.deltaMode !== 0) {
    const dy = ev.deltaMode === 1 ? ev.deltaY * 30 : ev.deltaY;
    zoomAt(Math.exp(-dy * (ev.ctrlKey ? 0.01 : 0.0018)), ev.clientX, ev.clientY);
  } else {
    S.view.x -= ev.deltaX; S.view.y -= ev.deltaY; applyView(); clearTimeout(onWheel.t); onWheel.t = setTimeout(saveView, 300);
  }
}

function toggleTerraformed(n) {
  snapshot();
  n.terraformed = !n.terraformed;
  n.terraformed_at = n.terraformed ? nowIso() : null;
  changed({ inspector: S.sel && S.sel.id === n.id });
  toast(n.terraformed ? `✓ ${labelOf(n)} terraformado` : `${labelOf(n)} marcado como pendiente`);
}

function deleteSelection() {
  if (!S.sel) return;
  snapshot();
  if (S.sel.kind === 'node') {
    P().nodes = P().nodes.filter((n) => n.id !== S.sel.id);
    P().edges = P().edges.filter((e) => e.source !== S.sel.id && e.target !== S.sel.id);
  } else P().edges = P().edges.filter((e) => e.id !== S.sel.id);
  S.sel = null;
  changed({ inspector: true });
}

function duplicateNode(n) {
  snapshot();
  const c = JSON.parse(JSON.stringify(n));
  c.id = uid('n'); c.x += 30; c.y += 30; c.label = n.label + ' (copia)'; c.terraformed = false; c.terraformed_at = null;
  c.questions = []; c.notes = [];
  P().nodes.push(c);
  select('node', c.id);
  changed();
}

function select(kind, id, tab) {
  S.sel = kind ? { kind, id } : null;
  if (tab) S.tab = tab;
  else if (kind === 'edge') S.tab = 'edge';
  else if (kind === 'node' && (S.tab === 'edge' || !S.tab)) S.tab = 'general';
  renderCanvas(); renderInspector();
  $('#inspector').scrollTop = 0;
}

/* ───────────────────────── Inspector ───────────────────────── */
function fieldHtml(f, val, attr) {
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

function rulesTableHtml(f, rows) {
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

function sgSuggestionsHtml(n) {
  const sug = S.analysis && S.analysis.sg_suggestions && S.analysis.sg_suggestions[n.id];
  if (!sug || !sug.length) return '';
  return `<div class="finding sev-medium"><h4>El Copilot sugiere ${sug.length} regla(s) para este SG</h4>
    <ul style="margin:4px 0 6px 16px;padding:0">${sug.map((r) => `<li><code>${esc(r.direction)} ${esc(r.protocol)}/${esc(r.from_port ?? 'todos')} ${r.direction === 'ingress' ? 'desde' : 'hacia'} ${esc(r.peer)}</code> <span class="muted">${esc(r.description)}</span></li>`).join('')}</ul>
    <button class="btn blue sm" data-act="applySg">Agregar reglas sugeridas</button></div>`;
}

function findingHtml(f, { links = true } = {}) {
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

function codeBlock(text) {
  return `<div class="codewrap"><button class="copy" data-copy="${esc(text)}">Copiar</button><pre class="code">${esc(text)}</pre></div>`;
}

function renderInspector() {
  const el = $('#inspector');
  if (!P()) { el.innerHTML = ''; return; }
  if (S.sel && S.sel.kind === 'node') { const n = nodeById(S.sel.id); if (n) return renderNodeInspector(el, n); }
  if (S.sel && S.sel.kind === 'edge') { const e = edgeById(S.sel.id); if (e) return renderEdgeInspector(el, e); }
  renderProjectInspector(el);
}

function nodeFindings(id) {
  return S.analysis ? S.analysis.findings.filter((f) => f.node_ids.includes(id)) : [];
}

function renderNodeInspector(el, n) {
  const comp = compOf(n);
  const prog = configProgress(n);
  const openQ = (n.questions || []).filter((q) => q.status !== 'closed').length;
  const nf = nodeFindings(n.id).filter((f) => !f.dismissed).length;
  const tabs = [['general', 'General'], ['config', `Configuración <span class="cnt">${prog.pct}%</span>`],
    ['notes', `Notas <span class="cnt">${(n.notes || []).length}</span>`], ['architect', `Arquitecto <span class="cnt">${openQ}</span>`],
    ['copilot', `Copilot <span class="cnt">${nf}</span>`]];
  if (n.type === 'note') { S.tab = 'general'; }
  if (!tabs.some(([k]) => k === S.tab)) S.tab = 'general';
  el.innerHTML = `
    <div class="ins-head">
      ${badgeHtml(comp, n.config)}
      <div><h3>${esc(labelOf(n))}</h3><div class="sub">${esc(comp.name)}${comp.desc ? ' — ' + esc(trunc(comp.desc, 70)) : ''}</div></div>
      <div class="actions"><button class="btn sm" data-act="dup" title="Duplicar (Ctrl+D)">⧉</button>
      <button class="btn sm danger" data-act="del" title="Eliminar (Supr)">🗑</button></div>
    </div>
    ${n.type === 'note' ? '' : `<div class="tabs">${tabs.map(([k, l]) => `<button class="tab ${S.tab === k ? 'on' : ''}" data-tab="${k}">${l}</button>`).join('')}</div>`}
    <div class="ins-body" id="insBody"></div>`;
  const body = $('#insBody');
  if (n.type === 'note') {
    body.innerHTML = fieldHtml({ label: 'Título', type: 'text' }, n.label, 'data-bind="label"') +
      fieldHtml({ label: 'Texto', type: 'textarea' }, n.description, 'data-bind="description"');
    return;
  }
  if (S.tab === 'general') {
    body.innerHTML = `
      ${comp.terraformable ? `<div class="tfbox ${n.terraformed ? 'on' : ''}" data-act="tf">
        <span class="big">${n.terraformed ? '✓' : ''}</span>
        <div><b>${n.terraformed ? 'Terraformado' : 'Pendiente de terraformar'}</b>
        <small>${n.terraformed && n.terraformed_at ? 'Desde ' + fmtDate(n.terraformed_at) : 'Clic para marcar como terraformado'}</small></div></div>` : ''}
      ${fieldHtml({ label: 'Nombre', type: 'text' }, n.label, 'data-bind="label"')}
      <div class="row2">
        ${fieldHtml({ label: 'Estado de diseño', type: 'select', options: STATUSES }, n.status || 'Borrador', 'data-bind="status"')}
        ${fieldHtml({ label: 'Responsable', type: 'text', placeholder: 'quién lo implementa' }, n.owner, 'data-bind="owner"')}
      </div>
      ${fieldHtml({ label: 'Recurso / módulo de Terraform', type: 'text', placeholder: 'module.network.aws_vpc.main' }, n.tf_address, 'data-bind="tf_address"')}
      <div class="row2">
        ${fieldHtml({ label: 'Ruta en el repo', type: 'text', placeholder: 'infra/envs/prod/network' }, n.tf_path, 'data-bind="tf_path"')}
        ${fieldHtml({ label: 'Ticket / referencia', type: 'text', placeholder: 'JIRA-123' }, n.ticket, 'data-bind="ticket"')}
      </div>
      ${fieldHtml({ label: 'Propósito / descripción', type: 'textarea', placeholder: '¿Para qué existe este componente?' }, n.description, 'data-bind="description"')}
      ${fieldHtml({ label: 'Tags propios (clave=valor por línea)', type: 'textarea', placeholder: 'DataClassification=confidencial',
    help: 'Se suman a los tags por defecto del proyecto y de la cuenta.' }, n.tags, 'data-bind="tags"')}
      <div class="section-title">Ubicación</div><div id="insLocation" class="muted"></div>
      <div class="section-title">Conexiones</div><div id="insConns"></div>`;
    refreshInspectorAnalysis();
  } else if (S.tab === 'config') {
    const cfg = n.config || {};
    const fields = comp.fields.filter((f) => showIf(f, cfg));
    body.innerHTML = `
      <div class="muted">Campos requeridos completos: ${prog.done}/${prog.total}</div>
      <div class="meter"><div style="width:${prog.pct}%"></div></div>
      ${n.type === 'sg' ? `<div id="sgSug">${sgSuggestionsHtml(n)}</div>` : ''}
      ${fields.length ? fields.map((f) => fieldHtml(f, cfg[f.key], `data-cfg="${esc(f.key)}" data-ftype="${f.type}"`)).join('') : '<p class="muted">Este componente no tiene configuración específica.</p>'}
      ${fieldHtml({ label: 'Otras configuraciones / parámetros', type: 'textarea', placeholder: 'Cualquier otro ajuste relevante para revisar con el arquitecto' }, cfg._extra, 'data-cfg="_extra" data-ftype="textarea"')}`;
  } else if (S.tab === 'notes') {
    const notes = [...(n.notes || [])].reverse();
    body.innerHTML = `
      <div class="field"><textarea id="newNote" placeholder="Escribe una nota (decisiones, pendientes, links, comandos)…"></textarea></div>
      <div style="display:flex;gap:8px;align-items:center;margin-bottom:12px">
        <input id="noteAuthor" type="text" placeholder="Tu nombre" value="${esc(S.author)}" style="flex:1;padding:5px 8px;border:1px solid var(--border);border-radius:6px;background:var(--panel-2)">
        <button class="btn blue" data-act="addNote">Agregar nota</button></div>
      ${notes.length ? notes.map((x) => `<div class="list-item"><div class="meta">${esc(x.author || 'anónimo')} · ${fmtDate(x.at)}
        <button class="btn sm ghost x" data-delnote="${x.id}" title="Eliminar">✕</button></div>
        <div style="white-space:pre-wrap">${esc(x.text)}</div></div>`).join('') : '<p class="muted">Sin notas todavía.</p>'}`;
  } else if (S.tab === 'architect') {
    const qs = n.questions || [];
    body.innerHTML = `
      <p class="muted">Preguntas, dudas y decisiones a validar con tu arquitecto. Aparecen en el reporte Markdown.</p>
      <div class="field"><textarea id="newQ" placeholder="Ej. ¿Usamos una NAT por AZ o una compartida en dev?"></textarea></div>
      <button class="btn blue" data-act="addQ" style="margin-bottom:14px">Agregar pregunta</button>
      ${qs.length ? qs.map((q) => {
        const st = q.status === 'closed' ? 'closed' : q.answer ? 'answered' : 'open';
        return `<div class="list-item">
          <div class="meta"><span class="chip st-${st}">${{ open: 'Abierta', answered: 'Respondida', closed: 'Cerrada' }[st]}</span>
          ${esc(q.author || '')} · ${fmtDate(q.at)}<button class="btn sm ghost x" data-delq="${q.id}" title="Eliminar">✕</button></div>
          <div style="margin:6px 0;font-weight:600;white-space:pre-wrap">${esc(q.text)}</div>
          <div class="field" style="margin:0 0 6px"><textarea data-qanswer="${q.id}" placeholder="Respuesta / decisión del arquitecto…" style="min-height:50px">${esc(q.answer)}</textarea></div>
          <button class="btn sm" data-qtoggle="${q.id}">${q.status === 'closed' ? 'Reabrir' : 'Cerrar'}</button>
        </div>`;
      }).join('') : '<p class="muted">Sin preguntas.</p>'}`;
  } else if (S.tab === 'copilot') {
    body.innerHTML = `<div id="insCopilot"></div>`;
    refreshInspectorAnalysis();
  }
}

function renderEdgeInspector(el, e) {
  const a = nodeById(e.source), b = nodeById(e.target);
  el.innerHTML = `
    <div class="ins-head">
      <span class="ab" style="background:#5f6b7a">→</span>
      <div><h3>Conexión</h3><div class="sub"><a class="link" data-goto="${a.id}">${esc(labelOf(a))}</a> → <a class="link" data-goto="${b.id}">${esc(labelOf(b))}</a></div></div>
      <div class="actions"><button class="btn sm" data-act="flip" title="Invertir dirección">⇄</button>
      <button class="btn sm danger" data-act="del" title="Eliminar (Supr)">🗑</button></div>
    </div>
    <div class="ins-body">
      <div class="tfbox ${e.terraformed ? 'on' : ''}" data-act="tf">
        <span class="big">${e.terraformed ? '✓' : ''}</span>
        <div><b>${e.terraformed ? 'Permisos y reglas terraformados' : 'Permisos/reglas pendientes'}</b>
        <small>Políticas IAM, Security Groups y rutas de esta conexión</small></div></div>
      ${isAssoc(e) ? `<p class="muted">Esta conexión <b>asigna</b> ${esc(labelOf(ASSOC_TYPES.has(a.type) ? a : b))} a ${esc(labelOf(ASSOC_TYPES.has(a.type) ? b : a))}; no transporta tráfico.</p>` : `
      <div class="field ${e.access ? '' : 'missing'}"><label>¿Qué hace ${esc(labelOf(a))} con ${esc(labelOf(b))}? <span class="req">*</span></label>
        <select data-ebind="access"><option value="">— Define el tipo de acceso —</option>
        ${ACCESS.map(([k, l]) => `<option value="${k}" ${e.access === k ? 'selected' : ''}>${l}</option>`).join('')}</select>
        <div class="help">La dirección de la flecha indica quién inicia la llamada.</div></div>
      <div class="row2">
        ${fieldHtml({ label: 'Puerto', type: 'number', placeholder: 'auto' }, e.port, 'data-ebind="port" data-ftype="number"')}
        ${fieldHtml({ label: 'Protocolo', type: 'select', options: ['tcp', 'udp'] }, e.protocol || 'tcp', 'data-ebind="protocol"')}
      </div>`}
      ${fieldHtml({ label: 'Etiqueta', type: 'text', placeholder: 'ej. eventos de pedidos' }, e.label, 'data-ebind="label"')}
      <div class="field"><label>Flujos</label>${flows().length ? `<div class="ms">${flows().map((f) => {
        const on = (e.flows || []).includes(f.id);
        return `<label class="${on ? 'on' : ''}"><input type="checkbox" data-eflow="${esc(f.id)}" ${on ? 'checked' : ''}><span class="fdot" style="background:${flowColor(f)}"></span>${esc(f.id)} ${esc(f.name || '')}</label>`;
      }).join('')}</div>` : '<div class="help">Define los flujos del proyecto (FL-01 Ingesta, FL-02 Egresión…) en el panel del proyecto.</div>'}</div>
      ${fieldHtml({ label: 'Notas', type: 'textarea', placeholder: 'Detalles del flujo, volumen, formato…' }, e.notes, 'data-ebind="notes"')}
      <div class="section-title">Lo que necesitas para esta conexión</div>
      <div id="edgePlan"><p class="muted">Analizando…</p></div>
    </div>`;
  refreshInspectorAnalysis();
}

function planHtml(plan, findings) {
  if (!plan) return '<p class="muted">Analizando…</p>';
  let h = `<p><b>${esc(plan.summary)}</b></p>`;
  if (plan.path.length) h += `<div class="section-title">Ruta de red</div>${plan.path.map((x) => `<div class="path-item">${esc(x)}</div>`).join('')}`;
  if (plan.principal) {
    const pr = plan.principal;
    h += `<div class="section-title">IAM — rol que necesita permisos</div>
      <div class="kv"><div>Rol</div><div><code>${esc(pr.role)}</code>${pr.explicit ? '' : ' <span class="muted">(sugerido)</span>'}</div>
      <div>Es el</div><div>${esc(pr.desc)}</div><div>Confía en</div><div><code>${esc(pr.service)}</code></div></div>`;
    if (plan.identity.length) h += codeBlock(JSON.stringify({ Version: '2012-10-17', Statement: plan.identity }, null, 2));
  }
  for (const rp of plan.resource_policies) {
    h += `<div class="section-title">${esc(rp.type)} en ${esc(rp.on)}</div>${codeBlock(JSON.stringify(rp.statement, null, 2))}`;
    if (rp.terraform) h += `<details class="tf"><summary>Terraform</summary>${codeBlock(rp.terraform)}</details>`;
  }
  if (plan.network.length) {
    h += `<div class="section-title">Security Groups / firewall</div><table class="tbl"><tr><th>SG</th><th>Dir.</th><th>Puerto</th><th>Origen/destino</th></tr>
      ${plan.network.map((r) => `<tr><td><code>${esc(r.sg)}</code></td><td>${r.direction === 'ingress' ? 'entrada' : 'salida'}</td><td>${esc(r.protocol)}/${esc(r.port)}</td><td><code>${esc(r.peer)}</code><div class="muted">${esc(r.description)}</div></td></tr>`).join('')}</table>`;
  }
  if (plan.notes.length) h += `<div class="section-title">Notas</div><ul style="margin:0 0 8px 16px;padding:0">${plan.notes.map((x) => `<li>${esc(x)}</li>`).join('')}</ul>`;
  if (plan.terraform) h += `<details class="tf"><summary>Terraform de la política</summary>${codeBlock(plan.terraform)}</details>`;
  if (!plan.principal && !plan.resource_policies.length && !plan.network.length && !plan.path.length && !plan.notes.length) {
    h += '<p class="muted">No se requieren permisos IAM ni reglas de red específicas para esta relación (o falta definir el tipo de acceso).</p>';
  }
  if (findings.length) h += `<div class="section-title">Hallazgos en esta conexión</div>${findings.map((f) => findingHtml(f)).join('')}`;
  return h;
}

function refreshInspectorAnalysis() {
  if (!P() || !S.sel) { if (P() && !S.sel) { const st = $('#projStats'); if (st) st.innerHTML = projectStatsHtml(); } return; }
  const A = S.analysis;
  if (S.sel.kind === 'edge') {
    const box = $('#edgePlan');
    if (box && A) box.innerHTML = planHtml(A.plans[S.sel.id], A.findings.filter((f) => f.edge_ids.includes(S.sel.id)));
    return;
  }
  const n = nodeById(S.sel.id);
  if (!n) return;
  const loc = $('#insLocation');
  if (loc && A) {
    const chain = [];
    let pid = A.parents[n.id];
    while (pid) { const p = nodeById(pid); if (!p) break; chain.unshift(labelOf(p) + (p.type === 'subnet' ? ` (${SUBNET_STYLE[(p.config || {}).tier || 'private'].name.toLowerCase()})` : '')); pid = A.parents[pid]; }
    loc.textContent = chain.length ? chain.join(' › ') : compOf(n).vpc === 'never' ? 'Servicio regional (fuera de la VPC)' : 'Fuera de cualquier VPC';
  }
  const conns = $('#insConns');
  if (conns) {
    const es = P().edges.filter((e) => e.source === n.id || e.target === n.id);
    conns.innerHTML = es.length ? es.map((e) => {
      const out = e.source === n.id; const other = nodeById(out ? e.target : e.source);
      return `<div class="list-item" style="padding:6px 8px"><a class="link" data-seledge="${e.id}">${out ? '→' : '←'} ${esc(labelOf(other))}</a>
        <span class="muted"> · ${e.access ? ACCESS_SHORT[e.access] : 'acceso sin definir'}${e.port ? ':' + e.port : ''}</span>${e.terraformed ? ' <span style="color:var(--ok)">✓</span>' : ''}</div>`;
    }).join('') : '<p class="muted">Sin conexiones. Arrastra desde el punto azul del borde derecho hacia otro componente.</p>';
  }
  const sgBox = $('#sgSug');
  if (sgBox) sgBox.innerHTML = sgSuggestionsHtml(n);
  const cp = $('#insCopilot');
  if (cp) {
    if (!A) { cp.innerHTML = '<p class="muted">Analizando…</p>'; return; }
    const fs = nodeFindings(n.id).filter((f) => S.showDismissed || !f.dismissed);
    const role = A.roles.find((r) => r.node_id === n.id);
    const sgs = A.security_groups.filter((g) => [...g.ingress, ...g.egress].length && g.sg === `sg-${roleSlug(n)}`);
    cp.innerHTML = `
      ${n.type === 'sg' ? sgSuggestionsHtml(n) : ''}
      ${fs.length ? fs.map((f) => findingHtml(f)).join('') : '<p>✅ Sin hallazgos para este componente.</p>'}
      ${role ? `<div class="section-title">Política IAM consolidada (${esc(role.role)})</div>${codeBlock(JSON.stringify(role.policy, null, 2))}
        <details class="tf"><summary>Terraform del rol</summary>${codeBlock(role.terraform)}</details>` : ''}
      ${sgs.map((g) => `<div class="section-title">Security Group ${esc(g.sg)}</div>${sgTable(g)}`).join('')}
      ${S.ai.available ? `<div class="section-title">Copilot IA</div><button class="btn blue" data-aifocus="${n.id}">Pedir revisión de este componente</button><div id="aiNodeOut" class="md" style="margin-top:10px"></div>` : ''}`;
  }
}

function roleSlug(n) {
  const pre = (P().settings || {}).prefix;
  const base = (labelOf(n) || 'recurso').normalize('NFKD').replace(/[̀-ͯ]/g, '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'recurso';
  const cfg = n.config || {};
  const explicit = cfg.bucket_name || cfg.table_name || cfg.role_name || cfg.workgroup;
  if (explicit) return explicit;
  return pre ? `${pre}-${base}` : base;
}

function sgTable(g) {
  const rows = [...g.ingress.map((r) => ({ ...r, d: 'entrada' })), ...g.egress.map((r) => ({ ...r, d: 'salida' }))];
  return `<table class="tbl"><tr><th>Dir.</th><th>Puerto</th><th>Origen/destino</th><th>Descripción</th></tr>
    ${rows.map((r) => `<tr><td>${r.d}</td><td>${esc(r.protocol)}/${esc(r.port)}</td><td><code>${esc(r.peer)}</code></td><td>${esc(r.description)}</td></tr>`).join('')}</table>`;
}

function projectStatsHtml() {
  const s = S.analysis && S.analysis.summary;
  if (!s) return '<p class="muted">Analizando…</p>';
  const f = s.findings;
  return `<div class="stat-grid">
      <div class="stat"><b>${s.terraform_pct}%</b><span>terraformado (${s.terraformed}/${s.components})</span></div>
      <div class="stat"><b>${s.config_pct}%</b><span>configuración completa</span></div>
      <div class="stat"><b>${s.open_questions}</b><span>preguntas abiertas</span></div>
      <div class="stat"><b>${s.edges_terraformed}/${s.edges}</b><span>conexiones terraformadas</span></div>
      ${S.analysis.posture ? `<div class="stat link" data-open-security="1" style="grid-column:span 2"><b>🛡 ${S.analysis.posture.score ?? '—'}%</b><span>postura de seguridad (${S.analysis.posture.unknown} controles sin evaluar) — ver detalle</span></div>` : ''}
    </div>
    <div style="display:flex;gap:5px;flex-wrap:wrap;margin-bottom:10px">${SEVS.map((k) => `<span class="chip sev-${k}">${SEV_LABEL[k]}: ${f[k]}</span>`).join('')}</div>
    <table class="tbl"><tr><th>Estado de diseño</th><th>Componentes</th></tr>${STATUSES.map((st) => `<tr><td>${st}</td><td>${s.by_status[st] || 0}</td></tr>`).join('')}</table>`;
}

/* Editor de listas del proyecto (flujos, tags). */
function listEditor(kind, rows, cols) {
  return `<div class="rules"><div class="rhead" style="grid-template-columns:${cols.map(() => '1fr').join(' ')} 26px">${cols.map((c) => `<span>${esc(c.label)}</span>`).join('')}<span></span></div>
    ${rows.map((r, i) => `<div class="rline" style="grid-template-columns:${cols.map(() => '1fr').join(' ')} 26px">${cols.map((c) => (c.options
      ? `<select data-plist="${kind}" data-row="${i}" data-col="${c.key}">${c.options.map((o) => `<option ${o === r[c.key] ? 'selected' : ''}>${esc(o)}</option>`).join('')}</select>`
      : `<input type="text" data-plist="${kind}" data-row="${i}" data-col="${c.key}" value="${esc(r[c.key])}" placeholder="${esc(c.placeholder || '')}">`)).join('')}
      <button class="btn sm ghost" data-pdel="${kind}" data-row="${i}" title="Quitar">✕</button></div>`).join('') || '<div class="muted" style="padding:6px">Sin elementos.</div>'}
  </div><button class="btn sm" data-padd="${kind}" style="margin:6px 0 10px">+ Agregar</button>`;
}

function renderProjectInspector(el) {
  const p = P(), st = p.settings || {};
  el.innerHTML = `
    <div class="ins-head"><span class="ab" style="background:#232f3e">PRJ</span><div><h3>${esc(p.name)}</h3><div class="sub">Actualizado ${fmtDate(p.updated)} · rev ${p.rev}</div></div></div>
    <div class="ins-body">
      ${fieldHtml({ label: 'Nombre del proyecto', type: 'text' }, p.name, 'data-pbind="name"')}
      ${fieldHtml({ label: 'Descripción', type: 'textarea', placeholder: 'Contexto, alcance, enlaces…' }, p.description, 'data-pbind="description"')}
      <div class="row2">
        ${fieldHtml({ label: 'Región', type: 'text', placeholder: 'us-east-1' }, st.region, 'data-sbind="region"')}
        ${fieldHtml({ label: 'Cuenta AWS', type: 'text', placeholder: '123456789012' }, st.account_id, 'data-sbind="account_id"')}
      </div>
      <div class="row2">
        ${fieldHtml({ label: 'Ambiente', type: 'select', options: ['dev', 'qa', 'staging', 'prod'] }, st.environment, 'data-sbind="environment"')}
        ${fieldHtml({ label: 'Prefijo de nombres', type: 'text', placeholder: 'empresa-app' }, st.prefix, 'data-sbind="prefix"')}
      </div>
      <div class="field"><label>Tu nombre (para notas y preguntas)</label><input type="text" id="authorInput" value="${esc(S.author)}"></div>
      <div class="section-title">Flujos (color de las conexiones)</div>
      ${listEditor('flows', flows(), [{ key: 'id', label: 'ID', placeholder: 'FL-01' }, { key: 'name', label: 'Nombre', placeholder: 'Ingesta' },
    { key: 'color', label: 'Color', options: COLOR_NAMES }])}
      <div class="section-title">Tags de gobierno</div>
      ${fieldHtml({ label: 'Tags obligatorios (uno por línea)', type: 'textarea', placeholder: 'CostCenter\nEnvironment\nProject',
    help: 'El Copilot avisa qué componentes no los tienen y genera el bloque default_tags de Terraform.' },
    (st.required_tags || []).join('\n'), 'data-sbind="required_tags"')}
      <button class="btn sm" data-act="tagTemplate" style="margin:-4px 0 10px">Usar los 12 tags de gobierno</button>
      <label class="field" style="display:block;font-weight:600;font-size:12px">Tags por defecto (default_tags)</label>
      ${listEditor('tags', st.tags || [], [{ key: 'key', label: 'Clave', placeholder: 'CostCenter' }, { key: 'value', label: 'Valor', placeholder: 'CC-123' }])}
      <div class="section-title">Resumen</div><div id="projStats">${projectStatsHtml()}</div>
      <div class="section-title">Cómo se usa</div>
      <div class="legend">
        <div>• Arrastra componentes desde la izquierda; suéltalos dentro de una VPC/Subnet para ubicarlos.</div>
        <div>• Conecta: arrastra desde el punto <b style="color:var(--accent)">●</b> del borde derecho al destino. La flecha va de quien llama a quien es llamado.</div>
        <div>• Clic en el círculo ✓ de un componente para marcarlo como terraformado.</div>
        <div>• Selecciona un componente para registrar su configuración, notas y preguntas al arquitecto.</div>
        <div><span class="sw" style="background:#3F8624"></span>Subnet pública <span class="sw" style="background:#147EBA;margin-left:8px"></span>Privada <span class="sw" style="background:#687078;margin-left:8px"></span>Aislada</div>
        <div>Borde de color = hallazgo del Copilot (rojo crítico, naranja alto, amarillo medio, azul bajo).</div>
        <div>Atajos: <span class="kbd">Supr</span> eliminar · <span class="kbd">Ctrl+Z</span> deshacer · <span class="kbd">Ctrl+D</span> duplicar · <span class="kbd">Esc</span> deseleccionar · rueda/pinch para zoom, arrastrar fondo para mover.</div>
      </div>
    </div>`;
}

/* inputs del inspector (delegación) */
function setPath(obj, key, val) { if (val === '' || val === null || val === undefined) delete obj[key]; else obj[key] = val; }
function readInput(t) {
  if (t.type === 'checkbox') return t.checked;
  if (t.dataset.ftype === 'number' || t.type === 'number') return t.value === '' ? null : Number(t.value);
  return t.value;
}
function onInspectorFocus(ev) {
  const t = ev.target;
  if (t.matches('[data-bind],[data-cfg],[data-ebind],[data-pbind],[data-sbind],[data-qanswer],[data-rcell],[data-plist]') && S.focusEl !== t) { S.focusEl = t; snapshot(); }
}
function onInspectorInput(ev) {
  const t = ev.target;
  if (t.id === 'authorInput' || t.id === 'noteAuthor') { S.author = t.value; lsSet('it.author', S.author); return; }
  const isChange = ev.type === 'change';
  if (t.type === 'checkbox' && !isChange) return;
  if (t.tagName === 'SELECT' && !isChange) return;
  if ((t.type === 'checkbox' || t.tagName === 'SELECT') && S.focusEl !== t) snapshot();
  let rerender = false;
  if (t.dataset.bind) {
    const n = nodeById(S.sel.id); setPath(n, t.dataset.bind, readInput(t));
    if (t.dataset.bind === 'label') { const h = $('.ins-head h3'); if (h) h.textContent = labelOf(n); }
  } else if (t.dataset.cfg) {
    const n = nodeById(S.sel.id); n.config = n.config || {};
    setPath(n.config, t.dataset.cfg, readInput(t));
    rerender = isChange && (t.type === 'checkbox' || t.tagName === 'SELECT');
  } else if (t.dataset.rcell) {
    const n = nodeById(S.sel.id); n.config = n.config || {};
    const rows = n.config[t.dataset.rcell] = n.config[t.dataset.rcell] || [];
    const row = rows[Number(t.dataset.row)];
    if (!row) return;
    let v = t.value;
    if (t.dataset.ctype === 'number') v = v === '' ? null : Number(v);
    if (v === '' || v === null) delete row[t.dataset.col]; else row[t.dataset.col] = v;
  } else if (t.dataset.ms) {
    const n = nodeById(S.sel.id); n.config = n.config || {};
    const set = new Set(n.config[t.dataset.ms] || []);
    if (t.checked) set.add(t.value); else set.delete(t.value);
    n.config[t.dataset.ms] = [...set];
    t.parentElement.classList.toggle('on', t.checked);
    rerender = true;
  } else if (t.dataset.ebind) {
    const e = edgeById(S.sel.id); setPath(e, t.dataset.ebind, readInput(t));
    if (t.dataset.ebind === 'access') t.closest('.field').classList.toggle('missing', !t.value);
  } else if (t.dataset.pbind) {
    setPath(P(), t.dataset.pbind, readInput(t));
    if (t.dataset.pbind === 'name') { const o = $(`#projectSelect option[value="${P().id}"]`); if (o) o.textContent = P().name; }
  } else if (t.dataset.plist) {
    P().settings = P().settings || {};
    const list = P().settings[t.dataset.plist] = P().settings[t.dataset.plist] || [];
    if (list[Number(t.dataset.row)]) list[Number(t.dataset.row)][t.dataset.col] = t.value;
    if (t.dataset.plist === 'flows') renderFlowFilter();
  } else if (t.dataset.eflow) {
    const e = edgeById(S.sel.id);
    const set = new Set(e.flows || []);
    if (t.checked) set.add(t.dataset.eflow); else set.delete(t.dataset.eflow);
    e.flows = [...set];
    t.parentElement.classList.toggle('on', t.checked);
  } else if (t.dataset.sbind === 'required_tags') {
    P().settings = P().settings || {};
    P().settings.required_tags = t.value.split(/[\n,]/).map((x) => x.trim()).filter(Boolean);
  } else if (t.dataset.sbind) {
    P().settings = P().settings || {}; setPath(P().settings, t.dataset.sbind, readInput(t));
  } else if (t.dataset.qanswer) {
    const q = nodeById(S.sel.id).questions.find((x) => x.id === t.dataset.qanswer);
    q.answer = t.value; q.answered_at = nowIso(); q.answered_by = S.author;
  } else return;
  changed({ canvas: true });
  if (rerender) { const sc = $('#inspector').scrollTop; renderInspector(); $('#inspector').scrollTop = sc; }
}

function onInspectorClick(ev) {
  const t = ev.target.closest('button, a, [data-act], .tfbox, [data-open-security]');
  if (!t) return;
  const n = S.sel && S.sel.kind === 'node' ? nodeById(S.sel.id) : null;
  const e = S.sel && S.sel.kind === 'edge' ? edgeById(S.sel.id) : null;
  if (t.dataset.tab) { S.tab = t.dataset.tab; renderInspector(); return; }
  if (t.dataset.openSecurity) { openCopilot('security'); return; }
  if (t.dataset.copy !== undefined) { copy(t.dataset.copy); return; }
  if (t.dataset.goto) { const g = nodeById(t.dataset.goto); if (g) { select('node', g.id, 'general'); centerOn(g); } return; }
  if (t.dataset.seledge) { select('edge', t.dataset.seledge); return; }
  if (t.dataset.dismiss) { dismissFinding(t.dataset.dismiss); return; }
  if (t.dataset.undismiss) { undismissFinding(t.dataset.undismiss); return; }
  if (t.dataset.aifocus) { askAI(null, t.dataset.aifocus, $('#aiNodeOut')); return; }
  if (t.dataset.padd || t.dataset.pdel) {
    snapshot(); P().settings = P().settings || {};
    const kind = t.dataset.padd || t.dataset.pdel;
    const list = P().settings[kind] = P().settings[kind] || [];
    if (t.dataset.padd) list.push(kind === 'flows' ? { id: `FL-${String(list.length + 1).padStart(2, '0')}`, name: '', color: COLOR_NAMES[list.length % COLOR_NAMES.length] } : { key: '', value: '' });
    else list.splice(Number(t.dataset.row), 1);
    const sc = $('#inspector').scrollTop; changed({ inspector: true }); renderFlowFilter(); $('#inspector').scrollTop = sc; return;
  }
  if (t.dataset.addrow) {
    const f = compOf(n).fields.find((x) => x.key === t.dataset.addrow);
    snapshot(); n.config = n.config || {};
    const rows = n.config[f.key] = n.config[f.key] || [];
    const row = {};
    f.columns.forEach((c) => {
      if (c.key === 'rule_no') row.rule_no = (Math.max(0, ...rows.map((r) => Number(r.rule_no) || 0)) || 90) + 10;
      else if (c.key === 'direction') row.direction = 'ingress';
      else if (c.key === 'protocol') row.protocol = 'tcp';
      else if (c.key === 'action') row.action = 'allow';
      else if (c.key === 'target_type') row.target_type = 'nat';
    });
    rows.push(row);
    const sc = $('#inspector').scrollTop; changed({ inspector: true }); $('#inspector').scrollTop = sc; return;
  }
  if (t.dataset.delrow) {
    snapshot(); n.config[t.dataset.delrow].splice(Number(t.dataset.row), 1);
    const sc = $('#inspector').scrollTop; changed({ inspector: true }); $('#inspector').scrollTop = sc; return;
  }
  if (t.dataset.delnote) { snapshot(); n.notes = n.notes.filter((x) => x.id !== t.dataset.delnote); changed({ inspector: true }); return; }
  if (t.dataset.delq) { if (!confirm('¿Eliminar la pregunta?')) return; snapshot(); n.questions = n.questions.filter((x) => x.id !== t.dataset.delq); changed({ inspector: true }); return; }
  if (t.dataset.qtoggle) {
    snapshot(); const q = n.questions.find((x) => x.id === t.dataset.qtoggle);
    q.status = q.status === 'closed' ? 'open' : 'closed'; q.closed_at = q.status === 'closed' ? nowIso() : null;
    changed({ inspector: true }); return;
  }
  switch (t.dataset.act) {
    case 'tf':
      if (n) toggleTerraformed(n);
      else if (e) { snapshot(); e.terraformed = !e.terraformed; changed({ inspector: true }); }
      break;
    case 'del': deleteSelection(); break;
    case 'tagTemplate': {
      const tpl = S.analysis?.tags?.template || [];
      snapshot(); P().settings = P().settings || {};
      const cur = new Set(P().settings.required_tags || []);
      P().settings.required_tags = [...cur, ...tpl.filter((x) => !cur.has(x))];
      changed({ inspector: true }); break;
    }
    case 'applySg': {
      const sug = (S.analysis && S.analysis.sg_suggestions && S.analysis.sg_suggestions[n.id]) || [];
      if (!sug.length) return;
      snapshot(); n.config.rules = [...(n.config.rules || []), ...sug.map((r) => ({ ...r }))];
      S.tab = 'config'; changed({ inspector: true }); toast(`${sug.length} regla(s) agregadas al SG`); break;
    }
    case 'dup': if (n) duplicateNode(n); break;
    case 'flip': snapshot(); [e.source, e.target] = [e.target, e.source]; changed({ inspector: true }); break;
    case 'addNote': {
      const txt = $('#newNote').value.trim(); if (!txt) return;
      snapshot(); n.notes = n.notes || []; n.notes.push({ id: uid('note'), text: txt, author: S.author, at: nowIso() });
      changed({ inspector: true }); break;
    }
    case 'addQ': {
      const txt = $('#newQ').value.trim(); if (!txt) return;
      snapshot(); n.questions = n.questions || []; n.questions.push({ id: uid('q'), text: txt, author: S.author, at: nowIso(), status: 'open', answer: '' });
      changed({ inspector: true }); break;
    }
    default:
  }
}

function dismissFinding(id) {
  const reason = prompt('¿Por qué se acepta este riesgo o no aplica? (queda registrado en el reporte)');
  if (!reason) return;
  snapshot();
  P().dismissed = P().dismissed || {};
  P().dismissed[id] = { reason, by: S.author || '', at: new Date().toISOString().slice(0, 10) };
  changed({ canvas: false });
}
function undismissFinding(id) { snapshot(); delete P().dismissed[id]; changed({ canvas: false }); }

/* ───────────────────────── Barra de estado y progreso ───────────────────────── */
function updateProgress() {
  if (!P()) return;
  const tf = P().nodes.filter((n) => compOf(n).terraformable !== false && S.comp[n.type]);
  const done = tf.filter((n) => n.terraformed).length;
  const pct = tf.length ? Math.round((100 * done) / tf.length) : 0;
  $('#progressLabel').textContent = `${done}/${tf.length} terraformado (${pct}%)`;
  $('#progressBar').style.width = pct + '%';
}
function renderStatusbar() {
  const A = S.analysis;
  if (!A) return;
  const f = A.summary.findings;
  const chips = SEVS.filter((k) => f[k]).map((k) => `<span class="chip sev-${k}" data-sev="${k}">${f[k]} ${SEV_LABEL[k]}</span>`);
  if (A.posture && A.posture.score !== null) chips.unshift(`<span class="chip sec-chip" data-mtab="security">🛡 Seguridad ${A.posture.score}%${A.posture.unknown ? ` · ${A.posture.unknown} sin evaluar` : ''}</span>`);
  if (A.summary.open_questions) chips.push(`<span class="chip st-open" data-mtab="questions">❓ ${A.summary.open_questions} preguntas abiertas</span>`);
  $('#statusbar').innerHTML = chips.join('');
}
function updateCopilotBadge() {
  const f = S.analysis ? S.analysis.summary.findings : { critical: 0, high: 0 };
  const n = f.critical + f.high;
  const b = $('#copilotBadge'); b.textContent = n; b.classList.toggle('hidden', !n);
}

/* ───────────────────────── Modal Copilot ───────────────────────── */
function openModal(kind, title) {
  S.modal = kind; $('#modalTitle').textContent = title; $('#modal').classList.remove('hidden');
}
function closeModal() { S.modal = null; $('#modal').classList.add('hidden'); $('#modalBody').innerHTML = ''; }

function openCopilot(tab) {
  if (tab) S.mtab = tab;
  openModal('copilot', 'Copilot de arquitectura AWS');
  renderCopilotTab();
}

function renderCopilotTab() {
  const A = S.analysis;
  const tabs = [['security', 'Seguridad'], ['findings', 'Hallazgos'], ['iam', 'Roles IAM'], ['sg', 'Security Groups'], ['questions', 'Preguntas al arquitecto'],
    ['pending', 'Pendientes de terraform'], ['tags', 'Tags y Terraform'], ['ai', 'Copilot IA']];
  let c = '';
  if (!A) c = '<p class="muted">Analizando…</p>';
  else if (S.mtab === 'security') c = securityHtml(A);
  else if (S.mtab === 'tags') c = tagsHtml(A);
  else if (S.mtab === 'findings') {
    const cats = [...new Set(A.findings.map((f) => f.category))].sort();
    const list = A.findings.filter((f) => S.sevFilter.has(f.severity) && (!S.catFilter || f.category === S.catFilter) && (S.showDismissed || !f.dismissed));
    c = `<div class="filters">${SEVS.map((k) => `<span class="chip sev-${k} ${S.sevFilter.has(k) ? '' : 'off'}" data-sevtoggle="${k}">${SEV_LABEL[k]} ${A.findings.filter((f) => f.severity === k && !f.dismissed).length}</span>`).join('')}
      <select id="catFilter" class="btn sm"><option value="">Todas las categorías</option>${cats.map((x) => `<option ${x === S.catFilter ? 'selected' : ''}>${esc(x)}</option>`).join('')}</select>
      <label class="tgl"><input type="checkbox" id="showDismissed" ${S.showDismissed ? 'checked' : ''}> Mostrar aceptados</label></div>
      ${list.length ? list.map((f) => findingHtml(f)).join('') : '<p>✅ Nada que mostrar con estos filtros.</p>'}
      <p class="muted">El Copilot evalúa reglas de AWS Well-Architected y requisitos de servicio (red, IAM, HA, datos, costo). No accede a tu cuenta: revisa lo que dibujas y configuras aquí.</p>`;
  } else if (S.mtab === 'iam') {
    const all = A.roles.map((r) => r.terraform).join('\n');
    c = A.roles.length ? `<p class="muted">Políticas de mínimo privilegio generadas a partir de las conexiones. Ajusta ARNs marcados con &lt;…&gt;.</p>
      <button class="btn" data-copy="${esc(all)}" style="margin-bottom:12px">Copiar todo el Terraform IAM</button>
      ${A.roles.map((r) => `<div class="role-card"><header><b>${esc(r.role)}</b> — <a class="link" data-goto="${r.node_id}">${esc(r.component)}</a>
        <span class="muted"> · ${esc(r.desc)}</span></header><div>
        ${r.managed ? `<p>Políticas administradas: ${r.managed.map((m) => `<code>${esc(m)}</code>`).join(', ')}</p>` : ''}
        ${r.trust ? `<details class="tf"><summary>Trust policy</summary>${codeBlock(JSON.stringify(r.trust, null, 2))}</details>` : `<p class="muted">Trust: ${esc(r.service)}</p>`}
        ${codeBlock(JSON.stringify(r.policy, null, 2))}
        <details class="tf"><summary>Terraform</summary>${codeBlock(r.terraform)}</details></div></div>`).join('')}`
      : '<p class="muted">Aún no hay conexiones que requieran permisos IAM. Conecta componentes (ej. Lambda → S3) y define el tipo de acceso.</p>';
  } else if (S.mtab === 'sg') {
    const all = A.security_groups.map((g) => g.terraform).join('\n');
    c = A.security_groups.length ? `<p class="muted">Reglas derivadas de las conexiones entre recursos con red (referenciando SG cuando es posible).</p>
      <button class="btn" data-copy="${esc(all)}" style="margin-bottom:12px">Copiar todo el Terraform de SG</button>
      ${A.security_groups.map((g) => `<div class="role-card"><header><b>${esc(g.sg)}</b></header><div>${sgTable(g)}
        <details class="tf"><summary>Terraform</summary>${codeBlock(g.terraform)}</details></div></div>`).join('')}`
      : '<p class="muted">No hay conexiones de red entre recursos en VPC todavía.</p>';
  } else if (S.mtab === 'questions') {
    const rows = [];
    P().nodes.forEach((n) => (n.questions || []).forEach((q) => rows.push({ n, q })));
    rows.sort((a, b) => (a.q.status === 'closed') - (b.q.status === 'closed'));
    c = rows.length ? `<table class="tbl"><tr><th>Componente</th><th>Pregunta</th><th>Respuesta</th><th>Estado</th></tr>
      ${rows.map(({ n, q }) => `<tr><td><a class="link" data-goto="${n.id}" data-gotab="architect">${esc(labelOf(n))}</a></td><td>${esc(q.text)}</td>
        <td>${esc(q.answer || '—')}</td><td>${q.status === 'closed' ? 'Cerrada' : q.answer ? 'Respondida' : '<b>Abierta</b>'}</td></tr>`).join('')}</table>`
      : '<p class="muted">No hay preguntas registradas. Agrégalas desde la pestaña “Arquitecto” de cada componente.</p>';
  } else if (S.mtab === 'pending') {
    const pend = P().nodes.filter((n) => compOf(n).terraformable && !n.terraformed);
    const pe = P().edges.filter((e) => !e.terraformed);
    c = `<p>${pend.length} componentes y ${pe.length} conexiones pendientes de terraformar.</p>
      <table class="tbl"><tr><th></th><th>Componente</th><th>Tipo</th><th>Estado</th><th>Config.</th><th>Responsable</th></tr>
      ${pend.map((n) => { const pr = configProgress(n); return `<tr><td><input type="checkbox" data-tfnode="${n.id}" title="Marcar terraformado"></td>
        <td><a class="link" data-goto="${n.id}">${esc(labelOf(n))}</a></td><td>${esc(compOf(n).name)}</td><td>${esc(n.status || 'Borrador')}</td>
        <td>${pr.pct}%</td><td>${esc(n.owner || '—')}</td></tr>`; }).join('')}</table>
      ${pe.length ? `<div class="section-title">Conexiones</div><table class="tbl">${pe.map((e) => `<tr><td><input type="checkbox" data-tfedge="${e.id}"></td>
        <td><a class="link" data-seledge="${e.id}">${esc(labelOf(nodeById(e.source)))} → ${esc(labelOf(nodeById(e.target)))}</a></td><td>${e.access ? ACCESS_SHORT[e.access] : 'sin definir'}</td></tr>`).join('')}</table>` : ''}`;
  } else if (S.mtab === 'ai') {
    c = S.ai.available ? `<div class="ai-box"><p class="muted">Usa ${esc(S.ai.model)} con el diagrama completo y los hallazgos de reglas como contexto.</p>
      <textarea id="aiQuestion" placeholder="Ej. ¿Conviene EMR Serverless o EMR on EC2 para jobs nocturnos de 3 h con 2 TB? ¿Qué me falta para pasar a producción?"></textarea>
      <div style="display:flex;gap:8px;margin:8px 0 14px"><button class="btn blue" data-ai="ask">Preguntar</button><button class="btn" data-ai="review">Revisión completa de arquitectura</button></div>
      <div id="aiOut" class="md"></div></div>`
      : `<p>El Copilot IA es opcional. Las reglas de AWS ya funcionan sin él.</p><p class="muted">Para habilitarlo: <code>pip install anthropic</code> y exporta <code>ANTHROPIC_API_KEY</code> antes de iniciar <code>app.py</code>. (${esc(S.ai.reason || '')})</p>`;
  }
  $('#modalBody').innerHTML = `<div class="mtabs">${tabs.map(([k, l]) => `<button class="tab ${S.mtab === k ? 'on' : ''}" data-mtabbtn="${k}">${l}</button>`).join('')}</div><div class="mcontent">${c}</div>`;
}

function tagsHtml(A) {
  const t = A.tags || {};
  const missing = A.findings.filter((f) => f.rule === 'TAG-MISSING');
  return `${t.required && t.required.length ? `<p>Tags obligatorios: ${t.required.map((k) => `<span class="chip ${t.missing_in_default.includes(k) ? 'st-open' : 'st-closed'}">${esc(k)}</span>`).join(' ')}</p>
      <p class="muted">Verde = definido en los tags por defecto del proyecto. Naranja = falta (cárgalo en el panel del proyecto, en la cuenta o en cada componente).</p>`
    : '<p class="muted">Define los tags obligatorios en el panel del proyecto (o usa “Usar los 12 tags de gobierno”).</p>'}
    ${missing.map((f) => findingHtml(f)).join('')}
    ${t.providers ? `<div class="section-title">Terraform: default_tags</div>${codeBlock(t.providers)}` : ''}
    ${t.node_tags && t.node_tags.length ? `<div class="section-title">Tags adicionales por componente</div><table class="tbl"><tr><th>Componente</th><th>Tags</th></tr>
      ${t.node_tags.map((x) => `<tr><td><a class="link" data-goto="${x.node_id}">${esc(x.label)}</a></td><td><code>${esc(Object.entries(x.tags).map(([k, v]) => `${k}=${v}`).join(', '))}</code></td></tr>`).join('')}</table>` : ''}`;
}

const CTRL_STATUS = {
  pass: ['✔', 'Cumple', 'ok'], fail: ['✖', 'Falla', 'bad'], accepted: ['≈', 'Riesgo aceptado', 'acc'],
  unknown: ['?', 'Sin evaluar', 'unk'], na: ['—', 'No aplica', 'na'],
};
function securityHtml(A) {
  const p = A.posture;
  const byId = Object.fromEntries(A.findings.map((f) => [f.id, f]));
  const scoreTxt = (v) => (v === null || v === undefined ? '—' : v + '%');
  const bar = (v) => `<div class="meter"><div style="width:${v || 0}%;background:${v >= 80 ? 'var(--ok)' : v >= 50 ? 'var(--sev-medium)' : 'var(--sev-high)'}"></div></div>`;
  return `<div class="sec-summary">
      <div class="stat"><b>${scoreTxt(p.score)}</b><span>controles que cumplen (${p.evaluated} evaluados)</span></div>
      <div class="stat"><b>${p.unknown}</b><span>sin evaluar${p.unknown ? ': agrega una “Cuenta AWS” y marca su línea base' : ''}</span></div>
      <div class="filters" style="align-self:center"><label class="tgl"><input type="checkbox" id="secShowNa" ${S.secShowNa ? 'checked' : ''}> Mostrar los que no aplican</label></div>
    </div>
    <p class="muted">Basado en el pilar de seguridad de AWS Well-Architected. Las referencias FSBP son controles de AWS Foundational
      Security Best Practices (Security Hub) y CIS indica temas de CIS AWS Foundations: valida la numeración con la versión que uses.</p>
    ${p.domains.map((d) => `<div class="role-card"><header><b>${esc(d.name)}</b>
        <span class="muted"> · ${d.pass} cumplen · ${d.fail} fallan${d.accepted ? ` · ${d.accepted} aceptados` : ''}${d.unknown ? ` · ${d.unknown} sin evaluar` : ''}</span>
        <span style="float:right;font-weight:700">${scoreTxt(d.score)}</span>${bar(d.score)}</header><div>
        ${d.controls.filter((c) => S.secShowNa || c.status !== 'na').map((c) => {
          const [icon, label, cls] = CTRL_STATUS[c.status];
          const fs = c.finding_ids.map((id) => byId[id]).filter(Boolean);
          return `<details class="ctrl ${cls}"><summary><span class="ctrl-icon">${icon}</span> ${esc(c.title)}
            ${c.refs.map((r) => `<span class="chip ref">${esc(r)}</span>`).join(' ')}
            ${c.worst ? `<span class="chip sev-${c.worst}">${SEV_LABEL[c.worst]}</span>` : ''}
            <span class="muted ctrl-label">${label}${fs.length ? ` · ${fs.length}` : ''}</span></summary>
            <div class="ctrl-body">${c.hint ? `<p class="muted">${esc(c.hint)}</p>` : ''}
              ${fs.length ? fs.map((f) => findingHtml(f)).join('') : c.status === 'pass' ? '<p class="muted">Sin hallazgos en los componentes del diagrama.</p>' : ''}</div></details>`;
        }).join('') || '<p class="muted">Ningún control aplica a este diagrama.</p>'}</div></div>`).join('')}`;
}

function onModalClick(ev) {
  const t = ev.target.closest('[data-mtabbtn],[data-sevtoggle],[data-copy],[data-goto],[data-seledge],[data-dismiss],[data-undismiss],[data-ai],[data-restore]');
  if (!t) return;
  if (t.dataset.mtabbtn) { S.mtab = t.dataset.mtabbtn; renderCopilotTab(); return; }
  if (t.dataset.sevtoggle) { const k = t.dataset.sevtoggle; S.sevFilter.has(k) ? S.sevFilter.delete(k) : S.sevFilter.add(k); renderCopilotTab(); return; }
  if (t.dataset.copy !== undefined) { copy(t.dataset.copy); return; }
  if (t.dataset.goto) { const n = nodeById(t.dataset.goto); closeModal(); if (n) { select('node', n.id, t.dataset.gotab || 'copilot'); centerOn(n); } return; }
  if (t.dataset.seledge) { closeModal(); select('edge', t.dataset.seledge); return; }
  if (t.dataset.dismiss) { dismissFinding(t.dataset.dismiss); return; }
  if (t.dataset.undismiss) { undismissFinding(t.dataset.undismiss); return; }
  if (t.dataset.ai) { const q = t.dataset.ai === 'ask' ? $('#aiQuestion').value.trim() : null; if (t.dataset.ai === 'ask' && !q) return; askAI(q, null, $('#aiOut')); return; }
  if (t.dataset.restore) { restoreBackup(t.dataset.restore); }
}
function onModalChange(ev) {
  const t = ev.target;
  if (t.id === 'catFilter') { S.catFilter = t.value; renderCopilotTab(); }
  if (t.id === 'showDismissed') { S.showDismissed = t.checked; renderCopilotTab(); }
  if (t.id === 'secShowNa') { S.secShowNa = t.checked; renderCopilotTab(); }
  if (t.dataset.tfnode) { const n = nodeById(t.dataset.tfnode); toggleTerraformed(n); setTimeout(renderCopilotTab, 50); }
  if (t.dataset.tfedge) { snapshot(); edgeById(t.dataset.tfedge).terraformed = true; changed(); setTimeout(renderCopilotTab, 50); }
}

function mdToHtml(md) {
  const lines = esc(md).split('\n');
  let html = '', inList = false, inCode = false;
  for (const raw of lines) {
    if (raw.startsWith('```')) { if (inCode) { html += '</pre>'; inCode = false; } else { if (inList) { html += '</ul>'; inList = false; } html += '<pre class="code">'; inCode = true; } continue; }
    if (inCode) { html += raw + '\n'; continue; }
    let l = raw.replace(/\*\*(.+?)\*\*/g, '<b>$1</b>').replace(/`([^`]+)`/g, '<code>$1</code>');
    const h = /^(#{1,4})\s+(.*)/.exec(l);
    const li = /^\s*(?:[-*]|\d+\.)\s+(.*)/.exec(l);
    if (li) { if (!inList) { html += '<ul>'; inList = true; } html += `<li>${li[1]}</li>`; continue; }
    if (inList) { html += '</ul>'; inList = false; }
    if (h) html += `<h3>${h[2]}</h3>`;
    else if (l.trim()) html += `<p>${l}</p>`;
  }
  if (inList) html += '</ul>';
  if (inCode) html += '</pre>';
  return html;
}

async function askAI(question, nodeId, outEl) {
  if (!outEl) return;
  outEl.innerHTML = '<p class="muted">Pensando… (puede tardar un minuto)</p>';
  try {
    const r = await api('POST', '/api/ai/ask', { project: P(), question, node_id: nodeId });
    outEl.innerHTML = mdToHtml(r.answer);
  } catch (e) { outEl.innerHTML = `<p style="color:var(--danger)">${esc(e.message)}</p>`; }
}

/* ───────────────────────── Menú de proyecto ───────────────────────── */
async function onMenu(act) {
  $('#menu').classList.add('hidden');
  const p = P();
  if (act === 'dup-env') { await duplicateForEnvironment(); return; }
  if (act === 'compare') { await openCompare(); return; }
  if (act === 'duplicate') { await flushSave(); const c = await api('POST', `/api/projects/${p.id}/duplicate`); await loadProjects(c.id); toast('Proyecto duplicado'); }
  else if (act === 'delete') {
    if (!confirm(`¿Eliminar “${p.name}”? Se moverá a data/trash.`)) return;
    await api('DELETE', `/api/projects/${p.id}`); S.project = null;
    const rest = await api('GET', '/api/projects');
    if (!rest.length) await api('POST', '/api/projects', { name: 'Nuevo proyecto' });
    await loadProjects();
  } else if (act === 'export-md' || act === 'export-json') {
    await flushSave();
    const a = document.createElement('a'); a.href = `/api/projects/${p.id}/export.${act === 'export-md' ? 'md' : 'json'}`; a.download = ''; a.click();
  } else if (act === 'import') $('#fileImport').click();
  else if (act === 'sample') newProject(true);
  else if (act === 'backups') {
    await flushSave();
    const list = await api('GET', `/api/projects/${p.id}/backups`);
    openModal('backups', 'Respaldos automáticos');
    $('#modalBody').innerHTML = `<div class="mcontent"><p class="muted">Se guarda una copia como máximo cada 5 minutos mientras editas (últimas 50).</p>
      ${list.length ? `<table class="tbl"><tr><th>Fecha</th><th>Tamaño</th><th></th></tr>${list.map((b) => `<tr><td>${esc(b.id.replace(/(\d{4})(\d{2})(\d{2})-(\d{2})(\d{2})(\d{2})/, '$1-$2-$3 $4:$5:$6'))}</td>
        <td>${Math.round(b.size / 1024)} KB</td><td><button class="btn sm" data-restore="${b.id}">Restaurar</button></td></tr>`).join('')}</table>` : '<p>Aún no hay respaldos.</p>'}</div>`;
  }
}
async function duplicateForEnvironment() {
  await flushSave();
  const env = prompt('Ambiente destino (ej. pre, pro, qa):', 'pre');
  if (!env) return;
  const map = {};
  for (const a of P().nodes.filter((n) => n.type === 'account')) {
    const old = a.config?.account_id || '';
    const v = prompt(`ID de la cuenta ${env.toUpperCase()} que reemplaza a “${labelOf(a)}” (${old || 'sin ID'}):`, '');
    if (v === null) return;
    if (v.trim() && old) map[old] = v.trim();
  }
  try {
    const c = await api('POST', `/api/projects/${P().id}/duplicate`, { environment: env.trim(), account_map: map });
    await loadProjects(c.id); toast(`Creado ${c.name}: la línea base de las cuentas quedó “Sin confirmar”`, 5000);
  } catch (e) { toast(e.message, 6000); }
}

async function openCompare() {
  await flushSave();
  const others = S.projects.filter((p) => p.id !== P().id);
  openModal('compare', 'Comparar ambientes');
  if (!others.length) { $('#modalBody').innerHTML = '<div class="mcontent"><p>No hay otro proyecto para comparar. Usa “Duplicar como otro ambiente”.</p></div>'; return; }
  $('#modalBody').innerHTML = `<div class="mcontent"><div class="filters">Comparar <b>${esc(P().name)}</b> con
    <select id="cmpOther" class="btn sm">${others.map((p) => `<option value="${p.id}">${esc(p.name)}</option>`).join('')}</select></div><div id="cmpOut"></div></div>`;
  const run = async () => {
    const d = await api('GET', `/api/compare/${P().id}/${$('#cmpOther').value}`);
    const v = (x) => esc(Array.isArray(x) ? x.join(', ') : (x ?? '—'));
    const list = (arr) => (arr.length ? `<ul>${arr.map((n) => `<li>${esc(n.label)} <span class="muted">(${esc(n.type_name)})</span></li>`).join('')}</ul>` : '<p class="muted">Ninguno.</p>');
    $('#cmpOut').innerHTML = `<p>${d.same} componentes iguales · ${d.changed.length} con diferencias · ${d.only_a.length} sólo en A · ${d.only_b.length} sólo en B</p>
      <div class="row2"><div><div class="section-title">Sólo en ${esc(d.a.name)}</div>${list(d.only_a)}</div>
      <div><div class="section-title">Sólo en ${esc(d.b.name)}</div>${list(d.only_b)}</div></div>
      <div class="section-title">Diferencias</div>
      ${d.changed.length ? `<table class="tbl"><tr><th>Componente</th><th>Campo</th><th>${esc(d.a.name)}</th><th>${esc(d.b.name)}</th></tr>
        ${d.changed.map((c) => [
          ...(c.terraformed_a !== c.terraformed_b ? [`<tr><td>${esc(c.label)}</td><td>Terraformado</td><td>${c.terraformed_a ? '✓' : '—'}</td><td>${c.terraformed_b ? '✓' : '—'}</td></tr>`] : []),
          ...c.diffs.map((x) => `<tr><td>${esc(c.label)}</td><td>${esc(x.field)}</td><td>${v(x.a)}</td><td>${v(x.b)}</td></tr>`)].join('')).join('')}</table>` : '<p class="muted">Sin diferencias.</p>'}
      <div class="section-title">Conexiones</div>
      <p class="muted">Sólo en A: ${d.edges_only_a.map((x) => `${esc(x.source)} → ${esc(x.target)}`).join('; ') || '—'}<br>
      Sólo en B: ${d.edges_only_b.map((x) => `${esc(x.source)} → ${esc(x.target)}`).join('; ') || '—'}<br>
      Distinto acceso/puerto: ${d.edges_changed.map((x) => `${esc(x.source)} → ${esc(x.target)} (${esc(x.a || '—')}${x.port_a ? ':' + esc(x.port_a) : ''} vs ${esc(x.b || '—')}${x.port_b ? ':' + esc(x.port_b) : ''})`).join('; ') || '—'}</p>`;
  };
  const runSafe = () => run().catch((e) => { $('#cmpOut').innerHTML = `<p style="color:var(--danger)">${esc(e.message)}</p>`; });
  $('#cmpOther').onchange = runSafe;
  await runSafe();
}

async function restoreBackup(id) {
  if (!confirm('¿Restaurar este respaldo? La versión actual quedará también respaldada.')) return;
  await api('POST', `/api/projects/${P().id}/backups/${id}/restore`);
  closeModal(); await openProject(P().id); toast('Respaldo restaurado');
}

/* ───────────────────────── Inicio ───────────────────────── */
function bind() {
  const c = svg();
  c.addEventListener('pointerdown', onPointerDown);
  window.addEventListener('pointermove', onPointerMove);
  window.addEventListener('pointerup', onPointerUp);
  c.addEventListener('wheel', onWheel, { passive: false });
  c.addEventListener('dblclick', (ev) => {
    const nd = ev.target.closest('[data-node]');
    if (nd) { select('node', nd.dataset.node, 'general'); const i = $('[data-bind="label"]'); if (i) { i.focus(); i.select(); } }
  });

  $('#paletteSearch').addEventListener('input', renderPalette);
  $('#btnIcons').onclick = (ev) => installIcons(ev.currentTarget);
  $('#paletteList').addEventListener('dragstart', (ev) => {
    const it = ev.target.closest('.pal-item'); if (!it) return;
    ev.dataTransfer.setData('text/plain', 'infratrack:' + it.dataset.type); ev.dataTransfer.effectAllowed = 'copy';
  });
  $('#paletteList').addEventListener('click', (ev) => {
    const it = ev.target.closest('.pal-item'); if (!it) return;
    const r = svg().getBoundingClientRect();
    addNode(it.dataset.type, toWorld(r.left + r.width / 2, r.top + r.height / 2));
  });
  const wrap = $('#canvasWrap');
  wrap.addEventListener('dragover', (ev) => { ev.preventDefault(); ev.dataTransfer.dropEffect = 'copy'; });
  wrap.addEventListener('drop', (ev) => {
    ev.preventDefault();
    const d = ev.dataTransfer.getData('text/plain');
    if (d && d.startsWith('infratrack:')) addNode(d.slice(11), toWorld(ev.clientX, ev.clientY));
  });

  $('#btnUndo').onclick = undo; $('#btnRedo').onclick = redo;
  $('#btnZoomIn').onclick = () => zoomAt(1.2); $('#btnZoomOut').onclick = () => zoomAt(1 / 1.2); $('#btnFit').onclick = fitView;
  $('#tglPending').onchange = (e) => { S.highlightPending = e.target.checked; renderCanvas(); };
  $('#tglFindings').onchange = (e) => { S.showFindings = e.target.checked; renderCanvas(); };
  $('#envFilter').onchange = (e) => { S.envFilter = e.target.value; renderCanvas(); };
  $('#flowFilter').onchange = (e) => { S.flowFilter = e.target.value; renderCanvas(); };
  $('#statusbar').addEventListener('click', (ev) => {
    const ch = ev.target.closest('.chip'); if (!ch) return;
    if (ch.dataset.sev) { S.sevFilter = new Set([ch.dataset.sev]); openCopilot('findings'); } else openCopilot(ch.dataset.mtab);
  });

  const ins = $('#inspector');
  ins.addEventListener('focusin', onInspectorFocus);
  ins.addEventListener('focusout', () => { S.focusEl = null; });
  ins.addEventListener('input', onInspectorInput);
  ins.addEventListener('change', onInspectorInput);
  ins.addEventListener('click', onInspectorClick);

  $('#projectSelect').onchange = (e) => openProject(e.target.value);
  $('#btnNew').onclick = () => newProject(false);
  $('#btnMenu').onclick = (ev) => { ev.stopPropagation(); $('#menu').classList.toggle('hidden'); };
  document.addEventListener('click', (ev) => { if (!ev.target.closest('.menu-wrap')) $('#menu').classList.add('hidden'); });
  $('#menu').addEventListener('click', (ev) => { const b = ev.target.closest('[data-act]'); if (b) onMenu(b.dataset.act); });
  $('#btnCopilot').onclick = () => { S.sevFilter = new Set(SEVS); openCopilot(); };
  S.mtab = 'security';
  $('#modalClose').onclick = closeModal;
  $('#modal').addEventListener('click', (ev) => { if (ev.target.id === 'modal') closeModal(); });
  $('#modalBody').addEventListener('click', onModalClick);
  $('#modalBody').addEventListener('change', onModalChange);
  $('#btnReload').onclick = () => { $('#conflict').classList.add('hidden'); openProject(P().id); };
  $('#btnForce').onclick = () => save(true);
  $('#fileImport').onchange = async (ev) => {
    const f = ev.target.files[0]; if (!f) return;
    try { const data = JSON.parse(await f.text()); const p = await api('POST', '/api/import', data); await loadProjects(p.id); toast('Proyecto importado'); }
    catch (e) { toast('No se pudo importar: ' + e.message, 5000); }
    ev.target.value = '';
  };

  document.addEventListener('keydown', (ev) => {
    const typing = ev.target.closest('input, textarea, select, [contenteditable]');
    if (ev.key === 'Escape') { if (S.modal) closeModal(); else if (!typing) select(null); return; }
    if (typing) return;
    const mod = ev.ctrlKey || ev.metaKey;
    if (mod && ev.key.toLowerCase() === 'z') { ev.preventDefault(); ev.shiftKey ? redo() : undo(); }
    else if (mod && ev.key.toLowerCase() === 'y') { ev.preventDefault(); redo(); }
    else if (mod && ev.key.toLowerCase() === 'd') { ev.preventDefault(); if (S.sel && S.sel.kind === 'node') duplicateNode(nodeById(S.sel.id)); }
    else if ((ev.key === 'Delete' || ev.key === 'Backspace') && S.sel && !S.modal) { ev.preventDefault(); deleteSelection(); }
  });
  window.addEventListener('beforeunload', (ev) => { if (S.saveT || S.saving) { save(); ev.preventDefault(); ev.returnValue = ''; } });
  window.addEventListener('resize', () => applyView());
}

async function init() {
  bind();
  S.catalog = await api('GET', '/api/catalog');
  S.catalog.components.forEach((c) => { S.comp[c.id] = c; });
  S.catalog.categories.forEach((c) => { S.cats[c.id] = c; });
  await loadIcons();
  renderPalette();
  api('GET', '/api/ai/status').then((s) => { S.ai = s; }).catch(() => {});
  await loadProjects();
}

init().catch((e) => { console.error(e); toast('Error al iniciar: ' + e.message, 8000); });
