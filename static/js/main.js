/* InfraTrack — main */
import { api, toast } from './api.js';
import { renderCanvas } from './canvas.js';
import { closeModal, onModalChange, onModalClick, openCopilot } from './copilot-modal.js';
import { $, S, SEVS } from './core.js';
import { catOf, catTableBody } from './glue-catalog.js';
import { installIcons, loadIcons } from './icons.js';
import { onInspectorClick, onInspectorFocus, onInspectorInput } from './inspector-events.js';
import { deleteSelection, duplicateNode, onPointerDown, onPointerMove, onPointerUp, onWheel, select, toggleTerraformed } from './interaction.js';
import { onMenu } from './menu.js';
import { P, changed, edgeById, nodeById, redo, undo } from './model.js';
import { addNode, renderPalette } from './palette.js';
import { save } from './persistence.js';
import { loadProjects, newProject, openProject } from './projects.js';
import { store, useBrowserStore } from './storage.js';
import { applyView, fitView, svg, toWorld, zoomAt } from './view.js';

/* ───────────────────────── Inicio ───────────────────────── */
export function bind() {
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
  // Las tablas del catálogo se dibujan al abrirlas (catálogos con miles de tablas)
  ins.addEventListener('toggle', (ev) => {
    const d = ev.target;
    if (!d.matches?.('details.cat-tb')) return;
    const key = `${d.dataset.di}:${d.dataset.ti}`;
    if (!d.open) { S.catOpen?.delete(key); return; }
    S.catOpen.add(key);
    const body = d.querySelector('.cat-tb-body');
    const n = nodeById(S.sel.id);
    const t = catOf(n).databases[Number(d.dataset.di)]?.tables[Number(d.dataset.ti)];
    if (body && t && !body.innerHTML) body.innerHTML = catTableBody(t, Number(d.dataset.di), Number(d.dataset.ti));
  }, true);

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
    try { const data = JSON.parse(await f.text()); const p = await store.importProject(data); await loadProjects(p.id); toast('Proyecto importado'); }
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

export async function init() {
  bind();
  S.catalog = await api('GET', '/api/catalog');
  S.catalog.components.forEach((c) => { S.comp[c.id] = c; });
  S.catalog.categories.forEach((c) => { S.cats[c.id] = c; });
  try {
    const cfg = await api('GET', '/api/config');
    S.demo = cfg.storage === 'browser';
  } catch { S.demo = false; }
  if (S.demo) {
    useBrowserStore();
    $('#demoBanner').classList.remove('hidden');
    if (!(await store.list()).length) await store.create(null, true);
  }
  await loadIcons();
  renderPalette();
  api('GET', '/api/ai/status').then((s) => { S.ai = s; }).catch(() => {});
  await loadProjects();
}

// Acceso de depuración (pruebas de interfaz y consola del navegador)
window.InfraTrack = { S, P, nodeById, edgeById, select, addNode, changed, openCopilot, toggleTerraformed };

init().catch((e) => { console.error(e); toast('Error al iniciar: ' + e.message, 8000); });
