/* InfraTrack — projects */
import { renderCanvas } from './canvas.js';
import { $, S, esc, lsGet, lsSet } from './core.js';
import { renderInspector } from './inspector-common.js';
import { P, updateUndoButtons } from './model.js';
import { analyzeNow, flushSave, setSaveStatus } from './persistence.js';
import { updateProgress } from './statusbar.js';
import { store } from './storage.js';
import { applyView, fitView } from './view.js';

/* ───────────────────────── Proyectos ───────────────────────── */
export async function loadProjects(selectId) {
  S.projects = await store.list();
  const sel = $('#projectSelect');
  sel.innerHTML = S.projects.map((p) => `<option value="${p.id}">${esc(p.name)} (${p.terraformed}/${p.nodes})</option>`).join('');
  const id = selectId || lsGet('it.lastProject', null);
  const target = S.projects.find((p) => p.id === id) || S.projects[0];
  if (target) await openProject(target.id);
}

export async function openProject(id) {
  if (P() && P().id !== id) await flushSave();
  const p = await store.get(id);
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
  await analyzeNow();
}

export async function newProject(sample = false) {
  const name = sample ? null : prompt('Nombre del proyecto', 'Nueva arquitectura');
  if (!sample && name === null) return;
  await flushSave();
  const p = await store.create(name, sample);
  await loadProjects(p.id);
}
