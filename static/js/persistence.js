/* InfraTrack — persistence */
import { api, toast } from './api.js';
import { renderCanvas, renderFlowFilter } from './canvas.js';
import { renderCopilotTab } from './copilot-modal.js';
import { $, S } from './core.js';
import { renderEnvFilter } from './filters.js';
import { refreshInspectorAnalysis } from './inspector-analysis.js';
import { P } from './model.js';
import { renderStatusbar, updateCopilotBadge } from './statusbar.js';
import { store } from './storage.js';

/* ───────────────────────── Guardado y análisis ───────────────────────── */
export function setSaveStatus(t) { $('#saveStatus').textContent = t; }
export function scheduleSave() { setSaveStatus('Sin guardar…'); clearTimeout(S.saveT); S.saveT = setTimeout(() => save(), 700); }
export async function save(force = false) {
  if (!P()) return;
  clearTimeout(S.saveT); S.saveT = null;
  if (S.saving) { S.saveAgain = true; return; }
  S.saving = true; setSaveStatus('Guardando…');
  try {
    const body = { ...P() };
    const r = await store.save(body, force);
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
export async function flushSave() { if (S.saveT || S.saving) { await save(); while (S.saving) await new Promise((r) => setTimeout(r, 50)); } }

export function scheduleAnalyze() { clearTimeout(S.anT); S.anT = setTimeout(analyzeNow, 350); }
export async function analyzeNow() {
  if (!P()) return;
  const seq = ++S.anSeq;
  try {
    const a = await api('POST', '/api/analyze', P());
    if (seq !== S.anSeq) return;
    S.analysis = a;
  } catch (e) {
    console.error(e);
    // Reintenta si el análisis falló por red y nadie pidió uno más nuevo
    if (seq === S.anSeq) setTimeout(() => { if (seq === S.anSeq) analyzeNow(); }, 2000);
    return;
  }
  renderEnvFilter(); renderFlowFilter(); renderCanvas(); renderStatusbar(); refreshInspectorAnalysis(); updateCopilotBadge();
  if (S.modal === 'copilot' && S.mtab !== 'ai') renderCopilotTab();
}
