/* InfraTrack — menu */
import { toast } from './api.js';
import { closeModal, openModal } from './copilot-modal.js';
import { $, S, esc } from './core.js';
import { select } from './interaction.js';
import { P, labelOf } from './model.js';
import { flushSave } from './persistence.js';
import { loadProjects, newProject, openProject } from './projects.js';
import { store } from './storage.js';

/* ───────────────────────── Menú de proyecto ───────────────────────── */
export async function onMenu(act) {
  $('#menu').classList.add('hidden');
  const p = P();
  if (act === 'dup-env') { await duplicateForEnvironment(); return; }
  if (act === 'compare') { await openCompare(); return; }
  if (act === 'duplicate') { await flushSave(); const c = await store.duplicate(p.id); await loadProjects(c.id); toast('Proyecto duplicado'); }
  else if (act === 'delete') {
    if (!confirm(`¿Eliminar “${p.name}”? Se moverá a data/trash.`)) return;
    await store.remove(p.id); S.project = null;
    const rest = await store.list();
    if (!rest.length) await store.create('Nuevo proyecto', true);
    await loadProjects();
  } else if (act === 'export-md' || act === 'export-json') {
    await flushSave();
    await store.download(p, act === 'export-md' ? 'md' : 'json');
  } else if (act === 'import') $('#fileImport').click();
  else if (act === 'sample') newProject(true);
  else if (act === 'backups') {
    await flushSave();
    const list = await store.backups(p.id);
    openModal('backups', 'Respaldos automáticos');
    $('#modalBody').innerHTML = `<div class="mcontent"><p class="muted">Se guarda una copia como máximo cada 5 minutos mientras editas (últimas 50).</p>
      ${S.demo ? '<p><b>En la demo</b> los proyectos viven sólo en este navegador: usa “Exportar JSON” para respaldarlos.</p>' : ''}
      ${list.length ? `<table class="tbl"><tr><th>Fecha</th><th>Tamaño</th><th></th></tr>${list.map((b) => `<tr><td>${esc(b.id.replace(/(\d{4})(\d{2})(\d{2})-(\d{2})(\d{2})(\d{2})/, '$1-$2-$3 $4:$5:$6'))}</td>
        <td>${Math.round(b.size / 1024)} KB</td><td><button class="btn sm" data-restore="${b.id}">Restaurar</button></td></tr>`).join('')}</table>` : '<p>Aún no hay respaldos.</p>'}</div>`;
  }
}
export async function duplicateForEnvironment() {
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
    const c = await store.duplicate(P().id, { environment: env.trim(), account_map: map });
    await loadProjects(c.id); toast(`Creado ${c.name}: la línea base de las cuentas quedó “Sin confirmar”`, 5000);
  } catch (e) { toast(e.message, 6000); }
}

export async function openCompare() {
  await flushSave();
  const others = S.projects.filter((p) => p.id !== P().id);
  openModal('compare', 'Comparar ambientes');
  if (!others.length) { $('#modalBody').innerHTML = '<div class="mcontent"><p>No hay otro proyecto para comparar. Usa “Duplicar como otro ambiente”.</p></div>'; return; }
  $('#modalBody').innerHTML = `<div class="mcontent"><div class="filters">Comparar <b>${esc(P().name)}</b> con
    <select id="cmpOther" class="btn sm">${others.map((p) => `<option value="${p.id}">${esc(p.name)}</option>`).join('')}</select></div><div id="cmpOut"></div></div>`;
  const run = async () => {
    const d = await store.compare(P().id, $('#cmpOther').value);
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

export async function restoreBackup(id) {
  if (!confirm('¿Restaurar este respaldo? La versión actual quedará también respaldada.')) return;
  await store.restore(P().id, id);
  closeModal(); await openProject(P().id); toast('Respaldo restaurado');
}
