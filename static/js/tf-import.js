/* InfraTrack — tf-import: estado y plan de Terraform contra el diagrama */
import { api, reportError, toast } from './api.js';
import { $, S, esc, snap, uid, nowIso } from './core.js';
import { P, changed, snapshot } from './model.js';
import { closeModal, openModal } from './copilot-modal.js';
import { defaultSize } from './palette.js';

const ACTION = { create: ['+', 'crear', 'plan-create'], update: ['~', 'modificar', 'plan-update'],
  delete: ['−', 'destruir', 'plan-delete'], replace: ['±', 'reemplazar', 'plan-replace'] };

/* Insignia del plan en el lienzo (+ ~ − ±) */
export function planBadge(n) {
  const action = P().tf_plan?.changes?.[n.id];
  if (!action || S.hidePlan) return '';
  const [sym, label, cls] = ACTION[action] || [];
  return sym ? `<g class="plan-badge ${cls}" transform="translate(-8,-8)"><circle r="9"/><text y="4">${sym}</text><title>Plan de Terraform: ${label}</title></g>` : '';
}

export function openTfImport() {
  openModal('tf', 'Importar estado o plan de Terraform');
  const plan = P().tf_plan;
  $('#modalBody').innerHTML = `<div class="mcontent">
    <p>Sube la salida de <code>terraform show -json</code> (estado), el archivo <code>terraform.tfstate</code>, o un plan:
      <code>terraform plan -out plan.tfplan</code> y luego <code>terraform show -json plan.tfplan &gt; plan.json</code>.</p>
    <p class="muted">Sólo se conservan nombres, direcciones, ARNs, CIDRs y tags; nunca contraseñas ni valores marcados como sensibles.
      ${S.demo ? 'En la demo el archivo se procesa sin guardarse en el servidor (máximo ~4 MB).' : ''}</p>
    <input type="file" id="tfFile" accept=".json,.tfstate,application/json">
    ${plan ? `<p style="margin-top:10px">Hay un plan cargado (${esc(plan.at?.slice(0, 16) || '')}).
      <button class="btn sm" data-tf="clear-plan">Quitar plan del diagrama</button></p>` : ''}
    <div id="tfOut"></div></div>`;
}

function rowsMatched(list) {
  return list.map((m, i) => `<tr><td><input type="checkbox" data-tfm="${i}" checked></td><td>${esc(m.label || '')}</td>
    <td><code>${esc(m.address)}</code></td><td class="muted">${esc(m.arn || '')}</td></tr>`).join('');
}

function stateHtml(r) {
  return `<p><b>${r.matched.length}</b> emparejados · <b>${r.only_tf.length}</b> sólo en Terraform · <b>${r.only_diagram.length}</b> sólo en el diagrama
      · ${r.total} recursos en el archivo</p>
    ${r.matched.length ? `<div class="section-title">Emparejados: marcar como terraformados y guardar dirección/ARN</div>
      <table class="tbl"><tr><th></th><th>Componente</th><th>Dirección</th><th>ARN</th></tr>${rowsMatched(r.matched)}</table>` : ''}
    ${r.only_tf.length ? `<div class="section-title">Sólo en Terraform: agregar al diagrama</div>
      <table class="tbl"><tr><th></th><th>Nombre</th><th>Tipo</th><th>Dirección</th></tr>
      ${r.only_tf.map((x, i) => `<tr><td><input type="checkbox" data-tfo="${i}"></td><td>${esc(x.name)}</td>
        <td>${esc(S.comp[x.component]?.name || x.component)}</td><td><code>${esc(x.address)}</code></td></tr>`).join('')}</table>` : ''}
    ${r.only_diagram.length ? `<div class="section-title">Sólo en el diagrama</div><p class="muted">${r.only_diagram.map((x) => esc(x.label)).join(', ')}</p>` : ''}
    ${r.unmapped_types.length ? `<p class="muted">Tipos sin componente en InfraTrack (no se dibujan): ${r.unmapped_types.map(esc).join(', ')}</p>` : ''}
    <button class="btn blue" data-tf="apply-state">Aplicar</button>`;
}

function planHtml(r) {
  const all = [...r.matched.map((m) => ({ ...m, label: m.label })), ...r.only_tf.map((x) => ({ ...x, label: '' }))];
  return `<p><b>${all.length}</b> cambios en el plan.</p>
    <table class="tbl"><tr><th>Acción</th><th>Componente</th><th>Dirección</th></tr>
    ${all.map((x) => { const a = ACTION[x.action] || ['?', x.action]; return `<tr><td><span class="plan-chip ${a[2] || ''}">${a[0]} ${esc(a[1])}</span></td>
      <td>${esc(x.label || '(no está en el diagrama)')}</td><td><code>${esc(x.address)}</code></td></tr>`; }).join('')}</table>
    <button class="btn blue" data-tf="apply-plan">Mostrar plan en el diagrama</button>`;
}

async function analyzeFile(file) {
  const text = await file.text();
  S.tfResult = await api('POST', '/api/tf/analyze', { project: P(), text });
  $('#tfOut').innerHTML = S.tfResult.kind === 'plan' ? planHtml(S.tfResult) : stateHtml(S.tfResult);
}

function addNodes(list) {
  const maxX = Math.max(0, ...P().nodes.map((n) => n.x + n.w));
  list.forEach((r, i) => {
    const size = defaultSize(r.component);
    P().nodes.push({ id: uid('n'), type: r.component, label: r.name, x: snap(maxX + 120 + (i % 5) * 190), y: snap(40 + Math.floor(i / 5) * 110),
      ...(['vpc', 'subnet', 'account', 'zone'].includes(r.component) ? { w: 300, h: 160 } : size),
      config: r.cidr ? { cidr: r.cidr } : {}, terraformed: true, terraformed_at: nowIso(), tf_address: r.address, arn: r.arn,
      status: 'Borrador', notes: [], questions: [] });
  });
}

function applyState() {
  const r = S.tfResult;
  snapshot();
  let marked = 0;
  r.matched.forEach((m, i) => {
    if (!$(`[data-tfm="${i}"]`)?.checked) return;
    const n = P().nodes.find((x) => x.id === m.node_id);
    if (!n) return;
    Object.assign(n, { terraformed: true, terraformed_at: n.terraformed_at || nowIso(), tf_address: m.address });
    if (m.arn) n.arn = m.arn;
    marked += 1;
  });
  const toAdd = r.only_tf.filter((_, i) => $(`[data-tfo="${i}"]`)?.checked);
  addNodes(toAdd);
  P().tf_import = { at: nowIso(), kind: 'state', only_tf: r.only_tf.filter((x) => !toAdd.includes(x)).slice(0, 500),
    only_diagram_ids: r.only_diagram.map((x) => x.node_id), matched: r.matched.length };
  changed({ inspector: true });
  closeModal();
  toast(`${marked} componentes marcados como terraformados · ${toAdd.length} agregados`);
}

function applyPlan() {
  const r = S.tfResult;
  snapshot();
  P().tf_plan = { at: nowIso(), changes: Object.fromEntries(r.matched.map((m) => [m.node_id, m.action])), unmatched: r.only_tf };
  S.hidePlan = false;
  changed({ inspector: true });
  closeModal();
  toast('Plan mostrado en el diagrama: + crear · ~ modificar · − destruir · ± reemplazar');
}

export function onTfChange(t) {
  if (t.id !== 'tfFile' || !t.files.length) return false;
  analyzeFile(t.files[0]).catch(reportError);
  return true;
}

export function onTfClick(t) {
  const act = t.dataset.tf;
  if (act === 'apply-state') applyState();
  else if (act === 'apply-plan') applyPlan();
  else if (act === 'clear-plan') { snapshot(); delete P().tf_plan; changed({ inspector: true }); closeModal(); }
}
