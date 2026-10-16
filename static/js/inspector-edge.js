/* InfraTrack — inspector-edge */
import { flowColor, flows } from './canvas.js';
import { $, ACCESS, ASSOC_TYPES, esc, isAssoc } from './core.js';
import { refreshInspectorAnalysis } from './inspector-analysis.js';
import { codeBlock, fieldHtml, findingHtml } from './inspector-common.js';
import { select } from './interaction.js';
import { labelOf, nodeById } from './model.js';

export function renderEdgeInspector(el, e) {
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

export function planHtml(plan, findings) {
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
