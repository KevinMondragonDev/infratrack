/* InfraTrack — inspector-node */
import { $, S, STATUSES, esc, fmtDate, trunc } from './core.js';
import { catalogTabHtml } from './glue-catalog.js';
import { badgeHtml } from './icons.js';
import { refreshInspectorAnalysis } from './inspector-analysis.js';
import { fieldHtml, nodeFindings, sgSuggestionsHtml } from './inspector-common.js';
import { center, compOf, configProgress, labelOf, showIf } from './model.js';

export function renderNodeInspector(el, n) {
  const comp = compOf(n);
  const prog = configProgress(n);
  const openQ = (n.questions || []).filter((q) => q.status !== 'closed').length;
  const nf = nodeFindings(n.id).filter((f) => !f.dismissed).length;
  const tabs = [['general', 'General'], ['config', `Configuración <span class="cnt">${prog.pct}%</span>`],
    ['notes', `Notas <span class="cnt">${(n.notes || []).length}</span>`], ['architect', `Arquitecto <span class="cnt">${openQ}</span>`],
    ['copilot', `Copilot <span class="cnt">${nf}</span>`]];
  if (n.type === 'glue_catalog') {
    const nt = (n.config?.catalog?.databases || []).reduce((acc, d) => acc + (d.tables || []).length, 0);
    tabs.splice(2, 0, ['catalog', `Catálogo <span class="cnt">${nt}</span>`]);
  }
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
  } else if (S.tab === 'catalog') {
    body.innerHTML = catalogTabHtml(n);
  } else if (S.tab === 'copilot') {
    body.innerHTML = `<div id="insCopilot"></div>`;
    refreshInspectorAnalysis();
  }
}
