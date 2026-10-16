/* InfraTrack — copilot-modal */
import { onTfChange, onTfClick } from './tf-import.js';
import { filterRules, onRulesChange, onRulesClick, rulesTabHtml } from './rules-tab.js';
import { api, copy, reportError } from './api.js';
import { $, ACCESS_SHORT, S, SEVS, SEV_LABEL, esc } from './core.js';
import { sgTable } from './inspector-analysis.js';
import { codeBlock, findingHtml } from './inspector-common.js';
import { dismissFinding, undismissFinding } from './inspector-events.js';
import { select, toggleTerraformed } from './interaction.js';
import { restoreBackup } from './menu.js';
import { P, center, changed, compOf, configProgress, edgeById, labelOf, nodeById, snapshot } from './model.js';
import { centerOn } from './view.js';

/* ───────────────────────── Modal Copilot ───────────────────────── */
export function openModal(kind, title) {
  S.modal = kind; $('#modalTitle').textContent = title; $('#modal').classList.remove('hidden');
}
export function closeModal() { S.modal = null; $('#modal').classList.add('hidden'); $('#modalBody').innerHTML = ''; }

export function openCopilot(tab) {
  if (tab) S.mtab = tab;
  openModal('copilot', 'Copilot de arquitectura AWS');
  renderCopilotTab();
}

export function renderCopilotTab() {
  const A = S.analysis;
  const tabs = [['security', 'Seguridad'], ['findings', 'Hallazgos'], ['iam', 'Roles IAM'], ['sg', 'Security Groups'], ['questions', 'Preguntas al arquitecto'],
    ['pending', 'Pendientes de terraform'], ['tags', 'Tags y Terraform'], ['rules', 'Reglas'], ['ai', 'Copilot IA']];
  let c = '';
  if (!A) c = '<p class="muted">Analizando…</p>';
  else if (S.mtab === 'security') c = securityHtml(A);
  else if (S.mtab === 'tags') c = tagsHtml(A);
  else if (S.mtab === 'rules') c = rulesTabHtml(A);
  else if (S.mtab === 'findings') {
    const cats = [...new Set(A.findings.map((f) => f.category))].sort((a, b) => a.localeCompare(b));
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
  const scroll = $('#modalBody').scrollTop;
  const search = $('#rulesSearch')?.value;
  $('#modalBody').innerHTML = `<div class="mtabs">${tabs.map(([k, l]) => `<button class="tab ${S.mtab === k ? 'on' : ''}" data-mtabbtn="${k}">${l}</button>`).join('')}</div><div class="mcontent">${c}</div>`;
  $('#modalBody').scrollTop = scroll;
  if (search && $('#rulesSearch')) { $('#rulesSearch').value = search; filterRules(); }
}

export function tagsHtml(A) {
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

export const CTRL_STATUS = {
  pass: ['✔', 'Cumple', 'ok'], fail: ['✖', 'Falla', 'bad'], accepted: ['≈', 'Riesgo aceptado', 'acc'],
  unknown: ['?', 'Sin evaluar', 'unk'], na: ['—', 'No aplica', 'na'],
};
export function securityHtml(A) {
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

export function onModalClick(ev) {
  const tf = ev.target.closest('[data-tf]');
  if (tf) { onTfClick(tf); return; }
  const r = ev.target.closest('[data-rules]');
  if (r) { onRulesClick(r).catch(reportError); return; }
  const t = ev.target.closest('[data-mtabbtn],[data-sevtoggle],[data-copy],[data-goto],[data-seledge],[data-dismiss],[data-undismiss],[data-ai],[data-restore]');
  if (!t) return;
  if (t.dataset.mtabbtn) { S.mtab = t.dataset.mtabbtn; renderCopilotTab(); return; }
  if (t.dataset.sevtoggle) { const k = t.dataset.sevtoggle; S.sevFilter.has(k) ? S.sevFilter.delete(k) : S.sevFilter.add(k); renderCopilotTab(); return; }
  if (t.dataset.copy !== undefined) { copy(t.dataset.copy).catch(reportError); return; }
  if (t.dataset.goto) { const n = nodeById(t.dataset.goto); closeModal(); if (n) { select('node', n.id, t.dataset.gotab || 'copilot'); centerOn(n); } return; }
  if (t.dataset.seledge) { closeModal(); select('edge', t.dataset.seledge); return; }
  if (t.dataset.dismiss) { dismissFinding(t.dataset.dismiss); return; }
  if (t.dataset.undismiss) { undismissFinding(t.dataset.undismiss); return; }
  if (t.dataset.ai) { const q = t.dataset.ai === 'ask' ? $('#aiQuestion').value.trim() : null; if (t.dataset.ai === 'ask' && !q) return; askAI(q, null, $('#aiOut')).catch(reportError); return; }
  if (t.dataset.restore) { restoreBackup(t.dataset.restore).catch(reportError); }
}
export function onModalChange(ev) {
  const t = ev.target;
  if (onRulesChange(t) || onTfChange(t)) return;
  if (t.id === 'catFilter') { S.catFilter = t.value; renderCopilotTab(); }
  if (t.id === 'showDismissed') { S.showDismissed = t.checked; renderCopilotTab(); }
  if (t.id === 'secShowNa') { S.secShowNa = t.checked; renderCopilotTab(); }
  if (t.dataset.tfnode) { const n = nodeById(t.dataset.tfnode); toggleTerraformed(n); setTimeout(renderCopilotTab, 50); }
  if (t.dataset.tfedge) { snapshot(); edgeById(t.dataset.tfedge).terraformed = true; changed(); setTimeout(renderCopilotTab, 50); }
}

export function mdToHtml(md) {
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

export async function askAI(question, nodeId, outEl) {
  if (!outEl) return;
  outEl.innerHTML = '<p class="muted">Pensando… (puede tardar un minuto)</p>';
  try {
    const r = await api('POST', '/api/ai/ask', { project: P(), question, node_id: nodeId });
    outEl.innerHTML = mdToHtml(r.answer);
  } catch (e) { outEl.innerHTML = `<p style="color:var(--danger)">${esc(e.message)}</p>`; }
}

export function onModalInput(ev) {
  if (ev.target.id === 'rulesSearch') filterRules();
}

