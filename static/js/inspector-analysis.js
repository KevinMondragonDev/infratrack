/* InfraTrack — inspector-analysis */
import { $, ACCESS_SHORT, S, SEVS, SEV_LABEL, STATUSES, SUBNET_STYLE, esc } from './core.js';
import { codeBlock, findingHtml, nodeFindings, sgSuggestionsHtml } from './inspector-common.js';
import { planHtml } from './inspector-edge.js';
import { P, compOf, labelOf, nodeById } from './model.js';

export function refreshInspectorAnalysis() {
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

export function roleSlug(n) {
  const pre = (P().settings || {}).prefix;
  const base = (labelOf(n) || 'recurso').normalize('NFKD').replace(/[̀-ͯ]/g, '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'recurso';
  const cfg = n.config || {};
  const explicit = cfg.bucket_name || cfg.table_name || cfg.role_name || cfg.workgroup;
  if (explicit) return explicit;
  return pre ? `${pre}-${base}` : base;
}

export function sgTable(g) {
  const rows = [...g.ingress.map((r) => ({ ...r, d: 'entrada' })), ...g.egress.map((r) => ({ ...r, d: 'salida' }))];
  return `<table class="tbl"><tr><th>Dir.</th><th>Puerto</th><th>Origen/destino</th><th>Descripción</th></tr>
    ${rows.map((r) => `<tr><td>${r.d}</td><td>${esc(r.protocol)}/${esc(r.port)}</td><td><code>${esc(r.peer)}</code></td><td>${esc(r.description)}</td></tr>`).join('')}</table>`;
}

export function projectStatsHtml() {
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
