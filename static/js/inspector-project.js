/* InfraTrack — inspector-project */
import { flows } from './canvas.js';
import { $, COLOR_NAMES, S, esc, fmtDate } from './core.js';
import { projectStatsHtml } from './inspector-analysis.js';
import { fieldHtml } from './inspector-common.js';
import { select } from './interaction.js';
import { P } from './model.js';

/* Editor de listas del proyecto (flujos, tags). */
export function listEditor(kind, rows, cols) {
  return `<div class="rules"><div class="rhead" style="grid-template-columns:${cols.map(() => '1fr').join(' ')} 26px">${cols.map((c) => `<span>${esc(c.label)}</span>`).join('')}<span></span></div>
    ${rows.map((r, i) => `<div class="rline" style="grid-template-columns:${cols.map(() => '1fr').join(' ')} 26px">${cols.map((c) => (c.options
      ? `<select data-plist="${kind}" data-row="${i}" data-col="${c.key}">${c.options.map((o) => `<option ${o === r[c.key] ? 'selected' : ''}>${esc(o)}</option>`).join('')}</select>`
      : `<input type="text" data-plist="${kind}" data-row="${i}" data-col="${c.key}" value="${esc(r[c.key])}" placeholder="${esc(c.placeholder || '')}">`)).join('')}
      <button class="btn sm ghost" data-pdel="${kind}" data-row="${i}" title="Quitar">✕</button></div>`).join('') || '<div class="muted" style="padding:6px">Sin elementos.</div>'}
  </div><button class="btn sm" data-padd="${kind}" style="margin:6px 0 10px">+ Agregar</button>`;
}

export function renderProjectInspector(el) {
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
