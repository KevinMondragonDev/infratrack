/* InfraTrack — inspector-events */
import { copy, reportError, toast } from './api.js';
import { renderFlowFilter } from './canvas.js';
import { askAI, openCopilot } from './copilot-modal.js';
import { $, $$, COLOR_NAMES, S, lsSet, nowIso, uid } from './core.js';
import { importCatalogFiles, onCatalogAction, onCatalogInput } from './glue-catalog.js';
import { renderInspector } from './inspector-common.js';
import { deleteSelection, duplicateNode, select, toggleTerraformed } from './interaction.js';
import { P, changed, compOf, edgeById, labelOf, nodeById, snapshot } from './model.js';
import { centerOn } from './view.js';

export function setPath(obj, key, val) { if (val === '' || val === null || val === undefined) delete obj[key]; else obj[key] = val; }
export function readInput(t) {
  if (t.type === 'checkbox') return t.checked;
  if (t.dataset.ftype === 'number' || t.type === 'number') return t.value === '' ? null : Number(t.value);
  return t.value;
}
export function onInspectorFocus(ev) {
  const t = ev.target;
  if (t.matches('[data-bind],[data-cfg],[data-ebind],[data-pbind],[data-sbind],[data-qanswer],[data-rcell],[data-plist],[data-cat]') && S.focusEl !== t) { S.focusEl = t; snapshot(); }
}
export function onInspectorInput(ev) {
  const t = ev.target;
  if (t.id === 'authorInput' || t.id === 'noteAuthor') { S.author = t.value; lsSet('it.author', S.author); return; }
  if (t.id === 'catFile') {
    if (ev.type === 'change' && t.files.length) {
      importCatalogFiles(nodeById(S.sel.id), [...t.files]).catch((e) => toast(`No se pudo importar: ${e.message}`, 8000));
    }
    return;
  }
  if (t.id === 'catReplace') return;
  if (t.id === 'catSearch') {
    const q = t.value.trim().toLowerCase();
    $$('#inspector details.cat-tb').forEach((x) => x.classList.toggle('hidden', !!q && !x.dataset.search.includes(q)));
    return;
  }
  const isChange = ev.type === 'change';
  if (t.type === 'checkbox' && !isChange) return;
  if (t.tagName === 'SELECT' && !isChange) return;
  if ((t.type === 'checkbox' || t.tagName === 'SELECT') && S.focusEl !== t) snapshot();
  let rerender = false;
  if (t.dataset.bind) {
    const n = nodeById(S.sel.id); setPath(n, t.dataset.bind, readInput(t));
    if (t.dataset.bind === 'label') { const h = $('.ins-head h3'); if (h) h.textContent = labelOf(n); }
  } else if (t.dataset.cfg) {
    const n = nodeById(S.sel.id); n.config = n.config || {};
    setPath(n.config, t.dataset.cfg, readInput(t));
    rerender = isChange && (t.type === 'checkbox' || t.tagName === 'SELECT');
  } else if (t.dataset.rcell) {
    const n = nodeById(S.sel.id); n.config = n.config || {};
    const rows = n.config[t.dataset.rcell] = n.config[t.dataset.rcell] || [];
    const row = rows[Number(t.dataset.row)];
    if (!row) return;
    let v = t.value;
    if (t.dataset.ctype === 'number') v = v === '' ? null : Number(v);
    if (v === '' || v === null) delete row[t.dataset.col]; else row[t.dataset.col] = v;
  } else if (t.dataset.ms) {
    const n = nodeById(S.sel.id); n.config = n.config || {};
    const set = new Set(n.config[t.dataset.ms] || []);
    if (t.checked) set.add(t.value); else set.delete(t.value);
    n.config[t.dataset.ms] = [...set];
    t.parentElement.classList.toggle('on', t.checked);
    rerender = true;
  } else if (t.dataset.ebind) {
    const e = edgeById(S.sel.id); setPath(e, t.dataset.ebind, readInput(t));
    if (t.dataset.ebind === 'access') t.closest('.field').classList.toggle('missing', !t.value);
  } else if (t.dataset.pbind) {
    setPath(P(), t.dataset.pbind, readInput(t));
    if (t.dataset.pbind === 'name') { const o = $(`#projectSelect option[value="${P().id}"]`); if (o) o.textContent = P().name; }
  } else if (t.dataset.plist) {
    P().settings = P().settings || {};
    const list = P().settings[t.dataset.plist] = P().settings[t.dataset.plist] || [];
    if (list[Number(t.dataset.row)]) list[Number(t.dataset.row)][t.dataset.col] = t.value;
    if (t.dataset.plist === 'flows') renderFlowFilter();
  } else if (t.dataset.eflow) {
    const e = edgeById(S.sel.id);
    const set = new Set(e.flows || []);
    if (t.checked) set.add(t.dataset.eflow); else set.delete(t.dataset.eflow);
    e.flows = [...set];
    t.parentElement.classList.toggle('on', t.checked);
  } else if (t.dataset.sbind === 'required_tags') {
    P().settings = P().settings || {};
    P().settings.required_tags = t.value.split(/[\n,]/).map((x) => x.trim()).filter(Boolean);
  } else if (t.dataset.sbind) {
    P().settings = P().settings || {}; setPath(P().settings, t.dataset.sbind, readInput(t));
  } else if (t.dataset.qanswer) {
    const q = nodeById(S.sel.id).questions.find((x) => x.id === t.dataset.qanswer);
    q.answer = t.value; q.answered_at = nowIso(); q.answered_by = S.author;
  } else if (t.dataset.cat) {
    if (t.type === 'checkbox' && !isChange) return;
    onCatalogInput(t, nodeById(S.sel.id));
  } else return;
  changed({ canvas: true });
  if (rerender) { const sc = $('#inspector').scrollTop; renderInspector(); $('#inspector').scrollTop = sc; }
}

export function onInspectorClick(ev) {
  const t = ev.target.closest('button, a, [data-act], .tfbox, [data-open-security]');
  if (!t) return;
  const n = S.sel && S.sel.kind === 'node' ? nodeById(S.sel.id) : null;
  const e = S.sel && S.sel.kind === 'edge' ? edgeById(S.sel.id) : null;
  if (t.dataset.tab) { S.tab = t.dataset.tab; renderInspector(); return; }
  if (t.dataset.openSecurity) { openCopilot('security'); return; }
  if (t.dataset.copy !== undefined) { copy(t.dataset.copy).catch(reportError); return; }
  if (t.dataset.goto) { const g = nodeById(t.dataset.goto); if (g) { select('node', g.id, 'general'); centerOn(g); } return; }
  if (t.dataset.seledge) { select('edge', t.dataset.seledge); return; }
  if (t.dataset.dismiss) { dismissFinding(t.dataset.dismiss); return; }
  if (t.dataset.undismiss) { undismissFinding(t.dataset.undismiss); return; }
  if (t.dataset.aifocus) { askAI(null, t.dataset.aifocus, $('#aiNodeOut')).catch(reportError); return; }
  if (t.dataset.catact) { onCatalogAction(t, n); return; }
  if (t.dataset.padd || t.dataset.pdel) {
    snapshot(); P().settings = P().settings || {};
    const kind = t.dataset.padd || t.dataset.pdel;
    const list = P().settings[kind] = P().settings[kind] || [];
    if (t.dataset.padd) list.push(kind === 'flows' ? { id: `FL-${String(list.length + 1).padStart(2, '0')}`, name: '', color: COLOR_NAMES[list.length % COLOR_NAMES.length] } : { key: '', value: '' });
    else list.splice(Number(t.dataset.row), 1);
    const sc = $('#inspector').scrollTop; changed({ inspector: true }); renderFlowFilter(); $('#inspector').scrollTop = sc; return;
  }
  if (t.dataset.addrow) {
    const f = compOf(n).fields.find((x) => x.key === t.dataset.addrow);
    snapshot(); n.config = n.config || {};
    const rows = n.config[f.key] = n.config[f.key] || [];
    const row = {};
    f.columns.forEach((c) => {
      if (c.key === 'rule_no') row.rule_no = (Math.max(0, ...rows.map((r) => Number(r.rule_no) || 0)) || 90) + 10;
      else if (c.key === 'direction') row.direction = 'ingress';
      else if (c.key === 'protocol') row.protocol = 'tcp';
      else if (c.key === 'action') row.action = 'allow';
      else if (c.key === 'target_type') row.target_type = 'nat';
    });
    rows.push(row);
    const sc = $('#inspector').scrollTop; changed({ inspector: true }); $('#inspector').scrollTop = sc; return;
  }
  if (t.dataset.delrow) {
    snapshot(); n.config[t.dataset.delrow].splice(Number(t.dataset.row), 1);
    const sc = $('#inspector').scrollTop; changed({ inspector: true }); $('#inspector').scrollTop = sc; return;
  }
  if (t.dataset.delnote) { snapshot(); n.notes = n.notes.filter((x) => x.id !== t.dataset.delnote); changed({ inspector: true }); return; }
  if (t.dataset.delq) { if (!confirm('¿Eliminar la pregunta?')) return; snapshot(); n.questions = n.questions.filter((x) => x.id !== t.dataset.delq); changed({ inspector: true }); return; }
  if (t.dataset.qtoggle) {
    snapshot(); const q = n.questions.find((x) => x.id === t.dataset.qtoggle);
    q.status = q.status === 'closed' ? 'open' : 'closed'; q.closed_at = q.status === 'closed' ? nowIso() : null;
    changed({ inspector: true }); return;
  }
  switch (t.dataset.act) {
    case 'tf':
      if (n) toggleTerraformed(n);
      else if (e) { snapshot(); e.terraformed = !e.terraformed; changed({ inspector: true }); }
      break;
    case 'del': deleteSelection(); break;
    case 'tagTemplate': {
      const tpl = S.analysis?.tags?.template || [];
      snapshot(); P().settings = P().settings || {};
      const cur = new Set(P().settings.required_tags || []);
      P().settings.required_tags = [...cur, ...tpl.filter((x) => !cur.has(x))];
      changed({ inspector: true }); break;
    }
    case 'applySg': {
      const sug = (S.analysis && S.analysis.sg_suggestions && S.analysis.sg_suggestions[n.id]) || [];
      if (!sug.length) return;
      snapshot(); n.config.rules = [...(n.config.rules || []), ...sug.map((r) => ({ ...r }))];
      S.tab = 'config'; changed({ inspector: true }); toast(`${sug.length} regla(s) agregadas al SG`); break;
    }
    case 'dup': if (n) duplicateNode(n); break;
    case 'flip': snapshot(); [e.source, e.target] = [e.target, e.source]; changed({ inspector: true }); break;
    case 'addNote': {
      const txt = $('#newNote').value.trim(); if (!txt) return;
      snapshot(); n.notes = n.notes || []; n.notes.push({ id: uid('note'), text: txt, author: S.author, at: nowIso() });
      changed({ inspector: true }); break;
    }
    case 'addQ': {
      const txt = $('#newQ').value.trim(); if (!txt) return;
      snapshot(); n.questions = n.questions || []; n.questions.push({ id: uid('q'), text: txt, author: S.author, at: nowIso(), status: 'open', answer: '' });
      changed({ inspector: true }); break;
    }
    default:
  }
}

export function dismissFinding(id) {
  const reason = prompt('¿Por qué se acepta este riesgo o no aplica? (queda registrado en el reporte)');
  if (!reason) return;
  snapshot();
  P().dismissed = P().dismissed || {};
  P().dismissed[id] = { reason, by: S.author || '', at: new Date().toISOString().slice(0, 10) };
  changed({ canvas: false });
}
export function undismissFinding(id) { snapshot(); delete P().dismissed[id]; changed({ canvas: false }); }
