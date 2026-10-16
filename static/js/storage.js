/* InfraTrack — storage */
import { api, copy } from './api.js';
import { $, lsGet, uid } from './core.js';
import { save } from './persistence.js';

/* ───────────────────────── Almacenamiento ─────────────────────────
   server: proyectos en archivos JSON del servidor (uso interno, `python3 app.py`).
   browser: demo pública (p. ej. en Vercel); cada visitante guarda sus proyectos en su navegador. */
export function download(filename, text, type) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = document.createElement('a'); a.href = url; a.download = filename; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
export const fileSafe = (s) => String(s || 'proyecto').replace(/[^\w\-. áéíóúñÁÉÍÓÚÑ]+/g, '_');

export const serverStore = {
  list: () => api('GET', '/api/projects'),
  get: (id) => api('GET', `/api/projects/${id}`),
  create: (name, sample) => api('POST', '/api/projects', { name, sample }),
  save: (p, force) => api('PUT', `/api/projects/${p.id}`, force ? { ...p, _force: true } : p),
  remove: (id) => api('DELETE', `/api/projects/${id}`),
  duplicate: (id, body) => api('POST', `/api/projects/${id}/duplicate`, body),
  importProject: (data) => api('POST', '/api/import', data),
  compare: (a, b) => api('GET', `/api/compare/${a}/${b}`),
  backups: (id) => api('GET', `/api/projects/${id}/backups`),
  restore: (id, bid) => api('POST', `/api/projects/${id}/backups/${bid}/restore`),
  async download(p, kind) {
    const a = document.createElement('a'); a.href = `/api/projects/${p.id}/export.${kind}`; a.download = ''; a.click();
  },
};

export const LS_PROJECTS = 'it.projects.v1';
/* Normaliza un proyecto antes de guardarlo en el navegador: sólo los campos y tipos esperados. */
export const asText = (v, max = 20000) => (typeof v === 'string' ? v.slice(0, max) : '');
export const asList = (v) => (Array.isArray(v) ? v.filter((x) => x && typeof x === 'object' && !Array.isArray(x)) : []);
export const asObj = (v) => (v && typeof v === 'object' && !Array.isArray(v) ? v : {});
export function cleanProject(p) {
  const src = asObj(p);
  const id = /^[\w-]{1,64}$/.test(src.id) ? src.id : uid('p');
  return {
    id, name: asText(src.name, 200) || 'Proyecto', description: asText(src.description),
    created: asText(src.created, 40), updated: asText(src.updated, 40), rev: Number.isFinite(src.rev) ? src.rev : 0,
    settings: asObj(src.settings), dismissed: asObj(src.dismissed),
    nodes: asList(src.nodes).filter((n) => typeof n.id === 'string' && typeof n.type === 'string'),
    edges: asList(src.edges).filter((e) => typeof e.id === 'string' && typeof e.source === 'string' && typeof e.target === 'string'),
  };
}
export const browserStore = {
  _all() { return lsGet(LS_PROJECTS, {}) || {}; },
  _put(all) {
    const clean = Object.fromEntries(Object.values(all).map(cleanProject).map((p) => [p.id, p]));
    try { localStorage.setItem(LS_PROJECTS, JSON.stringify(clean)); }
    catch { throw new Error('El navegador no tiene espacio para guardar: exporta el proyecto a JSON.'); }
  },
  async list() {
    return Object.values(this._all()).map((p) => ({ id: p.id, name: p.name, updated: p.updated, nodes: p.nodes.length,
      terraformed: p.nodes.filter((n) => n.terraformed).length })).sort((a, b) => String(b.updated).localeCompare(String(a.updated)));
  },
  async get(id) {
    const p = this._all()[id];
    if (!p) { const e = new Error('Proyecto no encontrado'); e.status = 404; throw e; }
    return structuredClone(p);
  },
  async create(name, sample, template) {
    let base = {};
    if (template) base = structuredClone(template);
    else if (sample) base = await api('GET', '/api/sample');
    const now = new Date().toISOString();
    const p = { description: '', settings: { region: 'us-east-1', account_id: '', environment: 'dev', prefix: '' }, nodes: [], edges: [],
      dismissed: {}, ...base, id: uid('p'), name: name || base.name || 'Nuevo proyecto', created: now, updated: now, rev: 1 };
    const all = this._all(); all[p.id] = p; this._put(all);
    return p;
  },
  async save(p, force) {
    const all = this._all();
    const cur = all[p.id];
    if (cur && !force && p.rev !== undefined && cur.rev !== p.rev) { const e = new Error('Conflicto'); e.status = 409; throw e; }
    const saved = { ...structuredClone(p), rev: (cur?.rev || 0) + 1, updated: new Date().toISOString() };
    all[p.id] = saved; this._put(all);
    return { rev: saved.rev, updated: saved.updated };
  },
  async remove(id) { const all = this._all(); delete all[id]; this._put(all); },
  async duplicate(id, body = {}) {
    const p = await this.get(id);
    if (body.environment) {
      const copy = await api('POST', '/api/duplicate-env', { project: p, environment: body.environment, account_map: body.account_map || {} });
      return this.create(copy.name, false, copy);
    }
    return this.create(`${p.name} (copia)`, false, p);
  },
  importProject(data) { return this.create(data.name || 'Importado', false, data); },
  async compare(a, b) { return api('POST', '/api/compare-projects', { a: await this.get(a), b: await this.get(b) }); },
  async backups() { return []; },
  async restore() { throw new Error('No disponible en la demo'); },
  async download(p, kind) {
    if (kind === 'json') { download(`${fileSafe(p.name)}.infratrack.json`, JSON.stringify(p, null, 2), 'application/json'); return; }
    const r = await api('POST', '/api/export-md', p);
    const md = new TextDecoder().decode(Uint8Array.from(atob(r.markdown_b64), (ch) => ch.charCodeAt(0)));
    download(`${fileSafe(p.name)}.md`, md, 'text/markdown');
  },
};
export let store = serverStore;
export function useBrowserStore() { store = browserStore; }
