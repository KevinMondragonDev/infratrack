/* InfraTrack — core */
import { nodeById, redo, undo } from './model.js';

/* InfraTrack — frontend sin dependencias. */

export const $ = (s, el = document) => el.querySelector(s);
export const $$ = (s, el = document) => [...el.querySelectorAll(s)];
export const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
export const uid = (p = 'n') => p + Date.now().toString(36).slice(-4) + Math.random().toString(36).slice(2, 7);
export const nowIso = () => new Date().toISOString();
export const trunc = (s, n) => (s && s.length > n ? s.slice(0, n - 1) + '…' : s || '');
export const snap = (v, g = 10) => Math.round(v / g) * g;
export const fmtDate = (s) => { if (!s) return ''; const d = new Date(s); return isNaN(d) ? s : d.toLocaleString('es', { dateStyle: 'short', timeStyle: 'short' }); };
export const lsGet = (k, d) => { try { const v = localStorage.getItem(k); return v === null ? d : JSON.parse(v); } catch { return d; } };
export const lsSet = (k, v) => { try { localStorage.setItem(k, JSON.stringify(v)); } catch { /* sin almacenamiento */ } };

export const SEVS = ['critical', 'high', 'medium', 'low', 'info'];
export const SEV_LABEL = { critical: 'Crítico', high: 'Alto', medium: 'Medio', low: 'Bajo', info: 'Info' };
export const STATUSES = ['Borrador', 'En revisión', 'Aprobado', 'Requiere cambios', 'Pendiente de definición', 'Descartado'];
export const NAMED_COLORS = { Naranja: '#ED7100', Azul: '#0972D3', Verde: '#3F8624', Morado: '#8C4FFF', Rojo: '#D13212',
  Gris: '#7D8998', Rosa: '#E7157B', Turquesa: '#01A88D', Amarillo: '#C99700' };
export const COLOR_NAMES = Object.keys(NAMED_COLORS);
export const ACCESS = [['read', 'Lectura'], ['write', 'Escritura'], ['readwrite', 'Lectura y escritura'], ['invoke', 'Invocación / llamada'], ['network', 'Tráfico de red (puerto)']];
export const ACCESS_SHORT = { read: 'lee', write: 'escribe', readwrite: 'lee/escribe', invoke: 'invoca', network: 'red' };
export const ASSOC_TYPES = new Set(['sg', 'iam_role']);
export const isAssocPair = (a, b) => !!(a && b && (ASSOC_TYPES.has(a.type) || ASSOC_TYPES.has(b.type)
  || (a.type === 'vpce' && b.type === 'subnet') || (a.type === 'subnet' && b.type === 'vpce')));
export const isAssoc = (e) => isAssocPair(nodeById(e.source), nodeById(e.target));
export const ENV_COLOR = { prod: '#D13212', staging: '#0972D3', qa: '#0972D3', dev: '#0972D3', sandbox: '#7D8998' };
export const CONTAINER_PREFIX = { vpc: 'VPC · ', account: 'Cuenta · ', zone: 'Zona · ' };
export const SUBNET_STYLE = {
  public: { stroke: '#3F8624', fill: 'rgba(63,134,36,.07)', name: 'Pública' },
  private: { stroke: '#147EBA', fill: 'rgba(20,126,186,.07)', name: 'Privada' },
  isolated: { stroke: '#687078', fill: 'rgba(104,112,120,.08)', name: 'Aislada' },
};

export const S = {
  catalog: null, comp: {}, cats: {},
  projects: [], project: null, analysis: null,
  sel: null, tab: 'general', view: { x: 40, y: 40, k: 1 },
  undo: [], redo: [], drag: null, temp: null, hover: null,
  highlightPending: false, showFindings: true, envFilter: '', flowFilter: '',
  saving: false, saveAgain: false, saveT: null, anT: null, anSeq: 0,
  author: lsGet('it.author', ''), ai: { available: false }, icons: new Set(), iconsVersion: null,
  modal: null, mtab: 'findings', sevFilter: new Set(SEVS), showDismissed: false, catFilter: '',
};
