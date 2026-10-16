/* InfraTrack — filters */
import { $, S, esc } from './core.js';
import { P, nodeById } from './model.js';

export function accountOf(n) {
  const parents = S.analysis ? S.analysis.parents : {};
  let id = n.type === 'account' ? n.id : parents[n.id];
  while (id) { const p = nodeById(id); if (!p) return null; if (p.type === 'account') return p; id = parents[id]; }
  return null;
}
export function envDim(n) {
  if (!S.envFilter) return false;
  const a = accountOf(n);
  return !a || ((a.config || {}).environment || '') !== S.envFilter;
}
export function renderEnvFilter() {
  const sel = $('#envFilter');
  const envs = [...new Set(P().nodes.filter((n) => n.type === 'account').map((n) => (n.config || {}).environment).filter(Boolean))].sort();
  if (S.envFilter && !envs.includes(S.envFilter)) S.envFilter = '';
  sel.innerHTML = `<option value="">Todos los ambientes</option>${envs.map((e) => `<option ${e === S.envFilter ? 'selected' : ''}>${esc(e)}</option>`).join('')}`;
  sel.classList.toggle('hidden', !envs.length);
}
