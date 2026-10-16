/* InfraTrack — icons */
import { api, toast } from './api.js';
import { renderCanvas } from './canvas.js';
import { $, S, esc } from './core.js';
import { renderInspector } from './inspector-common.js';
import { renderPalette } from './palette.js';

/* Iconos oficiales de AWS (si se instalaron con --setup-icons) */
export function iconKey(type, cfg) {
  if (type === 'subnet') return cfg?.tier === 'public' ? 'subnet-public' : 'subnet-private';
  return type;
}
export function iconUrl(type, cfg) {
  const k = iconKey(type, cfg);
  // La clave viene del catálogo y la versión del servidor: ambas se codifican antes de usarse en HTML.
  if (!S.icons.has(k)) return null;
  return `/icons/aws/${encodeURIComponent(k)}.svg?v=${encodeURIComponent(S.iconsVersion || '')}`;
}
export function badgeHtml(c, cfg, cls = 'ab') {
  const url = iconUrl(c.id, cfg);
  return url ? `<img class="${cls} icon" src="${esc(url)}" alt="" draggable="false">`
    : `<span class="${cls}" style="background:${c.color}">${esc(c.abbr)}</span>`;
}
export async function loadIcons() {
  try {
    const r = await api('GET', '/api/icons');
    S.icons = new Set(r.available); S.iconsVersion = r.version; S.iconsOutdated = !!r.outdated;
  } catch { S.icons = new Set(); S.iconsOutdated = false; }
  const hint = $('#iconsHint');
  hint.classList.toggle('hidden', S.icons.size > 0 && !S.iconsOutdated);
  if (S.iconsOutdated) {
    hint.querySelector('span').textContent = 'Hay componentes nuevos sin icono. Vuelve a descargar el paquete oficial para actualizarlos.';
    $('#btnIcons').textContent = 'Actualizar iconos';
  }
}
export async function installIcons(btn) {
  btn.disabled = true; btn.textContent = 'Descargando iconos oficiales (~14 MB)…';
  try {
    const r = await api('POST', '/api/icons/setup');
    S.icons = new Set(r.available); S.iconsVersion = r.version; S.iconsOutdated = false;
    $('#iconsHint').classList.add('hidden');
    renderPalette(); renderCanvas(); renderInspector();
    toast(`${r.installed} iconos de AWS instalados`);
  } catch (e) {
    toast(e.message, 9000); btn.disabled = false; btn.textContent = 'Reintentar descarga de iconos';
  }
}
