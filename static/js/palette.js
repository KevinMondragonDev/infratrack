/* InfraTrack — palette */
import { $, S, esc, snap, uid } from './core.js';
import { badgeHtml } from './icons.js';
import { select } from './interaction.js';
import { P, changed, containerAt, snapshot } from './model.js';

/* ───────────────────────── Paleta ───────────────────────── */
export function renderPalette() {
  const q = $('#paletteSearch').value.trim().toLowerCase();
  const html = S.catalog.categories.map((cat) => {
    const items = S.catalog.components.filter((c) => c.category === cat.id &&
      (!q || c.name.toLowerCase().includes(q) || c.abbr.toLowerCase().includes(q) || (c.desc || '').toLowerCase().includes(q)));
    if (!items.length) return '';
    return `<details class="pal-cat" open><summary><span class="dot" style="background:${cat.color}"></span>${esc(cat.name)}</summary>
      ${items.map((c) => `<div class="pal-item" draggable="true" data-type="${c.id}" title="${esc(c.desc || '')}">
        ${badgeHtml(c)}<span class="nm">${esc(c.name)}</span></div>`).join('')}
    </details>`;
  }).join('');
  $('#paletteList').innerHTML = html || '<p class="hint">Sin resultados.</p>';
}

export function defaultSize(type) {
  if (type === 'account') return { w: 1200, h: 800 };
  if (type === 'zone') return { w: 620, h: 420 };
  if (type === 'vpc') return { w: 680, h: 440 };
  if (type === 'subnet') return { w: 320, h: 210 };
  if (type === 'note') return { w: 200, h: 90 };
  if (type === 'igw') return { w: 110, h: 50 };
  return { w: 150, h: 56 };
}

export function addNode(type, pt) {
  const comp = S.comp[type];
  if (!comp) return;
  const cfg = {};
  comp.fields.forEach((f) => { if ('default' in f) cfg[f.key] = f.default; });
  const size = defaultSize(type);
  const count = P().nodes.filter((n) => n.type === type).length;
  const n = {
    id: uid('n'), type, label: type === 'note' ? 'Nota' : `${comp.name}${count ? ' ' + (count + 1) : ''}`,
    x: snap(pt.x - size.w / 2), y: snap(pt.y - size.h / 2), ...size, config: cfg,
    terraformed: false, status: 'Borrador', notes: [], questions: [],
  };
  if (type === 'subnet') {
    const vpc = containerAt(pt);
    const subs = P().nodes.filter((x) => x.type === 'subnet');
    n.config.az = ['a', 'b', 'c'][subs.length % 3];
    if (vpc && vpc.config && vpc.config.cidr) {
      const m = /^(\d+)\.(\d+)\./.exec(vpc.config.cidr);
      if (m) n.config.cidr = `${m[1]}.${m[2]}.${subs.length}.0/24`;
    }
  }
  snapshot();
  P().nodes.push(n);
  select('node', n.id, 'general');
  changed();
}
