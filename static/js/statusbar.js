/* InfraTrack — statusbar */
import { $, S, SEVS, SEV_LABEL } from './core.js';
import { P, compOf } from './model.js';

/* ───────────────────────── Barra de estado y progreso ───────────────────────── */
export function updateProgress() {
  if (!P()) return;
  const tf = P().nodes.filter((n) => compOf(n).terraformable !== false && S.comp[n.type]);
  const done = tf.filter((n) => n.terraformed).length;
  const pct = tf.length ? Math.round((100 * done) / tf.length) : 0;
  $('#progressLabel').textContent = `${done}/${tf.length} terraformado (${pct}%)`;
  $('#progressBar').style.width = pct + '%';
}
export function renderStatusbar() {
  const A = S.analysis;
  if (!A) return;
  const f = A.summary.findings;
  const chips = SEVS.filter((k) => f[k]).map((k) => `<span class="chip sev-${k}" data-sev="${k}">${f[k]} ${SEV_LABEL[k]}</span>`);
  if (A.posture && A.posture.score !== null) chips.unshift(`<span class="chip sec-chip" data-mtab="security">🛡 Seguridad ${A.posture.score}%${A.posture.unknown ? ` · ${A.posture.unknown} sin evaluar` : ''}</span>`);
  if (A.summary.open_questions) chips.push(`<span class="chip st-open" data-mtab="questions">❓ ${A.summary.open_questions} preguntas abiertas</span>`);
  $('#statusbar').innerHTML = chips.join('');
}
export function updateCopilotBadge() {
  const f = S.analysis ? S.analysis.summary.findings : { critical: 0, high: 0 };
  const n = f.critical + f.high;
  const b = $('#copilotBadge'); b.textContent = n; b.classList.toggle('hidden', !n);
}
