/* InfraTrack — aws-import: arma el diagrama desde la salida de la AWS CLI (sin credenciales en la app) */
import { api, reportError, toast } from './api.js';
import { $, S, esc } from './core.js';
import { P, changed, snapshot } from './model.js';
import { closeModal, openModal } from './copilot-modal.js';
import { store } from './storage.js';
import { loadProjects } from './projects.js';

const COMMANDS = ['describe-vpcs', 'describe-subnets', 'describe-route-tables', 'describe-internet-gateways', 'describe-nat-gateways',
  'describe-vpc-endpoints', 'describe-security-groups', 'describe-network-acls', 'describe-transit-gateways'];

export function openAwsImport() {
  openModal('aws', 'Importar la red existente desde AWS');
  const cmds = COMMANDS.map((c) => `aws ec2 ${c} --region us-east-1 > ${c}.json`).join('\n');
  $('#modalBody').innerHTML = `<div class="mcontent">
    <p>Corre estos comandos <b>de sólo lectura</b> con tu perfil de AWS (o el script <code>scripts/export-aws-network.sh</code>
      del repositorio) y sube los archivos. InfraTrack nunca recibe tus credenciales.</p>
    <div class="codewrap"><button class="copy" data-copy="${esc(cmds)}">Copiar</button><pre class="code">${esc(cmds)}</pre></div>
    <p class="muted">Se crean VPCs, subnets (pública, privada o aislada según sus rutas), IGW, NAT, endpoints, tablas de rutas, NACL y
      Security Groups con sus reglas. ${S.demo ? 'En la demo se procesan sin guardarse en el servidor (máximo ~4 MB en total).' : ''}</p>
    <input type="file" id="awsFiles" accept=".json,application/json" multiple>
    <div id="awsOut"></div></div>`;
}

async function preview(files) {
  S.awsTexts = await Promise.all([...files].map((f) => f.text()));
  const r = await api('POST', '/api/aws/import', { texts: S.awsTexts });
  const labels = { Vpcs: 'VPCs', Subnets: 'subnets', RouteTables: 'tablas de rutas', InternetGateways: 'IGW', NatGateways: 'NAT',
    VpcEndpoints: 'endpoints', SecurityGroups: 'Security Groups', NetworkAcls: 'NACL', TransitGateways: 'Transit Gateways' };
  $('#awsOut').innerHTML = `<p>Encontré: ${Object.entries(r.counts).map(([k, v]) => `<b>${v}</b> ${esc(labels[k] || k)}`).join(' · ')}
      ${r.region ? `en <b>${esc(r.region)}</b>` : ''} → ${r.nodes.length} componentes.</p>
    <div class="filters"><button class="btn blue" data-aws="add">Agregar al proyecto actual</button>
      <button class="btn" data-aws="new">Crear proyecto nuevo</button></div>`;
}

async function importInto(target) {
  const nodes = P().nodes;
  const origin = target === 'add' && nodes.length ? [Math.max(...nodes.map((n) => n.x + n.w)) + 200, 0] : [0, 0];
  const r = await api('POST', '/api/aws/import', { texts: S.awsTexts, origin });
  if (target === 'new') {
    const p = await store.importProject({ name: `Importado de AWS ${r.region || ''}`.trim(), nodes: r.nodes, edges: r.edges,
      settings: { region: r.region, account_id: '', environment: 'dev', prefix: '' } });
    closeModal();
    await loadProjects(p.id);
  } else {
    snapshot();
    P().nodes.push(...r.nodes);
    P().edges.push(...r.edges);
    changed({ inspector: true });
    closeModal();
  }
  toast(`${r.nodes.length} componentes importados desde AWS`);
}

export function onAwsChange(t) {
  if (t.id !== 'awsFiles' || !t.files.length) return false;
  preview(t.files).catch(reportError);
  return true;
}

export function onAwsClick(t) {
  importInto(t.dataset.aws).catch(reportError);
}
