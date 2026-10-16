// Verifica que todos los módulos ES del frontend enlacen (imports/exports existentes) sin abrir un navegador.
import { cpSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const src = join(dirname(fileURLToPath(import.meta.url)), '..', 'static', 'js');
const dir = mkdtempSync(join(tmpdir(), 'infratrack-js-'));
try {
  cpSync(src, dir, { recursive: true });
  writeFileSync(join(dir, 'package.json'), '{"type":"module"}');
  // main.js arranca la app (necesita DOM): se verifica sin la llamada final a init()
  const main = join(dir, 'main.js');
  writeFileSync(main, readFileSync(main, 'utf8').replace(/^\/\/ Acceso de depuración[\s\S]*$/m, ''));
  let failed = 0;
  for (const f of readdirSync(dir).filter((x) => x.endsWith('.js'))) {
    try { await import(join(dir, f)); } catch (e) { failed += 1; console.error(`✖ ${f}: ${e.message}`); }
  }
  if (failed) process.exit(1);
  console.log('✔ módulos del frontend enlazados correctamente');
} finally {
  rmSync(dir, { recursive: true, force: true });
}
