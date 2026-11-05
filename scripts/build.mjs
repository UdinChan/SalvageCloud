import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const cargoHome = process.env.CARGO_HOME || (process.env.HOME ? `${process.env.HOME}/.cargo` : null);
const cargoBin = cargoHome ? `${cargoHome}/bin` : null;
const trunk = process.env.TRUNK || (cargoBin && fs.existsSync(`${cargoBin}/trunk`) ? `${cargoBin}/trunk` : 'trunk');
const result = spawnSync(trunk, ['build', ...process.argv.slice(2)], {
  cwd: root,
  env: {
    ...process.env,
    PATH: `${cargoBin && fs.existsSync(cargoBin) ? `${cargoBin}:` : ''}${process.env.PATH || ''}`,
    CARGO_BUILD_JOBS: process.env.CARGO_BUILD_JOBS || '2',
  },
  stdio: 'inherit',
});
if (result.status === 0) {
  const dist = path.join(root, 'dist');
  const workerLoader = fs.readdirSync(dist).find((name) =>
    name.startsWith('salvage-crypto-worker') && name.endsWith('_loader.js'),
  );
  if (!workerLoader) {
    throw new Error('Trunk did not emit the Salvage Cloud encryption worker loader');
  }
  fs.writeFileSync(
    path.join(dist, 'crypto-worker.json'),
    `${JSON.stringify({ workerUrl: `/${workerLoader}` }, null, 2)}\n`,
  );
}
process.exit(result.status ?? 1);
