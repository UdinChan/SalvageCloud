import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const cargoHome = process.env.CARGO_HOME || (process.env.HOME ? `${process.env.HOME}/.cargo` : null);
const cargoBin = cargoHome ? `${cargoHome}/bin` : null;
const env = {
  ...process.env,
  PATH: `${cargoBin && fs.existsSync(cargoBin) ? `${cargoBin}:` : ''}${process.env.PATH || ''}`,
  CARGO_BUILD_JOBS: process.env.CARGO_BUILD_JOBS || '2',
};
const cargo = process.env.CARGO || 'cargo';
const commands = [
  [cargo, ['fmt', '--all', '--', '--check']],
  [cargo, ['clippy', '--all-targets', '-p', 'salvage-protocol', '-p', 'salvage-backend-core', '-p', 'salvage-server', '-p', 'salvage-tdenc2', '-p', 'salvage-crypto-worker', '--features', 'salvage-server/e2e-fixture', '--', '-D', 'warnings']],
  [cargo, ['clippy', '--target', 'wasm32-unknown-unknown', '-p', 'salvage-web', '-p', 'salvage-crypto-worker', '-p', 'salvage-tdenc2', '--', '-D', 'warnings']],
  [cargo, ['check', '--target', 'wasm32-unknown-unknown', '-p', 'salvage-web', '-p', 'salvage-crypto-worker', '-p', 'salvage-tdenc2']],
  [process.execPath, ['scripts/check-test-policy.mjs']],
];
for (const [command, args] of commands) {
  const result = spawnSync(command, args, { cwd: root, env, stdio: 'inherit' });
  if (result.status !== 0) process.exit(result.status ?? 1);
}
