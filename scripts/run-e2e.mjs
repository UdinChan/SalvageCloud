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
  CARGO_BUILD_JOBS: process.env.CARGO_BUILD_JOBS || '1',
};
const commands = [
  [process.env.CARGO || 'cargo', ['test', '-p', 'salvage-backend-core', '--features', 'native-e2e', '--test', 'native_e2e']],
  [process.env.CARGO || 'cargo', ['test', '-p', 'salvage-tdenc2', '--features', 'native-e2e', '--test', 'native_e2e']],
  [process.execPath, ['node_modules/@playwright/test/cli.js', 'test']],
];
for (const [command, args] of commands) {
  const result = spawnSync(command, args, { cwd: root, env, stdio: 'inherit' });
  if (result.status !== 0) process.exit(result.status ?? 1);
}
