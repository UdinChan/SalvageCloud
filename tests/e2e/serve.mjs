import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import fs from 'node:fs/promises';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const cargoHome = process.env.CARGO_HOME || (process.env.HOME ? `${process.env.HOME}/.cargo` : null);
const cargoBin = cargoHome ? `${cargoHome}/bin` : null;
const cargo = process.env.CARGO || 'cargo';
const dataDir = path.join(root, '.e2e-data');
await fs.rm(dataDir, { recursive: true, force: true });
await fs.mkdir(dataDir, { recursive: true });

const child = spawn(cargo, [
  'run', '--manifest-path', path.join(root, 'Cargo.toml'),
  '-p', 'salvage-server', '--features', 'e2e-fixture',
], {
  cwd: root,
  env: {
    ...process.env,
    PATH: `${cargoBin ? `${cargoBin}:` : ''}${process.env.PATH || ''}`,
    CARGO_BUILD_JOBS: process.env.CARGO_BUILD_JOBS || '2',
    SALVAGE_BIND: '127.0.0.1:4173',
    SALVAGE_DATA_DIR: dataDir,
    SALVAGE_WEB_DIST: path.join(root, 'dist'),
    SALVAGE_PUBLIC_ORIGIN: 'http://127.0.0.1:4173',
    SALVAGE_COOKIE_SECURE: 'false',
    SALVAGE_SESSION_KEY: '11'.repeat(32),
    SALVAGE_TELEGRAM_TRANSPORT: 'fixture',
    SALVAGE_CHANNEL_PART_LIMIT: '2',
    RUST_LOG: 'info',
  },
  stdio: 'inherit',
});

const stop = () => {
  if (!child.killed) child.kill('SIGTERM');
};
process.on('SIGTERM', stop);
process.on('SIGINT', stop);
process.on('exit', stop);
await new Promise((resolve, reject) => {
  child.on('exit', (code, signal) => {
    if (code === 0 || signal === 'SIGTERM') resolve();
    else reject(new Error(`Salvage server exited with ${code ?? signal}`));
  });
  child.on('error', reject);
});
