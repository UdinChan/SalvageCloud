import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const failures = [];
async function walk(directory) {
  for (const entry of await fs.readdir(directory, { withFileTypes: true })) {
    if (['target', 'node_modules', 'dist', '.e2e-data'].includes(entry.name)) continue;
    const full = path.join(directory, entry.name);
    if (entry.isDirectory()) await walk(full);
    else if (entry.name.endsWith('.rs')) {
      const source = await fs.readFile(full, 'utf8');
      if (source.includes('#[cfg(test)]')) failures.push(`${full}: inline/unit test modules are not permitted`);
      if (/^\s*#\[(tokio::)?test\]/.test(source) && !full.endsWith('native_e2e.rs')) {
        failures.push(`${full}: behavioral Rust tests belong in the dedicated native_e2e target`);
      }
    }
  }
}
await walk(path.join(root, 'crates'));
const packageJson = JSON.parse(await fs.readFile(path.join(root, 'package.json'), 'utf8'));
if (packageJson.scripts?.test !== 'npm run test:e2e') failures.push('npm test must run the E2E suite');
const forbidden = /react|tauri|vitest|testing-library/i;
for (const section of ['dependencies', 'devDependencies']) {
  for (const name of Object.keys(packageJson[section] || {})) {
    if (forbidden.test(name)) failures.push(`forbidden application/test dependency: ${name}`);
  }
}
if (failures.length) {
  console.error(failures.join('\n'));
  process.exit(1);
}
console.log('E2E-only and application dependency policy checks passed.');
