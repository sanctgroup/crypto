import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';

const version = process.argv[2];
const parsed = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/.exec(version ?? '');
if (!parsed || version !== version.trim() || parsed[4]?.split('.').some((part) => /^0\d+$/.test(part))) {
  throw new Error('Version must be a semver value without a v prefix');
}
if (!process.argv.includes('--check')) {
  const root = resolve(import.meta.dirname, '..');
  for (const crate of ['sanct-crypto', 'sanct-wasm']) {
    const path = resolve(root, 'crates', crate, 'Cargo.toml');
    const text = await readFile(path, 'utf8');
    await writeFile(path, text.replace(/^version = "[^"]+"/m, `version = "${version}"`));
  }
  const path = resolve(root, 'package.json');
  const data = JSON.parse(await readFile(path, 'utf8'));
  data.version = version;
  await writeFile(path, `${JSON.stringify(data, null, 2)}\n`);
}
