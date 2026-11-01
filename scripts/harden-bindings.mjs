import { copyFile, readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';

const path = resolve(process.argv[2] ?? 'wasm/sanct_wasm.js');
let source = await readFile(path, 'utf8');
const stripComments = (text) => text
  .replace(/^[\t ]*\/\*[\s\S]*?\*\/[\t ]*\r?\n/gm, '')
  .replace(/^[\t ]*\/\/[^\r\n]*(?:\r?\n|$)/gm, '');
const helper = '\nfunction zeroizeAndFree(ptr, length, alignment) {\n    getUint8ArrayMemory0().fill(0, ptr, ptr + length);\n    wasm.__wbindgen_free(ptr, length, alignment);\n}\n';
if (!source.includes('function zeroizeAndFree(')) {
  const matches = source.match(/wasm\.__wbindgen_free\(/g);
  if (!matches?.length || !source.includes('function getUint8ArrayMemory0()')) {
    throw new Error('Unsupported wasm-bindgen output; refusing to skip output-buffer cleanup');
  }
  source = source.replaceAll('wasm.__wbindgen_free(', 'zeroizeAndFree(') + helper;
}
await writeFile(path, stripComments(source));
for (const declaration of [path.replace(/\.js$/, '.d.ts'), path.replace(/\.js$/, '_bg.wasm.d.ts')]) {
  await writeFile(declaration, stripComments(await readFile(declaration, 'utf8')));
}

const directory = dirname(path);
const root = resolve(import.meta.dirname, '..');
for (const [source, target] of [
  ['LICENSE', 'LICENSE'],
  ['vendor/pgp/LICENSE-MIT', 'RPGP-LICENSE-MIT'],
  ['vendor/pgp/LICENSE-APACHE', 'RPGP-LICENSE-APACHE'],
  ['vendor/pgp/NOTICE.txt', 'RPGP-NOTICE.txt'],
]) {
  await copyFile(resolve(root, source), resolve(directory, target));
}
const manifestPath = resolve(directory, 'package.json');
const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
manifest.files = [...new Set([...manifest.files, 'LICENSE', 'RPGP-LICENSE-MIT', 'RPGP-LICENSE-APACHE', 'RPGP-NOTICE.txt'])];
await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
