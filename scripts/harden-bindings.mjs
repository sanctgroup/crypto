import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';

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
