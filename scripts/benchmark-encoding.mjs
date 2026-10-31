import { bytesToBase64, base64ToBytes, bytesToHex, hexToBytes } from '../src/index.ts';
import { performance } from 'node:perf_hooks';
import { writeFile } from 'node:fs/promises';
import assert from 'node:assert/strict';

const fallback = process.argv.includes('--fallback');
if (fallback) {
  for (const [object, names] of [[Uint8Array, ['fromBase64', 'fromHex']], [Uint8Array.prototype, ['toBase64', 'toHex']]]) {
    for (const name of names) Object.defineProperty(object, name, { configurable: true, value: undefined });
  }
}
const rows = [];
for (const size of [1024, 65536, 1048576]) {
  const bytes = new Uint8Array(size).fill(0xad);
  const base64 = bytesToBase64(bytes);
  const hex = bytesToHex(bytes);
  assert.deepEqual(base64ToBytes(base64), bytes);
  assert.deepEqual(hexToBytes(hex), bytes);
  for (const [name, fn] of [
    ['bytesToBase64', () => bytesToBase64(bytes)],
    ['base64ToBytes', () => base64ToBytes(base64)],
    ['bytesToHex', () => bytesToHex(bytes)],
    ['hexToBytes', () => hexToBytes(hex)],
  ]) {
    for (let i = 0; i < 5; i++) fn();
    const samples = [];
    for (let i = 0; i < 9; i++) {
      const start = performance.now();
      const value = fn();
      samples.push(performance.now() - start);
      assert.ok(value.length);
    }
    const medianMs = [...samples].sort((a, b) => a - b)[4];
    rows.push({ name, payloadBytes: size, medianMs, samplesMs: samples });
    console.error(`${name}/${size}: ${medianMs.toFixed(3)} ms`);
  }
}
await writeFile(process.argv[2] ?? 'benchmarks/encoding.json', `${JSON.stringify({ node: process.version, mode: fallback ? 'fallback' : 'native', rows }, null, 2)}\n`);
