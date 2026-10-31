import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { performance } from 'node:perf_hooks';
import { cpus } from 'node:os';
import { createHash } from 'node:crypto';
import { gzipSync } from 'node:zlib';

const bundle = resolve(process.argv[2] ?? 'wasm');
const output = process.argv[3];
const api = await import(pathToFileURL(resolve(bundle, 'sanct_wasm.js')));
const bytes = await readFile(resolve(bundle, 'sanct_wasm_bg.wasm'));
const started = performance.now();
const instance = api.initSync({ module: bytes });
const initializationMs = performance.now() - started;
const rows = [];
let sink;

function measure(name, fn, payloadBytes = 0, slow = false) {
  for (let i = 0; i < (slow ? 1 : 8); i++) sink = fn();
  let iterations = 1;
  if (!slow) {
    let elapsed;
    do {
      const t = performance.now();
      for (let i = 0; i < iterations; i++) sink = fn();
      elapsed = performance.now() - t;
      if (elapsed >= 15) break;
      iterations *= 2;
    } while (iterations <= 16384);
  }
  const samples = [];
  for (let sample = 0; sample < 9; sample++) {
    const t = performance.now();
    for (let i = 0; i < iterations; i++) sink = fn();
    samples.push((performance.now() - t) / iterations);
  }
  const sorted = [...samples].sort((a, b) => a - b);
  const medianMs = sorted[4];
  rows.push({ name, payloadBytes, iterations, medianMs, minMs: sorted[0], maxMs: sorted.at(-1),
    mibPerSecond: payloadBytes ? payloadBytes / 1048576 / (medianMs / 1000) : null, samplesMs: samples });
  console.error(`${name}: ${medianMs.toFixed(3)} ms${payloadBytes ? `, ${rows.at(-1).mibPerSecond.toFixed(1)} MiB/s` : ''}`);
}

const key = new Uint8Array(32).fill(0x42);
const salt = new Uint8Array(32).fill(0x17);
measure('deriveMasterKey/64MiB,t=3,p=1', () => api.deriveMasterKey('benchmark password', salt), 0, true);
measure('generateIdentityKeys', () => { const v = api.generateIdentityKeys(key); v.free(); });
const identity = api.generateIdentityKeys(key);
const xPublic = identity.x25519Public;
const mlPublic = identity.mlkem768Public;
const privateBundle = identity.encryptedPrivateBundle;
const privateKeys = api.decryptPrivateKeys(key, privateBundle);
const xSecret = privateKeys.x25519Secret;
const mlSecret = privateKeys.mlkem768Secret;
measure('decryptPrivateKeys', () => { const v = api.decryptPrivateKeys(key, privateBundle); v.free(); });
measure('computeSubjectHash', () => api.computeSubjectHash(key, 'Re: Fwd: Benchmark subject'));
measure('generateRecoveryPhrase', () => { const v = api.generateRecoveryPhrase(); v.free(); });

for (const size of [0, 1024, 65536, 1048576, 8388608]) {
  const plain = new Uint8Array(size).fill(0x6d);
  const symmetric = api.encryptMetadata(key, plain);
  const envelope = api.encryptMessage(xPublic, mlPublic, plain);
  assert.deepEqual(api.decryptMetadata(key, symmetric), plain);
  assert.deepEqual(api.decryptMessage(xSecret, mlSecret, envelope), plain);
  measure(`encryptMetadata/${size}`, () => api.encryptMetadata(key, plain), size);
  measure(`decryptMetadata/${size}`, () => api.decryptMetadata(key, symmetric), size);
  measure(`encryptMessage/${size}`, () => api.encryptMessage(xPublic, mlPublic, plain), size);
  measure(`decryptMessage/${size}`, () => api.decryptMessage(xSecret, mlSecret, envelope), size);
}

measure('pgpGenerateKey', () => { const v = api.pgpGenerateKey('Benchmark', 'bench@example.invalid'); v.free(); });
const pgp = api.pgpGenerateKey('Benchmark', 'bench@example.invalid');
const encoder = new TextEncoder();
const publicPgp = encoder.encode(pgp.armoredPublic);
const secretPgp = encoder.encode(pgp.armoredSecret);
const pgpPlain = new Uint8Array(1024).fill(0x6d);
const pgpCipher = encoder.encode(api.pgpEncryptToRecipients([publicPgp], pgpPlain));
const pgpCheck = api.pgpDecryptMessage([secretPgp], pgpCipher);
assert.deepEqual(pgpCheck.plaintext, pgpPlain);
pgpCheck.free();
measure('pgpEncrypt/1024', () => api.pgpEncryptToRecipients([publicPgp], pgpPlain), 1024);
measure('pgpDecrypt/1024', () => { const v = api.pgpDecryptMessage([secretPgp], pgpCipher); v.free(); }, 1024);
pgp.free();
identity.free();
privateKeys.free();
const result = { measuredAt: new Date().toISOString(), node: process.version, v8: process.versions.v8,
  platform: process.platform, arch: process.arch, cpu: cpus()[0]?.model, bundle,
  wasmSha256: createHash('sha256').update(bytes).digest('hex'), wasmBytes: bytes.length,
  wasmGzipBytes: gzipSync(bytes).length, initializationMs, wasmMemoryBytes: instance.memory.buffer.byteLength,
  methodology: '8 warmups (1 for Argon2), calibrated batches >=15ms, 9 batches; median batch time/op; setup and correctness checks excluded; JS/WASM transfers included', rows };
if (output) await writeFile(output, `${JSON.stringify(result, null, 2)}\n`);
else console.log(JSON.stringify(result, null, 2));
assert.notEqual(sink, null);
