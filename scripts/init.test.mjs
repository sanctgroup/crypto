import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { initCrypto, generateIdentityKeys } from '../src/index.ts';

test('initialization retries after failure and concurrent callers share one instance', async () => {
  await assert.rejects(initCrypto(new Uint8Array([0, 1, 2])));
  const bytes = await readFile(new URL('../wasm/sanct_wasm_bg.wasm', import.meta.url));
  const instantiate = WebAssembly.instantiate;
  let calls = 0;
  WebAssembly.instantiate = async (...args) => {
    calls++;
    return instantiate(...args);
  };
  try {
    await Promise.all(Array.from({ length: 16 }, () => initCrypto(bytes)));
    assert.equal(calls, 1);
    const identity = generateIdentityKeys(new Uint8Array(32).fill(0x42));
    await initCrypto(bytes);
    assert.equal(calls, 1);
    assert.equal(identity.x25519Public.length, 32);
    identity.free();
  } finally {
    WebAssembly.instantiate = instantiate;
  }
});
