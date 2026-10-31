import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import * as api from '../wasm/sanct_wasm.js';

test('WASM argument and output buffers release plaintext without retaining the fixture', async () => {
  const module = await readFile(new URL('../wasm/sanct_wasm_bg.wasm', import.meta.url));
  const raw = api.initSync({ module });
  const key = new Uint8Array(32).fill(0x73);
  const plain = new TextEncoder().encode('fixture-only plaintext marker for checking native input and output cleanup');
  const ciphertext = api.encryptMetadata(key, plain);
  assert.equal(Buffer.from(raw.memory.buffer).includes(plain), false);
  assert.deepEqual(api.decryptMetadata(key, ciphertext), plain);
  assert.equal(Buffer.from(raw.memory.buffer).includes(plain), false);
  assert.equal(key[0], 0x73);
  const password = 'fixture-only-password-marker-used-to-check-native-argument-cleanup';
  api.deriveMasterKey(password, new Uint8Array(32).fill(0x18));
  assert.equal(Buffer.from(raw.memory.buffer).includes(Buffer.from(password)), false);
});
