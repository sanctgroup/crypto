import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

async function load(directory) {
  const api = await import(pathToFileURL(resolve(directory, 'sanct_wasm.js')));
  api.initSync({ module: await readFile(resolve(directory, 'sanct_wasm_bg.wasm')) });
  return api;
}

const api = await load(process.argv[2] ?? 'wasm');
const previous = process.argv[3] ? await load(process.argv[3]) : api;
const key = new Uint8Array(32).fill(0x42);
const salt = new Uint8Array(32).fill(0x17);
assert.deepEqual(api.deriveMasterKey('compatibility password', salt), previous.deriveMasterKey('compatibility password', salt));
for (const [producer, consumer] of [[api, previous], [previous, api]]) {
  const identity = producer.generateIdentityKeys(key);
  const privateKeys = consumer.decryptPrivateKeys(key, identity.encryptedPrivateBundle);
  const x = privateKeys.x25519Secret;
  const ml = privateKeys.mlkem768Secret;
  for (const size of [0, 1, 1024, 65536, 1048576]) {
    const plain = new Uint8Array(size).fill(0x71);
    const symmetric = producer.encryptMetadata(key, plain);
    assert.deepEqual(consumer.decryptMetadata(key, symmetric), plain);
    const sealed = producer.encryptMessage(identity.x25519Public, identity.mlkem768Public, plain);
    assert.deepEqual(consumer.decryptMessage(x, ml, sealed), plain);
    for (const index of [0, 1, 33, 1121, sealed.length - 1]) {
      const corrupted = sealed.slice();
      corrupted[index] ^= 0x80;
      assert.throws(() => consumer.decryptMessage(x, ml, corrupted));
    }
    for (const length of [0, 1, 1120, 1121, sealed.length - 1]) {
      assert.throws(() => consumer.decryptMessage(x, ml, sealed.subarray(0, length)));
    }
  }
  identity.free();
  privateKeys.free();
}
const identity = api.generateIdentityKeys(key);
for (const first of [0, 1]) {
  const lowOrder = new Uint8Array(32);
  lowOrder[0] = first;
  assert.throws(() => api.encryptMessage(lowOrder, identity.mlkem768Public, key));
}
assert.throws(() => api.encryptMessage(identity.x25519Public, new Uint8Array(1184).fill(0xff), key));
for (const length of [0, 1, 31, 33, 1183, 1185]) {
  assert.throws(() => api.encryptMessage(identity.x25519Public, new Uint8Array(length), key));
}
assert.equal(api.encryptMessage(identity.x25519Public, identity.mlkem768Public, key).length, 1193);
const generated = previous.pgpGenerateKey('Compatibility', 'test@example.invalid');
const encoder = new TextEncoder();
const publicKey = encoder.encode(generated.armoredPublic);
const secretKey = encoder.encode(generated.armoredSecret);
for (const [producer, consumer] of [[api, previous], [previous, api]]) {
  const ciphertext = encoder.encode(producer.pgpEncryptToRecipients([publicKey], key));
  const result = consumer.pgpDecryptMessage([secretKey], ciphertext);
  assert.deepEqual(result.plaintext, key);
  if (consumer === api) {
    assert.equal(result.signatureVerified, false);
    assert.equal(result.signerFingerprint, undefined);
    assert.throws(() => api.pgpDecryptMessageVerified([secretKey], ciphertext, [publicKey]));
    assert.throws(() => api.pgpDecryptMessageVerified([secretKey], ciphertext, []));
  }
  result.free();
}
generated.free();
identity.free();
console.log('WASM interoperability, malformed input, tamper, key-validation and OpenPGP checks passed.');
