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
const split = api.derivePasswordKeys('compatibility password', salt);
const splitPrevious = previous.derivePasswordKeys('compatibility password', salt);
assert.deepEqual(split.authKey, splitPrevious.authKey);
assert.deepEqual(split.wrapKey, splitPrevious.wrapKey);
assert.notDeepEqual(split.authKey, split.wrapKey);
const wrapped = api.wrapAccountKey(split.wrapKey, key, 'password');
assert.deepEqual(previous.unwrapAccountKey(split.wrapKey, wrapped, 'password'), key);
assert.throws(() => previous.unwrapAccountKey(split.authKey, wrapped, 'password'));
assert.throws(() => previous.unwrapAccountKey(split.wrapKey, wrapped, 'recovery'));
for (const [producer, consumer] of [[api, previous], [previous, api]]) {
  const identity = producer.generateIdentityKeys(key);
  const bundle = consumer.decryptPrivateBundle(key, identity.encryptedPrivateBundle);
  for (const size of [0, 1, 1024, 65536, 1048576]) {
    const plain = new Uint8Array(size).fill(0x71);
    const metadata = new Uint8Array(32).fill(0x72);
    const record = producer.sealRecord(bundle, 'contact', plain);
    assert.deepEqual(consumer.openRecord(bundle, 'contact', record), plain);
    assert.throws(() => consumer.openRecord(bundle, 'signature', record));
    const mine = producer.sealMailForSelf(bundle, plain, metadata);
    const openedMine = consumer.openMail(bundle, 'mail-body', mine.body);
    assert.deepEqual(openedMine.plaintext, plain);
    assert.equal(openedMine.selfSealed, true);
    const sealed = producer.sealMailForRecipient(identity.x25519Public, identity.mlkem768Public, bundle, 'alice@sanct.test', plain, metadata);
    const openedBody = consumer.openMail(bundle, 'mail-body', sealed.body);
    const openedMetadata = consumer.openMail(bundle, 'mail-metadata', sealed.metadata);
    assert.deepEqual(openedBody.plaintext, plain);
    assert.deepEqual(openedMetadata.plaintext, metadata);
    assert.deepEqual(openedBody.bindingId, openedMetadata.bindingId);
    assert.equal(consumer.mailSignatureKeyVersion(openedBody.signature), 1);
    assert.equal(consumer.verifyMailSignature(openedBody.signature, identity.ed25519Public, identity.mldsa65Public, 'alice@sanct.test', openedBody.recipientKeyHash, openedBody.bindingId, plain, metadata), true);
    assert.equal(consumer.verifyMailSignature(openedBody.signature, identity.ed25519Public, identity.mldsa65Public, 'mallory@sanct.test', openedBody.recipientKeyHash, openedBody.bindingId, plain, metadata), false);
    assert.throws(() => consumer.openMail(bundle, 'mail-metadata', sealed.body));
    for (const index of [0, 1, 2, 33, 1121, sealed.metadata.length - 1]) {
      const corrupted = sealed.metadata.slice();
      corrupted[index] ^= 0x80;
      assert.throws(() => consumer.openMail(bundle, 'mail-metadata', corrupted));
    }
    for (const length of [0, 1, 1120, 1121, sealed.metadata.length - 1]) {
      assert.throws(() => consumer.openMail(bundle, 'mail-metadata', sealed.metadata.subarray(0, length)));
    }
  }
  identity.free();
}
const identity = api.generateIdentityKeys(key);
const bundle = api.decryptPrivateBundle(key, identity.encryptedPrivateBundle);
for (const first of [0, 1]) {
  const lowOrder = new Uint8Array(32);
  lowOrder[0] = first;
  assert.throws(() => api.sealMailForRecipient(lowOrder, identity.mlkem768Public, bundle, undefined, key, key));
}
assert.throws(() => api.sealMailForRecipient(identity.x25519Public, new Uint8Array(1184).fill(0xff), bundle, undefined, key, key));
for (const length of [0, 1, 31, 33, 1183, 1185]) {
  assert.throws(() => api.sealMailForRecipient(identity.x25519Public, new Uint8Array(length), bundle, undefined, key, key));
}
const rotated = api.rotateIdentityKeys(key, bundle);
const rotatedBundle = api.decryptPrivateBundle(key, rotated.encryptedPrivateBundle);
const old = api.sealMailForRecipient(identity.x25519Public, identity.mlkem768Public, bundle, undefined, key, key);
assert.deepEqual(api.openMail(rotatedBundle, 'mail-body', old.body).plaintext, key);
identity.free();
rotated.free();
