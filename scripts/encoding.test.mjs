import assert from 'node:assert/strict';
import { test } from 'node:test';
import { bytesToBase64, base64ToBytes, bytesToHex, hexToBytes } from '../src/index.ts';

function checkEncodings() {
  for (const size of [0, 1, 2, 3, 255, 32768, 32769, 1048576]) {
    const bytes = Uint8Array.from({ length: size }, (_, i) => i % 256);
    const base64 = Buffer.from(bytes).toString('base64');
    const hex = Buffer.from(bytes).toString('hex');
    assert.equal(bytesToBase64(bytes), base64);
    assert.deepEqual(base64ToBytes(base64), bytes);
    assert.equal(bytesToHex(bytes), hex);
    assert.deepEqual(hexToBytes(hex.toUpperCase()), bytes);
    const view = bytes.subarray(1, Math.min(bytes.length, 125));
    assert.equal(bytesToBase64(view), Buffer.from(view).toString('base64'));
    assert.equal(bytesToHex(view), Buffer.from(view).toString('hex'));
  }
  for (const invalid of ['0', 'abc', '0g', 'gg', '0x', ' 00', '00\n', '-1']) {
    assert.throws(() => hexToBytes(invalid), TypeError);
  }
  for (const invalid of ['A', '*', 'AA=', 'A===']) assert.throws(() => base64ToBytes(invalid));
  assert.deepEqual(base64ToBytes(' Y Q ==\n'), new Uint8Array([97]));
}

test('native encoding APIs match reference encodings and reject malformed inputs', checkEncodings);
test('fallback encoders work without the new Uint8Array APIs', () => {
  const saved = [];
  try {
    for (const [object, names] of [[Uint8Array, ['fromBase64', 'fromHex']], [Uint8Array.prototype, ['toBase64', 'toHex']]]) {
      for (const name of names) {
        saved.push([object, name, Object.getOwnPropertyDescriptor(object, name)]);
        Object.defineProperty(object, name, { configurable: true, value: undefined });
      }
    }
    checkEncodings();
  } finally {
    for (const [object, name, descriptor] of saved) {
      if (descriptor) Object.defineProperty(object, name, descriptor);
      else delete object[name];
    }
  }
});
