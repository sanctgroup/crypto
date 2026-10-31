import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';

test('release version validation rejects malformed values and shell syntax', () => {
  const script = new URL('./set-version.mjs', import.meta.url);
  for (const version of ['0.3.0', '1.2.3-rc.1', '1.2.3+build.2']) {
    assert.equal(spawnSync(process.execPath, [script.pathname, version, '--check']).status, 0);
  }
  for (const version of ['v1.0.0', '01.0.0', '1.0', '1.0.0-01', '1.0.0\n', '1.0.0"; exit 0; #', '$(exit 0)']) {
    assert.notEqual(spawnSync(process.execPath, [script.pathname, version, '--check']).status, 0);
  }
});
