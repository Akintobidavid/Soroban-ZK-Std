import test from 'node:test';
import assert from 'node:assert/strict';
import { decryptAmount } from './decryption.mjs';

test('decryptAmount returns a deterministic amount for the provided viewing key', async () => {
  const result = await decryptAmount(12.5, 'auditor-key');

  assert.equal(typeof result, 'number');
  assert.equal(result, Number(result.toFixed(2)));
  assert.ok(result >= 12.5);
});

test('decryptAmount rejects invalid numeric input', async () => {
  await assert.rejects(() => decryptAmount(Number.NaN, 'auditor-key'), /finite number/);
});
