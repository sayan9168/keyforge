import assert from 'node:assert/strict';
import test from 'node:test';
import { log2BigInt, randomBigIntBelow, randomIndex } from '../../src/lib/random.js';

test('rejects the biased tail instead of reducing it modulo the bound', () => {
  let calls = 0;
  const source = {
    getRandomValues(bytes) {
      bytes.fill(calls++ === 0 ? 255 : 9);
      return bytes;
    },
  };
  assert.equal(randomBigIntBelow(10n, source), 9n);
  assert.equal(calls, 2);
});

test('handles one-element spaces, power-of-two spaces, and huge bounds', () => {
  const zero = { getRandomValues: (bytes) => bytes.fill(0) };
  assert.equal(randomBigIntBelow(1n, zero), 0n);
  assert.equal(randomBigIntBelow(256n, { getRandomValues: (bytes) => bytes.fill(255) }), 255n);
  for (const bound of [2n, 10n, 7776n, 1n << 900n]) {
    for (let index = 0; index < 25; index++) {
      const value = randomBigIntBelow(bound);
      assert.ok(value >= 0n && value < bound);
    }
  }
});

test('fails closed without Web Crypto, including one-element spaces', () => {
  assert.throws(() => randomBigIntBelow(10n, {}), /Secure randomness/);
  assert.throws(() => randomBigIntBelow(1n, null), /Secure randomness/);
});

test('validates bounds and calculates big-integer entropy without overflow', () => {
  for (const bound of [0n, -1n, 2, null]) assert.throws(() => randomBigIntBelow(bound), RangeError);
  for (const size of [0, -1, 1.5, Infinity, Number.MAX_SAFE_INTEGER + 1])
    assert.throws(() => randomIndex(size), RangeError);
  assert.equal(log2BigInt(1n), 0);
  assert.equal(log2BigInt(1n << 1024n), 1024);
  assert.ok(Math.abs(log2BigInt(14n) - Math.log2(14)) < 1e-12);
  assert.throws(() => log2BigInt(0n), RangeError);
});
