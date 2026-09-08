import assert from 'node:assert/strict';
import test from 'node:test';
import { SessionHistory } from '../../src/lib/history.js';

const entries = Array.from({ length: 25 }, (_, index) => ({
  password: `test-only-${index}`,
  mode: 'random',
  entropyBits: 64,
  length: 12,
}));

test('history is opt-in and does not retroactively retain passwords', () => {
  const history = new SessionHistory();
  history.add(entries);
  assert.equal(history.enabled, false);
  assert.deepEqual(history.items, []);
  history.setEnabled(true);
  assert.deepEqual(history.items, []);
});

test('history is bounded, newest-first, and protects its internal entries', () => {
  const history = new SessionHistory();
  history.setEnabled(true);
  history.add(entries);
  assert.equal(history.items.length, 10);
  assert.equal(history.items[0].password, 'test-only-24');
  assert.equal(history.items[9].password, 'test-only-15');
  const exposed = history.items;
  exposed[0].password = 'changed';
  exposed.pop();
  assert.equal(history.items.length, 10);
  assert.equal(history.items[0].password, 'test-only-24');
});

test('clear keeps opt-in; disabling history also clears it', () => {
  const history = new SessionHistory();
  history.setEnabled(true);
  history.add(entries);
  history.clear();
  assert.equal(history.enabled, true);
  assert.deepEqual(history.items, []);
  history.add(entries);
  history.setEnabled(false);
  assert.equal(history.enabled, false);
  assert.deepEqual(history.items, []);
});
