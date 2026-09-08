import assert from 'node:assert/strict';
import test from 'node:test';
import { analyzePassword } from '../../src/lib/analysis.js';
import {
  ATTACK_SCENARIOS,
  compareAnalyses,
  entropyScore,
  formatCrackTime,
  formatGuesses,
  validatePassword,
} from '../../src/lib/constants.js';

test('empty and very short inputs have well-defined, non-misleading results', () => {
  assert.equal(analyzePassword(''), null);
  assert.equal(analyzePassword('a').score, 0);
  assert.equal(analyzePassword('1234').score, 0);
});

test('familiar substitutions and long repetitions are not called strong', () => {
  for (const input of [
    'Password123!',
    'P@ssw0rd!',
    'a'.repeat(128),
    'abc'.repeat(30),
    'qwertyuiop123!',
  ]) {
    assert.ok(analyzePassword(input).score <= 2);
  }
  assert.ok(analyzePassword('aaaaaa').patterns.includes('Repeated pattern'));
  assert.ok(analyzePassword('P@ssw0rd!').patterns.includes('Predictable substitutions'));
});

test('analysis counts Unicode code points and never trims or normalizes input', () => {
  const result = analyzePassword('Éé١😀 ');
  assert.equal(result.length, 5);
  assert.equal(result.unique, 5);
  assert.deepEqual(result.types, { upper: true, lower: true, numbers: true, symbols: true });
  assert.equal(analyzePassword(' test ').length, 6);
  assert.equal(analyzePassword('e\u0301').length, 2);
  validatePassword('😀'.repeat(128));
  assert.throws(() => analyzePassword('😀'.repeat(129)), /128/);
  assert.throws(() => analyzePassword('a'.repeat(129)), /128/);
  assert.throws(() => validatePassword('x'.repeat(1_000_000)), /128/);
  assert.throws(() => validatePassword(null), TypeError);
});

test('worker-safe reports contain aggregates, not passwords or matched tokens', () => {
  const input = 'q6^xD8@zH2&wR9!s';
  const result = analyzePassword(input);
  assert.ok(result.score >= 3);
  assert.equal('password' in result, false);
  assert.equal('sequence' in result, false);
  assert.equal('entropy' in result, false);
  assert.equal(JSON.stringify(result).includes(input), false);
});

test('comparison ranks modeled guessing effort, not raw length', () => {
  const a = analyzePassword('a'.repeat(40));
  const b = analyzePassword('q6^xD8@zH2&wR9!s');
  assert.match(compareAnalyses(a, b), /Password B/);
  assert.match(compareAnalyses(b, a), /Password A/);
  assert.match(compareAnalyses(a, a), /Similar/);
  assert.match(compareAnalyses(a, null), /Enter both/);
});

test('attack scenarios change times, not strength scores', () => {
  assert.equal(formatCrackTime(2), 'Less than a second');
  assert.equal(formatCrackTime(10), '1 second');
  assert.equal(formatCrackTime(10, 'online'), '3 years');
  assert.equal(formatCrackTime(300), 'Over a billion years');
  assert.equal(formatCrackTime(Infinity), '—');
  assert.equal(Object.keys(ATTACK_SCENARIOS).length, 4);
  assert.throws(() => formatCrackTime(10, 'invalid'), /Unknown/);
  assert.equal(formatGuesses(1), '10');
  assert.equal(formatGuesses(10.123), '10^10.1');
  assert.equal(formatGuesses(NaN), '—');
});

test('generator entropy levels acknowledge short PIN limitations', () => {
  assert.equal(entropyScore(6 * Math.log2(10)), 0);
  assert.equal(entropyScore(77.5), 3);
  assert.equal(entropyScore(128), 4);
});
