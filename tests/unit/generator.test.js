import assert from 'node:assert/strict';
import test from 'node:test';
import words from '../../src/data/eff-words.json' with { type: 'json' };
import {
  ALPHABETS,
  WORD_COUNT,
  createGenerator,
  createRandomPlan,
  generateBatch,
  getCharacterGroups,
  parsePattern,
} from '../../src/lib/generator.js';

const noGroups = { upper: false, lower: false, numbers: false, symbols: false, brackets: false };
const zero = { getRandomValues: (bytes) => bytes.fill(0) };

test('every alphabet is unique and all character groups are disjoint', () => {
  const alphabet = Object.values(ALPHABETS).join('');
  assert.equal(new Set(alphabet).size, alphabet.length);
});

test('exhaustively unranking a tiny constrained space is uniform and complete', () => {
  const plan = createRandomPlan({
    ...noGroups,
    upper: true,
    lower: true,
    length: 4,
    exclude: ALPHABETS.upper.slice(1) + ALPHABETS.lower.slice(1),
  });
  // Four binary choices, except AAAA and aaaa.
  assert.equal(plan.possibilities, 14n);
  assert.equal(plan.entropyBits, Math.log2(14));
  const outputs = Array.from({ length: 14 }, (_, index) => plan.unrank(BigInt(index)));
  assert.equal(new Set(outputs).size, 14);
  for (const password of outputs) {
    assert.match(password, /^[Aa]{4}$/);
    assert.ok(password.includes('A') && password.includes('a'));
  }
  assert.throws(() => plan.unrank(-1n), RangeError);
  assert.throws(() => plan.unrank(14n), RangeError);
});

test('unranking also weights unequal-sized groups exactly', () => {
  const plan = createRandomPlan({
    ...noGroups,
    upper: true,
    lower: true,
    length: 4,
    exclude: ALPHABETS.upper.slice(2) + ALPHABETS.lower.slice(1),
  });
  assert.equal(plan.possibilities, 3n ** 4n - 2n ** 4n - 1n);
  const outputs = Array.from({ length: Number(plan.possibilities) }, (_, index) =>
    plan.unrank(BigInt(index)),
  );
  assert.equal(new Set(outputs).size, 64);
  for (const password of outputs) {
    assert.match(password, /^[ABa]{4}$/);
    assert.ok(password.includes('a') && /[AB]/.test(password));
  }
});

test('unconstrained single groups have the expected space and exact length', () => {
  const plan = createRandomPlan({ ...noGroups, numbers: true, length: 128 });
  assert.equal(plan.possibilities, 10n ** 128n);
  assert.ok(Math.abs(plan.entropyBits - 128 * Math.log2(10)) < 1e-10);
  assert.equal(plan.next(zero), '0'.repeat(128));
});

test('random generation respects every group, exclusions, and requested bounds', () => {
  for (const length of [5, 20, 128]) {
    const options = {
      mode: 'random',
      length,
      brackets: true,
      excludeSimilar: true,
      exclude: '<>"\'',
    };
    const groups = getCharacterGroups(options);
    for (const { password, entropyBits } of generateBatch(options, 25)) {
      assert.equal(password.length, length);
      assert.ok(Number.isFinite(entropyBits));
      assert.doesNotMatch(password, /[0O1lI<>"']/);
      for (const group of groups) assert.ok([...password].some((char) => group.includes(char)));
    }
  }
});

test('invalid or impossible settings fail explicitly', () => {
  assert.throws(() => createRandomPlan(noGroups), /at least one/);
  assert.throws(() => createRandomPlan({ length: 4, brackets: true }), /at least 5/);
  assert.throws(() => createRandomPlan({ exclude: ALPHABETS.upper }), /every uppercase/);
  for (const length of [0, 3, 129, 4.5, NaN, Infinity])
    assert.throws(() => createRandomPlan({ length }), /whole number/);
  for (const count of [0, 26, 1.5]) assert.throws(() => generateBatch({}, count), /Batch size/);
  assert.throws(() => createGenerator({ mode: 'unknown' }), /Unknown/);
});

test('the complete unmodified EFF vocabulary and delimiters are unambiguous', () => {
  assert.equal(WORD_COUNT, 7776);
  assert.equal(new Set(words).size, 7776);
  assert.ok(words.every((word) => /^[a-z]+(?:-[a-z]+)*$/.test(word)));
  assert.equal(words[0], 'abacus');
  assert.equal(words.at(-1), 'zoom');
  assert.ok(words.includes('yo-yo'));
  for (const delimiter of [' ', '.', '_'])
    assert.ok(words.every((word) => !word.includes(delimiter)));
});

test('passphrase entropy comes from word choices, not printed length or capitalization', () => {
  const base = createGenerator({ mode: 'passphrase', words: 6 });
  const capitalized = createGenerator({
    mode: 'passphrase',
    words: 6,
    capitalize: true,
    separator: '.',
  });
  assert.equal(base.entropyBits, capitalized.entropyBits);
  assert.ok(Math.abs(base.entropyBits - 77.548875) < 0.00001);
  assert.equal(base.next(zero).password, Array(6).fill('abacus').join(' '));
  assert.equal(capitalized.next(zero).password, Array(6).fill('Abacus').join('.'));
  const numbered = createGenerator({
    mode: 'passphrase',
    appendNumber: true,
    words: 6,
    separator: '_',
  });
  assert.equal(numbered.entropyBits, base.entropyBits + Math.log2(1000));
  assert.ok(numbered.next(zero).password.endsWith('_000'));
  assert.throws(() => createGenerator({ mode: 'passphrase', separator: '' }), /separator/);
  assert.throws(() => createGenerator({ mode: 'passphrase', separator: '-' }), /separator/);
  assert.throws(() => createGenerator({ mode: 'passphrase', words: 11 }), /Word count/);
  const vocabulary = new Set(words);
  for (const { password } of generateBatch({ mode: 'passphrase', words: 10 }, 10)) {
    assert.ok(password.split(' ').every((word) => vocabulary.has(word)));
  }
});

test('PINs preserve leading zeros and report their small search space', () => {
  const pin = createGenerator({ mode: 'pin', length: 6 }).next(zero);
  assert.equal(pin.password, '000000');
  assert.equal(pin.entropyBits, 6 * Math.log2(10));
  assert.throws(() => createGenerator({ mode: 'pin', length: 13 }), /PIN length/);
});

test('pattern tokens, escaping, Unicode, and literal entropy work as specified', () => {
  const generated = createGenerator({ mode: 'pattern', pattern: 'Llds-\\L😀' }).next(zero);
  assert.equal(generated.password, 'Aa0!-L😀');
  assert.equal(generated.length, 7);
  assert.equal(generated.entropyBits, 2 * Math.log2(26) + Math.log2(10) + Math.log2(13));
  const payload = '<img src=x onerror=alert(1)>';
  const escaped = [...payload].map((char) => '\\' + char).join('');
  assert.equal(
    createGenerator({ mode: 'pattern', pattern: escaped + 'L' }).next(zero).password,
    payload + 'A',
  );
  for (const pattern of ['', '\\', 'L\\', 'ABC', 'L'.repeat(129), 'L\n'])
    assert.throws(() => parsePattern(pattern));
});

test('all modes fail closed if randomness is unavailable', () => {
  for (const mode of ['random', 'passphrase', 'pin', 'pattern'])
    assert.throws(() => generateBatch({ mode }, 1, {}), /Secure randomness/);
});
