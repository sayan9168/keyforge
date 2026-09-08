import words from '../data/eff-words.json' with { type: 'json' };
import { randomBigIntBelow, randomIndex, log2BigInt } from './random.js';

export const WORD_COUNT = words.length;
export const ALPHABETS = Object.freeze({
  upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  lower: 'abcdefghijklmnopqrstuvwxyz',
  numbers: '0123456789',
  symbols: '!@#$%^&*_-+=?~:;.,/|\\\'"<>`',
  brackets: '[]{}()',
});
const GROUP_NAMES = {
  upper: 'uppercase',
  lower: 'lowercase',
  numbers: 'number',
  symbols: 'symbol',
  brackets: 'bracket',
};
export const DEFAULT_RANDOM_OPTIONS = Object.freeze({
  length: 20,
  upper: true,
  lower: true,
  numbers: true,
  symbols: true,
  brackets: false,
  excludeSimilar: false,
  exclude: '',
});
const PATTERN_POOLS = Object.freeze({
  L: ALPHABETS.upper,
  l: ALPHABETS.lower,
  d: ALPHABETS.numbers,
  s: '!@#$%^&*_-+=?',
});

function integerInRange(value, min, max, name) {
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new RangeError(`${name} must be a whole number from ${min} to ${max}.`);
  }
}

export function getCharacterGroups(options = {}) {
  const settings = { ...DEFAULT_RANDOM_OPTIONS, ...options };
  const excluded = new Set([
    ...String(settings.exclude),
    ...(settings.excludeSimilar ? '0O1lI' : ''),
  ]);
  const groups = [];
  for (const [key, alphabet] of Object.entries(ALPHABETS)) {
    if (!settings[key]) continue;
    const pool = [...alphabet].filter((char) => !excluded.has(char)).join('');
    if (!pool) {
      throw new RangeError(
        `Exclusions remove every ${GROUP_NAMES[key]} character. Restore one or disable that set.`,
      );
    }
    groups.push(pool);
  }
  if (!groups.length) throw new RangeError('Enable at least one character set.');
  return groups;
}

/**
 * Count every valid suffix by length and already-seen group mask. Uniformly
 * unranking one cryptographic integer yields a uniform password conditioned on
 * containing every selected group, unlike 'insert required characters + sort'.
 * This also gives the actual sample-space entropy, including the constraint.
 */
export function createRandomPlan(options = {}) {
  const settings = { ...DEFAULT_RANDOM_OPTIONS, ...options };
  integerInRange(settings.length, 4, 128, 'Password length');
  const groups = getCharacterGroups(settings);
  if (settings.length < groups.length) {
    throw new RangeError(`Use at least ${groups.length} characters for the selected sets.`);
  }
  const allSeen = (1 << groups.length) - 1;
  const ways = Array.from({ length: settings.length + 1 }, () => Array(allSeen + 1).fill(0n));
  ways[0][allSeen] = 1n;
  for (let remaining = 1; remaining <= settings.length; remaining++) {
    for (let mask = 0; mask <= allSeen; mask++) {
      ways[remaining][mask] = groups.reduce(
        (sum, pool, group) => sum + BigInt(pool.length) * ways[remaining - 1][mask | (1 << group)],
        0n,
      );
    }
  }
  const possibilities = ways[settings.length][0];
  const entropyBits = log2BigInt(possibilities);
  function unrank(rank) {
    if (typeof rank !== 'bigint' || rank < 0n || rank >= possibilities) {
      throw new RangeError('Rank is outside this password space.');
    }
    let mask = 0;
    let password = '';
    for (let remaining = settings.length - 1; remaining >= 0; remaining--) {
      for (let group = 0; group < groups.length; group++) {
        const nextMask = mask | (1 << group);
        const suffixes = ways[remaining][nextMask];
        const block = BigInt(groups[group].length) * suffixes;
        if (rank >= block) {
          rank -= block;
          continue;
        }
        password += groups[group][Number(rank / suffixes)];
        rank %= suffixes;
        mask = nextMask;
        break;
      }
    }
    return password;
  }
  return {
    possibilities,
    entropyBits,
    unrank,
    next: (cryptoSource) => unrank(randomBigIntBelow(possibilities, cryptoSource)),
  };
}

export function parsePattern(pattern) {
  if (typeof pattern !== 'string' || !pattern) {
    throw new RangeError('Enter a pattern with at least one random token.');
  }
  if (pattern.length > 384)
    throw new RangeError('The generated pattern must be at most 128 characters.');
  if (/\p{Cc}/u.test(pattern))
    throw new RangeError('Control characters are not allowed in patterns.');
  const characters = [...pattern];
  const slots = [];
  for (let index = 0; index < characters.length; index++) {
    const char = characters[index];
    if (char === '\\') {
      if (index === characters.length - 1)
        throw new RangeError('A trailing backslash needs a literal character after it.');
      slots.push({ literal: characters[++index] });
    } else if (PATTERN_POOLS[char]) {
      slots.push({ pool: PATTERN_POOLS[char] });
    } else {
      slots.push({ literal: char });
    }
  }
  if (slots.length > 128)
    throw new RangeError('The generated pattern must be at most 128 characters.');
  if (!slots.some((slot) => slot.pool))
    throw new RangeError('Include at least one random token: L, l, d, or s.');
  return slots;
}

export function createGenerator(options = {}) {
  const mode = options.mode ?? 'random';
  let entropyBits;
  let next;
  if (mode === 'random') {
    ({ entropyBits, next } = createRandomPlan(options));
  } else if (mode === 'pin') {
    const length = options.length ?? 6;
    integerInRange(length, 4, 12, 'PIN length');
    entropyBits = length * Math.log2(10);
    next = (cryptoSource) => Array.from({ length }, () => randomIndex(10, cryptoSource)).join('');
  } else if (mode === 'passphrase') {
    const count = options.words ?? 6;
    const separator = options.separator ?? ' ';
    integerInRange(count, 3, 10, 'Word count');
    // These delimiters never occur in the unmodified EFF list: encoding is injective.
    if (![' ', '.', '_'].includes(separator))
      throw new RangeError('Choose a space, dot, or underscore separator.');
    entropyBits = count * Math.log2(WORD_COUNT) + (options.appendNumber ? Math.log2(1000) : 0);
    next = (cryptoSource) => {
      const selected = Array.from({ length: count }, () => {
        const word = words[randomIndex(WORD_COUNT, cryptoSource)];
        return options.capitalize ? word[0].toUpperCase() + word.slice(1) : word;
      });
      if (options.appendNumber)
        selected.push(String(randomIndex(1000, cryptoSource)).padStart(3, '0'));
      return selected.join(separator);
    };
  } else if (mode === 'pattern') {
    const slots = parsePattern(options.pattern ?? 'Llllddss-Llllddss');
    entropyBits = slots.reduce(
      (sum, slot) => sum + (slot.pool ? Math.log2(slot.pool.length) : 0),
      0,
    );
    next = (cryptoSource) =>
      slots
        .map((slot) =>
          slot.pool ? slot.pool[randomIndex(slot.pool.length, cryptoSource)] : slot.literal,
        )
        .join('');
  } else {
    throw new RangeError('Unknown generation mode.');
  }
  return {
    mode,
    entropyBits,
    next(cryptoSource = globalThis.crypto) {
      const password = next(cryptoSource);
      return { password, entropyBits, mode, length: [...password].length };
    },
  };
}

export function generateBatch(options, count = 1, cryptoSource = globalThis.crypto) {
  integerInRange(count, 1, 25, 'Batch size');
  const generator = createGenerator(options);
  // Independent draws; forcing uniqueness would change the distribution.
  return Array.from({ length: count }, () => generator.next(cryptoSource));
}
