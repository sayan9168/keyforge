import { ZxcvbnFactory } from '@zxcvbn-ts/core';
import * as common from '@zxcvbn-ts/language-common';
import * as english from '@zxcvbn-ts/language-en';
import { MAX_PASSWORD_LENGTH, validatePassword } from './constants.js';

const estimator = new ZxcvbnFactory({
  dictionary: { ...common.dictionary, ...english.dictionary },
  graphs: common.adjacencyGraphs,
  translations: english.translations,
  // The UI limit counts code points; zxcvbn counts UTF-16 code units.
  maxLength: MAX_PASSWORD_LENGTH * 2,
});
const PATTERN_NAMES = {
  dictionary: 'Dictionary word',
  spatial: 'Keyboard pattern',
  repeat: 'Repeated pattern',
  sequence: 'Character sequence',
  wordSequence: 'Word sequence',
  regex: 'Predictable date or number',
  date: 'Date pattern',
};

/** Return only aggregates: never echo passwords or matched substrings. */
export function analyzePassword(password) {
  validatePassword(password);
  if (!password) return null;
  const result = estimator.check(password);
  const patterns = new Set();
  for (const match of result.sequence) {
    if (PATTERN_NAMES[match.pattern]) patterns.add(PATTERN_NAMES[match.pattern]);
    if (match.dictionaryName === 'passwords') patterns.add('Common password');
    if (match.l33t) patterns.add('Predictable substitutions');
    if (match.reversed) patterns.add('Reversed word');
  }
  return {
    score: result.score,
    guessesLog10: result.guessesLog10,
    length: [...password].length,
    unique: new Set([...password]).size,
    types: {
      upper: /\p{Lu}/u.test(password),
      lower: /\p{Ll}/u.test(password),
      numbers: /\p{N}/u.test(password),
      symbols: /[^\p{L}\p{N}\s]/u.test(password),
    },
    patterns: [...patterns],
    warning: result.feedback.warning || '',
    suggestions: result.feedback.suggestions,
  };
}
