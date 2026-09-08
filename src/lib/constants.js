export const MAX_PASSWORD_LENGTH = 128;
export const SCORE_LABELS = ['Very weak', 'Weak', 'Fair', 'Strong', 'Very strong'];
export const ATTACK_SCENARIOS = Object.freeze({
  'offline-fast': {
    rate: 1e10,
    label: 'Offline · fast hash',
    detail: '10 billion guesses / second',
  },
  'offline-slow': { rate: 1e4, label: 'Offline · slow hash', detail: '10,000 guesses / second' },
  online: { rate: 100, label: 'Online · unthrottled', detail: '100 guesses / second' },
  throttled: { rate: 100 / 3600, label: 'Online · rate-limited', detail: '100 guesses / hour' },
});

export function validatePassword(password) {
  if (typeof password !== 'string') throw new TypeError('A password must be text.');
  if (password.length > MAX_PASSWORD_LENGTH * 2 || [...password].length > MAX_PASSWORD_LENGTH) {
    throw new RangeError(
      `Use at most ${MAX_PASSWORD_LENGTH} Unicode code points. Nothing has been analyzed or sent.`,
    );
  }
}

export function formatGuesses(log10) {
  if (!Number.isFinite(log10)) return '—';
  if (log10 < 4) return Math.round(10 ** log10).toLocaleString('en-US');
  return `10^${log10.toFixed(1)}`;
}

/** Illustrative guessing time, never a guarantee or an 'uncrackable' claim. */
export function formatCrackTime(log10, scenario = 'offline-fast') {
  if (!Number.isFinite(log10)) return '—';
  const attack = ATTACK_SCENARIOS[scenario];
  if (!attack) throw new RangeError('Unknown attack scenario.');
  const secondsLog = log10 - Math.log10(attack.rate);
  if (secondsLog < 0) return 'Less than a second';
  if (secondsLog >= Math.log10(31_557_600 * 1e9)) return 'Over a billion years';
  const seconds = 10 ** secondsLog;
  const units = [
    [31_557_600, 'year'],
    [86_400, 'day'],
    [3_600, 'hour'],
    [60, 'minute'],
    [1, 'second'],
  ];
  const [divisor, unit] = units.find(([divisor]) => seconds >= divisor);
  const amount = Math.floor(seconds / divisor);
  return `${amount.toLocaleString('en-US')} ${unit}${amount === 1 ? '' : 's'}`;
}

export function entropyScore(bits) {
  if (bits < 28) return 0;
  if (bits < 40) return 1;
  if (bits < 60) return 2;
  if (bits < 80) return 3;
  return 4;
}

export function compareAnalyses(a, b) {
  if (!a || !b) return 'Enter both passwords to compare.';
  const difference = a.guessesLog10 - b.guessesLog10;
  if (Math.abs(difference) < 0.05) return 'Similar estimated guess resistance.';
  return `Password ${difference > 0 ? 'A' : 'B'} has higher estimated guess resistance.`;
}
