const CRYPTO_ERROR =
  'Secure randomness is unavailable. Use a modern browser over HTTPS; no insecure fallback is used.';

/** An unbiased integer in [0, limit). Rejection avoids modulo bias. */
export function randomBigIntBelow(limit, cryptoSource = globalThis.crypto) {
  if (typeof limit !== 'bigint' || limit < 1n) {
    throw new RangeError('The random bound must be a positive bigint.');
  }
  if (typeof cryptoSource?.getRandomValues !== 'function') {
    throw new Error(CRYPTO_ERROR);
  }
  if (limit === 1n) return 0n;

  const bits = (limit - 1n).toString(2).length;
  const bytes = new Uint8Array(Math.ceil(bits / 8));
  const mask = 0xff >>> (bytes.length * 8 - bits);
  let value;
  do {
    cryptoSource.getRandomValues(bytes);
    bytes[0] &= mask;
    value = bytes.reduce((result, byte) => (result << 8n) | BigInt(byte), 0n);
  } while (value >= limit);
  bytes.fill(0);
  return value;
}

export function randomIndex(size, cryptoSource = globalThis.crypto) {
  if (!Number.isSafeInteger(size) || size < 1) {
    throw new RangeError('The collection must have a positive, safe integer size.');
  }
  return Number(randomBigIntBelow(BigInt(size), cryptoSource));
}

/** Logarithm without converting a potentially enormous bigint to Infinity. */
export function log2BigInt(value) {
  if (typeof value !== 'bigint' || value < 1n) {
    throw new RangeError('The value must be a positive bigint.');
  }
  const shift = Math.max(0, value.toString(2).length - 53);
  return Math.log2(Number(value >> BigInt(shift))) + shift;
}
