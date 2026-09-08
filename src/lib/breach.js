import { validatePassword } from './constants.js';

export class BreachError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'BreachError';
    this.code = code;
  }
}

export function parseRangeResponse(body, suffix) {
  if (!/^[A-F0-9]{35}$/i.test(suffix)) throw new TypeError('Invalid hash suffix.');
  if (typeof body !== 'string' || !body.trim() || body.length > 2_000_000) {
    throw new BreachError(
      'response',
      'The service returned an invalid response. No result is available.',
    );
  }
  let count = 0;
  for (const line of body.trim().split(/\r?\n/u)) {
    const match = /^([A-F0-9]{35}):(\d+)$/iu.exec(line);
    if (!match || !Number.isSafeInteger(Number(match[2]))) {
      throw new BreachError(
        'response',
        'The service returned an invalid response. No result is available.',
      );
    }
    if (match[1].toUpperCase() === suffix.toUpperCase()) count = Math.max(count, Number(match[2]));
  }
  // Zero-count records are padding, not evidence of exposure.
  return { found: count > 0, count };
}

/** Explicit consent only. Never call this on input, blur, or a timer. */
export async function checkBreach(
  password,
  {
    consent = false,
    signal,
    timeoutMs = 10_000,
    fetchImpl = globalThis.fetch,
    cryptoSource = globalThis.crypto,
  } = {},
) {
  if (consent !== true)
    throw new BreachError('consent', 'Allow the external lookup before checking.');
  validatePassword(password);
  if (!password) throw new BreachError('empty', 'Enter a password first.');
  if (!cryptoSource?.subtle || typeof fetchImpl !== 'function') {
    throw new BreachError('unavailable', 'Breach checking needs a modern browser over HTTPS.');
  }
  signal?.throwIfAborted();
  const controller = new AbortController();
  const abort = () => controller.abort(signal.reason);
  signal?.addEventListener('abort', abort, { once: true });
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, timeoutMs);
  try {
    // SHA-1 is required by this lookup protocol, NOT used for password storage.
    const bytes = new TextEncoder().encode(password);
    let digest;
    try {
      digest = new Uint8Array(await cryptoSource.subtle.digest('SHA-1', bytes));
    } finally {
      bytes.fill(0);
    }
    controller.signal.throwIfAborted();
    const hash = Array.from(digest, (byte) => byte.toString(16).padStart(2, '0'))
      .join('')
      .toUpperCase();
    digest.fill(0);
    const response = await fetchImpl(`https://api.pwnedpasswords.com/range/${hash.slice(0, 5)}`, {
      method: 'GET',
      headers: { 'Add-Padding': 'true' },
      credentials: 'omit',
      cache: 'no-store',
      referrerPolicy: 'no-referrer',
      redirect: 'error',
      mode: 'cors',
      signal: controller.signal,
    });
    if (response.status === 429)
      throw new BreachError('rate-limit', 'The service is busy. Wait a moment, then try again.');
    if (response.status !== 200)
      throw new BreachError('service', 'The breach service is unavailable. Try again later.');
    const body = await response.text();
    controller.signal.throwIfAborted();
    return parseRangeResponse(body, hash.slice(5));
  } catch (error) {
    if (signal?.aborted) throw signal.reason;
    if (timedOut)
      throw new BreachError(
        'timeout',
        'The lookup timed out. Try again when your connection is stable.',
      );
    if (error instanceof BreachError) throw error;
    throw new BreachError(
      'network',
      'Could not reach the breach service. Check your connection and try again.',
    );
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener('abort', abort);
  }
}
