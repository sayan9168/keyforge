import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { checkBreach, parseRangeResponse } from '../../src/lib/breach.js';

const HASH = '5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8'; // Public test fixture: 'password'.
const SUFFIX = HASH.slice(5);
const PADDING = `${'A'.repeat(35)}:0`;
const response = (body, status = 200) => ({ status, text: async () => body });

test('requires consent before hashing or making a request', async () => {
  let called = false;
  await assert.rejects(
    checkBreach('password', {
      fetchImpl: () => {
        called = true;
      },
    }),
    { code: 'consent' },
  );
  assert.equal(called, false);
  await assert.rejects(checkBreach('password', { consent: 'false' }), { code: 'consent' });
  await assert.rejects(checkBreach('', { consent: true }), { code: 'empty' });
  await assert.rejects(checkBreach('x'.repeat(129), { consent: true }), /128/);
  await assert.rejects(checkBreach('password', { consent: true, cryptoSource: {} }), {
    code: 'unavailable',
  });
});

test('only a 5-character prefix leaves the device, with padding and privacy headers', async () => {
  let calls = 0;
  const result = await checkBreach('password', {
    consent: true,
    fetchImpl: async (url, options) => {
      calls++;
      assert.equal(url, 'https://api.pwnedpasswords.com/range/5BAA6');
      assert.deepEqual(options.headers, { 'Add-Padding': 'true' });
      assert.equal(options.credentials, 'omit');
      assert.equal(options.cache, 'no-store');
      assert.equal(options.referrerPolicy, 'no-referrer');
      assert.equal(options.redirect, 'error');
      assert.equal(options.method, 'GET');
      assert.equal(options.body, undefined);
      assert.ok(!JSON.stringify([url, options]).includes(HASH));
      assert.ok(!JSON.stringify([url, options]).includes(SUFFIX));
      return response(`${PADDING}\r\n${SUFFIX}:42\r\n`);
    },
  });
  assert.equal(calls, 1);
  assert.deepEqual(result, { found: true, count: 42 });
});

test('hashes the exact UTF-8 bytes, preserving whitespace and Unicode normalization', async () => {
  for (const password of [' password ', 'é', 'e\u0301', '😀']) {
    const hash = createHash('sha1').update(password, 'utf8').digest('hex').toUpperCase();
    const result = await checkBreach(password, {
      consent: true,
      fetchImpl: async (url) => {
        assert.ok(url.endsWith(hash.slice(0, 5)));
        return response(`${hash.slice(5)}:7`);
      },
    });
    assert.equal(result.count, 7);
  }
});

test('padding is not a breach and malformed responses are never treated as no match', () => {
  assert.deepEqual(parseRangeResponse(`${SUFFIX}:0`, SUFFIX), { found: false, count: 0 });
  assert.deepEqual(parseRangeResponse(PADDING, SUFFIX), { found: false, count: 0 });
  assert.deepEqual(parseRangeResponse(`${SUFFIX.toLowerCase()}:5\n${SUFFIX}:0`, SUFFIX), {
    found: true,
    count: 5,
  });
  for (const body of [
    '',
    ' ',
    '<html>Oops</html>',
    'BAD:3',
    `${SUFFIX}:-1`,
    `${SUFFIX}:9007199254740992`,
    `${SUFFIX}:1\nmalformed`,
  ]) {
    assert.throws(() => parseRangeResponse(body, SUFFIX), { code: 'response' });
  }
  assert.throws(() => parseRangeResponse(PADDING, '123'), TypeError);
});

test('network errors, rate limits, invalid bodies, and non-200 statuses remain errors', async () => {
  await assert.rejects(
    checkBreach('password', {
      consent: true,
      fetchImpl: async () => {
        throw new TypeError('offline');
      },
    }),
    { code: 'network' },
  );
  await assert.rejects(
    checkBreach('password', { consent: true, fetchImpl: async () => response('', 429) }),
    { code: 'rate-limit' },
  );
  for (const status of [204, 404, 500, 503]) {
    await assert.rejects(
      checkBreach('password', { consent: true, fetchImpl: async () => response('', status) }),
      { code: 'service' },
    );
  }
  await assert.rejects(
    checkBreach('password', { consent: true, fetchImpl: async () => response('') }),
    { code: 'response' },
  );
});

test('pre-aborted and mid-hash aborted checks cannot issue a request', async () => {
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(checkBreach('password', { consent: true, signal: controller.signal }), {
    name: 'AbortError',
  });
  const midHash = new AbortController();
  let fetched = false;
  await assert.rejects(
    checkBreach('password', {
      consent: true,
      signal: midHash.signal,
      cryptoSource: {
        subtle: {
          digest: async () => {
            midHash.abort();
            return new Uint8Array(20).buffer;
          },
        },
      },
      fetchImpl: () => {
        fetched = true;
      },
    }),
    { name: 'AbortError' },
  );
  assert.equal(fetched, false);
});

test('a stalled request times out and cancellation is distinct from a negative match', async () => {
  const hang = (_url, { signal }) =>
    new Promise((_resolve, reject) =>
      signal.addEventListener('abort', () => reject(signal.reason), { once: true }),
    );
  await assert.rejects(checkBreach('password', { consent: true, timeoutMs: 20, fetchImpl: hang }), {
    code: 'timeout',
  });
  const controller = new AbortController();
  const fetchImpl = (...args) => {
    const pending = hang(...args);
    controller.abort();
    return pending;
  };
  await assert.rejects(
    checkBreach('password', { consent: true, signal: controller.signal, fetchImpl }),
    { name: 'AbortError' },
  );
});

test('an abort after a response also discards the result', async () => {
  const controller = new AbortController();
  await assert.rejects(
    checkBreach('password', {
      consent: true,
      signal: controller.signal,
      fetchImpl: async () => ({
        status: 200,
        text: async () => {
          controller.abort();
          return `${SUFFIX}:42`;
        },
      }),
    }),
    { name: 'AbortError' },
  );
});
