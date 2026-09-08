import assert from 'node:assert/strict';
import test from 'node:test';
import { AnalysisClient } from '../../src/lib/analysis-client.js';

function harness(t) {
  const original = globalThis.Worker;
  const instances = [];
  class FakeWorker {
    listeners = new Map();
    messages = [];
    terminated = false;
    constructor() {
      instances.push(this);
    }
    addEventListener(name, handler) {
      this.listeners.set(name, handler);
    }
    postMessage(data) {
      this.messages.push(data);
    }
    terminate() {
      this.terminated = true;
    }
    deliver(id, results) {
      this.listeners.get('message')({ data: { id, results } });
    }
    fail() {
      this.listeners.get('error')();
    }
  }
  globalThis.Worker = FakeWorker;
  const client = new AnalysisClient();
  t.after(() => {
    client.dispose();
    if (original) globalThis.Worker = original;
    else delete globalThis.Worker;
  });
  return { client, instances };
}

test('keeps a warm worker and ignores superseded replies', async (t) => {
  const { client, instances } = harness(t);
  const first = client.check(['old-fixture']);
  const firstRejection = assert.rejects(first, { name: 'AbortError' });
  client.cancel();
  await firstRejection;
  const next = client.check(['new-fixture']);
  assert.equal(instances.length, 1);
  const worker = instances[0];
  assert.equal(worker.terminated, false);
  worker.deliver(worker.messages[0].id, [{ score: 0 }]);
  worker.deliver(worker.messages[1].id, [{ score: 3 }]);
  assert.deepEqual(await next, [{ score: 3 }]);
  const third = client.check(['another-fixture']);
  worker.deliver(worker.messages[2].id, [{ score: 2 }]);
  assert.deepEqual(await third, [{ score: 2 }]);
  assert.equal(instances.length, 1);
});

test('session disposal terminates workers and stale errors cannot kill a replacement', async (t) => {
  const { client, instances } = harness(t);
  const old = client.check(['old-fixture']);
  const oldRejection = assert.rejects(old, { name: 'AbortError' });
  client.dispose();
  await oldRejection;
  assert.equal(instances[0].terminated, true);
  const next = client.check(['new-fixture']);
  instances[0].fail();
  instances[0].deliver(1, [{ score: 0 }]);
  assert.equal(instances[1].terminated, false);
  instances[1].deliver(instances[1].messages[0].id, [{ score: 4 }]);
  assert.deepEqual(await next, [{ score: 4 }]);
});

test('worker load errors reject with a non-secret message and allow recovery', async (t) => {
  const { client, instances } = harness(t);
  const failed = client.check(['private-test-fixture']);
  const rejection = assert.rejects(failed, /analysis engine could not load/);
  instances[0].fail();
  await rejection;
  assert.equal(instances[0].terminated, true);
  const next = client.check(['new-fixture']);
  instances[1].deliver(instances[1].messages[0].id, [{ score: 2 }]);
  assert.deepEqual(await next, [{ score: 2 }]);
});
