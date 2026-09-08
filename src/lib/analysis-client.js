/** Keeps dictionary work off the main thread and discards superseded requests. */
export class AnalysisClient {
  #worker = null;
  #pending = null;
  #id = 0;
  #timers = new Map();

  check(passwords) {
    this.cancel();
    if (!this.#worker) {
      this.#worker = new Worker(new URL('../analysis.worker.js', import.meta.url), {
        type: 'module',
      });
      const worker = this.#worker;
      worker.addEventListener('message', ({ data }) => {
        if (worker !== this.#worker) return;
        clearTimeout(this.#timers.get(data.id));
        this.#timers.delete(data.id);
        if (data.id !== this.#pending?.id) return;
        const pending = this.#pending;
        this.#pending = null;
        if (data.error) pending.reject(new Error(data.error));
        else pending.resolve(data.results);
      });
      worker.addEventListener('error', () => {
        if (worker !== this.#worker) return;
        this.dispose(
          new Error('The analysis engine could not load. Reload the page and try again.'),
        );
      });
    }
    return new Promise((resolve, reject) => {
      const id = ++this.#id;
      // Keep a watchdog even for superseded work. A stuck worker must not run forever.
      const timer = setTimeout(() => {
        this.dispose(new Error('Analysis took too long. Try a shorter input.'));
      }, 12_000);
      this.#timers.set(id, timer);
      this.#pending = { id, resolve, reject };
      this.#worker.postMessage({ id, passwords });
    });
  }

  cancel(reason = new DOMException('Analysis cancelled.', 'AbortError')) {
    this.#pending?.reject(reason);
    this.#pending = null;
    // Keep the loaded dictionary worker warm, including when working offline.
    // Replies from obsolete jobs are ignored; they never overwrite newer input.
  }

  dispose(reason = new DOMException('Analysis cancelled.', 'AbortError')) {
    this.cancel(reason);
    this.#worker?.terminate();
    this.#worker = null;
    for (const timer of this.#timers.values()) clearTimeout(timer);
    this.#timers.clear();
  }
}
