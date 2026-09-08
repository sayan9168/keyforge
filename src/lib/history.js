/** Opt-in, bounded, page-memory-only history. Never uses browser storage. */
export class SessionHistory {
  #enabled = false;
  #items = [];
  #nextId = 0;

  get enabled() {
    return this.#enabled;
  }

  get items() {
    return this.#items.map((item) => ({ ...item }));
  }

  setEnabled(enabled) {
    this.#enabled = Boolean(enabled);
    if (!this.#enabled) this.clear();
  }

  add(results) {
    if (!this.#enabled) return;
    for (const result of results) {
      this.#items.unshift({ ...result, id: ++this.#nextId });
    }
    this.#items = this.#items.slice(0, 10);
  }

  clear() {
    this.#items = [];
  }
}
