import { analyzePassword } from './lib/analysis.js';

self.addEventListener('message', ({ data }) => {
  try {
    const results = data.passwords.map(analyzePassword);
    self.postMessage({ id: data.id, results });
  } catch {
    // Do not serialize exception objects or estimator internals containing secrets.
    self.postMessage({
      id: data.id,
      error: 'Analysis could not finish. Try a shorter input or reload the page.',
    });
  }
});
