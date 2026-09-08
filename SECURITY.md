# Security and privacy model

KeyForge is a browser-based generation and education tool, **not a password vault or a security certification**. Do not type real passwords into an origin or browser you do not trust.

## Reporting a vulnerability

Use GitHub’s **Security → Report a vulnerability** option if private reporting is enabled for this repository. If it is not available, open an issue asking for a private reporting channel without publishing exploit details or credentials. Never include real passwords, tokens, breach responses for private passwords, or user data in a report.

The deployed site exposes a machine-readable `/.well-known/security.txt` that points to the same
channels.

## Trust boundaries

- The user must trust the app’s origin, application/dependency code, browser, extensions, and device.
- Generation uses the browser’s Web Crypto RNG. There is no insecure random fallback.
- Analysis runs in local Web Workers, not a remote service. Workers improve responsiveness; they are not a security sandbox against compromised same-origin application code.
- Have I Been Pwned is a third-party boundary contacted only after separate consent and an explicit action.
- Copying and exporting intentionally move secrets outside the page’s control.

There is no backend, account system, analytics, service worker, localStorage, sessionStorage, or IndexedDB password store.

## Cryptographic generation

`randomBigIntBelow` fills random bytes with `crypto.getRandomValues`, masks unused high bits, and rejects values outside the requested interval. It does not apply a biased remainder operation to an unrestricted sample. Missing Web Crypto is an error; the UI also requires a secure context.

Random passwords must include at least one character from every enabled character group. Groups are disjoint and are filtered before generation. Empty groups, empty selections, invalid lengths, and impossible combinations are rejected.

For length `n` and group mask `m`, the generator counts valid suffixes using:

```text
ways[0][allGroupsSeen] = 1; other base states = 0
ways[n][m] = Σ |group[g]| × ways[n−1][m ∪ {g}]
```

It draws one uniform integer below `ways[length][0]`, then un-ranks it into exactly one valid string. This avoids the non-uniform distribution from inserting required characters and randomly sorting them. The displayed entropy is `log₂(ways[length][0])`, including character requirements and exclusions. BigInt arithmetic avoids overflow; logarithms use the high significant bits.

Passphrase words are independent selections from the complete 7,776-entry EFF list. Allowed separators cannot appear inside those words. Capitalization is deterministic and adds no entropy. The optional random three-digit suffix is uniformly sampled from 000–999.

PIN and pattern entropy use the actual number of random choices, not the resulting text length. Literal pattern content adds no randomness. Batch members are independent; no uniqueness promise is made.

## Strength estimates

The local zxcvbn-ts engine uses common and English-language dictionaries, keyboard graphs, and pattern matchers. Scores and guessing effort are heuristics. They can miss other languages, personal information, leaked secrets, or attacker knowledge.

The UI does not interpret `length × log₂(character-set size)` as the actual entropy of human-chosen text. Only generated outputs receive a known generation-entropy figure. The checker and comparison receive sanitized aggregate reports, not the estimator’s echoed password or matched substrings.

Inputs are limited to 128 Unicode code points before analysis or hashing. Password input fields do not silently truncate, trim, or normalize secrets. The estimator’s internal UTF-16 limit is high enough to cover accepted inputs. Unicode code points are not the same as grapheme clusters; the English estimator may overestimate unfamiliar scripts.

Guess times are illustrative `estimated guesses / selected rate`, using configurable fixed scenarios. Hashing cost, hardware, online rate limits, and other information can materially change real resistance. No score or long time estimate proves safety.

Workers have watchdogs, stale-request identifiers, and error handling. Superseded replies cannot update a newer input. Session clearing terminates workers and drops pending references; loaded workers otherwise remain available for local/offline analysis.

## Optional breach checking

The lookup is never triggered by typing, blur, a timer, generation, or comparison.

1. The user allows the external lookup and clicks the check button.
2. Web Crypto computes SHA-1 locally over the exact UTF-8 password bytes. SHA-1 is used only because the HIBP range protocol specifies it; it is **not** being recommended for password storage.
3. A GET request sends only the first five hexadecimal hash characters to `https://api.pwnedpasswords.com/range/{prefix}`.
4. The request includes `Add-Padding: true`, `credentials: omit`, `cache: no-store`, `referrerPolicy: no-referrer`, and rejects redirects.
5. The full suffix is matched locally against the response. Zero-count padded rows do not indicate exposure. Malformed, empty, oversized, non-200, timed-out, and failed responses produce errors, never a reassuring negative result.

The service and its network/CDN providers can see the client IP and hash prefix. Padding reduces response-size disclosure but is not anonymity. The origin and browser/device may also be observable. A no-match result refers only to this dataset, not to universal safety or account-specific breach status. Occurrence counts are dataset occurrences, **not a count of breached accounts or sites**.

Editing the password, withdrawing consent, cancelling, or clearing the session invalidates and aborts an outstanding lookup. Checks also verify the current password and request revision before displaying a result. Passwords, full hashes, prefixes, and returned hash ranges are not deliberately persisted or logged by the app.

## DOM, browser, and session safeguards

- Secret-derived values are rendered with `textContent` and DOM APIs. No inline handlers, `innerHTML`, `eval`, or dynamic function construction are used. ESLint enforces these restrictions.
- The production build uses a strict CSP: scripts/styles/fonts/workers are local; external connections are limited to HIBP. No third-party script or font CDN is required. The development server intentionally omits this CSP for Vite HMR.
- The deployment adds hardened response headers (see `vercel.json`, mirrored in the Vite preview
  server): `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`,
  `X-Frame-Options: DENY`, `Cross-Origin-Opener-Policy: same-origin`,
  `Cross-Origin-Resource-Policy: same-origin`, and a restrictive `Permissions-Policy` — in
  addition to the built-in CSP meta tag (scripts/styles/fonts/workers local, connections limited
  to HIBP, `frame-ancestors 'none'`, `form-action 'none'`, `base-uri 'self'`). Other hosts should
  apply equivalent response headers.
- History is off by default, bounded to 10, held only in page memory, and masked. Opting out clears it. Opting in only retains future explicit generations.
- Backgrounding the page or pressing Escape hides revealed inputs, generated outputs, and list rows. Clear session resets fields/results/counters/consent, clears history, closes export confirmation, revokes outstanding Blob URLs, cancels requests, and terminates workers.
- Page-hide/back-forward-cache lifecycle handling also resets page secrets. This does not control external browser snapshots or extensions.
- Clipboard success is reported only after the API resolves. Clipboard failure is visible. There is no automatic delayed clipboard overwrite that could destroy something the user copied later.
- Plaintext batch export needs a separate warning and confirmation. No encrypted-vault claims are made.

JavaScript strings and garbage collection do not support guaranteed erasure. Dropping references and hiding output reduce exposure but are not forensic wiping. Clear session cannot delete clipboard-manager entries, downloaded files, OS/browser snapshots, or third-party logs from previously authorized requests.

## Verification and scope

Unit tests cover constrained sample spaces, RNG rejection, generation limits, entropy, analysis regressions, history, the hash-prefix protocol, error handling, and cancellation. Production-browser tests cover XSS-shaped literals, consent and stale responses, copy/export/session workflows, local-only requests, responsive layout, keyboard use, and automated WCAG AA checks.

API tests use synthetic fixtures and mocked HIBP responses. They do not attest to third-party uptime, live dataset completeness, cryptographic implementation auditing, or full manual accessibility conformance. The project has not received an independent security audit.
