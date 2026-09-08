# KeyForge Ultra 3.0

**Your keys. Your control.** A privacy-first password security workspace built with semantic HTML, CSS, vanilla JavaScript, and Vite. No accounts, backend, analytics, or persistent password storage.

[Production site](https://keyforge-sigma.vercel.app/) · [Security model](SECURITY.md) · [Privacy policy](https://keyforge-sigma.vercel.app/privacy.html) · [Third-party credits](public/credits.txt)

KeyForge Ultra is a product of **Sayanox Private Limited**. Owner and lead developer: **Sayan**
(GitHub: [sayan9168](https://github.com/sayan9168)).

## What’s new

- **Secure generation:** Web Crypto randomness in every mode, with rejection sampling instead of modulo bias or `Math.random()`.
- **Four modes:** random passwords (4–128 characters), EFF passphrases (3–10 words, six by default), PINs (4–12 digits), and escaped patterns.
- **Advanced controls:** presets, mandatory character groups, lookalike/custom exclusions, passphrase separators, capitalization, and optional random digits.
- **Honest entropy:** generator entropy comes from its actual output space. The random generator uniformly samples strings satisfying every selected group, and accounts for those constraints in its entropy.
- **Pattern-aware analysis:** local zxcvbn-ts dictionaries and keyboard graphs run in a lazy-loaded Web Worker. Comparisons use estimated guessing effort rather than length alone.
- **Attack scenarios:** compare illustrative offline fast/slow hashing and online throttled/unthrottled guessing rates. No “uncrackable” guarantees.
- **Optional breach lookup:** explicit consent **and** a button click, a five-character SHA-1 prefix, padded responses, no cookies/referrer/cache, cancellation, and stale-result protection.
- **Batch tools:** generate 1, 5, 10, or 25 passwords; copy/analyze individual results; export plaintext only after a separate warning and confirmation.
- **Session controls:** opt-in, masked, memory-only history (last 10); hide secrets on backgrounding or Escape; clear the session without pretending to erase the clipboard or saved files.
- **Accessible UI:** responsive layout, native inputs, labeled reveal buttons, roving keyboard tabs, visible focus, reduced-motion support, and locally hosted fonts.

## Run locally

Use **Node.js 22.13+ (22 LTS recommended)** and npm.

```sh
npm ci
npm run dev
```

Open the URL printed by Vite. The dev server binds to `0.0.0.0:5173` and accepts Arena’s `*.e2b.app` preview hosts. Browser-facing code uses relative local asset URLs; it never calls a backend at `localhost`.

Use HTTPS on a hosted site. Browsers also treat loopback development origins as secure contexts. Do not open `index.html` directly as a file: Vite resolves the modules and bundled assets.

```sh
npm run build
npm run preview
```

The production output is in `dist/` (not committed). `vercel.json` configures the Vite build and security headers for the existing Vercel deployment. Other static hosts can serve `dist/`; the built HTML contains a strict Content Security Policy. Serve proper JavaScript MIME types and use HTTPS.

**A branch push is not a production deployment or a merge into `main`.** Vercel deployment behavior depends on the repository’s Git integration and production-branch settings.

## Tests and quality checks

```sh
npm run lint
npm run format:check
npm test
npm run build
npx playwright install --with-deps chromium
npm run test:e2e
```

Or run `npm run test:all` after installing the browser. The browser tests exercise the **production build**, not the development server, on desktop and mobile Chromium. They include automated WCAG AA checks with axe-core.

Tests cover exact constrained output spaces, secure RNG rejection, every generator mode, Unicode boundaries, pattern escaping/XSS regressions, model weaknesses, history lifecycle, clipboard failure, export confirmation, opt-in/padded breach lookups, cancellation races, offline use of a loaded engine, keyboard interaction, and narrow viewports. Breach calls are mocked; tests never submit real passwords to an external service.

GitHub Actions runs formatting, linting, unit tests, build, and browser tests on pushes and pull requests. Test artifacts contain only synthetic fixtures/generated test data and are excluded from Git.

For a constrained environment with an existing Chromium executable, set `PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH`. The normal setup does not need this override.

## How generation works

| Mode       | Defaults                                  | Entropy source                                                        |
| ---------- | ----------------------------------------- | --------------------------------------------------------------------- |
| Random     | 20 characters; upper/lower/digits/symbols | Log₂ of valid strings containing every selected group                 |
| Passphrase | Six words, separated by spaces            | Six independent choices from 7,776 EFF words: approximately 77.5 bits |
| PIN        | Six digits, leading zeros preserved       | 10⁶ possible PINs: approximately 19.9 bits                            |
| Pattern    | `Llllddss-Llllddss`                       | Sum of log₂ of each random token’s alphabet size                      |

Pattern tokens are `L` (uppercase), `l` (lowercase), `d` (digit), and `s` (symbol). Other characters are literal; `\L` emits a literal `L`, and `\\` emits one backslash. Empty, all-literal, dangling-escape, control-character, and oversized patterns are rejected. Literal text adds no entropy.

Passphrase separators are space, dot, or underscore. These do not occur inside the unmodified EFF words, so distinct word sequences remain distinct outputs. Predictable capitalization adds no entropy; an optional three-digit random suffix adds log₂(1,000) bits. Independent draws can repeat, especially with small PIN spaces; batches are not silently deduplicated.

Changing settings clears the current output and batch rather than leaving an old, copyable password under new settings. Only explicit generation adds to the session count or opted-in history. Enabling history does not retroactively capture earlier outputs.

## Privacy and limitations

- Passwords, hashes, and results are not placed in browser storage, logs, URLs, or analytics. Local dictionaries and fonts are packaged with the app.
- The generator works after the app loads; the checker/comparison workers need to load once before working offline. This is **not** an installable PWA or an offline-reload guarantee. Clearing a session terminates workers, which may need a connection to load again.
- Breach checking is the only external API feature. HIBP receives a hash prefix and the connection’s IP address, not a full password/hash. K-anonymity reduces disclosure; it does not provide anonymity. A missing match is **not proof of safety**.
- zxcvbn’s English/common dictionaries do not model every language, personal detail, or attacker. Human-entered text is shown with guess estimates, **not claimed entropy**. Unicode length counts code points, not user-perceived grapheme clusters. Inputs over 128 code points are rejected without truncation or normalization.
- An exposed password must be replaced even if its model score is high. Use unique passwords and a reputable password manager; prefer passkeys/security keys or enable MFA.
- A compromised browser, extension, device, or site can still read secrets. JavaScript cannot guarantee forensic memory erasure. Clipboard histories and downloaded plaintext files are outside the session-clear mechanism.

See [SECURITY.md](SECURITY.md) for the threat model and implementation details. This project has automated regression coverage, **not an independent security audit**.

## Project layout

```text
index.html                  Semantic interface, no inline event handlers
src/main.js                 UI, session lifecycle, consent, and safe DOM rendering
src/styles.css              Responsive styling and locally bundled fonts
src/lib/random.js           Unbiased Web Crypto integer sampling
src/lib/generator.js        Constrained sampling, passphrases, PINs, patterns
src/lib/analysis.js         Local zxcvbn-ts setup; secret-free aggregate reports
src/lib/analysis-client.js  Worker lifecycle and stale-response protection
src/analysis.worker.js      Off-main-thread analysis
src/lib/breach.js           Opt-in padded HIBP range protocol
src/lib/history.js          Bounded, opt-in in-memory history
src/data/                  EFF vocabulary and provenance
public/                    Favicon, share card, SEO files, privacy page, security.txt
tests/                    Unit and production-browser regression tests
```

## Search-engine optimization and Google indexing

KeyForge is published by **Sayanox Private Limited** with full crawl/index metadata. The home page
carries the Google Search Console verification tag:

```html
<meta name="google-site-verification" content="uyb7Y9wXsprQjKNrrv9c71J_s-F7AOYX7fBlZJFEY5c" />
```

Ready for Google and other search engines:

- `robots.txt` — allow crawling, points to the sitemaps.
- `sitemap.xml` / `sitemap-index.xml` — single canonical sitemap with `lastmod` and the
  `social-card.png` image entry.
- Structured data (schema.org `WebSite`, `Organization`, `SoftwareApplication`, `Person`) in
  `index.html` maps KeyForge, Sayanox Private Limited, and owner Sayan (sayan9168).
- Open Graph / Twitter cards (`social-card.png`, 1200×630) for rich link previews.
- Descriptive, keyword-aligned `title`, `description`, canonical URL, and index/follow robots
  directives; `humans.txt` and `.well-known/security.txt` for attribution and vulnerability
  contact.
- `privacy.html` — a crawlable, styled privacy policy under the Sayanox brand.

If the production domain ever changes from `keyforge-sigma.vercel.app`, update the canonical URL,
`og:url`, sitemap URLs, and structured-data URLs before redeploying.

### After deploying

1. Push/merge to the production branch so Vercel deploys the new build.
2. In [Google Search Console](https://search.google.com/search-console), add the property
   `https://keyforge-sigma.vercel.app/` and verify it (the meta tag above is already on the page).
3. Submit `https://keyforge-sigma.vercel.app/sitemap-index.xml` in **Sitemaps**.
4. Later, use **URL Inspection** to request indexing of the homepage after crawlers have seen it.

The site is fully static with no server-side secrets, so the deployment above is all the
"backend" work required. To keep the index current, every HTML page also stays in sync with the
security headers defined in `vercel.json`.

## License

Application code is [MIT](LICENSE), © 2026 Sayan (Sayanox Private Limited). The EFF wordlist, fonts, and bundled dictionaries retain their respective licenses and attribution; see [credits](public/credits.txt) and [wordlist provenance](src/data/README.md).
