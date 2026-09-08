import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { readFile } from 'node:fs/promises';

const MASK = '••••••••••••••••';
const fullSuffix = '5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8'.slice(5);
const BREACH_URL = 'https://api.pwnedpasswords.com/range/*';

async function generator(page) {
  await page.getByRole('tab', { name: 'Generator' }).click();
}
async function generate(page) {
  await page.locator('#generatePassword').click();
  await expect(page.locator('#generationStatus')).toContainText('generated with');
}
async function assertNoOverflow(page) {
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(
    true,
  );
}

test.beforeEach(async ({ page }) => {
  await page.goto('/');
});

test('loads a strict-CSP build and all local tools without external requests or script errors', async ({
  page,
}) => {
  const external = [];
  const errors = [];
  page.on('request', (request) => {
    if (!new URL(request.url()).hostname.match(/^(127\.0\.0\.1|localhost)$/))
      external.push(request.url());
  });
  page.on('pageerror', (error) => errors.push(error.message));
  page.on('console', (message) => {
    if (message.type() === 'error') errors.push(message.text());
  });
  await page.reload();
  await expect(page.locator('meta[http-equiv="Content-Security-Policy"]')).toHaveAttribute(
    'content',
    /script-src 'self'/,
  );
  await page.locator('#mainPassword').fill('password123');
  await expect(page.locator('#strengthLabel')).toHaveText('Very weak');
  await generator(page);
  await generate(page);
  await expect(page.locator('#generatedPassword')).not.toHaveText(MASK);
  await page.getByRole('tab', { name: 'Compare' }).click();
  await page.locator('#compareA').fill('password123');
  await page.locator('#compareB').fill('q6^xD8@zH2&wR9!s');
  await expect(page.locator('#comparisonVerdict')).toContainText('Password B');
  await page.getByRole('tab', { name: 'Security guide' }).click();
  await assertNoOverflow(page);
  expect(external).toEqual([]);
  expect(errors).toEqual([]);
});

test('the checker recognizes repetitions and does not silently truncate Unicode input', async ({
  page,
}) => {
  await page.locator('#mainPassword').fill('a'.repeat(40));
  await expect(page.locator('#patternTags')).toContainText('Repeated pattern');
  await expect(page.locator('#strengthLabel')).toHaveText('Very weak');
  await page.locator('#mainPassword').fill('😀'.repeat(129));
  await expect(page.locator('#checkerError')).toContainText('128 Unicode code points');
  expect([...(await page.locator('#mainPassword').inputValue())]).toHaveLength(129);
  await expect(page.locator('#strengthScore')).toHaveText('—');
  await page.locator('#mainPassword').fill('Éé١😀 ');
  await expect(page.locator('#profileLength')).toHaveText('5');
  await expect(page.locator('#profileUpper')).toHaveText('Yes');
  await page.locator('#clearChecker').click();
  await expect(page.locator('#mainPassword')).toHaveValue('');
  await expect(page.locator('#guessCount')).toHaveText('—');
});

test('changing the attack model changes only illustrative time', async ({ page }) => {
  await page.locator('#mainPassword').fill('my little rainbow');
  await expect(page.locator('#strengthScore')).not.toHaveText('—');
  const score = await page.locator('#strengthScore').textContent();
  const time = await page.locator('#crackTime').textContent();
  const analyses = await page.locator('#statAnalyzed').textContent();
  await page.locator('#attackScenario').selectOption('throttled');
  await expect(page.locator('#crackTime')).not.toHaveText(time);
  await expect(page.locator('#strengthScore')).toHaveText(score);
  await expect(page.locator('#statAnalyzed')).toHaveText(analyses);
});

test('all generation modes, presets, range controls, and validation work', async ({ page }) => {
  await generator(page);
  await page.getByRole('button', { name: 'Extra long · 32' }).click();
  await generate(page);
  expect((await page.locator('#generatedPassword').textContent()).length).toBe(32);
  await page.locator('#passwordLength').fill('4');
  await expect(page.locator('#passwordLengthRange')).toHaveValue('4');
  await expect(page.locator('#copyGenerated')).toBeDisabled();
  await page.locator('#includeBrackets').check();
  await page.locator('#generatePassword').click();
  await expect(page.locator('#generatorError')).toContainText('at least 5');
  await page.locator('#passwordLength').fill('5');
  await generate(page);
  await page.getByRole('button', { name: 'Memorable · 6 words' }).click();
  await generate(page);
  expect((await page.locator('#generatedPassword').textContent()).split(' ')).toHaveLength(6);
  await expect(page.locator('#generatedEntropy')).toHaveText('77.5 bits');
  await page.locator('#capitalizeWords').check();
  await page.locator('#wordSeparator').selectOption('_');
  await generate(page);
  await expect(page.locator('#generatedPassword')).toHaveText(/^[A-Z][a-z-]*(?:_[A-Z][a-z-]*){5}$/);
  await expect(page.locator('#generatedEntropy')).toHaveText('77.5 bits');
  await page.locator('#appendNumber').check();
  await generate(page);
  await expect(page.locator('#generatedPassword')).toHaveText(/_\d{3}$/);
  await expect(page.locator('#generatedEntropy')).toHaveText('87.5 bits');
  await page.getByRole('radio', { name: 'PIN', exact: true }).check();
  await generate(page);
  await expect(page.locator('#generatedPassword')).toHaveText(/^\d{6}$/);
  await expect(page.locator('#generatedEntropy')).toHaveText('19.9 bits');
  await page.getByRole('radio', { name: 'Pattern', exact: true }).check();
  await page.locator('#passwordPattern').fill('Lld-\\L');
  await generate(page);
  await expect(page.locator('#generatedPassword')).toHaveText(/^[A-Z][a-z]\d-L$/);
  await page.locator('#passwordPattern').fill('');
  await page.locator('#generatePassword').click();
  await expect(page.locator('#generatorError')).toContainText('Enter a pattern');
  await assertNoOverflow(page);
});

test('disabling all character sets or excluding a whole set cannot leave a stale usable password', async ({
  page,
}) => {
  await generator(page);
  await generate(page);
  await page.locator('#excludeCharacters').fill('ABCDEFGHIJKLMNOPQRSTUVWXYZ');
  await page.locator('#generatePassword').click();
  await expect(page.locator('#generatorError')).toContainText('every uppercase');
  await expect(page.locator('#copyGenerated')).toBeDisabled();
  await page.locator('#excludeCharacters').fill('');
  for (const id of ['includeUpper', 'includeLower', 'includeNumbers', 'includeSymbols'])
    await page.locator('#' + id).uncheck();
  await page.locator('#generatePassword').click();
  await expect(page.locator('#generatorError')).toContainText('at least one character set');
  await expect(page.locator('#statGenerated')).toHaveText('1');
});

test('quotes and HTML-like pattern literals remain inert across output, batch, history, and analysis', async ({
  page,
}) => {
  await generator(page);
  await page.locator('#rememberHistory').check();
  await page.getByRole('radio', { name: 'Pattern', exact: true }).check();
  const payload = `<img src=x onerror="window.__xss=1">'`;
  const pattern = [...payload].map((char) => '\\' + char).join('') + 'L';
  await page.locator('#passwordPattern').fill(pattern);
  await page.locator('#batchSize').selectOption('5');
  await generate(page);
  expect(await page.locator('#generatedPassword').textContent()).toContain(payload);
  await page.getByRole('button', { name: 'Show batch password 1', exact: true }).click();
  await expect(page.locator('#batchList .secret-value').first()).toContainText(payload);
  await page.getByRole('button', { name: 'Show history password 1', exact: true }).click();
  await expect(page.locator('#historyList .secret-value').first()).toContainText(payload);
  await expect(page.locator('#panel-generator img')).toHaveCount(0);
  expect(await page.evaluate(() => window.__xss)).toBeUndefined();
  await page.getByRole('button', { name: 'Analyze batch password 1', exact: true }).click();
  await expect(page.locator('#mainPassword')).toHaveValue(new RegExp('^<img'));
  await expect(page.locator('#strengthScore')).not.toHaveText('—');
  expect(await page.evaluate(() => window.__xss)).toBeUndefined();
});

test('history is opt-in, masked, bounded to ten, and cleared on opt-out and reload', async ({
  page,
}) => {
  await generator(page);
  await generate(page);
  await expect(page.locator('#historyList li')).toHaveCount(0);
  await page.locator('#rememberHistory').check();
  await expect(page.locator('#historyList li')).toHaveCount(0);
  await page.locator('#batchSize').selectOption('25');
  await generate(page);
  await expect(page.locator('#batchList li')).toHaveCount(25);
  await expect(page.locator('#historyList li')).toHaveCount(10);
  await expect(page.locator('#historyList .secret-value').first()).toHaveText(MASK);
  await page.locator('#rememberHistory').uncheck();
  await expect(page.locator('#historyList li')).toHaveCount(0);
  await page.locator('#rememberHistory').check();
  await generate(page);
  await page.reload();
  await generator(page);
  await expect(page.locator('#historyList li')).toHaveCount(0);
  await expect(page.locator('#rememberHistory')).not.toBeChecked();
  expect(
    await page.evaluate(() => ({
      local: localStorage.length,
      session: sessionStorage.length,
      cookies: document.cookie,
    })),
  ).toEqual({ local: 0, session: 0, cookies: '' });
});

test('copy reports success only after it succeeds, and denied clipboard access is handled', async ({
  page,
}) => {
  await page.evaluate(() =>
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: {
        writeText: async (value) => {
          window.__copiedFixture = value;
        },
      },
    }),
  );
  await generator(page);
  await generate(page);
  const secret = await page.locator('#generatedPassword').textContent();
  await page.locator('#copyGenerated').click();
  await expect(page.locator('#statCopied')).toHaveText('1');
  expect(await page.evaluate(() => window.__copiedFixture)).toBe(secret);
  await page.evaluate(() => {
    navigator.clipboard.writeText = async () => {
      throw new DOMException('Denied', 'NotAllowedError');
    };
  });
  await page.locator('#copyGenerated').click();
  await expect(page.locator('#toast')).toContainText('Copy was not allowed');
  await expect(page.locator('#statCopied')).toHaveText('1');
});

test('plaintext export requires confirmation and contains exactly the requested batch', async ({
  page,
}) => {
  await generator(page);
  await page.locator('#batchSize').selectOption('5');
  await generate(page);
  let downloads = 0;
  page.on('download', () => {
    downloads++;
  });
  await page.locator('#exportBatch').click();
  await expect(page.getByRole('dialog')).toBeVisible();
  await page.locator('#cancelExport').click();
  expect(downloads).toBe(0);
  await page.locator('#exportBatch').click();
  const event = page.waitForEvent('download');
  await page.locator('#confirmExport').click();
  const download = await event;
  expect(download.suggestedFilename()).toBe('keyforge-passwords.txt');
  const content = await readFile(await download.path(), 'utf8');
  expect(content.trimEnd().split('\n')).toHaveLength(5);
  expect(content.split('\n')[0]).toBe(await page.locator('#generatedPassword').textContent());
  await expect(page.getByRole('dialog')).not.toBeVisible();
});

test('breach checks are opt-in, explicit, padded, and bound to the exact current password', async ({
  page,
}) => {
  const requests = [];
  await page.route(BREACH_URL, async (route) => {
    requests.push(route.request());
    await route.fulfill({
      contentType: 'text/plain',
      body: `${fullSuffix}:42\r\n${'A'.repeat(35)}:0`,
    });
  });
  await page.locator('#mainPassword').fill('password');
  await expect(page.locator('#strengthScore')).not.toHaveText('—');
  await expect(page.locator('#checkBreach')).toBeDisabled();
  expect(requests).toHaveLength(0);
  await page.locator('#breachConsent').check();
  expect(requests).toHaveLength(0);
  await page.locator('#checkBreach').click();
  await expect(page.locator('#breachStatus')).toContainText('Seen 42 times');
  expect(requests).toHaveLength(1);
  expect(requests[0].url()).toBe('https://api.pwnedpasswords.com/range/5BAA6');
  expect(requests[0].headers()['add-padding']).toBe('true');
  expect(requests[0].headers()['referer']).toBeUndefined();
  expect(requests[0].headers()['cookie']).toBeUndefined();
  expect(requests[0].postData()).toBeNull();
  await page.locator('#mainPassword').fill('another-test-value');
  await expect(page.locator('#breachStatus')).toContainText('Previous results have been cleared');
  expect(requests).toHaveLength(1);
  await page.locator('#breachConsent').uncheck();
  await expect(page.locator('#checkBreach')).toBeDisabled();
});

test('a no-match response is qualified, while an API failure is never displayed as safe', async ({
  page,
}) => {
  await page.route(BREACH_URL, (route) =>
    route.fulfill({ contentType: 'text/plain', body: `${'A'.repeat(35)}:0` }),
  );
  await page.locator('#mainPassword').fill('password');
  await page.locator('#breachConsent').check();
  await page.locator('#checkBreach').click();
  await expect(page.locator('#breachStatus')).toContainText('not proof of safety');
  await page.unroute(BREACH_URL);
  await page.route(BREACH_URL, (route) =>
    route.fulfill({ status: 503, body: 'Service unavailable' }),
  );
  await page.locator('#checkBreach').click();
  await expect(page.locator('#breachStatus')).toHaveAttribute('data-state', 'error');
  await expect(page.locator('#breachStatus')).not.toContainText('No match');
});

test('an in-flight breach response cannot overwrite an edited password or a cleared session', async ({
  page,
}) => {
  let release;
  let reached;
  const arrived = new Promise((resolve) => {
    reached = resolve;
  });
  const gate = new Promise((resolve) => {
    release = resolve;
  });
  await page.route(BREACH_URL, async (route) => {
    reached();
    await gate;
    await route.fulfill({ contentType: 'text/plain', body: `${fullSuffix}:900` }).catch(() => {});
  });
  await page.locator('#mainPassword').fill('password');
  await page.locator('#breachConsent').check();
  await page.locator('#checkBreach').click();
  await arrived;
  await page.locator('#mainPassword').fill('different-test-password');
  await page.locator('#clearSession').click();
  release();
  await expect(page.locator('#breachStatus')).toHaveText(
    'Not checked. No external request has been made.',
  );
  await expect(page.locator('#mainPassword')).toHaveValue('');
  await expect(page.locator('#breachConsent')).not.toBeChecked();
  await expect(page.locator('#checkBreach')).toBeDisabled();
  await expect(page.locator('#statAnalyzed')).toHaveText('0');
});

test('Escape and backgrounding mask secrets; clear session drops outputs and history', async ({
  page,
}) => {
  await generator(page);
  await page.locator('#rememberHistory').check();
  await generate(page);
  await page.getByRole('button', { name: 'Show history password 1', exact: true }).click();
  await page.keyboard.press('Escape');
  await expect(
    page.getByRole('button', { name: 'Show history password 1', exact: true }),
  ).toBeFocused();
  await expect(page.locator('#generatedPassword')).toHaveText(MASK);
  await expect(page.locator('#historyList .secret-value').first()).toHaveText(MASK);
  await page.locator('#toggleGenerated').click();
  await page.evaluate(() => {
    Object.defineProperty(document, 'hidden', { configurable: true, get: () => true });
    document.dispatchEvent(new Event('visibilitychange'));
  });
  await expect(page.locator('#generatedPassword')).toHaveText(MASK);
  await page.locator('#clearSession').click();
  await expect(page.locator('#historyList li')).toHaveCount(0);
  await expect(page.locator('#generatedPassword')).toHaveText('Ready when you are.');
  await expect(page.locator('#statGenerated')).toHaveText('0');
  await expect(page.locator('#copyGenerated')).toBeDisabled();
  await expect(page.locator('#rememberHistory')).not.toBeChecked();
});

test('tab navigation supports arrows, Home/End, and the generation shortcut', async ({ page }) => {
  await page.locator('#tab-checker').focus();
  await page.keyboard.press('ArrowRight');
  await expect(page.locator('#tab-generator')).toBeFocused();
  await expect(page.locator('#panel-generator')).toBeVisible();
  await page.keyboard.press('End');
  await expect(page.locator('#tab-guide')).toBeFocused();
  await page.keyboard.press('Home');
  await expect(page.locator('#tab-checker')).toBeFocused();
  await page.keyboard.press('Alt+g');
  await expect(page.locator('#panel-generator')).toBeVisible();
  await expect(page.locator('#statGenerated')).toHaveText('1');
});

test('the loaded checker and generator keep working when the connection goes offline', async ({
  page,
  context,
}) => {
  await page.locator('#mainPassword').fill('password');
  await expect(page.locator('#strengthScore')).not.toHaveText('—');
  await context.setOffline(true);
  await page.locator('#mainPassword').fill('a'.repeat(30));
  await expect(page.locator('#strengthLabel')).toHaveText('Very weak');
  await expect(page.locator('#patternTags')).toContainText('Repeated pattern');
  await generator(page);
  await generate(page);
  await expect(page.locator('#generatedEntropy')).not.toHaveText('— bits');
  await context.setOffline(false);
});

test('lack of a secure context fails closed instead of generating weak fallback secrets', async ({
  page,
}) => {
  await page.addInitScript(() =>
    Object.defineProperty(window, 'isSecureContext', { configurable: true, value: false }),
  );
  await page.reload();
  await expect(page.locator('#capabilityWarning')).toBeVisible();
  await generator(page);
  await expect(page.locator('#generatePassword')).toBeDisabled();
  await expect(page.locator('#generatedPassword')).toHaveText('Ready when you are.');
});

test('all four panels meet automated WCAG AA checks and fit narrow screens', async ({ page }) => {
  for (const tab of ['Strength check', 'Generator', 'Compare', 'Security guide']) {
    await page.getByRole('tab', { name: tab }).click();
    const results = await new AxeBuilder({ page })
      .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'])
      .analyze();
    expect(results.violations, `${tab} accessibility`).toEqual([]);
    await assertNoOverflow(page);
  }
  await page.setViewportSize({ width: 320, height: 740 });
  for (const tab of ['Strength check', 'Generator', 'Compare', 'Security guide']) {
    await page.getByRole('tab', { name: tab }).click();
    await assertNoOverflow(page);
  }
});
