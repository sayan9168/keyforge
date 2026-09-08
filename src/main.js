import './styles.css';
import { generateBatch, DEFAULT_RANDOM_OPTIONS } from './lib/generator.js';
import { SessionHistory } from './lib/history.js';
import { AnalysisClient } from './lib/analysis-client.js';
import { checkBreach } from './lib/breach.js';
import {
  ATTACK_SCENARIOS,
  MAX_PASSWORD_LENGTH,
  SCORE_LABELS,
  compareAnalyses,
  entropyScore,
  formatCrackTime,
  formatGuesses,
  validatePassword,
} from './lib/constants.js';

const $ = (id) => document.getElementById(id);
const all = (selector) => [...document.querySelectorAll(selector)];
const SVG_NS = 'http://www.w3.org/2000/svg';
const MASK = '••••••••••••••••';
const INPUT_NAMES = {
  mainPassword: 'password to analyze',
  compareA: 'password A',
  compareB: 'password B',
};
const history = new SessionHistory();
const checker = new AnalysisClient();
const comparison = new AnalysisClient();
const stats = { analyzed: 0, generated: 0, copied: 0 };
let sessionEpoch = 0;
let activeTab = 'checker';
let batch = [];
let outputVisible = true;
let checkerResult = null;
let compareResults = [null, null];
let checkerRevision = 0;
let compareRevision = 0;
let checkerTimer;
let compareTimer;
let toastTimer;
let breachRevision = 0;
let breachController = null;
let breachAttempted = false;
const downloadUrls = new Map();

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function paintIcon(container, name) {
  container.dataset.icon = name;
  const svg = document.createElementNS(SVG_NS, 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('aria-hidden', 'true');
  const use = document.createElementNS(SVG_NS, 'use');
  use.setAttribute('href', `${import.meta.env.BASE_URL}icons.svg#${name}`);
  svg.append(use);
  container.replaceChildren(svg);
}

function icon(name) {
  const node = element('span');
  node.setAttribute('aria-hidden', 'true');
  paintIcon(node, name);
  return node;
}

function notify(message) {
  clearTimeout(toastTimer);
  $('toast').textContent = message;
  $('toast').dataset.visible = 'true';
  toastTimer = setTimeout(() => {
    $('toast').dataset.visible = 'false';
    $('toast').textContent = '';
  }, 4500);
}

function setError(id, message = '') {
  $(id).textContent = message;
  $(id).hidden = !message;
}

function updateStats(key, amount = 1) {
  if (key) stats[key] += amount;
  for (const [name, value] of Object.entries(stats)) {
    $(`stat${name[0].toUpperCase()}${name.slice(1)}`).textContent = value.toLocaleString('en-US');
  }
}

function revealInput(id, visible) {
  $(id).type = visible ? 'text' : 'password';
  const button = document.querySelector(`[data-reveal="${id}"]`);
  button.setAttribute('aria-pressed', String(visible));
  button.setAttribute('aria-label', `${visible ? 'Hide' : 'Show'} ${INPUT_NAMES[id]}`);
  paintIcon(button.querySelector('[data-icon]'), visible ? 'eye-off' : 'eye');
}

function hideSecrets() {
  Object.keys(INPUT_NAMES).forEach((id) => revealInput(id, false));
  outputVisible = false;
  renderOutput();
  // Mask existing rows in place so Escape never destroys keyboard focus.
  all('.secret-value').forEach((node) => {
    node.textContent = MASK;
    node.dataset.masked = 'true';
  });
  all('[data-secret-reveal]').forEach((button) => {
    button.textContent = 'Show';
    button.setAttribute('aria-pressed', 'false');
    button.setAttribute('aria-label', button.getAttribute('aria-label').replace(/^Hide/u, 'Show'));
  });
}

function switchTab(name, focus = false) {
  if (!$(`tab-${name}`)) return;
  if (name !== activeTab) hideSecrets();
  activeTab = name;
  all('[data-tab]').forEach((tab) => {
    const selected = tab.dataset.tab === name;
    tab.setAttribute('aria-selected', String(selected));
    tab.tabIndex = selected ? 0 : -1;
    $(tab.getAttribute('aria-controls')).hidden = !selected;
  });
  if (focus) $(`tab-${name}`).focus();
}

async function copySecret(password) {
  const epoch = sessionEpoch;
  try {
    if (typeof navigator.clipboard?.writeText !== 'function')
      throw new Error('Clipboard unavailable.');
    await navigator.clipboard.writeText(password);
    if (epoch !== sessionEpoch) return;
    updateStats('copied');
    notify('Copied. Your clipboard may retain this password.');
  } catch {
    if (epoch !== sessionEpoch) return;
    notify('Copy was not allowed. Show the password, then select and copy it manually.');
  }
}

function renderChecker(result, loading = false) {
  $('checkerResults').dataset.score = result ? String(result.score) : 'empty';
  $('checkerResults').setAttribute('aria-busy', String(loading));
  $('strengthLabel').textContent = result
    ? SCORE_LABELS[result.score]
    : loading
      ? 'Analyzing locally…'
      : 'Waiting for a password';
  $('strengthScore').textContent = result ? String(result.score) : '—';
  $('strengthMeter').setAttribute('aria-valuenow', String(result?.score ?? 0));
  $('strengthMeter').setAttribute(
    'aria-valuetext',
    result ? `${SCORE_LABELS[result.score]}, ${result.score} out of 4` : 'No result yet',
  );
  [...$('strengthMeter').children].forEach((segment, index) => {
    segment.dataset.filled = String(Boolean(result && index <= result.score));
  });
  $('analysisStatus').textContent = result
    ? `${SCORE_LABELS[result.score]} · ${result.score} out of 4. Estimated locally, not a guarantee.`
    : loading
      ? 'Working in an isolated local worker…'
      : 'A local, pattern-aware estimate. Not a security guarantee.';
  $('guessCount').textContent = result ? formatGuesses(result.guessesLog10) : '—';
  $('crackTime').textContent = result
    ? formatCrackTime(result.guessesLog10, $('attackScenario').value)
    : '—';
  $('profileLength').textContent = result ? String(result.length) : '—';
  $('profileUnique').textContent = result ? String(result.unique) : '—';
  for (const name of ['upper', 'lower', 'numbers', 'symbols']) {
    const node = $(`profile${name[0].toUpperCase()}${name.slice(1)}`);
    node.textContent = result ? (result.types[name] ? 'Yes' : 'No') : '—';
    node.dataset.present = String(Boolean(result?.types[name]));
  }
  $('patternTags').replaceChildren();
  if (result) {
    for (const pattern of result.patterns)
      $('patternTags').append(element('span', 'pattern-tag', pattern));
    if (!result.patterns.length) {
      const tag = element('span', 'pattern-tag', 'No obvious patterns detected');
      tag.dataset.tone = 'neutral';
      $('patternTags').append(tag);
    }
  }
  $('feedbackSummary').textContent = result
    ? result.warning ||
      'No obvious weak patterns were found. Keep it unique and enable a second factor; this model cannot know every attack strategy.'
    : 'Common words, repeated characters, dates, and keyboard patterns can make a long password surprisingly predictable.';
  $('feedbackSuggestions').replaceChildren(
    ...(result?.suggestions ?? []).map((suggestion) => element('li', '', suggestion)),
  );
}

function scheduleChecker(delay = 240) {
  const revision = ++checkerRevision;
  clearTimeout(checkerTimer);
  checker.cancel();
  checkerResult = null;
  const password = $('mainPassword').value;
  $('characterCount').textContent =
    `${password.length > MAX_PASSWORD_LENGTH * 2 ? '128+' : [...password].length} / 128`;
  resetBreach(
    breachAttempted
      ? 'Not checked for this password. Previous results have been cleared.'
      : 'Not checked. No external request has been made.',
  );
  setError('checkerError');
  $('mainPassword').setAttribute('aria-invalid', 'false');
  renderChecker(null);
  try {
    validatePassword(password);
  } catch (error) {
    setError('checkerError', error.message);
    $('mainPassword').setAttribute('aria-invalid', 'true');
    return;
  }
  if (!password) return;
  renderChecker(null, true);
  checkerTimer = setTimeout(async () => {
    try {
      const [result] = await checker.check([password]);
      if (revision !== checkerRevision) return;
      checkerResult = result;
      renderChecker(result);
      updateStats('analyzed');
    } catch (error) {
      if (revision !== checkerRevision || error.name === 'AbortError') return;
      renderChecker(null);
      setError('checkerError', error.message);
    }
  }, delay);
}

function sendToChecker(password) {
  $('mainPassword').value = password;
  revealInput('mainPassword', false);
  switchTab('checker');
  scheduleChecker(0);
  $('mainPassword').focus();
}

function renderComparison() {
  $('comparisonVerdict').textContent = compareAnalyses(...compareResults);
  compareResults.forEach((result, index) => {
    const letter = index === 0 ? 'A' : 'B';
    $(`compareScore${letter}`).textContent = result
      ? `${SCORE_LABELS[result.score]} (${result.score}/4)`
      : '—';
    $(`compareScore${letter}`).dataset.score = result ? String(result.score) : 'empty';
    $(`compareGuesses${letter}`).textContent = result ? formatGuesses(result.guessesLog10) : '—';
    $(`compareTime${letter}`).textContent = result
      ? formatCrackTime(result.guessesLog10, $('attackScenario').value)
      : '—';
    $(`compareLength${letter}`).textContent = result ? String(result.length) : '—';
    $(`compareUnique${letter}`).textContent = result ? String(result.unique) : '—';
  });
}

function scheduleComparison() {
  const revision = ++compareRevision;
  clearTimeout(compareTimer);
  comparison.cancel();
  compareResults = [null, null];
  renderComparison();
  setError('compareError');
  const passwords = [$('compareA').value, $('compareB').value];
  for (let index = 0; index < passwords.length; index++) {
    const input = $(index === 0 ? 'compareA' : 'compareB');
    input.setAttribute('aria-invalid', 'false');
    try {
      validatePassword(passwords[index]);
    } catch (error) {
      input.setAttribute('aria-invalid', 'true');
      setError('compareError', `Password ${index === 0 ? 'A' : 'B'}: ${error.message}`);
      return;
    }
  }
  if (passwords.some((password) => !password)) return;
  $('comparisonVerdict').textContent = 'Comparing locally…';
  compareTimer = setTimeout(async () => {
    try {
      const results = await comparison.check(passwords);
      if (revision !== compareRevision) return;
      compareResults = results;
      renderComparison();
      updateStats('analyzed', 2);
    } catch (error) {
      if (revision !== compareRevision || error.name === 'AbortError') return;
      renderComparison();
      setError('compareError', error.message);
    }
  }, 240);
}

function currentOptions() {
  const mode = document.querySelector('[name="generationMode"]:checked').value;
  if (mode === 'random')
    return {
      mode,
      length: Number($('passwordLength').value),
      upper: $('includeUpper').checked,
      lower: $('includeLower').checked,
      numbers: $('includeNumbers').checked,
      symbols: $('includeSymbols').checked,
      brackets: $('includeBrackets').checked,
      excludeSimilar: $('excludeSimilar').checked,
      exclude: $('excludeCharacters').value,
    };
  if (mode === 'passphrase')
    return {
      mode,
      words: Number($('wordCount').value),
      separator: $('wordSeparator').value,
      capitalize: $('capitalizeWords').checked,
      appendNumber: $('appendNumber').checked,
    };
  if (mode === 'pin') return { mode, length: Number($('pinLength').value) };
  return { mode, pattern: $('passwordPattern').value };
}

function syncMode() {
  const mode = document.querySelector('[name="generationMode"]:checked').value;
  for (const name of ['random', 'passphrase', 'pin', 'pattern'])
    $('options-' + name).hidden = name !== mode;
  const count = Number($('batchSize').value);
  $('generateButtonLabel').textContent =
    count === 1 ? 'Generate password' : `Generate ${count} passwords`;
}

function invalidateGeneration(changed = true) {
  batch = [];
  outputVisible = false;
  $('exportDialog').close();
  renderOutput();
  renderBatch();
  setError('generatorError');
  $('generationStatus').textContent = changed
    ? 'Settings changed. Generate a new password to apply them.'
    : 'No password has been generated yet.';
}

function renderOutput() {
  const current = batch[0];
  $('generatorOutput').dataset.empty = String(!current);
  $('generatedModeLabel').textContent = current ? current.mode.toUpperCase() : 'READY TO FORGE';
  $('generatedPassword').textContent = current
    ? outputVisible
      ? current.password
      : MASK
    : 'Ready when you are.';
  $('generatedPassword').setAttribute(
    'aria-label',
    current && !outputVisible ? 'Generated password, hidden' : 'Generated password',
  );
  $('generatedEntropy').textContent = current ? `${current.entropyBits.toFixed(1)} bits` : '— bits';
  const score = current ? entropyScore(current.entropyBits) : null;
  $('generatedStrength').dataset.score = current ? String(score) : 'empty';
  $('generatedStrength').textContent = current
    ? `${current.length} characters · ${SCORE_LABELS[score]} random search space${batch.length > 1 ? ` · First of ${batch.length}` : ''}`
    : 'Your next password starts here.';
  for (const id of ['toggleGenerated', 'copyGenerated', 'analyzeGenerated'])
    $(id).disabled = !current;
  $('toggleGenerated').setAttribute('aria-pressed', String(outputVisible));
  $('toggleGenerated').setAttribute(
    'aria-label',
    `${outputVisible ? 'Hide' : 'Show'} generated password`,
  );
  paintIcon($('toggleGenerated').querySelector('[data-icon]'), outputVisible ? 'eye-off' : 'eye');
}

function renderSecretList(id, entries, kind) {
  const rows = entries.map((entry, index) => {
    const row = element('li', 'secret-item');
    const content = element('div', 'secret-item-content');
    const secret = element('code', 'secret-value', MASK);
    secret.dataset.masked = 'true';
    content.append(
      secret,
      element(
        'span',
        'secret-item-meta',
        `${entry.mode.toUpperCase()} · ${entry.length} chars · ${entry.entropyBits.toFixed(1)} bits`,
      ),
    );
    const actions = element('div', 'secret-item-actions');
    const reveal = element('button', 'row-button', 'Show');
    reveal.type = 'button';
    reveal.dataset.secretReveal = 'true';
    reveal.setAttribute('aria-label', `Show ${kind} password ${index + 1}`);
    reveal.setAttribute('aria-pressed', 'false');
    reveal.addEventListener('click', () => {
      const show = secret.dataset.masked === 'true';
      secret.textContent = show ? entry.password : MASK;
      secret.dataset.masked = String(!show);
      reveal.textContent = show ? 'Hide' : 'Show';
      reveal.setAttribute('aria-label', `${show ? 'Hide' : 'Show'} ${kind} password ${index + 1}`);
      reveal.setAttribute('aria-pressed', String(show));
    });
    const copy = element('button', 'row-button', 'Copy');
    copy.type = 'button';
    copy.setAttribute('aria-label', `Copy ${kind} password ${index + 1}`);
    copy.addEventListener('click', () => void copySecret(entry.password));
    const analyze = element('button', 'row-button', 'Analyze');
    analyze.type = 'button';
    analyze.setAttribute('aria-label', `Analyze ${kind} password ${index + 1}`);
    analyze.addEventListener('click', () => sendToChecker(entry.password));
    actions.append(reveal, copy, analyze);
    row.append(element('span', 'item-index', String(index + 1).padStart(2, '0')), content, actions);
    return row;
  });
  $(id).replaceChildren(...rows);
}

function renderBatch() {
  $('batchSection').hidden = batch.length < 2;
  renderSecretList('batchList', batch.length > 1 ? batch : [], 'batch');
}

function renderHistory() {
  const items = history.items;
  $('clearHistory').disabled = !items.length;
  $('historyEmpty').hidden = items.length > 0;
  $('historyEmpty').textContent = history.enabled
    ? 'Your next generated passwords will appear here.'
    : 'Your history is off. A clean slate, by design.';
  renderSecretList('historyList', items, 'history');
}

function generate() {
  if (!globalThis.isSecureContext) {
    setError(
      'generatorError',
      'Secure generation requires HTTPS or a local development server. No insecure fallback is used.',
    );
    return;
  }
  try {
    const results = generateBatch(currentOptions(), Number($('batchSize').value));
    batch = results;
    outputVisible = true;
    history.add(results);
    setError('generatorError');
    renderOutput();
    renderBatch();
    renderHistory();
    updateStats('generated', results.length);
    $('generationStatus').textContent =
      `${results.length} ${results.length === 1 ? 'password' : 'passwords'} generated with ${results[0].entropyBits.toFixed(1)} bits of generation entropy each. Kept only in page memory.`;
  } catch (error) {
    invalidateGeneration(false);
    setError('generatorError', error.message);
    $('generationStatus').textContent = 'Nothing generated. Review the settings above.';
  }
}

function applyPreset(preset) {
  const mode = preset === 'memorable' ? 'passphrase' : 'random';
  document.querySelector(`[name="generationMode"][value="${mode}"]`).checked = true;
  $('batchSize').value = '1';
  if (mode === 'random') {
    const length = preset === 'maximum' ? 32 : DEFAULT_RANDOM_OPTIONS.length;
    $('passwordLength').value = String(length);
    $('passwordLengthRange').value = String(length);
    for (const id of ['includeUpper', 'includeLower', 'includeNumbers', 'includeSymbols'])
      $(id).checked = true;
    $('includeBrackets').checked = false;
    $('excludeSimilar').checked = false;
    $('excludeCharacters').value = '';
  } else {
    $('wordCount').value = '6';
    $('wordCountRange').value = '6';
    $('wordSeparator').value = ' ';
    $('capitalizeWords').checked = false;
    $('appendNumber').checked = false;
  }
  syncMode();
  invalidateGeneration();
}

function canCheckBreach() {
  try {
    validatePassword($('mainPassword').value);
    return Boolean(
      $('mainPassword').value &&
      $('breachConsent').checked &&
      globalThis.isSecureContext &&
      globalThis.crypto?.subtle,
    );
  } catch {
    return false;
  }
}

function updateBreachControls() {
  $('checkBreach').disabled = !canCheckBreach() || Boolean(breachController);
  $('checkBreach').replaceChildren(
    icon('radar'),
    document.createTextNode(breachController ? 'Checking…' : 'Check breach dataset'),
  );
  $('cancelBreach').hidden = !breachController;
}

function resetBreach(message) {
  ++breachRevision;
  breachController?.abort();
  breachController = null;
  $('breachStatus').textContent = message;
  $('breachStatus').dataset.state = 'idle';
  updateBreachControls();
}

async function runBreachCheck() {
  if (!canCheckBreach() || breachController) return;
  if (!navigator.onLine) {
    $('breachStatus').textContent =
      'You are offline. Local tools still work; reconnect to check the breach dataset.';
    $('breachStatus').dataset.state = 'error';
    return;
  }
  const revision = ++breachRevision;
  const password = $('mainPassword').value;
  breachController = new AbortController();
  const controller = breachController;
  breachAttempted = true;
  $('breachStatus').dataset.state = 'loading';
  $('breachStatus').textContent =
    'Looking up a padded hash range. Your password and full hash are not sent.';
  updateBreachControls();
  try {
    const result = await checkBreach(password, {
      consent: $('breachConsent').checked,
      signal: controller.signal,
    });
    if (
      revision !== breachRevision ||
      password !== $('mainPassword').value ||
      !$('breachConsent').checked
    )
      return;
    $('breachStatus').dataset.state = result.found ? 'found' : 'not-found';
    $('breachStatus').textContent = result.found
      ? `Seen ${result.count.toLocaleString('en-US')} times in the Pwned Passwords dataset. Do not use it. Change it everywhere it was used.`
      : 'No match in the Pwned Passwords dataset. This is not proof of safety; the dataset is incomplete.';
  } catch (error) {
    if (revision !== breachRevision || controller.signal.aborted) return;
    $('breachStatus').dataset.state = 'error';
    $('breachStatus').textContent = error.message;
  } finally {
    if (revision === breachRevision) {
      breachController = null;
      updateBreachControls();
    }
  }
}

function exportPlaintext() {
  if (!$('exportDialog').open || batch.length < 2) return;
  $('exportDialog').close();
  const blob = new Blob([batch.map((entry) => entry.password).join('\n') + '\n'], {
    type: 'text/plain;charset=utf-8',
  });
  const url = URL.createObjectURL(blob);
  const link = element('a');
  link.href = url;
  link.download = 'keyforge-passwords.txt';
  document.body.append(link);
  link.click();
  link.remove();
  const timer = setTimeout(() => {
    URL.revokeObjectURL(url);
    downloadUrls.delete(url);
  }, 1000);
  downloadUrls.set(url, timer);
  notify(
    'Plaintext download requested. Keep the file private or import it into a password manager.',
  );
}

function updateAttackModel() {
  const scenario = $('attackScenario').value;
  $('attackRate').textContent = ATTACK_SCENARIOS[scenario].detail;
  $('crackTime').textContent = checkerResult
    ? formatCrackTime(checkerResult.guessesLog10, scenario)
    : '—';
  renderComparison();
}

function clearSession(announce = true) {
  ++sessionEpoch;
  ++checkerRevision;
  ++compareRevision;
  clearTimeout(checkerTimer);
  clearTimeout(compareTimer);
  clearTimeout(toastTimer);
  checker.dispose();
  comparison.dispose();
  for (const [url, timer] of downloadUrls) {
    clearTimeout(timer);
    URL.revokeObjectURL(url);
  }
  downloadUrls.clear();
  history.setEnabled(false);
  batch = [];
  checkerResult = null;
  compareResults = [null, null];
  breachAttempted = false;
  all('input').forEach((input) => {
    if (input.type === 'checkbox' || input.type === 'radio') input.checked = input.defaultChecked;
    else input.value = input.defaultValue;
    input.removeAttribute('aria-invalid');
  });
  all('select').forEach((select) => {
    select.selectedIndex = 0;
  });
  Object.keys(INPUT_NAMES).forEach((id) => {
    $(id).value = '';
  });
  resetBreach('Not checked. No external request has been made.');
  $('characterCount').textContent = '0 / 128';
  for (const id of ['checkerError', 'compareError', 'generatorError']) setError(id);
  $('toast').dataset.visible = 'false';
  $('toast').textContent = '';
  for (const name of Object.keys(stats)) stats[name] = 0;
  updateStats();
  syncMode();
  invalidateGeneration(false);
  renderChecker(null);
  renderComparison();
  renderHistory();
  updateAttackModel();
  hideSecrets();
  if (announce)
    notify('Session cleared. Your clipboard and downloaded files have not been cleared.');
}

// Static UI wiring: no inline handlers or HTML interpolation of secrets.
all('[data-icon]').forEach((node) => paintIcon(node, node.dataset.icon));
all('[data-tab]').forEach((tab, index, tabs) => {
  tab.addEventListener('click', () => switchTab(tab.dataset.tab));
  tab.addEventListener('keydown', (event) => {
    let target;
    if (event.key === 'ArrowRight') target = (index + 1) % tabs.length;
    if (event.key === 'ArrowLeft') target = (index - 1 + tabs.length) % tabs.length;
    if (event.key === 'Home') target = 0;
    if (event.key === 'End') target = tabs.length - 1;
    if (target === undefined) return;
    event.preventDefault();
    switchTab(tabs[target].dataset.tab, true);
  });
});
all('[data-open-tab]').forEach((button) =>
  button.addEventListener('click', () => switchTab(button.dataset.openTab, true)),
);
all('[data-reveal]').forEach((button) =>
  button.addEventListener('click', () =>
    revealInput(button.dataset.reveal, $(button.dataset.reveal).type === 'password'),
  ),
);
$('mainPassword').addEventListener('input', () => scheduleChecker());
$('clearChecker').addEventListener('click', () => {
  $('mainPassword').value = '';
  revealInput('mainPassword', false);
  scheduleChecker(0);
  $('mainPassword').focus();
});
all('[data-example]').forEach((button) =>
  button.addEventListener('click', () => sendToChecker(button.dataset.example)),
);
for (const id of ['compareA', 'compareB']) $(id).addEventListener('input', scheduleComparison);
$('clearComparison').addEventListener('click', () => {
  for (const id of ['compareA', 'compareB']) {
    $(id).value = '';
    revealInput(id, false);
  }
  scheduleComparison();
  $('compareA').focus();
});
$('generatorSettings').addEventListener('input', (event) => {
  const pairs = [
    ['passwordLength', 'passwordLengthRange'],
    ['wordCount', 'wordCountRange'],
    ['pinLength', 'pinLengthRange'],
  ];
  for (const [numberId, rangeId] of pairs) {
    if (event.target.id === rangeId) $(numberId).value = $(rangeId).value;
    if (event.target.id === numberId && $(numberId).value !== '' && $(numberId).validity.valid)
      $(rangeId).value = $(numberId).value;
  }
  syncMode();
  invalidateGeneration();
});
all('[data-preset]').forEach((button) =>
  button.addEventListener('click', () => applyPreset(button.dataset.preset)),
);
$('generatePassword').addEventListener('click', generate);
$('copyGenerated').addEventListener('click', () => {
  if (batch[0]) void copySecret(batch[0].password);
});
$('toggleGenerated').addEventListener('click', () => {
  outputVisible = !outputVisible;
  renderOutput();
});
$('analyzeGenerated').addEventListener('click', () => {
  if (batch[0]) sendToChecker(batch[0].password);
});
$('rememberHistory').addEventListener('change', () => {
  history.setEnabled($('rememberHistory').checked);
  renderHistory();
});
$('clearHistory').addEventListener('click', () => {
  history.clear();
  renderHistory();
  notify('History cleared from this tab.');
});
$('exportBatch').addEventListener('click', () => {
  if (batch.length > 1) $('exportDialog').showModal();
});
$('cancelExport').addEventListener('click', () => $('exportDialog').close());
$('confirmExport').addEventListener('click', exportPlaintext);
$('attackScenario').addEventListener('change', updateAttackModel);
$('breachConsent').addEventListener('change', () => {
  resetBreach(
    $('breachConsent').checked
      ? 'Permission granted. Click Check breach dataset when you are ready.'
      : 'Lookup permission is off. Results have been cleared.',
  );
});
$('checkBreach').addEventListener('click', () => void runBreachCheck());
$('cancelBreach').addEventListener('click', () =>
  resetBreach('Lookup cancelled. No result is available.'),
);
$('clearSession').addEventListener('click', () => clearSession());
document.addEventListener('keydown', (event) => {
  if (event.key === 'Escape') hideSecrets();
  if (
    event.altKey &&
    !event.ctrlKey &&
    !event.metaKey &&
    !event.shiftKey &&
    !event.getModifierState('AltGraph') &&
    event.key.toLowerCase() === 'g' &&
    !$('exportDialog').open
  ) {
    event.preventDefault();
    switchTab('generator', true);
    generate();
  }
});
document.addEventListener('visibilitychange', () => {
  if (document.hidden) hideSecrets();
});
window.addEventListener('pagehide', () => clearSession(false));
window.addEventListener('pageshow', (event) => {
  if (event.persisted) clearSession(false);
});
function updateConnection() {
  $('connectionStatus').dataset.offline = String(!navigator.onLine);
  $('connectionStatus').replaceChildren(
    element('span', 'status-dot'),
    document.createTextNode(navigator.onLine ? 'LOCAL ENGINE' : 'OFFLINE / LOCAL'),
  );
}
window.addEventListener('online', updateConnection);
window.addEventListener('offline', updateConnection);

clearSession(false);
updateConnection();
if (!globalThis.isSecureContext || typeof globalThis.crypto?.getRandomValues !== 'function') {
  $('capabilityWarning').hidden = false;
  $('capabilityWarning').textContent =
    'Secure generation needs a modern browser over HTTPS. No insecure randomness fallback is used. Local analysis remains available if your browser supports workers.';
  $('generatePassword').disabled = true;
}
