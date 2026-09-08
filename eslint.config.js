import js from '@eslint/js';
import globals from 'globals';

export default [
  {
    ignores: [
      'dist/**',
      'node_modules/**',
      'playwright-report/**',
      'test-results/**',
      'artifacts/**',
    ],
  },
  js.configs.recommended,
  {
    files: ['**/*.js'],
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'module',
      globals: { ...globals.browser, ...globals.node, ...globals.worker },
    },
    rules: {
      eqeqeq: ['error', 'always'],
      'no-eval': 'error',
      'no-implied-eval': 'error',
      'no-new-func': 'error',
      'no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
      'no-restricted-properties': [
        'error',
        { object: 'Math', property: 'random', message: 'Password generation must use Web Crypto.' },
        {
          property: 'innerHTML',
          message: 'Use DOM nodes and textContent; passwords are untrusted text.',
        },
        { property: 'outerHTML', message: 'Use DOM nodes and textContent.' },
        { property: 'insertAdjacentHTML', message: 'Never parse password-derived HTML.' },
      ],
    },
  },
];
