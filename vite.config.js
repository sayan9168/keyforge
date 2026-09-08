import { defineConfig } from 'vite';

const contentSecurityPolicy = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self'",
  "font-src 'self'",
  "img-src 'self' data:",
  "connect-src 'self' https://api.pwnedpasswords.com",
  "worker-src 'self'",
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'none'",
].join('; ');

export default defineConfig({
  base: './',
  server: {
    host: '0.0.0.0',
    allowedHosts: ['.e2b.app'],
    port: 5173,
    strictPort: true,
    watch: {
      ignored: ['**/playwright-report/**', '**/test-results/**', '**/artifacts/**'],
    },
  },
  preview: {
    host: '0.0.0.0',
    allowedHosts: ['.e2b.app'],
    port: 4173,
    strictPort: true,
    headers: {
      'Referrer-Policy': 'no-referrer',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'X-XSS-Protection': '1; mode=block',
      'Cross-Origin-Opener-Policy': 'same-origin',
      'Cross-Origin-Resource-Policy': 'same-origin',
      'Permissions-Policy':
        'camera=(), microphone=(), geolocation=(), payment=(), usb=(), autoplay=(), clipboard-write=(self), fullscreen=(self)',
      'Cache-Control': 'no-store',
    },
  },
  build: { target: 'es2022' },
  plugins: [
    {
      name: 'production-content-security-policy',
      apply: 'build',
      transformIndexHtml() {
        // Development HMR needs inline styles and a websocket; production does not.
        return [
          {
            tag: 'meta',
            attrs: { 'http-equiv': 'Content-Security-Policy', content: contentSecurityPolicy },
            injectTo: 'head-prepend',
          },
        ];
      },
    },
  ],
});
