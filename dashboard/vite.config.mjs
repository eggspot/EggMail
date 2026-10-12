import { defineConfig } from 'vite';
import preact from '@preact/preset-vite';

// The mock API server (mock/server.mjs) listens on MOCK_PORT; `npm run dev:mock`
// starts it next to the Vite dev server and Vite proxies /api to it.
const mockPort = process.env.MOCK_PORT || '8787';

export default defineConfig({
  plugins: [preact()],
  server: {
    port: 5173,
    proxy: {
      '/api': `http://127.0.0.1:${mockPort}`,
      '/healthz': `http://127.0.0.1:${mockPort}`,
      '/readyz': `http://127.0.0.1:${mockPort}`,
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    target: 'es2022',
    sourcemap: false,
    // Never inline assets as data: URIs; the host CSP forbids them (img-src 'self').
    assetsInlineLimit: 0,
    cssCodeSplit: true,
    // The polyfill is not needed for evergreen browsers and keeps the output free of extra code.
    modulePreload: { polyfill: false },
  },
  test: {
    environment: 'jsdom',
    include: ['tests/**/*.test.{ts,tsx,mjs}'],
    setupFiles: ['tests/setup.ts'],
    restoreMocks: true,
    css: false,
  },
});
