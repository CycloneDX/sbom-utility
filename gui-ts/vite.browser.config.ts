// SPDX-License-Identifier: Apache-2.0
/**
 * vite.browser.config.ts — browser-only dev server (no Electron)
 *
 * Used by `npm run dev:browser`.  Starts the Vite dev server without
 * vite-plugin-electron so the renderer loads in a regular browser tab.
 * The mock bridge in src/renderer/mockBridge.ts stubs window.sbomBridge
 * so every screen is navigable without the CLI binary.
 *
 * Usage:
 *   cd gui-ts && npm run dev:browser
 *   Then open http://localhost:5173 in Chrome or Safari.
 */
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { resolve } from 'path'

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': resolve(__dirname, 'src/renderer'),
    },
  },
  root: '.',
  build: {
    outDir: 'dist',
    rollupOptions: {
      input: resolve(__dirname, 'index.html'),
    },
  },
  // Silence the "module is not available in browser" warnings for Node built-ins
  // that vite-plugin-electron-renderer normally handles.
  optimizeDeps: {
    exclude: ['electron'],
  },
})
