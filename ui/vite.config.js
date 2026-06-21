import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  cacheDir: process.env.VITE_CACHE_DIR || '/tmp/vite-cache',
  server: {
    host: '0.0.0.0',
    port: 5173,
    watch: {
      usePolling: process.env.VITE_FORCE_POLLING === 'true',
      interval: 300,
    },
    proxy: {
      '/algorithms': 'http://backend:8000',
      '/packs': 'http://backend:8000',
      '/catalogs': 'http://backend:8000',
      '/resolve': 'http://backend:8000',
      '/search-hash': 'http://backend:8000',
      '/hash-string': 'http://backend:8000',
      '/build-catalogs': 'http://backend:8000',
      '/export-enum': 'http://backend:8000',
      '/bulk-auto': 'http://backend:8000',
      '/validate-pack': 'http://backend:8000',
      '/analyze-binary': 'http://backend:8000',
      '/health': 'http://backend:8000',
      '/scaffold/algorithm': 'http://backend:8000',
    },
  },
  test: {
    environment: 'jsdom',
    globals: true,
  },
})
