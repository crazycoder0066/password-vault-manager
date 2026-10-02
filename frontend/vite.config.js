import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

const backend = 'http://127.0.0.1:8000';

const proxy = () => ({
  target: backend,
  changeOrigin: true,
  configure(server) {
    server.on('proxyReq', (proxyRequest, request) => {
      // Preserve Django's origin validation across the local development proxy.
      if (request.headers.origin === `http://${request.headers.host}`) {
        proxyRequest.setHeader('Origin', backend);
      }
    });
  },
});

export default defineConfig({
  plugins: [react()],
  server: {
    host: '127.0.0.1',
    port: 5173,
    strictPort: true,
    proxy: { '/api': proxy(), '/health': proxy() },
  },
  build: {
    outDir: '../src/password_vault_manager/static',
    emptyOutDir: true,
  },
  test: {
    environment: 'jsdom',
    setupFiles: './src/test-setup.js',
    clearMocks: true,
  },
});
