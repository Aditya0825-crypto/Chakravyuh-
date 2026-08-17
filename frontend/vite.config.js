import { createLogger, defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// ── 1. Custom logger that silences harmless proxy pipe / reset noise ──────────
// Vite 8 logs WebSocket socket-level errors (EPIPE, ECONNRESET) directly via
// config.logger.error — they cannot be suppressed by proxy.on('error').
// These happen naturally when the browser navigates away mid-stream; they are
// not real failures and should never reach the developer console.
const IGNORED_PATTERNS = /EPIPE|ECONNRESET|ECONNREFUSED|ws proxy|write EPIPE/i;

const logger = createLogger();
const _origError = logger.error.bind(logger);
logger.error = (msg, opts) => {
  if (IGNORED_PATTERNS.test(msg)) return;   // drop harmless socket noise
  _origError(msg, opts);
};

// ── 2. http-proxy level suppression (HTTP-layer errors) ──────────────────────
const IGNORED_CODES = ['EPIPE', 'ECONNRESET', 'ECONNREFUSED'];

function suppressPipeErrors(proxy) {
  const swallow = (err) => {
    if (IGNORED_CODES.includes(err?.code) || IGNORED_PATTERNS.test(err?.message ?? '')) return;
    console.error('[proxy]', err.message);
  };

  proxy.on('error', (err, _req, res) => {
    swallow(err);
    // For HTTP (not WS) requests, try to send a clean 502 response
    try {
      if (res && typeof res.writeHead === 'function' && !res.headersSent) {
        res.writeHead(502, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Backend unavailable', code: err.code }));
      }
    } catch (_) {}
  });

  // WebSocket-specific proxy events
  proxy.on('proxyReqWsError', swallow);
  proxy.on('wsClientError', swallow);
}

// ── 3. Vite config ────────────────────────────────────────────────────────────
export default defineConfig({
  plugins: [react()],
  customLogger: logger,          // ← silences logger-level WS noise
  server: {
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
        ws: true,                // proxy WebSocket connections to FastAPI
        configure: suppressPipeErrors,
      },
    },
  },
})
