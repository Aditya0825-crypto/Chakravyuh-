const API_BASE = '/api';

async function request(path, options = {}) {
  const res = await fetch(`${API_BASE}${path}`, options);
  if (!res.ok) {
    const detail = await res.json().catch(() => ({}));
    throw new Error(detail.detail || res.statusText || 'Request failed');
  }
  return res.json();
}

export async function healthCheck() {
  return request('/health');
}

export async function uploadScan(files) {
  const form = new FormData();
  files.forEach((file) => form.append('files', file));
  return request('/scans/upload', { method: 'POST', body: form });
}

export async function listScans() {
  return request('/scans');
}

export async function getScan(scanId) {
  return request(`/scans/${scanId}`);
}

export function connectScanStream(scanId, handlers = {}) {
  const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws';
  const ws = new WebSocket(`${protocol}://${window.location.host}/api/scans/${scanId}/stream`);

  ws.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      handlers.onEvent?.(data);
      if (data.type === 'stage_started') handlers.onStageStarted?.(data);
      if (data.type === 'stage_completed') handlers.onStageCompleted?.(data);
      if (data.type === 'log') handlers.onLog?.(data);
      if (data.type === 'scan_complete') handlers.onScanComplete?.(data);
      if (data.type === 'stage_failed') handlers.onStageFailed?.(data);
    } catch {
      handlers.onError?.(event.data);
    }
  };

  ws.onerror = () => handlers.onError?.('WebSocket error');
  ws.onclose = () => handlers.onClose?.();

  return ws;
}

export const SCAN_ID_KEY = 'chakravyuh:activeScanId';

export function getActiveScanId() {
  return localStorage.getItem(SCAN_ID_KEY);
}

export function setActiveScanId(scanId) {
  if (scanId) localStorage.setItem(SCAN_ID_KEY, scanId);
  else localStorage.removeItem(SCAN_ID_KEY);
}
