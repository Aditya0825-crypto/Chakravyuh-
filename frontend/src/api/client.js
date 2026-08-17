const API_BASE = '/api';

async function request(path, options = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: {
      Accept: 'application/json',
      ...options.headers,
    },
    ...options,
  });
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

export async function getRecon(scanId) {
  return request(`/scans/${scanId}/recon`);
}

export async function getFindings(scanId) {
  return request(`/scans/${scanId}/findings`);
}

export async function getPoVs(scanId) {
  return request(`/scans/${scanId}/povs`);
}

export async function getVulnDNA(scanId) {
  return request(`/scans/${scanId}/vulndna`);
}

export async function searchVulnDNA(payload) {
  return request('/vulndna/search', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
}

export async function getPatches(scanId) {
  return request(`/scans/${scanId}/patches`);
}

export async function getReport(scanId) {
  return request(`/scans/${scanId}/report`);
}

export async function submitGateDecision(scanId, payload) {
  return request(`/scans/${scanId}/gate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
}

export async function getLearningLog() {
  return request('/learning-log');
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
      if (data.type === 'gate_decision') handlers.onGateDecision?.(data);
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
