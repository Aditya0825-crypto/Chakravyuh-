import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import {
  connectScanStream,
  getActiveScanId,
  getScan,
  setActiveScanId,
} from '../api/client';

const ScanContext = createContext(null);

export function ScanProvider({ children }) {
  const [scanId, setScanIdState] = useState(() => getActiveScanId());
  const [scan, setScan] = useState(null);
  const [events, setEvents] = useState([]);
  const [stageStatus, setStageStatus] = useState({});
  const [connected, setConnected] = useState(false);

  const setScanId = useCallback((id) => {
    setScanIdState(id);
    setActiveScanId(id);
  }, []);

  // Fetch scan metadata; auto-clear stale IDs that 404
  useEffect(() => {
    if (!scanId) {
      setScan(null);
      return undefined;
    }

    let cancelled = false;
    getScan(scanId)
      .then((data) => {
        if (!cancelled) setScan(data);
      })
      .catch((err) => {
        if (!cancelled) {
          setScan(null);
          // Remove stale scanId from localStorage so we stop hammering the backend
          const msg = err?.message || '';
          if (msg.includes('404') || msg.includes('Not Found')) {
            setScanId(null);
          }
        }
      });

    return () => { cancelled = true; };
  }, [scanId, setScanId]);

  // WebSocket stream with safe error handling and auto-reconnect
  useEffect(() => {
    if (!scanId) return undefined;

    let ws = null;
    let retryTimeout = null;
    let destroyed = false;

    function connect() {
      if (destroyed) return;

      try {
        ws = connectScanStream(scanId, {
          onEvent: (data) => {
            setEvents((prev) => [...prev.slice(-199), data]);
            if (data.type === 'stage_started' && data.stage) {
              setStageStatus((prev) => ({ ...prev, [data.stage]: 'running' }));
            }
            if (data.type === 'stage_completed' && data.stage) {
              setStageStatus((prev) => ({ ...prev, [data.stage]: 'done' }));
            }
            if (data.type === 'scan_complete') {
              getScan(scanId).then(setScan).catch(() => {});
            }
          },
          onClose: () => {
            setConnected(false);
            // Reconnect after 3 s unless we intentionally tore down
            if (!destroyed) {
              retryTimeout = setTimeout(connect, 3000);
            }
          },
          onError: () => {
            // swallow — browser already logs WS errors; no need to bubble
            setConnected(false);
          },
        });

        ws.onopen = () => setConnected(true);
      } catch (_) {
        // WebSocket constructor can throw for invalid URLs
        setConnected(false);
      }
    }

    connect();

    return () => {
      destroyed = true;
      clearTimeout(retryTimeout);
      if (ws) {
        try { ws.close(); } catch (_) {}
      }
      setConnected(false);
    };
  }, [scanId]);

  const value = useMemo(
    () => ({
      scanId,
      setScanId,
      scan,
      events,
      stageStatus,
      connected,
    }),
    [scanId, setScanId, scan, events, stageStatus, connected],
  );

  return <ScanContext.Provider value={value}>{children}</ScanContext.Provider>;
}

export function useScan() {
  const ctx = useContext(ScanContext);
  if (!ctx) throw new Error('useScan must be used within ScanProvider');
  return ctx;
}
