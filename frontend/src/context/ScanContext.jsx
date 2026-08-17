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
      .catch(() => {
        if (!cancelled) setScan(null);
      });

    return () => { cancelled = true; };
  }, [scanId]);

  useEffect(() => {
    if (!scanId) return undefined;

    const ws = connectScanStream(scanId, {
      onEvent: (data) => {
        setEvents((prev) => [...prev.slice(-199), data]);
        if (data.type === 'stage_started' && data.stage) {
          setStageStatus((prev) => ({
            ...prev,
            [data.stage]: 'running',
          }));
        }
        if (data.type === 'stage_completed' && data.stage) {
          setStageStatus((prev) => ({
            ...prev,
            [data.stage]: 'done',
          }));
        }
        if (data.type === 'scan_complete') {
          getScan(scanId).then(setScan).catch(() => {});
        }
      },
      onClose: () => setConnected(false),
    });

    ws.onopen = () => setConnected(true);
    return () => ws.close();
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
