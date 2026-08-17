import React, { useState, useEffect } from 'react';
import { useLocation } from 'react-router-dom';
import { Bell, Clock } from 'lucide-react';
import './TopBar.css';

const META = {
  '/console':           { label: 'Dashboard',       badge: null },
  '/console/upload':    { label: 'Upload Target',   badge: { text: 'Stage 00', color: 'neutral' } },
  '/console/recon':     { label: 'Recon Engine',    badge: { text: 'Stage 01', color: 'green' } },
  '/console/bugfinding':{ label: 'Bug Finding',     badge: { text: 'Stage 02', color: 'green' } },
  '/console/verifier':  { label: 'PoV Verifier',    badge: { text: 'Stage 03', color: 'green' } },
  '/console/vulndna':   { label: 'VulnDNA Engine',  badge: { text: 'Stage 04', color: 'green' } },
  '/console/patch':     { label: 'Patch Engine',    badge: { text: 'Stage 05 · Running', color: 'amber' } },
  '/console/report':    { label: 'Security Report', badge: { text: 'Stage 06', color: 'neutral' } },
  '/console/learning':  { label: 'Learning Log',    badge: null },
};

export default function TopBar() {
  const { pathname } = useLocation();
  const meta = META[pathname] || META['/console'];
  const [time, setTime] = useState(new Date());

  useEffect(() => {
    const id = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(id);
  }, []);

  const hh = String(time.getHours()).padStart(2, '0');
  const mm = String(time.getMinutes()).padStart(2, '0');
  const ss = String(time.getSeconds()).padStart(2, '0');

  return (
    <header className="topbar">
      <div className="topbar__left">
        <span className="topbar__page-title">{meta.label}</span>
        {meta.badge && (
          <span className={`topbar__stage-pill topbar__stage-pill--${meta.badge.color}`}>
            {meta.badge.text}
          </span>
        )}
      </div>

      <div className="topbar__right">
        <div className="topbar__clock">
          <Clock size={11} />
          <span>{hh}:{mm}:{ss}</span>
        </div>

        <button className="topbar__icon-btn" title="Alerts">
          <Bell size={14} />
          <span className="topbar__notif" />
        </button>
      </div>
    </header>
  );
}
