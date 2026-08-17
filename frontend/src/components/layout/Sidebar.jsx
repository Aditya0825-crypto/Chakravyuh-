import React, { useMemo } from 'react';
import { NavLink, useLocation } from 'react-router-dom';
import {
  Shield, LayoutDashboard, Radar, Bug,
  ShieldCheck, Dna, Wrench, FileText,
  BookOpen, UploadCloud
} from 'lucide-react';
import { useScan } from '../../context/ScanContext';
import './Sidebar.css';

const STAGES = [
  { to: '/console/recon',      icon: Radar,      label: 'Recon Engine',    num: '01', id: 'recon' },
  { to: '/console/bugfinding', icon: Bug,         label: 'Bug Finding',     num: '02', id: 'bugfinding' },
  { to: '/console/verifier',   icon: ShieldCheck, label: 'PoV Verifier',    num: '03', id: 'verification' },
  { to: '/console/vulndna',    icon: Dna,         label: 'VulnDNA',         num: '04', id: 'vulndna' },
  { to: '/console/patch',      icon: Wrench,      label: 'Patch Engine',    num: '05', id: 'patchengine' },
  { to: '/console/report',     icon: FileText,    label: 'Security Report', num: '06', id: 'reportgate' },
];

const STAGE_ORDER = STAGES.map((s) => s.id);

function resolveStageStatus(stageId, scan, stageStatus) {
  if (stageStatus[stageId]) return stageStatus[stageId];
  if (!scan?.current_stage) return 'pending';
  const currentIdx = STAGE_ORDER.indexOf(scan.current_stage);
  const stageIdx = STAGE_ORDER.indexOf(stageId);
  if (currentIdx < 0 || stageIdx < 0) return 'pending';
  if (stageIdx < currentIdx) return 'done';
  if (stageIdx === currentIdx && scan.status === 'running') return 'running';
  if (stageIdx === currentIdx) return 'running';
  return 'pending';
}

export default function Sidebar() {
  const { pathname } = useLocation();
  const { scan, stageStatus, connected, scanId } = useScan();

  const statusText = useMemo(() => {
    if (!scanId) return 'Awaiting Upload';
    if (connected) return 'Pipeline Live';
    if (scan?.status === 'running') return 'Pipeline Active';
    if (scan?.status === 'queued') return 'Pipeline Queued';
    return 'Pipeline Idle';
  }, [scanId, connected, scan?.status]);

  return (
    <aside className="sb">
      {/* Brand */}
      <div className="sb__brand">
        <div className="sb__brand-icon">
          <Shield size={16} strokeWidth={2.5} />
        </div>
        <div>
          <div className="sb__brand-name">CHAKRAVYUH</div>
          <div className="sb__brand-sub">AI Kavach · v4.1</div>
        </div>
      </div>

      {/* New Scan — entry point for the whole pipeline */}
      <div className="sb__new-scan">
        <NavLink to="/console/upload" className="sb__new-scan-btn">
          <UploadCloud size={15} />
          <span>Upload Target</span>
        </NavLink>
      </div>

      {/* System Status */}
      <div className="sb__status-bar">
        <div className="sb__status-row">
          <span className={`dot ${connected ? 'dot--green' : 'dot--yellow'}`} />
          <span className="sb__status-text">{statusText}</span>
        </div>
        {scanId && (
          <div className="sb__status-row sb__status-row--sub mono">
            {scan?.target_name || scanId.slice(0, 8)}
          </div>
        )}
      </div>

      {/* Nav */}
      <nav className="sb__nav">
        <NavLink
          to="/console"
          end
          className={({ isActive }) => `sb__item ${isActive ? 'sb__item--active' : ''}`}
        >
          <LayoutDashboard size={14} />
          <span className="sb__item-label">Dashboard</span>
        </NavLink>

        <div className="sb__section-label">Pipeline Stages</div>

        {STAGES.map(({ to, icon: Icon, label, num, id }) => {
          const isActive = pathname === to;
          const status = resolveStageStatus(id, scan, stageStatus);
          return (
            <NavLink
              key={to}
              to={to}
              className={`sb__item sb__item--stage ${isActive ? 'sb__item--active' : ''}`}
            >
              <div className={`sb__stage-num sb__stage-num--${status}`}>{num}</div>
              <Icon size={13} className="sb__item-icon" />
              <span className="sb__item-label">{label}</span>
              <span className={`sb__stage-dot sb__stage-dot--${status}`} />
            </NavLink>
          );
        })}

        <div className="sb__section-label" style={{ marginTop: 16 }}>System</div>
        <NavLink
          to="/console/learning"
          className={({ isActive }) => `sb__item ${isActive ? 'sb__item--active' : ''}`}
        >
          <BookOpen size={14} />
          <span className="sb__item-label">Learning Log</span>
        </NavLink>
      </nav>
    </aside>
  );
}
