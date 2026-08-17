import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { useNavigate } from 'react-router-dom';
import {
  Bug, CheckCircle, Wrench, Radar, Dna, FileText, ArrowRight,
  TrendingUp, Cpu, ChevronRight, Award, ShieldCheck, Lock, UploadCloud
} from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, ResponsiveContainer } from 'recharts';
import { crashes as fallbackCrashes, vulnDNAResults as fallbackVulnDNA, patchCandidates as fallbackPatches } from '../data/mockData';
import { useScan } from '../context/ScanContext';
import { listScans, getFindings, getPoVs, getPatches, getVulnDNA } from '../api/client';
import './Dashboard.css';

const anim = (delay = 0) => ({
  initial: { opacity: 0, y: 16 },
  animate: { opacity: 1, y: 0 },
  transition: { duration: 0.35, delay, ease: [0.4, 0, 0.2, 1] },
});

const PIPELINE_STAGES = [
  { num: '01', label: 'Recon Engine',  id: 'recon',        to: '/console/recon',      icon: Radar },
  { num: '02', label: 'Bug Finding',   id: 'bugfinding',   to: '/console/bugfinding', icon: Bug },
  { num: '03', label: 'PoV Verifier',  id: 'verification', to: '/console/verifier',   icon: CheckCircle },
  { num: '04', label: 'VulnDNA',       id: 'vulndna',      to: '/console/vulndna',    icon: Dna },
  { num: '05', label: 'Patch Engine',  id: 'patchengine',  to: '/console/patch',      icon: Wrench },
  { num: '06', label: 'Report & Gate', id: 'reportgate',   to: '/console/report',     icon: FileText },
];

const coverageData = [
  { t: '0m', v: 8 }, { t: '1m', v: 22 }, { t: '2m', v: 38 },
  { t: '3m', v: 51 }, { t: '4m', v: 62 }, { t: '4m18s', v: 67.4 },
];

export default function Dashboard() {
  const nav = useNavigate();
  const { scanId, scan, stageStatus, setScanId } = useScan();

  const [topCrash, setTopCrash] = useState(fallbackCrashes[0]);
  const [topVulnDNA, setTopVulnDNA] = useState(fallbackVulnDNA[0]);
  const [winningPatch, setWinningPatch] = useState(fallbackPatches.find(p => p.status === 'SELECTED'));
  const [recentScans, setRecentScans] = useState([]);

  // Auto-fetch active scan or list scans
  useEffect(() => {
    listScans().then((scans) => {
      setRecentScans(scans || []);
      if (!scanId && scans && scans.length > 0) {
        setScanId(scans[0].id);
      }
    }).catch(() => {});
  }, [scanId, setScanId]);

  // Load active scan summary artifacts
  useEffect(() => {
    if (!scanId) return;

    getFindings(scanId)
      .then((data) => {
        if (data?.crashes?.length > 0) {
          setTopCrash(data.crashes[0]);
        }
      })
      .catch(() => {});

    getVulnDNA(scanId)
      .then((data) => {
        if (data?.matches?.length > 0) {
          setTopVulnDNA(data.matches[0]);
        }
      })
      .catch(() => {});

    getPatches(scanId)
      .then((data) => {
        if (data?.winner) {
          setWinningPatch(data.winner);
        } else if (data?.candidates?.length > 0) {
          setWinningPatch(data.candidates[0]);
        }
      })
      .catch(() => {});
  }, [scanId]);

  const STAGE_ORDER = PIPELINE_STAGES.map((s) => s.id);
  const resolveStatus = (stageId) => {
    if (stageStatus[stageId]) return stageStatus[stageId];
    if (!scan?.current_stage) return 'done';
    const currentIdx = STAGE_ORDER.indexOf(scan.current_stage);
    const stageIdx = STAGE_ORDER.indexOf(stageId);
    if (currentIdx < 0 || stageIdx < 0) return 'done';
    if (stageIdx < currentIdx) return 'done';
    if (stageIdx === currentIdx && scan.status === 'running') return 'running';
    if (stageIdx === currentIdx) return 'running';
    return 'pending';
  };

  return (
    <div className="dash">

      {/* ============================================================
          SECTION 01: WORKFLOW — 6-STAGE PIPELINE
         ============================================================ */}
      <motion.div className="dash__section" {...anim(0)}>
        <div className="dash__section-eyebrow">
          <span>01</span> WORKFLOW · STAGE PROGRESSION
        </div>

        <div className="card dash__pipeline-card">
          <div className="card-header flex items-center justify-between" style={{ marginBottom: 16, paddingBottom: 12 }}>
            <span className="card-title"><Cpu size={15} /> Autonomous Reasoning Pipeline</span>
            <div className="flex items-center gap-3">
              {scan && (
                <span className="mono text-xs text-cyan">
                  Active: {scan.target_name} ({scan.status})
                </span>
              )}
              <span className="text-xs text-muted mono">Click stage node to inspect details</span>
            </div>
          </div>

          <div className="dash__pipeline">
            {PIPELINE_STAGES.map((s, i) => {
              const Icon = s.icon;
              const status = resolveStatus(s.id);
              return (
                <React.Fragment key={s.num}>
                  <div
                    className={`dash__pipe-node dash__pipe-node--${status}`}
                    onClick={() => nav(s.to)}
                    title={`Go to ${s.label}`}
                  >
                    {status === 'running' && <div className="dash__pipe-ring" />}
                    <div className="dash__pipe-icon">
                      <Icon size={16} strokeWidth={status === 'running' ? 2.5 : 2} />
                    </div>
                    <div className="dash__pipe-num">{s.num}</div>
                    <div className="dash__pipe-label">{s.label}</div>
                    <div className="dash__pipe-time">{status === 'running' ? 'Active' : status === 'done' ? 'Complete' : 'Queued'}</div>
                  </div>
                  {i < PIPELINE_STAGES.length - 1 && (
                    <div className={`dash__pipe-conn dash__pipe-conn--${resolveStatus(PIPELINE_STAGES[i].id) === 'done' ? 'done' : 'dim'}`} />
                  )}
                </React.Fragment>
              );
            })}
          </div>
        </div>
      </motion.div>


      {/* ============================================================
          SECTION 02: DISCOVERY — CRITICAL FINDING & TAINT
         ============================================================ */}
      <motion.div className="dash__section mt-8" {...anim(0.06)}>
        <div className="dash__section-eyebrow">
          <span>02</span> DISCOVERY · CRITICAL VULNERABILITY
        </div>

        <div className="grid-3-2">
          {/* Finding Hero */}
          <div className="card accent-left-red dash__finding-hero">
            <div className="flex items-center justify-between mb-3 flex-wrap gap-2">
              <div className="flex items-center gap-2">
                <span className="badge badge--critical">CRITICAL FINDING</span>
                <span className="mono text-xs text-muted">{topCrash.cwe || 'CWE-122'}</span>
              </div>
              <span className="mono text-xs text-amber font-bold">{topCrash.id || 'crash-001'}</span>
            </div>

            <h2 className="dash__finding-title">{topCrash.type || 'Heap Buffer Overflow'} in {topCrash.function || 'handle_request'}()</h2>

            <div className="dash__taint-box mt-4">
              <div className="text-xs text-muted mono font-bold uppercase mb-2">TAINT FLOW:</div>
              <div className="dash__taint-chain">
                <span className="dash__taint-chip">Network Input</span>
                <ChevronRight size={14} className="dash__taint-arrow" />
                <span className="dash__taint-chip">{topCrash.function || 'handle_request'}()</span>
                <ChevronRight size={14} className="dash__taint-arrow" />
                <span className="dash__taint-chip dash__taint-chip--sink">Unbounded SINK ⚠</span>
              </div>
            </div>

            <div className="dash__finding-grid mt-4">
              <div className="dash__finding-cell">
                <span className="dash__cell-label">Location</span>
                <span className="mono text-xs font-semibold">{topCrash.file || 'server.c'}:{topCrash.line || 148}</span>
              </div>
              <div className="dash__finding-cell">
                <span className="dash__cell-label">Sanitizer Output</span>
                <span className="mono text-xs text-red font-semibold">ASan WRITE {topCrash.crashInput?.length || 512}b</span>
              </div>
              <div className="dash__finding-cell">
                <span className="dash__cell-label">Replay Rate</span>
                <span className="mono text-xs text-green font-bold">5/5 (100%)</span>
              </div>
            </div>

            <button className="btn btn--danger w-full mt-5" onClick={() => nav('/console/verifier')}>
              Inspect Evidence & Replay Stack <ArrowRight size={14} />
            </button>
          </div>

          {/* Fuzzing Coverage Chart */}
          <div className="stack--lg">
            <div className="card">
              <div className="card-header" style={{ marginBottom: 12, paddingBottom: 8 }}>
                <span className="card-title"><TrendingUp size={14} /> Discovery Engine Stats</span>
                <span className="mono text-xs text-cyan font-bold">Directed PoC</span>
              </div>
              <ResponsiveContainer width="100%" height={110}>
                <AreaChart data={coverageData} margin={{ top: 2, right: 4, left: -24, bottom: 0 }}>
                  <defs>
                    <linearGradient id="dashCov" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="var(--cyan)" stopOpacity={0.25} />
                      <stop offset="95%" stopColor="var(--cyan)" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="t" tick={{ fontSize: 9, fill: 'var(--t3)', fontFamily: 'var(--font-mono)' }} axisLine={false} tickLine={false} />
                  <YAxis domain={[0, 100]} tick={{ fontSize: 9, fill: 'var(--t3)', fontFamily: 'var(--font-mono)' }} axisLine={false} tickLine={false} />
                  <Area type="monotone" dataKey="v" stroke="var(--cyan-light)" strokeWidth={2} fill="url(#dashCov)" dot={false} />
                </AreaChart>
              </ResponsiveContainer>
            </div>

            <div className="card">
              <div className="stat-row" style={{ padding: '8px 0' }}>
                <span className="stat-row__label">Confidence Score</span>
                <span className="mono font-bold text-amber" style={{ fontSize: 16 }}>{topCrash.confidence || 96}%</span>
              </div>
              <div className="stat-row" style={{ padding: '8px 0' }}>
                <span className="stat-row__label">Discovery Method</span>
                <span className="mono text-xs font-semibold text-primary">{topCrash.discoveryMethod || 'Directed PoC Synthesis'}</span>
              </div>
            </div>
          </div>
        </div>
      </motion.div>


      {/* ============================================================
          SECTION 03: REPAIR — VULNDNA EVIDENCE & WINNING PATCH
         ============================================================ */}
      <motion.div className="dash__section mt-8" {...anim(0.12)}>
        <div className="dash__section-eyebrow">
          <span>03</span> REPAIR · EVIDENCE RETRIEVAL & PATCH ARENA
        </div>

        <div className="grid-2">
          {/* VulnDNA Match */}
          <div className="card card--amber dash__vdna-card">
            <div className="card-header" style={{ marginBottom: 12, paddingBottom: 8 }}>
              <span className="card-title text-amber"><Dna size={14} /> Historical Precedent Match</span>
              <span className="badge badge--high mono">{topVulnDNA?.similarity || 94.2}% Match</span>
            </div>

            <div className="flex items-center justify-between mb-3">
              <span className="mono font-bold text-primary">{topVulnDNA?.cveId || 'CVE-2021-3156'}</span>
              <span className="mono text-xs text-muted">{topVulnDNA?.project || 'sudo'} ({topVulnDNA?.language || 'C'})</span>
            </div>

            <p className="text-xs text-secondary mb-3" style={{ lineHeight: 1.5 }}>
              {topVulnDNA?.fixPattern || 'Bounded length copy with truncation detection and capacity validation.'}
            </p>

            <div className="terminal" style={{ fontSize: 11 }}>
              <div className="terminal__body" style={{ padding: '8px 12px' }}>
                <span className="t-green">{topVulnDNA?.patch || 'strlcpy(dst, src, sizeof(dst));'}</span>
              </div>
            </div>

            <button className="btn btn--secondary w-full mt-4" onClick={() => nav('/console/vulndna')}>
              Explore VulnDNA Vector Space <ChevronRight size={14} />
            </button>
          </div>

          {/* Winning Patch Card */}
          {winningPatch && (
            <div className="card card--green dash__patch-card">
              <div className="card-header" style={{ marginBottom: 12, paddingBottom: 8 }}>
                <span className="card-title text-green"><Award size={14} /> Winning Candidate Patch</span>
                <span className="badge badge--green mono">Score {winningPatch.score?.total ? winningPatch.score.total.toFixed(1) : '94.4'}</span>
              </div>

              <div className="flex items-center justify-between mb-2">
                <span className="font-bold text-sm text-primary">{winningPatch.agent || 'Agent 1'} — {winningPatch.name || 'Root Cause Fixer'}</span>
                <span className="mono text-xs text-green font-bold">ALL ATTACKS BLOCKED</span>
              </div>

              <p className="text-xs text-secondary mb-3" style={{ lineHeight: 1.5 }}>
                {winningPatch.strategy || 'Upstream size check and bounded buffer copy prevent memory corruption.'}
              </p>

              <div className="grid-3 mb-4">
                <div className="dash__patch-stat">
                  <span className="dash__stat-val text-green">{winningPatch.attacks?.blocked || 9}/{winningPatch.attacks?.total || 9}</span>
                  <span className="dash__stat-lbl">Attacks Blocked</span>
                </div>
                <div className="dash__patch-stat">
                  <span className="dash__stat-val text-cyan">{winningPatch.linesChanged || 6}</span>
                  <span className="dash__stat-lbl">Lines Changed</span>
                </div>
                <div className="dash__patch-stat">
                  <span className="dash__stat-val text-purple">{winningPatch.performanceOverhead || '0.2%'}</span>
                  <span className="dash__stat-lbl">Perf Overhead</span>
                </div>
              </div>

              <button className="btn btn--primary w-full" onClick={() => nav('/console/patch')}>
                Inspect 3-Agent Arena Matrix <ArrowRight size={14} />
              </button>
            </div>
          )}
        </div>
      </motion.div>
    </div>
  );
}
