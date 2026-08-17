import React from 'react';
import { motion } from 'framer-motion';
import { useNavigate } from 'react-router-dom';
import {
  Bug, CheckCircle, Wrench, Radar, Dna, FileText, ArrowRight,
  TrendingUp, Cpu, ChevronRight, Award, ShieldCheck, Lock
} from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, ResponsiveContainer } from 'recharts';
import { crashes, vulnDNAResults, patchCandidates } from '../data/mockData';
import './Dashboard.css';

const anim = (delay = 0) => ({
  initial: { opacity: 0, y: 16 },
  animate: { opacity: 1, y: 0 },
  transition: { duration: 0.35, delay, ease: [0.4, 0, 0.2, 1] },
});

const PIPELINE = [
  { num: '01', label: 'Recon Engine',  status: 'done',    time: '12s',    to: '/recon',      icon: Radar },
  { num: '02', label: 'Bug Finding',   status: 'done',    time: '4m 18s', to: '/bugfinding', icon: Bug },
  { num: '03', label: 'PoV Verifier',  status: 'done',    time: '23s',    to: '/verifier',   icon: CheckCircle },
  { num: '04', label: 'VulnDNA',       status: 'done',    time: '84ms',   to: '/vulndna',    icon: Dna },
  { num: '05', label: 'Patch Engine',  status: 'running', time: 'Active', to: '/patch',      icon: Wrench },
  { num: '06', label: 'Report & Gate', status: 'pending', time: 'Queued', to: '/report',     icon: FileText },
];

const coverageData = [
  { t: '0m', v: 8 }, { t: '1m', v: 22 }, { t: '2m', v: 38 },
  { t: '3m', v: 51 }, { t: '4m', v: 62 }, { t: '4m18s', v: 67.4 },
];

export default function Dashboard() {
  const nav = useNavigate();

  const topCrash = crashes[0];
  const topVulnDNA = vulnDNAResults[0];
  const winningPatch = patchCandidates.find(p => p.status === 'SELECTED');

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
          <div className="card-header" style={{ marginBottom: 16, paddingBottom: 12 }}>
            <span className="card-title"><Cpu size={15} /> Autonomous Reasoning Pipeline</span>
            <span className="text-xs text-muted mono">Click stage node to inspect details</span>
          </div>

          <div className="dash__pipeline">
            {PIPELINE.map((s, i) => {
              const Icon = s.icon;
              return (
                <React.Fragment key={s.num}>
                  <div
                    className={`dash__pipe-node dash__pipe-node--${s.status}`}
                    onClick={() => nav(s.to)}
                    title={`Go to ${s.label}`}
                  >
                    {s.status === 'running' && <div className="dash__pipe-ring" />}
                    <div className="dash__pipe-icon">
                      <Icon size={16} strokeWidth={s.status === 'running' ? 2.5 : 2} />
                    </div>
                    <div className="dash__pipe-num">{s.num}</div>
                    <div className="dash__pipe-label">{s.label}</div>
                    <div className="dash__pipe-time">{s.time}</div>
                  </div>
                  {i < PIPELINE.length - 1 && (
                    <div className={`dash__pipe-conn dash__pipe-conn--${PIPELINE[i].status === 'done' ? 'done' : 'dim'}`} />
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
                <span className="mono text-xs text-muted">CWE-122</span>
              </div>
              <span className="mono text-xs text-amber font-bold">crash-001</span>
            </div>

            <h2 className="dash__finding-title">Heap Buffer Overflow in handle_request()</h2>

            <div className="dash__taint-box mt-4">
              <div className="text-xs text-muted mono font-bold uppercase mb-2">TAINT FLOW:</div>
              <div className="dash__taint-chain">
                <span className="dash__taint-chip">Network Input</span>
                <ChevronRight size={14} className="dash__taint-arrow" />
                <span className="dash__taint-chip">accept_conn()</span>
                <ChevronRight size={14} className="dash__taint-arrow" />
                <span className="dash__taint-chip dash__taint-chip--sink">strcpy() SINK ⚠</span>
              </div>
            </div>

            <div className="dash__finding-grid mt-4">
              <div className="dash__finding-cell">
                <span className="dash__cell-label">Location</span>
                <span className="mono text-xs font-semibold">src/server.c:148</span>
              </div>
              <div className="dash__finding-cell">
                <span className="dash__cell-label">Sanitizer Output</span>
                <span className="mono text-xs text-red font-semibold">ASan WRITE 512b</span>
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
                <span className="card-title"><TrendingUp size={14} /> Fuzzing Coverage Trajectory</span>
                <span className="mono text-xs text-cyan font-bold">67.4%</span>
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
                <span className="stat-row__label">Unique Crashes Confirmed</span>
                <span className="mono font-bold text-red" style={{ fontSize: 16 }}>3 Unique</span>
              </div>
              <div className="stat-row" style={{ padding: '8px 0' }}>
                <span className="stat-row__label">Fuzzing Speed</span>
                <span className="mono text-xs font-semibold text-primary">12,400 exec/sec</span>
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
          <div className="card accent-left-amber">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <Dna size={16} className="text-amber" />
                <span className="font-bold text-sm">VulnDNA Evidence Citation</span>
              </div>
              <span className="mono text-xs font-bold text-green">91.3% Match</span>
            </div>

            <div className="dash__evidence-box">
              <div className="flex items-center justify-between mb-2">
                <span className="mono text-amber font-bold" style={{ fontSize: 16 }}>{topVulnDNA.cveId}</span>
                <span className="badge badge--info" style={{ fontSize: 9 }}>Historical Evidence</span>
              </div>
              <p className="text-xs text-secondary mb-3" style={{ lineHeight: 1.5 }}>
                {topVulnDNA.fixPattern}
              </p>
              <div className="mono text-xs text-muted" style={{ background: 'var(--bg-void)', padding: '6px 10px', borderRadius: 4 }}>
                Guides LLM repair synthesis using real production CVE patch patterns.
              </div>
            </div>

            <button className="btn btn--secondary w-full mt-4" onClick={() => nav('/console/vulndna')}>
              Explore VulnDNA Database <ArrowRight size={14} />
            </button>
          </div>

          {/* Winning Repair Candidate */}
          <div className="card accent-left-green">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <Award size={16} className="text-green" />
                <span className="font-bold text-sm">Winning Patch Candidate</span>
              </div>
              <span className="badge badge--green">Score: 94.4 / 100</span>
            </div>

            <div className="dash__winner-box">
              <div className="flex items-center gap-2 mb-1">
                <strong className="text-sm">{winningPatch.agent}: {winningPatch.name}</strong>
                <span className="badge badge--green" style={{ fontSize: 9 }}>SELECTED</span>
              </div>
              <p className="text-xs text-secondary mb-3" style={{ lineHeight: 1.5 }}>
                {winningPatch.strategy}
              </p>

              <div className="terminal">
                <div className="terminal__body" style={{ maxHeight: 70, fontSize: 11, padding: '8px 12px' }}>
                  <span className="t-error">- strcpy(req-&gt;body, input_buffer);</span>{'\n'}
                  <span className="t-success">+ size_t input_len = strnlen(input_buffer, MAX_BODY_SIZE + 1);</span>{'\n'}
                  <span className="t-success">+ if (input_len &gt; MAX_BODY_SIZE) send_error(conn, 413, ...);</span>
                </div>
              </div>
            </div>

            <button className="btn btn--success w-full mt-4" onClick={() => nav('/console/patch')}>
              Inspect Patch Arena & Diffs <ArrowRight size={14} />
            </button>
          </div>
        </div>
      </motion.div>


      {/* ============================================================
          SECTION 04: PROOF — ADVERSARIAL VERIFICATION & GATE
         ============================================================ */}
      <motion.div className="dash__section mt-8 mb-8" {...anim(0.16)}>
        <div className="dash__section-eyebrow">
          <span>04</span> PROOF · VERIFICATION & SAFETY GATE
        </div>

        <div className="card dash__gate-card">
          <div className="dash__gate-header">
            <div className="flex items-center gap-3">
              <div className="dash__gate-icon"><ShieldCheck size={22} /></div>
              <div>
                <h3 style={{ fontSize: 18, color: 'var(--t1)' }}>Adversarial Verification Suite</h3>
                <span className="text-xs text-muted">All safety passes verified clean</span>
              </div>
            </div>
            <span className="badge badge--green" style={{ fontSize: 11, padding: '6px 12px' }}>
              RECOMMENDATION: APPROVED FOR DEPLOYMENT
            </span>
          </div>

          <div className="dash__proof-grid mt-6">
            {[
              { label: 'Original PoV Replay', result: '0 Crashes' },
              { label: 'Adversarial Fuzzing', result: '9/9 Blocked' },
              { label: 'Regression Suite', result: '47/47 Passed' },
              { label: 'Performance Overhead', result: '+1.2% Delta' },
              { label: 'Human Safety Gate', result: 'Ready for Sign-Off' },
            ].map(p => (
              <div key={p.label} className="dash__proof-cell">
                <CheckCircle size={14} className="text-green flex-shrink-0" />
                <div>
                  <div className="dash__proof-label">{p.label}</div>
                  <div className="dash__proof-val mono">{p.result}</div>
                </div>
              </div>
            ))}
          </div>

          <div className="divider" style={{ margin: '20px 0 16px' }} />

          <div className="flex items-center justify-between flex-wrap gap-4">
            <span className="text-xs text-secondary">
              Authoritative human decision required before patch is written.
            </span>
            <button className="btn btn--primary btn--lg" onClick={() => nav('/console/report')}>
              <Lock size={15} /> Authorize Deployment in Safety Gate
            </button>
          </div>
        </div>
      </motion.div>

    </div>
  );
}
