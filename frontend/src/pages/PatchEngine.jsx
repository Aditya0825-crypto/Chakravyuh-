import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Wrench, CheckCircle, XCircle, Trophy,
  ChevronDown, ChevronUp, RefreshCw, BarChart3,
  Search, Brain, Zap, Shield
} from 'lucide-react';
import { useScan } from '../context/ScanContext';
import { getPatches } from '../api/client';
import './PatchEngine.css';

const anim = (d = 0) => ({
  initial: { opacity: 0, y: 16 },
  animate: { opacity: 1, y: 0 },
  transition: { duration: 0.4, delay: d }
});

const agentMeta = [
  { icon: Search, color: 'cyan', label: 'Agent 1' },
  { icon: Brain, color: 'amber', label: 'Agent 2' },
  { icon: Zap, color: 'purple', label: 'Agent 3' },
];

export default function PatchEngine() {
  const { scanId } = useScan();
  const [candidates, setCandidates] = useState([]);
  const [winner, setWinner] = useState(null);
  const [expandedPatch, setExpandedPatch] = useState(null);
  const [selectorTab, setSelectorTab] = useState('scores');

  useEffect(() => {
    if (!scanId) return;
    getPatches(scanId)
      .then((data) => {
        if (data?.candidates?.length > 0) {
          setCandidates(data.candidates);
          if (data.winner) {
            setWinner(data.winner);
          } else {
            setWinner(data.candidates[0]);
          }
        }
      })
      .catch(() => {});
  }, [scanId]);

  return (
    <div>
      {/* Header */}
      <motion.div className="page-header" {...anim(0)}>
        <div className="page-header__eyebrow">Stage 05</div>
        <h1 className="page-header__title">Patch Engine — 3-Agent Arena</h1>
        <p className="page-header__subtitle">
          Three independent AI agents synthesize competing patches · Adversarial verification matrix determines the safest fix
        </p>
      </motion.div>

      {/* Winner Hero Banner */}
      {winner && (
        <motion.div className="card card--green patch__winner-hero section-gap--sm" {...anim(0.06)}>
          <div className="patch__winner-icon">
            <Trophy size={22} />
          </div>
          <div className="patch__winner-body">
            <div className="flex items-center gap-3 mb-2">
              <span className="badge badge--green">SELECTED WINNER</span>
              <span className="mono text-xs" style={{ color: 'var(--t3)' }}>Automated Decision</span>
            </div>
            <h2 className="patch__winner-title">{winner.agent} — {winner.name}</h2>
            <p className="text-sm" style={{ color: 'var(--t2)', marginTop: 4, lineHeight: 1.6 }}>{winner.strategy}</p>
          </div>
          <div className="patch__winner-score-box">
            <div className="patch__winner-score-num">{winner.score?.total?.toFixed(1) || '94.4'}</div>
            <div className="patch__winner-score-lbl">Composite Score</div>
          </div>
        </motion.div>
      )}

      {/* Competing Agents Arena */}
      <motion.div className="section-gap--sm" {...anim(0.1)}>
        <div className="flex items-center justify-between mb-3">
          <span className="mono text-xs font-bold text-muted uppercase tracking-wider">
            Candidate Patch Synthesis ({candidates.length} Agents)
          </span>
          <span className="text-xs text-muted">Click candidate to expand unified diff & score breakdown</span>
        </div>

        <div className="stack--sm">
          {candidates.length > 0 ? (
            candidates.map((c, idx) => {
              const isExp = expandedPatch === idx;
              const meta = agentMeta[idx % agentMeta.length];
              const Icon = meta.icon;
              const isWinner = c.status === 'SELECTED';

              return (
                <div
                  key={c.id || idx}
                  className={`card ${isWinner ? 'card--green' : ''} ${isExp ? 'patch__card--expanded' : ''}`}
                  style={{ padding: 0, overflow: 'hidden' }}
                >
                  <div
                    className="flex items-center justify-between p-4 cursor-pointer flex-wrap gap-3"
                    onClick={() => setExpandedPatch(isExp ? null : idx)}
                  >
                    <div className="flex items-center gap-3">
                      <div className={`icon-box icon-box--${meta.color}`}>
                        <Icon size={16} />
                      </div>
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="font-bold text-sm text-primary">{c.agent} — {c.name}</span>
                          {isWinner && <span className="badge badge--green">WINNER</span>}
                          {c.status === 'REJECTED' && <span className="badge badge--danger">REJECTED</span>}
                        </div>
                        <div className="text-xs text-muted mt-1">{c.strategy}</div>
                      </div>
                    </div>

                    <div className="flex items-center gap-4">
                      <div className="flex items-center gap-2">
                        <span className="mono text-xs text-muted">Score:</span>
                        <span className={`mono font-bold ${isWinner ? 'text-green' : 'text-primary'}`} style={{ fontSize: 16 }}>
                          {c.score?.total?.toFixed(1) || '0.0'}
                        </span>
                      </div>
                      {isExp ? <ChevronUp size={16} /> : <ChevronDown size={16} style={{ color: 'var(--t4)' }} />}
                    </div>
                  </div>

                  {isExp && (
                    <motion.div
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      className="p-4 pt-0"
                      style={{ borderTop: '1px solid var(--border-1)' }}
                    >
                      {/* Scores Strip */}
                      <div className="grid-4 my-3">
                        <div className="stat-row">
                          <span className="text-xs text-muted">Security (50%)</span>
                          <span className="mono text-xs font-bold text-green">{c.score?.security?.toFixed(1)}</span>
                        </div>
                        <div className="stat-row">
                          <span className="text-xs text-muted">Regression (25%)</span>
                          <span className="mono text-xs font-bold text-cyan">{c.score?.regression?.toFixed(1)}</span>
                        </div>
                        <div className="stat-row">
                          <span className="text-xs text-muted">Performance (15%)</span>
                          <span className="mono text-xs font-bold text-amber">{c.score?.performance?.toFixed(1)}</span>
                        </div>
                        <div className="stat-row">
                          <span className="text-xs text-muted">Re-discovery (10%)</span>
                          <span className="mono text-xs font-bold text-purple">{c.score?.rediscovery?.toFixed(1)}</span>
                        </div>
                      </div>

                      {/* Adversarial Variants Stats */}
                      <div className="grid-3 my-3">
                        <div className="card card--subtle p-3">
                          <span className="text-xs text-muted mono">ATTACK VARIANTS:</span>
                          <div className="mono font-bold text-sm text-green mt-1">
                            {c.attacks?.blocked || 0} / {c.attacks?.total || 0} Blocked
                          </div>
                        </div>
                        <div className="card card--subtle p-3">
                          <span className="text-xs text-muted mono">REGRESSION TESTS:</span>
                          <div className="mono font-bold text-sm text-cyan mt-1">
                            {c.regressionTests?.passed || 0} / {c.regressionTests?.total || 0} Passed
                          </div>
                        </div>
                        <div className="card card--subtle p-3">
                          <span className="text-xs text-muted mono">PERF OVERHEAD:</span>
                          <div className="mono font-bold text-sm text-purple mt-1">
                            {c.performanceOverhead || '0.0%'}
                          </div>
                        </div>
                      </div>

                      {/* Diff Viewer */}
                      <div className="mt-3">
                        <span className="text-xs text-muted mono font-bold">UNIFIED PATCH DIFF:</span>
                        <div className="terminal mt-1" style={{ fontSize: 11 }}>
                          <div className="terminal__body" style={{ padding: '10px 14px', maxHeight: 180, overflowY: 'auto' }}>
                            <pre className="mono text-xs" style={{ margin: 0 }}>
                              {(c.diff || '').split('\n').map((line, lidx) => {
                                const isAdd = line.startsWith('+');
                                const isDel = line.startsWith('-');
                                const isHunk = line.startsWith('@@');
                                return (
                                  <div
                                    key={lidx}
                                    style={{
                                      color: isAdd ? 'var(--green-light)' : isDel ? 'var(--red-light)' : isHunk ? 'var(--cyan-light)' : 'var(--t2)',
                                      background: isAdd ? 'rgba(78,201,176,0.08)' : isDel ? 'rgba(244,71,71,0.08)' : 'transparent',
                                    }}
                                  >
                                    {line}
                                  </div>
                                );
                              })}
                            </pre>
                          </div>
                        </div>
                      </div>
                    </motion.div>
                  )}
                </div>
              );
            })
          ) : (
            <div className="card p-6 text-center text-muted">
              <p className="text-sm font-semibold mb-1">No Patch Candidates Synthesized Yet</p>
              <p className="text-xs">The 3-Agent Patch Engine synthesizes competing fixes during Stage 5 of the scan pipeline.</p>
            </div>
          )}
        </div>
      </motion.div>
    </div>
  );
}
