import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Wrench, CheckCircle, XCircle, Trophy,
  ChevronDown, ChevronUp, RefreshCw, BarChart3,
  Search, Brain, Zap, Shield
} from 'lucide-react';
import { patchCandidates } from '../data/mockData';
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
  const [expandedPatch, setExpandedPatch] = useState(0);
  const [selectorTab, setSelectorTab] = useState('scores');

  const winner = patchCandidates.find(p => p.status === 'SELECTED');

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
          <div className="patch__winner-score-num">{winner.score.total.toFixed(1)}</div>
          <div className="patch__winner-score-lbl">Composite Score</div>
        </div>
      </motion.div>

      {/* Competing Agents Arena */}
      <motion.div className="section-gap--sm" {...anim(0.1)}>
        <div className="patch__section-label">Competing Repair Candidates</div>
        <div className="stack--lg">
          {patchCandidates.map((patch, i) => {
            const Icon = agentMeta[i].icon;
            const isWinner = patch.status === 'SELECTED';
            const isExpanded = expandedPatch === i;

            return (
              <div
                key={patch.agent}
                className={`card patch__agent-card ${isWinner ? 'accent-left-green patch__agent-card--winner' : 'accent-left-amber'}`}
              >
                <div className="patch__agent-header" onClick={() => setExpandedPatch(isExpanded ? null : i)}>
                  <div className={`patch__agent-badge patch__agent-badge--${agentMeta[i].color}`}>
                    <Icon size={18} />
                  </div>
                  <div className="patch__agent-title-block">
                    <div className="flex items-center gap-3">
                      <strong style={{ fontSize: 16 }}>{patch.agent}: {patch.name}</strong>
                      {isWinner && <span className="badge badge--green">SELECTED</span>}
                      {!isWinner && <span className="badge badge--neutral">REJECTED</span>}
                    </div>
                    <div className="text-sm" style={{ color: 'var(--t3)', marginTop: 4 }}>{patch.strategy}</div>
                  </div>
                  <div className="patch__agent-score-summary">
                    <div className="patch__agent-score-num" style={{ color: isWinner ? 'var(--green-light)' : 'var(--t1)' }}>
                      {patch.score.total.toFixed(1)}
                    </div>
                    <button className="btn btn--ghost" style={{ padding: '6px 10px', minHeight: 'unset' }}>
                      {isExpanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
                    </button>
                  </div>
                </div>

                {/* Rejection notice if failed */}
                {!patch.verificationPassed && patch.rejectedReason && (
                  <div className="patch__reject-banner">
                    <XCircle size={14} style={{ color: 'var(--red-light)', flexShrink: 0 }} />
                    <span className="text-sm" style={{ color: 'var(--red-light)' }}>
                      <strong>Rejection Cause:</strong> {patch.rejectedReason}
                    </span>
                  </div>
                )}

                {/* Score Pills */}
                <div className="patch__score-pills">
                  {[
                    { label: 'Security', val: patch.score.security, max: 100, color: 'red' },
                    { label: 'Regression', val: patch.score.regression, max: 100, color: 'blue' },
                    { label: 'Performance', val: patch.score.performance, max: 100, color: 'cyan' },
                    { label: 'Re-discovery', val: patch.score.rediscovery, max: 100, color: 'amber' },
                  ].map(sc => (
                    <div key={sc.label} className="patch__score-pill">
                      <span className="patch__score-pill-label">{sc.label}</span>
                      <span className="patch__score-pill-val">{sc.val}</span>
                      <div className="progress-track" style={{ height: 3, marginTop: 4 }}>
                        <div className={`progress-fill progress-fill--${sc.color}`} style={{ width: `${sc.val}%` }} />
                      </div>
                    </div>
                  ))}
                </div>

                {/* Expanded Details */}
                <AnimatePresence>
                  {isExpanded && (
                    <motion.div
                      initial={{ opacity: 0, height: 0 }}
                      animate={{ opacity: 1, height: 'auto' }}
                      exit={{ opacity: 0, height: 0 }}
                      transition={{ duration: 0.25 }}
                      className="patch__expanded-content"
                    >
                      <div className="grid-2" style={{ gap: 20, marginTop: 16 }}>
                        {/* Diff */}
                        <div>
                          <div className="patch__field-label">Unified Patch Diff</div>
                          <div className="terminal">
                            <div className="terminal__header">
                              <div className="terminal__dot"/><div className="terminal__dot"/><div className="terminal__dot"/>
                              <span className="terminal__label">{patch.linesChanged} lines changed · {patch.filesChanged} file</span>
                            </div>
                            <div className="terminal__body">
                              {patch.diff.split('\n').map((line, li) => (
                                <span
                                  key={li}
                                  className={
                                    line.startsWith('+++') || line.startsWith('---') ? 't-highlight' :
                                    line.startsWith('+') ? 't-success' :
                                    line.startsWith('-') ? 't-error' :
                                    line.startsWith('@@') ? 't-warning' : 't-comment'
                                  }
                                >
                                  {line}{'\n'}
                                </span>
                              ))}
                            </div>
                          </div>
                        </div>

                        {/* Test Verification Grid */}
                        <div>
                          <div className="patch__field-label">Adversarial Verification Checks</div>
                          <div className="card card--panel" style={{ padding: 18 }}>
                            {[
                              { label: 'Original PoV Replay', status: 'BLOCKED', ok: true },
                              { label: 'Attack Variations', status: `${patch.attacks.blocked}/${patch.attacks.total} blocked`, ok: patch.attacks.blocked === patch.attacks.total },
                              { label: 'Regression Suite', status: `${patch.regressionTests.passed}/${patch.regressionTests.total} passed`, ok: patch.regressionTests.passed === patch.regressionTests.total },
                              { label: 'Performance Delta', status: patch.performanceOverhead, ok: parseFloat(patch.performanceOverhead) < 10 },
                              { label: 'Directed Re-fuzzing', status: patch.score.rediscovery === 100 ? 'Zero variants found' : 'Vulnerability re-triggered', ok: patch.score.rediscovery === 100 },
                            ].map(chk => (
                              <div key={chk.label} className="stat-row">
                                <span className="stat-row__label">{chk.label}</span>
                                <div className="flex items-center gap-2">
                                  {chk.ok
                                    ? <CheckCircle size={13} style={{ color: 'var(--green-light)', flexShrink: 0 }} />
                                    : <XCircle size={13} style={{ color: 'var(--red-light)', flexShrink: 0 }} />}
                                  <span className="mono text-xs font-semibold" style={{ color: chk.ok ? 'var(--green-light)' : 'var(--red-light)' }}>
                                    {chk.status}
                                  </span>
                                </div>
                              </div>
                            ))}
                          </div>
                        </div>
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            );
          })}
        </div>
      </motion.div>

      {/* Decision Matrix Table */}
      <motion.div className="card section-gap--sm" {...anim(0.14)}>
        <div className="card-header">
          <span className="card-title"><BarChart3 size={14} /> Evaluation Scoring Matrix</span>
          <div className="flex gap-2">
            {['scores', 'weights'].map(tab => (
              <button
                key={tab}
                className={`btn btn--ghost ${selectorTab === tab ? 'btn--secondary' : ''}`}
                style={{ padding: '6px 14px', fontSize: 12, minHeight: 32 }}
                onClick={() => setSelectorTab(tab)}
              >
                {tab.charAt(0).toUpperCase() + tab.slice(1)}
              </button>
            ))}
          </div>
        </div>

        {selectorTab === 'scores' ? (
          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>Criterion & Weight</th>
                  <th>Agent 1 (Root Cause)</th>
                  <th>Agent 2 (Evidence-Based)</th>
                  <th>Agent 3 (Direct Bounds)</th>
                </tr>
              </thead>
              <tbody>
                {[
                  { label: 'Security Verification (×0.50)', k: 'security' },
                  { label: 'Regression Suite (×0.25)', k: 'regression' },
                  { label: 'Performance Overhead (×0.15)', k: 'performance' },
                  { label: 'Re-discovery Resistance (×0.10)', k: 'rediscovery' },
                ].map(r => (
                  <tr key={r.k}>
                    <td><strong>{r.label}</strong></td>
                    {patchCandidates.map((p, idx) => (
                      <td key={idx}>
                        <span className="mono font-semibold" style={{ color: p.score[r.k] >= 90 ? 'var(--green-light)' : p.score[r.k] >= 75 ? 'var(--amber-light)' : 'var(--red-light)' }}>
                          {p.score[r.k]} / 100
                        </span>
                      </td>
                    ))}
                  </tr>
                ))}
                <tr style={{ background: 'var(--bg-elevated)', borderTop: '2px solid var(--border-2)' }}>
                  <td><strong style={{ color: 'var(--amber-light)' }}>FINAL WEIGHTED SCORE</strong></td>
                  {patchCandidates.map((p, idx) => (
                    <td key={idx}>
                      <span className={`mono font-bold text-sm ${p.status === 'SELECTED' ? 'text-green' : 'text-primary'}`}>
                        {p.score.total.toFixed(1)} {p.status === 'SELECTED' ? '🏆 (Winner)' : ''}
                      </span>
                    </td>
                  ))}
                </tr>
              </tbody>
            </table>
          </div>
        ) : (
          <div className="patch__weights-grid">
            {[
              { label: 'Security', weight: '50%', desc: 'Must block the original PoV exploit and all mutated variations.' },
              { label: 'Regression', weight: '25%', desc: 'Existing functional test suite must pass without behavioral breakage.' },
              { label: 'Performance', weight: '15%', desc: 'Execution time regression must stay strictly under 10%.' },
              { label: 'Re-discovery', weight: '10%', desc: 'Directed fuzzer cannot synthesize a new exploit in the patched region.' },
            ].map(w => (
              <div key={w.label} className="patch__weight-card">
                <div className="patch__weight-header">
                  <span className="patch__weight-label">{w.label}</span>
                  <span className="patch__weight-val">{w.weight}</span>
                </div>
                <p className="text-sm" style={{ color: 'var(--t3)', lineHeight: 1.5, marginTop: 6 }}>{w.desc}</p>
              </div>
            ))}
          </div>
        )}
      </motion.div>

      {/* Continuous Feedback Loop */}
      <motion.div className="card" {...anim(0.18)}>
        <div className="card-header">
          <span className="card-title"><RefreshCw size={14} /> Autonomous Feedback Loop</span>
          <span className="badge badge--green">Single-Pass Success</span>
        </div>
        <p className="text-sm" style={{ color: 'var(--t2)', lineHeight: 1.6, marginBottom: 16 }}>
          If candidate verification fails, failure logs and sanitizer traces are automatically fed back to the LLM agent as constrained prompts to synthesize targeted second-iteration candidates.
        </p>
        <div className="patch__feedback-chain">
          {['Generation', 'PoV Replay', 'Variant Fuzz', 'Regression', 'Decision'].map((st, i, arr) => (
            <React.Fragment key={st}>
              <div className={`patch__chain-node ${i === arr.length - 1 ? 'patch__chain-node--active' : ''}`}>
                <CheckCircle size={12} style={{ color: 'var(--green-light)' }} />
                <span>{st}</span>
              </div>
              {i < arr.length - 1 && <span className="patch__chain-arrow">→</span>}
            </React.Fragment>
          ))}
        </div>
      </motion.div>
    </div>
  );
}
