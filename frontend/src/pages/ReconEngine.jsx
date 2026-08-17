import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { Radar, ChevronDown, ChevronUp, Code2, ChevronRight } from 'lucide-react';
import { reconTargets, semgrepFindings } from '../data/mockData';
import './ReconEngine.css';

const anim = (d = 0) => ({
  initial: { opacity: 0, y: 12 },
  animate: { opacity: 1, y: 0 },
  transition: { duration: 0.35, delay: d }
});

export default function ReconEngine() {
  const [expandedTarget, setExpandedTarget] = useState(null);

  const topTarget = reconTargets[0];

  return (
    <div>
      {/* Header */}
      <motion.div className="page-header" {...anim(0)}>
        <div className="page-header__eyebrow">STAGE 01 · ATTACK SURFACE RECON</div>
        <h1 className="page-header__title">Recon Engine</h1>
        <p className="page-header__subtitle">
          Tree-sitter AST parsing · Semgrep security audit · Inter-procedural call graphs · LLM-ranked priority queue
        </p>
      </motion.div>

      {/* Metric Pills */}
      <motion.div className="recon__metric-strip section-gap--sm" {...anim(0.04)}>
        {[
          { label: 'Files Parsed', val: '23 files (2,847 LOC)', hot: false },
          { label: 'Functions Mapped', val: '47 functions', hot: false },
          { label: 'Dangerous Sinks', val: '8 detected (3 critical)', hot: true },
          { label: 'Recon Latency', val: '12.3 seconds', hot: false },
        ].map(m => (
          <div key={m.label} className={`recon__metric-pill ${m.hot ? 'recon__metric-pill--hot' : ''}`}>
            <span className="recon__metric-label">{m.label}</span>
            <span className="recon__metric-val">{m.val}</span>
          </div>
        ))}
      </motion.div>

      {/* #1 Priority Target Hero */}
      <motion.div className="section-gap--sm" {...anim(0.08)}>
        <div className="card accent-left-red recon__hero">
          <div className="flex items-center justify-between mb-3 flex-wrap gap-2">
            <div className="flex items-center gap-2">
              <span className="badge badge--critical">#1 ATTACK TARGET</span>
              <span className="mono text-xs text-muted">{topTarget.file}:{topTarget.line}</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="mono text-xs text-muted">Risk Score:</span>
              <span className="mono font-bold text-red" style={{ fontSize: 18 }}>{topTarget.score}/100</span>
            </div>
          </div>

          <h2 className="mono" style={{ fontSize: 20, color: 'var(--t1)', marginBottom: 8 }}>
            {topTarget.function}()
          </h2>

          <p className="text-sm text-secondary mb-4" style={{ lineHeight: 1.5 }}>
            {topTarget.reason}
          </p>

          {/* Visual Call Path */}
          <div className="recon__callpath-box">
            <span className="text-xs text-muted mono" style={{ marginRight: 6 }}>CALL PATH:</span>
            {topTarget.callPath.split(' → ').map((node, idx, arr) => (
              <React.Fragment key={node}>
                <span className={`recon__node-chip ${idx === arr.length - 1 ? 'recon__node-chip--sink' : ''}`}>
                  {node}
                </span>
                {idx < arr.length - 1 && <ChevronRight size={12} style={{ color: 'var(--t4)' }} />}
              </React.Fragment>
            ))}
          </div>

          <div className="flex items-center gap-3 mt-4 flex-wrap">
            <span className="text-xs text-muted mono">SINKS:</span>
            {topTarget.sinks.map(s => (
              <span key={s} className="badge badge--critical" style={{ fontSize: 10 }}>
                {s}() (Unbounded)
              </span>
            ))}
            <span className="text-xs text-muted mono" style={{ marginLeft: 8 }}>INPUTS:</span>
            {topTarget.inputSources.map(i => (
              <span key={i} className="tag" style={{ fontSize: 10 }}>{i}</span>
            ))}
          </div>
        </div>
      </motion.div>

      {/* Ranked Queue Table */}
      <motion.div className="section-gap--sm" {...anim(0.1)}>
        <div className="flex items-center justify-between mb-3">
          <span className="mono text-xs font-bold text-muted uppercase tracking-wider">
            Prioritized Attack Target Queue ({reconTargets.length})
          </span>
          <span className="text-xs text-muted">Click row to expand tainted input sources</span>
        </div>

        <div className="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>Rank</th>
                <th>Function</th>
                <th>Location</th>
                <th>Risk Level</th>
                <th>Sinks</th>
                <th>Score</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {reconTargets.map((target, idx) => {
                const isExpanded = expandedTarget === target.id;
                return (
                  <React.Fragment key={target.id}>
                    <tr
                      onClick={() => setExpandedTarget(isExpanded ? null : target.id)}
                      style={{ cursor: 'pointer' }}
                      className={idx === 0 ? 'recon__row--top' : ''}
                    >
                      <td className="mono text-xs text-muted">#{idx + 1}</td>
                      <td><strong className="mono text-sm">{target.function}()</strong></td>
                      <td className="mono text-xs text-muted">{target.file}:{target.line}</td>
                      <td>
                        <span className={`badge ${target.risk === 'CRITICAL' ? 'badge--critical' : target.risk === 'HIGH' ? 'badge--high' : 'badge--medium'}`}>
                          {target.risk}
                        </span>
                      </td>
                      <td>
                        <div className="flex gap-1 flex-wrap">
                          {target.sinks.length > 0 ? (
                            target.sinks.map(s => <span key={s} className="mono text-xs text-red">{s}()</span>)
                          ) : (
                            <span className="text-xs text-muted">None</span>
                          )}
                        </div>
                      </td>
                      <td>
                        <div className="flex items-center gap-2">
                          <div className="progress-track" style={{ width: 50 }}>
                            <div
                              className={`progress-fill ${target.risk === 'CRITICAL' ? 'progress-fill--red' : 'progress-fill--amber'}`}
                              style={{ width: `${target.score}%` }}
                            />
                          </div>
                          <span className="mono text-xs font-bold">{target.score}</span>
                        </div>
                      </td>
                      <td>
                        {isExpanded ? <ChevronUp size={14} /> : <ChevronDown size={14} style={{ color: 'var(--t4)' }} />}
                      </td>
                    </tr>
                    {isExpanded && (
                      <tr>
                        <td colSpan={7} style={{ background: 'var(--bg-panel)', padding: '14px 20px' }}>
                          <div className="flex items-center justify-between gap-4 flex-wrap">
                            <div>
                              <span className="text-xs text-muted mono">CALL PATH: </span>
                              <span className="mono text-xs text-primary">{target.callPath}</span>
                            </div>
                            <div>
                              <span className="text-xs text-muted mono">INPUT SOURCES: </span>
                              {target.inputSources.map(inp => <span key={inp} className="tag ml-1" style={{ fontSize: 10 }}>{inp}</span>)}
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      </motion.div>

      {/* Non-collapsible Static Semgrep & AST Audit Findings */}
      <motion.div className="card section-gap--sm" {...anim(0.12)}>
        <div className="flex items-center gap-2 mb-4 pb-3" style={{ borderBottom: '1px solid var(--border-1)' }}>
          <Code2 size={16} style={{ color: 'var(--amber-light)' }} />
          <span className="font-semibold text-sm">Semgrep Security Findings ({semgrepFindings.length})</span>
        </div>

        <div className="stack--sm">
          {semgrepFindings.map(f => (
            <div key={f.id} className="recon__semgrep-item">
              <div className="flex items-center justify-between mb-1">
                <span className="badge badge--critical">{f.severity}</span>
                <span className="mono text-xs text-muted">{f.file}:{f.line}</span>
              </div>
              <div className="mono text-xs font-semibold text-primary mb-1">{f.rule}</div>
              <p className="text-xs text-muted mb-2">{f.message}</p>
              <div className="terminal" style={{ fontSize: 11 }}>
                <div className="terminal__body" style={{ padding: '6px 12px', maxHeight: 44 }}>
                  <span className="t-error">{f.code}</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      </motion.div>
    </div>
  );
}
