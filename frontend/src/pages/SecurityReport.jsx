import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  FileText, CheckCircle, AlertTriangle, XCircle,
  Shield, User, Lock, Unlock, Download, Printer,
  ChevronRight, Clock, Dna, ArrowRight
} from 'lucide-react';
import { securityReport, patchCandidates, vulnDNAResults } from '../data/mockData';
import './SecurityReport.css';

const anim = (d = 0) => ({
  initial: { opacity: 0, y: 16 },
  animate: { opacity: 1, y: 0 },
  transition: { duration: 0.4, delay: d }
});

export default function SecurityReport() {
  const [decision, setDecision] = useState(null); // 'APPROVED' | 'HOLD' | 'REJECTED'
  const [gateArmed, setGateArmed] = useState(false);

  const r = securityReport;
  const winner = patchCandidates.find(p => p.status === 'SELECTED');

  return (
    <div className="report">
      {/* Header */}
      <motion.div className="page-header" {...anim(0)}>
        <div className="page-header__eyebrow">Stage 06</div>
        <h1 className="page-header__title">Security Report & Human Safety Gate</h1>
        <p className="page-header__subtitle">
          Complete evidence chain · Explainable taint trace · Authoritative human decision required before production deployment
        </p>
      </motion.div>

      {/* Report Header Metadata Strip */}
      <motion.div className="card report__meta-strip section-gap--sm" {...anim(0.06)}>
        <div className="report__meta-item">
          <span className="report__meta-key">Report ID</span>
          <span className="report__meta-val mono font-semibold">{r.id}</span>
        </div>
        <div className="report__meta-item">
          <span className="report__meta-key">Target Binary</span>
          <span className="report__meta-val font-semibold">{r.target}</span>
        </div>
        <div className="report__meta-item">
          <span className="report__meta-key">Vulnerability</span>
          <div className="flex items-center gap-2">
            <span className="badge badge--critical">{r.vulnerability.cvssScore} CRITICAL</span>
            <span className="mono text-xs" style={{ color: 'var(--t2)' }}>{r.vulnerability.cweId}</span>
          </div>
        </div>
        <div className="report__meta-item">
          <span className="report__meta-key">AI Confidence</span>
          <span className="report__meta-val mono text-amber font-bold" style={{ fontSize: 16 }}>{r.confidence}%</span>
        </div>
        <div className="report__meta-actions">
          <button className="btn btn--secondary" style={{ padding: '6px 12px', minHeight: 34 }}>
            <Download size={13} /> Export PDF
          </button>
        </div>
      </motion.div>

      {/* Main Evidence Grid */}
      <motion.div className="grid-2 section-gap--sm" style={{ gap: 24 }} {...anim(0.1)}>
        {/* Left Column: Finding & Root Cause */}
        <div className="stack--lg">
          {/* Finding Summary */}
          <div className="card accent-left-red">
            <div className="card-header">
              <span className="card-title"><AlertTriangle size={14} /> Vulnerability Findings</span>
              <span className="badge badge--critical">CVSS {r.vulnerability.cvssScore}</span>
            </div>
            <div>
              <h3 style={{ fontSize: 18, color: 'var(--t1)', marginBottom: 4 }}>{r.vulnerability.type}</h3>
              <div className="text-sm" style={{ color: 'var(--t3)', marginBottom: 16 }}>{r.vulnerability.cweName}</div>
              <div className="stat-row">
                <span className="stat-row__label">File & Location</span>
                <span className="stat-row__value mono">{r.vulnerability.location}</span>
              </div>
              <div className="stat-row">
                <span className="stat-row__label">Surrounding Function</span>
                <span className="stat-row__value mono">{r.vulnerability.function}()</span>
              </div>
            </div>
          </div>

          {/* Root Cause & Taint Trace */}
          <div className="card">
            <div className="card-header">
              <span className="card-title"><ChevronRight size={14} /> Root Cause & Taint Path</span>
            </div>
            <p className="text-sm" style={{ color: 'var(--t2)', lineHeight: 1.65 }}>
              {r.rootCause}
            </p>
            <div className="report__taint-box mt-4">
              <div className="report__taint-label">End-to-End Taint Trace</div>
              <div className="report__taint-chain">
                {[
                  { name: 'TCP Socket (User input)', role: 'source' },
                  { name: 'accept_conn()', role: 'path' },
                  { name: 'handle_request()', role: 'path' },
                  { name: 'strcpy() — Unbounded Write', role: 'sink' },
                ].map((step, idx, arr) => (
                  <React.Fragment key={step.name}>
                    <div className={`report__taint-node report__taint-node--${step.role}`}>
                      {step.name}
                    </div>
                    {idx < arr.length - 1 && <span className="report__taint-arrow">↓</span>}
                  </React.Fragment>
                ))}
              </div>
            </div>
          </div>

          {/* VulnDNA Evidence Citation */}
          <div className="card">
            <div className="card-header">
              <span className="card-title"><Dna size={14} /> Historical Patch Evidence</span>
              <span className="badge badge--amber">{r.numSimilarCVEs} Similar Fixes</span>
            </div>
            <div className="flex items-center justify-between p-3 bg-panel rounded mb-3" style={{ background: 'var(--bg-panel)', padding: 14, borderRadius: 'var(--r-md)' }}>
              <div>
                <span className="mono text-sm font-bold" style={{ color: 'var(--amber-light)' }}>{r.vulnDNATopMatch.cveId}</span>
                <div className="text-xs text-muted" style={{ marginTop: 2 }}>sudo Heap Buffer Overflow Fix</div>
              </div>
              <div className="text-right">
                <span className="mono font-bold text-green" style={{ fontSize: 16 }}>{r.vulnDNATopMatch.similarity}%</span>
                <div className="text-xs text-muted">similarity</div>
              </div>
            </div>
            <p className="text-xs text-muted" style={{ lineHeight: 1.6 }}>
              Patches were synthesized with direct structural guidance from verified historical commits.
            </p>
          </div>
        </div>

        {/* Right Column: Selected Patch & Verification Checks */}
        <div className="stack--lg">
          {/* Selected Patch Diff */}
          <div className="card accent-left-green">
            <div className="card-header">
              <span className="card-title"><CheckCircle size={14} /> Synthesized Fix Candidate</span>
              <span className="badge badge--green">Agent 1 (Root Cause)</span>
            </div>
            <p className="text-sm text-secondary mb-3" style={{ lineHeight: 1.5 }}>
              {winner.strategy}
            </p>
            <div className="terminal">
              <div className="terminal__header">
                <div className="terminal__dot"/><div className="terminal__dot"/><div className="terminal__dot"/>
                <span className="terminal__label">patch diff · {winner.linesChanged} lines</span>
              </div>
              <div className="terminal__body" style={{ maxHeight: 220 }}>
                {winner.diff.split('\n').map((line, idx) => (
                  <span
                    key={idx}
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

          {/* Verification Results */}
          <div className="card">
            <div className="card-header">
              <span className="card-title"><Shield size={14} /> Full Verification Suite</span>
              <span className="badge badge--green">All 5 Passes</span>
            </div>
            <div className="stack--sm">
              {[
                { label: 'Original PoV Exploit', result: 'BLOCKED', detail: 'Zero crash on replay' },
                { label: 'Adversarial Mutations', result: '9/9 BLOCKED', detail: 'Fuzzer could not bypass' },
                { label: 'Regression Suite', result: '47/47 PASSED', detail: 'Full feature integrity retained' },
                { label: 'Performance Delta', result: '+0.8%', detail: 'Well below 10% threshold' },
                { label: 'Refuzzing Resilience', result: 'CLEAN', detail: 'No secondary bugs generated' },
              ].map(chk => (
                <div key={chk.label} className="report__verify-row">
                  <CheckCircle size={14} style={{ color: 'var(--green-light)', flexShrink: 0 }} />
                  <div className="flex-1">
                    <div className="text-sm font-semibold" style={{ color: 'var(--t1)' }}>{chk.label}</div>
                    <div className="text-xs text-muted">{chk.detail}</div>
                  </div>
                  <span className="mono text-xs font-bold text-green">{chk.result}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </motion.div>

      {/* Human Safety Gate — Prominent Decision Section */}
      <motion.div className="card report__gate-section" {...anim(0.16)}>
        <div className="report__gate-header">
          <div className="report__gate-icon">
            {decision ? <Unlock size={24} /> : <Lock size={24} />}
          </div>
          <div>
            <h2 style={{ fontSize: 20, color: 'var(--t1)' }}>Human Safety Gate & Authorization</h2>
            <div className="text-sm text-muted" style={{ marginTop: 2 }}>
              Autonomous reasoning verified · Human sign-off required to apply patch to target environment
            </div>
          </div>
          <div className="ml-auto">
            <span className="badge badge--amber" style={{ fontSize: 11, padding: '6px 12px' }}>
              RECOMMENDATION: DEPLOY
            </span>
          </div>
        </div>

        <div className="divider" style={{ margin: '20px 0' }} />

        {!decision ? (
          <div>
            {!gateArmed ? (
              <div className="flex items-center justify-between">
                <span className="text-sm text-secondary">
                  Click to unlock safety controls and make a binding deployment decision.
                </span>
                <button
                  className="btn btn--primary btn--lg"
                  onClick={() => setGateArmed(true)}
                >
                  <User size={16} /> Unlock Decision Controls
                </button>
              </div>
            ) : (
              <div className="report__gate-actions">
                <div className="report__gate-prompt">
                  Select authoritative action for <strong>{r.target}</strong>:
                </div>
                <div className="flex gap-4 mt-4 flex-wrap">
                  <button
                    className="btn btn--success btn--xl flex-1"
                    onClick={() => setDecision('APPROVED')}
                  >
                    <CheckCircle size={18} /> APPROVE & DEPLOY PATCH
                  </button>
                  <button
                    className="btn btn--secondary btn--xl flex-1"
                    onClick={() => setDecision('HOLD')}
                  >
                    <Clock size={18} /> HOLD FOR AUDIT
                  </button>
                  <button
                    className="btn btn--danger btn--xl flex-1"
                    onClick={() => setDecision('REJECTED')}
                  >
                    <XCircle size={18} /> REJECT & RE-ANALYZE
                  </button>
                </div>
              </div>
            )}
          </div>
        ) : (
          <div className={`report__decision-banner report__decision-banner--${decision.toLowerCase()}`}>
            {decision === 'APPROVED' && (
              <>
                <CheckCircle size={24} />
                <div>
                  <div className="font-bold" style={{ fontSize: 16 }}>Patch Approved for Deployment</div>
                  <div className="text-sm" style={{ opacity: 0.9 }}>
                    Action logged with cryptographic signature in SQLite audit ledger. Deployment pipeline initiated.
                  </div>
                </div>
              </>
            )}
            {decision === 'HOLD' && (
              <>
                <Clock size={24} />
                <div>
                  <div className="font-bold" style={{ fontSize: 16 }}>Deployment Placed On Hold</div>
                  <div className="text-sm" style={{ opacity: 0.9 }}>
                    Patch held in staging registry pending further manual review.
                  </div>
                </div>
              </>
            )}
            {decision === 'REJECTED' && (
              <>
                <XCircle size={24} />
                <div>
                  <div className="font-bold" style={{ fontSize: 16 }}>Patch Rejected</div>
                  <div className="text-sm" style={{ opacity: 0.9 }}>
                    Feedback forwarded to Patch Engine to synthesize alternative candidate with updated constraints.
                  </div>
                </div>
              </>
            )}
          </div>
        )}
      </motion.div>
    </div>
  );
}
