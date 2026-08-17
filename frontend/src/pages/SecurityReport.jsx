import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  FileText, CheckCircle, AlertTriangle, XCircle,
  Shield, User, Lock, Unlock, Download, Printer,
  ChevronRight, Clock, Dna, ArrowRight, Loader2
} from 'lucide-react';
import toast from 'react-hot-toast';
import { securityReport as fallbackReport, patchCandidates as fallbackCandidates } from '../data/mockData';
import { useScan } from '../context/ScanContext';
import { getReport, getPatches, submitGateDecision } from '../api/client';
import './SecurityReport.css';

const anim = (d = 0) => ({
  initial: { opacity: 0, y: 16 },
  animate: { opacity: 1, y: 0 },
  transition: { duration: 0.4, delay: d }
});

export default function SecurityReport() {
  const { scanId, scan } = useScan();
  const [report, setReport] = useState(fallbackReport);
  const [winner, setWinner] = useState(fallbackCandidates[0]);
  const [decision, setDecision] = useState(null); // 'APPROVED' | 'HOLD' | 'REJECTED'
  const [notes, setNotes] = useState('');
  const [gateArmed, setGateArmed] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (!scanId) return;

    getReport(scanId)
      .then((data) => {
        if (data) {
          setReport(data);
          if (data.humanDecision) {
            setDecision(data.humanDecision.decision);
            setNotes(data.humanDecision.notes || '');
          }
        }
      })
      .catch(() => {});

    getPatches(scanId)
      .then((data) => {
        if (data?.winner) {
          setWinner(data.winner);
        } else if (data?.candidates?.length > 0) {
          setWinner(data.candidates[0]);
        }
      })
      .catch(() => {});
  }, [scanId]);

  const handleDecisionSubmit = async (dec) => {
    if (!scanId) {
      setDecision(dec);
      toast.success(`Gate Decision recorded: ${dec}`);
      return;
    }

    setSubmitting(true);
    try {
      await submitGateDecision(scanId, {
        decision: dec,
        notes: notes || `Decision ${dec} submitted via console UI.`,
        decided_by: 'Security Lead (Human Gate)',
      });
      setDecision(dec);
      toast.success(`HUMAN GATE: ${dec} status saved to backend & learning log!`);
    } catch (err) {
      toast.error(`Gate submission failed: ${err.message}`);
    } finally {
      setSubmitting(false);
    }
  };

  const r = report || fallbackReport;
  const vul = r.vulnerability || { cvssScore: 9.8, cweId: 'CWE-122', cweName: 'Heap Buffer Overflow' };

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
          <span className="report__meta-val mono font-semibold">{r.id || 'CHK-2026-0047'}</span>
        </div>
        <div className="report__meta-item">
          <span className="report__meta-key">Target Binary</span>
          <span className="report__meta-val font-semibold">{scan?.target_name || r.target}</span>
        </div>
        <div className="report__meta-item">
          <span className="report__meta-key">Vulnerability</span>
          <div className="flex items-center gap-2">
            <span className="badge badge--critical">{vul.cvssScore} CRITICAL</span>
            <span className="mono text-xs" style={{ color: 'var(--t2)' }}>{vul.cweId}</span>
          </div>
        </div>
        <div className="report__meta-item">
          <span className="report__meta-key">Recommendation</span>
          <span className={`badge ${r.recommendation === 'SAFE' ? 'badge--green' : r.recommendation === 'REVIEW' ? 'badge--amber' : 'badge--danger'} mono font-bold`}>
            {r.recommendation || 'SAFE'}
          </span>
        </div>
        <div className="report__meta-item">
          <span className="report__meta-key">AI Confidence</span>
          <span className="report__meta-val mono text-amber font-bold" style={{ fontSize: 16 }}>{r.confidence || 96}%</span>
        </div>
      </motion.div>

      {/* Root Cause & Taint Explanation */}
      <motion.div className="card accent-left-amber section-gap--sm" {...anim(0.08)}>
        <h3 className="mono font-bold text-base text-primary mb-2">Root Cause Analysis & Taint Trace</h3>
        <p className="text-sm text-secondary" style={{ lineHeight: 1.6 }}>
          {r.rootCause}
        </p>
      </motion.div>

      {/* Human Safety Gate Interactive Card */}
      <motion.div className="card card--subtle section-gap--sm p-5" {...anim(0.1)}>
        <div className="flex items-center justify-between mb-4 pb-3" style={{ borderBottom: '1px solid var(--border-1)' }}>
          <div className="flex items-center gap-2">
            <Shield size={18} style={{ color: 'var(--cyan-light)' }} />
            <h3 className="font-bold text-base text-primary">Human Safety Gate — Authoritative Sign-Off</h3>
          </div>
          <span className="mono text-xs text-muted">Zero Auto-Deploy Policy Enforced</span>
        </div>

        <p className="text-xs text-secondary mb-4" style={{ lineHeight: 1.5 }}>
          The autonomous system has generated candidate patches, executed concolic adversarial stress tests, and scored results.
          Deployment to production requires an explicit sign-off by a qualified security engineer.
        </p>

        <div className="mb-4">
          <label className="text-xs text-muted mono block mb-1">AUDITOR NOTES / SIGN-OFF RATIONALE:</label>
          <input
            type="text"
            placeholder="e.g. Verified patch logic and approved for staging release."
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            style={{
              width: '100%',
              padding: '8px 12px',
              background: 'var(--bg-panel)',
              border: '1px solid var(--border-1)',
              borderRadius: 'var(--radius-sm)',
              color: 'var(--t1)',
              fontFamily: 'var(--font-mono)',
              fontSize: 12,
              outline: 'none',
            }}
          />
        </div>

        <div className="flex items-center gap-3 flex-wrap">
          <button
            className={`btn btn--primary ${decision === 'APPROVED' ? 'ring-2' : ''}`}
            onClick={() => handleDecisionSubmit('APPROVED')}
            disabled={submitting}
          >
            {submitting ? <Loader2 size={14} className="animate-spin" /> : <CheckCircle size={14} />}
            Approve & Tag Release (APPROVED)
          </button>

          <button
            className={`btn btn--secondary ${decision === 'HOLD' ? 'ring-2' : ''}`}
            onClick={() => handleDecisionSubmit('HOLD')}
            disabled={submitting}
          >
            <Clock size={14} />
            Hold for Manual Review (HOLD)
          </button>

          <button
            className={`btn btn--danger ${decision === 'REJECTED' ? 'ring-2' : ''}`}
            onClick={() => handleDecisionSubmit('REJECTED')}
            disabled={submitting}
          >
            <XCircle size={14} />
            Reject Patch (REJECTED)
          </button>
        </div>

        {decision && (
          <div className="mt-4 p-3 card card--green flex items-center justify-between">
            <span className="text-xs text-green font-bold mono">CURRENT STATUS: {decision}</span>
            <span className="text-xs text-muted mono">Logged to System Learning Database</span>
          </div>
        )}
      </motion.div>

      {/* Selected Winner Patch Diff */}
      {winner && (
        <motion.div className="card section-gap--sm" {...anim(0.12)}>
          <div className="flex items-center justify-between mb-3">
            <span className="mono font-bold text-sm text-primary">Selected Winning Fix: {winner.agent} — {winner.name}</span>
            <span className="badge badge--green mono">Score {winner.score?.total ? winner.score.total.toFixed(1) : '94.4'}</span>
          </div>

          <div className="terminal" style={{ fontSize: 11 }}>
            <div className="terminal__body" style={{ padding: '10px 14px', maxHeight: 200, overflowY: 'auto' }}>
              <pre className="mono text-xs" style={{ margin: 0 }}>
                {winner.diff.split('\n').map((line, lidx) => {
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
        </motion.div>
      )}
    </div>
  );
}
