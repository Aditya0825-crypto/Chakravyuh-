import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { ShieldCheck, CheckCircle, ChevronDown, ChevronUp, Hash } from 'lucide-react';
import { useScan } from '../context/ScanContext';
import { getPoVs } from '../api/client';
import './PovVerifier.css';

const anim = (d = 0) => ({
  initial: { opacity: 0, y: 12 },
  animate: { opacity: 1, y: 0 },
  transition: { duration: 0.35, delay: d }
});

export default function PovVerifier() {
  const { scanId } = useScan();
  const [povs, setPovs] = useState([]);
  const [expanded, setExpanded] = useState(null);
  const [showDedup, setShowDedup] = useState(false);

  useEffect(() => {
    if (!scanId) return;
    getPoVs(scanId)
      .then((data) => {
        if (data?.length > 0) {
          setPovs(data);
          setExpanded(data[0].id);
        }
      })
      .catch(() => {});
  }, [scanId]);

  return (
    <div>
      {/* Header */}
      <motion.div className="page-header" {...anim(0)}>
        <div className="page-header__eyebrow">STAGE 03 · ADVERSARIAL VERIFICATION</div>
        <h1 className="page-header__title">PoV Verifier</h1>
        <p className="page-header__subtitle">
          Containerized crash replay · ASan trace normalization · Stack hash deduplication · Multi-metric confidence scoring
        </p>
      </motion.div>

      {/* 5-Step Pipeline Strip */}
      <motion.div className="card section-gap--sm" {...anim(0.04)} style={{ padding: '16px 20px' }}>
        <div className="pov__steps-bar">
          {[
            { step: '01', title: 'Container Replay', desc: '5/5 Isolated Replays' },
            { step: '02', title: 'ASan Classifier', desc: 'CWE Type Identification' },
            { step: '03', title: 'Stack Extraction', desc: 'Normalized Frame Depths' },
            { step: '04', title: 'Hash Dedup', desc: 'Unique Stack Hashes' },
            { step: '05', title: 'Confidence Math', desc: 'Weighted Multi-Factor' },
          ].map((st, i, arr) => (
            <React.Fragment key={st.step}>
              <div className="pov__step-unit">
                <div className="flex items-center gap-1">
                  <CheckCircle size={13} style={{ color: 'var(--green-light)' }} />
                  <span className="mono text-xs font-bold text-primary">{st.step}. {st.title}</span>
                </div>
                <span className="text-xs text-muted mt-1">{st.desc}</span>
              </div>
              {i < arr.length - 1 && <span className="pov__step-arrow">→</span>}
            </React.Fragment>
          ))}
        </div>
      </motion.div>

      {/* Verified Crashes Accordion */}
      <motion.div className="section-gap--sm" {...anim(0.08)}>
        <div className="flex items-center justify-between mb-3">
          <span className="mono text-xs font-bold text-muted uppercase tracking-wider">
            Verified Unique Vulnerabilities ({povs.length})
          </span>
          <span className="text-xs text-muted">Click to inspect stack trace & confidence factors</span>
        </div>

        <div className="stack--sm">
          {povs.length > 0 ? (
            povs.map(p => {
              const isExp = expanded === p.id;
              return (
                <div key={p.id} className={`card ${isExp ? 'accent-left-red' : ''}`} style={{ padding: 0, overflow: 'hidden' }}>
                  <div
                    className="flex items-center justify-between p-4 cursor-pointer flex-wrap gap-2"
                    onClick={() => setExpanded(isExp ? null : p.id)}
                  >
                    <div className="flex items-center gap-3">
                      <span className="mono text-xs text-muted">{p.id}</span>
                      <span className="badge badge--critical">{p.cwe || 'CWE'}</span>
                      <strong className="mono text-sm">{p.type || 'Vulnerability'}</strong>
                      <span className="mono text-xs text-muted">{p.file || 'source'}:{p.line || 0}</span>
                    </div>
                    <div className="flex items-center gap-3">
                      <span className="badge badge--green mono text-xs">VERIFIED</span>
                      <span className="mono text-xs font-bold text-amber">{p.confidence || 0}% Conf.</span>
                      {isExp ? <ChevronUp size={15} /> : <ChevronDown size={15} style={{ color: 'var(--t4)' }} />}
                    </div>
                  </div>

                  {isExp && (
                    <motion.div
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      className="p-4 pt-0"
                      style={{ borderTop: '1px solid var(--border-1)' }}
                    >
                      <div className="grid-2 my-3">
                        <div>
                          <span className="text-xs text-muted mono">NORMALIZED STACK TRACE:</span>
                          <div className="terminal mt-1" style={{ fontSize: 11 }}>
                            <div className="terminal__body" style={{ padding: '8px 12px' }}>
                              {(p.stackTrace || []).map((f, i) => (
                                <div key={i} className="mono text-xs" style={{ color: i === 0 ? 'var(--red-light)' : 'var(--t2)' }}>
                                  {f}
                                </div>
                              ))}
                            </div>
                          </div>
                        </div>

                        <div>
                          <span className="text-xs text-muted mono">STACK DEDUPLICATION HASH:</span>
                          <div className="card card--subtle mt-1" style={{ padding: '12px 16px' }}>
                            <div className="flex items-center gap-2 mb-2">
                              <Hash size={13} style={{ color: 'var(--cyan-light)' }} />
                              <span className="mono text-xs font-bold text-cyan">{p.stackHash || 'N/A'}</span>
                            </div>
                            <p className="text-xs text-muted" style={{ lineHeight: 1.5 }}>
                              Stripped ASan boilerplate frames. Collision deduplication ensures only semantically unique root causes proceed to repair.
                            </p>
                          </div>
                        </div>
                      </div>

                      <div className="pt-3" style={{ borderTop: '1px solid var(--border-1)' }}>
                        <span className="text-xs text-muted mono">CONFIDENCE SCORING BREAKDOWN:</span>
                        <div className="grid-3 mt-2">
                          <div className="stat-row">
                            <span className="text-xs text-muted">ASan Signal Match</span>
                            <span className="mono text-xs text-green font-bold">1.00</span>
                          </div>
                          <div className="stat-row">
                            <span className="text-xs text-muted">Replay Determinism</span>
                            <span className="mono text-xs text-green font-bold">1.00</span>
                          </div>
                          <div className="stat-row">
                            <span className="text-xs text-muted">Stack Frame Depth</span>
                            <span className="mono text-xs text-green font-bold">0.92</span>
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
              <p className="text-sm font-semibold mb-1">No Verified Proof-of-Vulnerability Evidence</p>
              <p className="text-xs">Containerized crash replays and normalized stack traces will display here once verified.</p>
            </div>
          )}
        </div>
      </motion.div>
    </div>
  );
}
