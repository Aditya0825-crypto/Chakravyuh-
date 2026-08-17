import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  BookOpen, CheckCircle, XCircle, Search,
  Filter, TrendingUp, Database, Calendar, ChevronDown, ChevronUp
} from 'lucide-react';
import { learningLog as fallbackLog } from '../data/mockData';
import { getLearningLog } from '../api/client';
import './LearningLog.css';

const anim = (d = 0) => ({
  initial: { opacity: 0, y: 16 },
  animate: { opacity: 1, y: 0 },
  transition: { duration: 0.4, delay: d }
});

const cweBadges = {
  'CWE-122': 'badge--critical',
  'CWE-121': 'badge--high',
  'CWE-416': 'badge--high',
  'CWE-89':  'badge--high',
  'CWE-476': 'badge--medium',
  'CWE-190': 'badge--medium',
};

export default function LearningLog() {
  const [log, setLog] = useState(fallbackLog);
  const [search, setSearch] = useState('');
  const [cweFilter, setCweFilter] = useState('ALL');
  const [expandedId, setExpandedId] = useState(null);

  useEffect(() => {
    getLearningLog()
      .then((data) => {
        if (data && data.length > 0) {
          setLog(data);
        }
      })
      .catch(() => {});
  }, []);

  const cwes = ['ALL', ...new Set(log.map(l => l.cwe))];

  const filtered = log.filter(l => {
    const matchSearch = !search ||
      l.target.toLowerCase().includes(search.toLowerCase()) ||
      l.cwe.toLowerCase().includes(search.toLowerCase()) ||
      l.crashType.toLowerCase().includes(search.toLowerCase());
    const matchCwe = cweFilter === 'ALL' || l.cwe === cweFilter;
    return matchSearch && matchCwe;
  });

  const successCount = log.filter(l => l.patchSuccess).length;
  const successRate = log.length > 0 ? Math.round((successCount / log.length) * 100) : 100;

  return (
    <div>
      {/* Header */}
      <motion.div className="page-header" {...anim(0)}>
        <div className="page-header__eyebrow">System Memory</div>
        <h1 className="page-header__title">Autonomous Learning Log</h1>
        <p className="page-header__subtitle">
          Historical repository of analyzed binaries, synthesized patches, and adversarial verification outcomes stored in database
        </p>
      </motion.div>

      {/* KPI Cards */}
      <motion.div className="grid-4 section-gap--sm" {...anim(0.06)}>
        {[
          { label: 'Total Runs', value: log.length, accent: 'amber', icon: Database },
          { label: 'Patches Verified', value: successCount, accent: 'green', icon: CheckCircle },
          { label: 'Unresolved / Failed', value: log.length - successCount, accent: 'red', icon: XCircle },
          { label: 'Autonomous Success Rate', value: `${successRate}%`, accent: 'cyan', icon: TrendingUp },
        ].map(k => {
          const Icon = k.icon;
          return (
            <div key={k.label} className={`card kpi-card kpi-card--${k.accent}`}>
              <div className="flex items-center justify-between mb-2">
                <span className="kpi-card__label">{k.label}</span>
                <Icon size={14} style={{ color: `var(--${k.accent}-light)` }} />
              </div>
              <div className="kpi-card__val mono">{k.value}</div>
            </div>
          );
        })}
      </motion.div>

      {/* Filter / Search Bar */}
      <motion.div className="card section-gap--sm" {...anim(0.08)} style={{ padding: '12px 18px' }}>
        <div className="flex items-center justify-between gap-4 flex-wrap">
          <div className="flex items-center gap-2 flex-1" style={{ minWidth: 200 }}>
            <Search size={14} style={{ color: 'var(--t4)' }} />
            <input
              type="text"
              placeholder="Search by binary target, CWE, or crash signature..."
              value={search}
              onChange={e => setSearch(e.target.value)}
              style={{
                background: 'transparent',
                border: 'none',
                color: 'var(--t1)',
                fontFamily: 'var(--font-mono)',
                fontSize: 12,
                outline: 'none',
                width: '100%',
              }}
            />
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            <Filter size={13} style={{ color: 'var(--t4)' }} />
            <span className="text-xs text-muted">CWE:</span>
            {cwes.map(c => (
              <button
                key={c}
                onClick={() => setCweFilter(c)}
                className={`tag ${cweFilter === c ? 'tag--active' : ''}`}
                style={{ cursor: 'pointer' }}
              >
                {c}
              </button>
            ))}
          </div>
        </div>
      </motion.div>

      {/* Runs Table */}
      <motion.div className="section-gap--sm" {...anim(0.1)}>
        <div className="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>Date</th>
                <th>Target Binary</th>
                <th>CWE</th>
                <th>Crash Type</th>
                <th>Winning Agent</th>
                <th>Top CVE Precedent</th>
                <th>Conf.</th>
                <th>Outcome</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {filtered.map(l => {
                const isExp = expandedId === l.id;
                const badgeCls = cweBadges[l.cwe] || 'badge--neutral';

                return (
                  <React.Fragment key={l.id}>
                    <tr
                      onClick={() => setExpandedId(isExp ? null : l.id)}
                      style={{ cursor: 'pointer' }}
                    >
                      <td className="mono text-xs text-muted">{l.date}</td>
                      <td><strong className="mono text-sm">{l.target}</strong></td>
                      <td><span className={`badge ${badgeCls}`}>{l.cwe}</span></td>
                      <td className="text-xs text-secondary">{l.crashType}</td>
                      <td className="text-xs font-semibold text-primary">{l.winningAgent}</td>
                      <td>
                        {l.topCVE ? (
                          <span className="mono text-xs text-amber font-semibold">{l.topCVE}</span>
                        ) : (
                          <span className="mono text-xs text-muted">—</span>
                        )}
                      </td>
                      <td className="mono text-xs text-muted">{l.confidence}%</td>
                      <td>
                        {l.patchSuccess ? (
                          <span className="badge badge--green">VERIFIED</span>
                        ) : (
                          <span className="badge badge--danger">UNRESOLVED</span>
                        )}
                      </td>
                      <td>
                        {isExp ? <ChevronUp size={14} /> : <ChevronDown size={14} style={{ color: 'var(--t4)' }} />}
                      </td>
                    </tr>
                    {isExp && (
                      <tr>
                        <td colSpan={9} style={{ background: 'var(--bg-panel)', padding: '14px 20px' }}>
                          <div className="stack--xs">
                            <div className="flex items-center gap-4 text-xs text-muted mono">
                              <span>DISCOVERY: <strong className="text-primary">{l.discoveryMethod}</strong></span>
                              <span>ENTRY ID: <strong className="text-muted">{l.id}</strong></span>
                            </div>
                            <p className="text-xs text-secondary mt-1" style={{ lineHeight: 1.5 }}>
                              <strong>Notes:</strong> {l.notes}
                            </p>
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
    </div>
  );
}
