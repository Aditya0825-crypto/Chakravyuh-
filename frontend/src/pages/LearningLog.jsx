import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  BookOpen, CheckCircle, XCircle, Search,
  Filter, TrendingUp, Database, Calendar, ChevronDown, ChevronUp
} from 'lucide-react';
import { learningLog } from '../data/mockData';
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
  const [search, setSearch] = useState('');
  const [cweFilter, setCweFilter] = useState('ALL');
  const [expandedId, setExpandedId] = useState(null);

  const cwes = ['ALL', ...new Set(learningLog.map(l => l.cwe))];

  const filtered = learningLog.filter(l => {
    const matchSearch = !search ||
      l.target.toLowerCase().includes(search.toLowerCase()) ||
      l.cwe.toLowerCase().includes(search.toLowerCase()) ||
      l.crashType.toLowerCase().includes(search.toLowerCase());
    const matchCwe = cweFilter === 'ALL' || l.cwe === cweFilter;
    return matchSearch && matchCwe;
  });

  const successCount = learningLog.filter(l => l.patchSuccess).length;
  const successRate = Math.round((successCount / learningLog.length) * 100);

  return (
    <div>
      {/* Header */}
      <motion.div className="page-header" {...anim(0)}>
        <div className="page-header__eyebrow">System Memory</div>
        <h1 className="page-header__title">Autonomous Learning Log</h1>
        <p className="page-header__subtitle">
          Historical repository of analyzed binaries, synthesized patches, and adversarial verification outcomes stored in SQLite
        </p>
      </motion.div>

      {/* KPI Cards */}
      <motion.div className="grid-4 section-gap--sm" {...anim(0.06)}>
        {[
          { label: 'Total Runs', value: learningLog.length, accent: 'amber', icon: Database },
          { label: 'Patches Verified', value: successCount, accent: 'green', icon: CheckCircle },
          { label: 'Unresolved / Failed', value: learningLog.length - successCount, accent: 'red', icon: XCircle },
          { label: 'Autonomous Success Rate', value: `${successRate}%`, accent: 'cyan', icon: TrendingUp },
        ].map(kpi => {
          const Icon = kpi.icon;
          return (
            <div key={kpi.label} className={`card ll__kpi-card accent-left-${kpi.accent}`}>
              <div className="flex items-center justify-between">
                <span className="text-xs text-muted font-medium">{kpi.label}</span>
                <Icon size={16} style={{ color: `var(--${kpi.accent}-light)` }} />
              </div>
              <div className="ll__kpi-value">{kpi.value}</div>
            </div>
          );
        })}
      </motion.div>

      {/* Search & Filters */}
      <motion.div className="ll__filter-bar section-gap--sm" {...anim(0.1)}>
        <div className="ll__search-box">
          <Search size={14} style={{ color: 'var(--t3)' }} />
          <input
            type="text"
            className="ll__search-input"
            placeholder="Filter by target name, CWE identifier, or crash type..."
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
        </div>
        <div className="ll__pills">
          <Filter size={13} style={{ color: 'var(--t3)', marginRight: 4 }} />
          {cwes.map(cwe => (
            <button
              key={cwe}
              className={`ll__pill ${cweFilter === cwe ? 'll__pill--active' : ''}`}
              onClick={() => setCweFilter(cwe)}
            >
              {cwe}
            </button>
          ))}
        </div>
      </motion.div>

      {/* Main Table */}
      <motion.div className="table-wrapper section-gap--sm" {...anim(0.14)}>
        <table>
          <thead>
            <tr>
              <th>Date</th>
              <th>Target Binary</th>
              <th>CWE & Crash Type</th>
              <th>Discovery Engine</th>
              <th>Winning Repair Agent</th>
              <th>VulnDNA Citation</th>
              <th>Confidence</th>
              <th>Outcome</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {filtered.map(entry => {
              const isExpanded = expandedId === entry.id;
              return (
                <React.Fragment key={entry.id}>
                  <tr
                    onClick={() => setExpandedId(isExpanded ? null : entry.id)}
                    style={{ cursor: 'pointer' }}
                  >
                    <td>
                      <div className="flex items-center gap-2">
                        <Calendar size={12} style={{ color: 'var(--t3)' }} />
                        <span className="mono text-xs">{entry.date}</span>
                      </div>
                    </td>
                    <td><strong className="mono text-sm">{entry.target}</strong></td>
                    <td>
                      <div className="stack--4">
                        <span className={`badge ${cweBadges[entry.cwe] || 'badge--neutral'}`}>{entry.cwe}</span>
                        <span className="text-xs text-muted">{entry.crashType}</span>
                      </div>
                    </td>
                    <td><span className="tag">{entry.discoveryMethod}</span></td>
                    <td><span className="text-sm text-secondary">{entry.winningAgent}</span></td>
                    <td><span className="mono text-xs text-amber font-semibold">{entry.topCVE}</span></td>
                    <td>
                      <div className="flex items-center gap-2">
                        <div className="progress-track" style={{ width: 44 }}>
                          <div className="progress-fill progress-fill--green" style={{ width: `${entry.confidence}%` }} />
                        </div>
                        <span className="mono text-xs font-bold text-green">{entry.confidence}%</span>
                      </div>
                    </td>
                    <td>
                      {entry.patchSuccess ? (
                        <span className="badge badge--green">Verified</span>
                      ) : (
                        <span className="badge badge--critical">Failed</span>
                      )}
                    </td>
                    <td>
                      {isExpanded ? <ChevronUp size={14} style={{ color: 'var(--t3)' }} /> : <ChevronDown size={14} style={{ color: 'var(--t4)' }} />}
                    </td>
                  </tr>
                  {isExpanded && (
                    <tr>
                      <td colSpan={9} style={{ background: 'var(--bg-panel)', padding: '16px 24px', borderBottom: '1px solid var(--border-2)' }}>
                        <div className="flex items-start gap-3">
                          <BookOpen size={16} style={{ color: 'var(--amber-light)', flexShrink: 0, marginTop: 2 }} />
                          <div>
                            <div className="text-xs font-bold text-muted uppercase tracking-wider mb-1">Reasoning & Verification Notes</div>
                            <p className="text-sm" style={{ color: 'var(--t2)', lineHeight: 1.6 }}>{entry.notes}</p>
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
      </motion.div>

      {/* SQLite Footer */}
      <motion.div className="card ll__db-footer" {...anim(0.18)}>
        <Database size={16} style={{ color: 'var(--amber-light)', flexShrink: 0 }} />
        <div className="text-xs text-muted">
          Persisted in <strong className="mono text-primary">chakravyuh_learning.db</strong> (SQLite 3.42) · Full schema stores normalized callgraphs, LLM temperature logs, AST embeddings, and verified patch checksums.
        </div>
      </motion.div>
    </div>
  );
}
