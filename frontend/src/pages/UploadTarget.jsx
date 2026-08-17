import React, { useState, useRef, useCallback } from 'react';
import { motion } from 'framer-motion';
import { useNavigate } from 'react-router-dom';
import toast from 'react-hot-toast';
import { uploadScan } from '../api/client';
import { useScan } from '../context/ScanContext';
import {
  UploadCloud, FileArchive, FileCode2, File as FileIcon,
  X, Trash2, ArrowRight, Loader2, CheckCircle2, ShieldAlert,
} from 'lucide-react';
import './UploadTarget.css';

const anim = (d = 0) => ({
  initial: { opacity: 0, y: 12 },
  animate: { opacity: 1, y: 0 },
  transition: { duration: 0.35, delay: d },
});

// Extensions Chakravyuh knows how to ingest for static/dynamic analysis
const SOURCE_EXTENSIONS = [
  'c', 'h', 'cpp', 'cc', 'cxx', 'hpp', 'hxx',
  'py', 'js', 'jsx', 'ts', 'tsx', 'mjs', 'cjs',
  'java', 'kt', 'go', 'rs', 'rb', 'php', 'cs',
  'swift', 'm', 'mm', 'scala', 'sql', 'sh',
  'yaml', 'yml', 'json', 'toml', 'xml', 'txt', 'md',
];
const ARCHIVE_EXTENSIONS = ['zip'];
const ALL_ACCEPTED = [...SOURCE_EXTENSIONS, ...ARCHIVE_EXTENSIONS];

const LANGUAGE_MAP = {
  c: 'C', h: 'C', cpp: 'C++', cc: 'C++', cxx: 'C++', hpp: 'C++', hxx: 'C++',
  py: 'Python', js: 'JavaScript', jsx: 'JavaScript', ts: 'TypeScript', tsx: 'TypeScript',
  mjs: 'JavaScript', cjs: 'JavaScript', java: 'Java', kt: 'Kotlin', go: 'Go',
  rs: 'Rust', rb: 'Ruby', php: 'PHP', cs: 'C#', swift: 'Swift', m: 'Obj-C',
  mm: 'Obj-C++', scala: 'Scala', sql: 'SQL', sh: 'Shell',
  yaml: 'Config', yml: 'Config', json: 'Config', toml: 'Config', xml: 'Config',
  txt: 'Text', md: 'Docs',
};

function extOf(filename) {
  const parts = filename.split('.');
  return parts.length > 1 ? parts.pop().toLowerCase() : '';
}

function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
}

function iconFor(ext) {
  if (ARCHIVE_EXTENSIONS.includes(ext)) return FileArchive;
  if (SOURCE_EXTENSIONS.includes(ext)) return FileCode2;
  return FileIcon;
}

let uid = 0;

export default function UploadTarget() {
  const nav = useNavigate();
  const inputRef = useRef(null);
  const fileObjectsRef = useRef(new Map());
  const { setScanId } = useScan();

  const [files, setFiles] = useState([]);
  const [rejected, setRejected] = useState([]);
  const [dragActive, setDragActive] = useState(false);
  const [status, setStatus] = useState('idle'); // idle | uploading | ready

  const addFiles = useCallback((fileList) => {
    const incoming = Array.from(fileList);
    const accepted = [];
    const newlyRejected = [];

    incoming.forEach((f) => {
      const ext = extOf(f.name);
      if (ALL_ACCEPTED.includes(ext)) {
        const id = `f${++uid}`;
        fileObjectsRef.current.set(id, f);
        accepted.push({
          id,
          name: f.name,
          size: f.size,
          ext,
          isArchive: ARCHIVE_EXTENSIONS.includes(ext),
        });
      } else {
        newlyRejected.push(f.name);
      }
    });

    if (accepted.length) {
      setFiles((prev) => [...prev, ...accepted]);
      setStatus('ready');
    }
    if (newlyRejected.length) {
      setRejected((prev) => [...prev, ...newlyRejected]);
      toast.error(
        newlyRejected.length === 1
          ? `Unsupported file type: ${newlyRejected[0]}`
          : `${newlyRejected.length} files rejected — unsupported type`
      );
    }
  }, []);

  const onInputChange = (e) => {
    if (e.target.files?.length) addFiles(e.target.files);
    e.target.value = '';
  };

  const onDrop = (e) => {
    e.preventDefault();
    setDragActive(false);
    if (e.dataTransfer.files?.length) addFiles(e.dataTransfer.files);
  };

  const onDragOver = (e) => { e.preventDefault(); setDragActive(true); };
  const onDragLeave = (e) => { e.preventDefault(); setDragActive(false); };

  const removeFile = (id) => {
    fileObjectsRef.current.delete(id);
    setFiles((prev) => prev.filter((f) => f.id !== id));
  };
  const clearAll = () => {
    fileObjectsRef.current.clear();
    setFiles([]);
    setRejected([]);
    setStatus('idle');
  };

  const totalSize = files.reduce((sum, f) => sum + f.size, 0);
  const hasArchive = files.some((f) => f.isArchive);
  const languages = [...new Set(
    files.filter((f) => !f.isArchive).map((f) => LANGUAGE_MAP[f.ext]).filter(Boolean)
  )];

  const beginAnalysis = async () => {
    if (!files.length) return;
    setStatus('uploading');
    toast.loading('Ingesting target into Chakravyuh…', { id: 'ingest' });

    try {
      const blobList = files.map((f) => fileObjectsRef.current.get(f.id)).filter(Boolean);
      const result = await uploadScan(blobList);
      setScanId(result.id);
      toast.success('Target ingested — autonomous pipeline started', { id: 'ingest' });
      nav('/console/recon');
    } catch (err) {
      setStatus('ready');
      toast.error(err.message || 'Upload failed', { id: 'ingest' });
    }
  };

  return (
    <div>
      <motion.div className="page-header" {...anim(0)}>
        <div className="page-header__eyebrow">STAGE 00 · TARGET INGESTION</div>
        <h1 className="page-header__title">Upload Target</h1>
        <p className="page-header__subtitle">
          Upload a zipped project, or select individual / multiple source files. Chakravyuh
          parses the codebase and hands it straight to the Recon Engine — this is where the
          autonomous pipeline begins.
        </p>
      </motion.div>

      {/* Dropzone */}
      <motion.div
        className="card ut__dropzone-card section-gap--sm"
        {...anim(0.05)}
      >
        <div
          className={`ut__dropzone ${dragActive ? 'ut__dropzone--active' : ''}`}
          onDrop={onDrop}
          onDragOver={onDragOver}
          onDragLeave={onDragLeave}
          onClick={() => inputRef.current?.click()}
          role="button"
          tabIndex={0}
        >
          <input
            ref={inputRef}
            type="file"
            multiple
            accept={ALL_ACCEPTED.map((e) => `.${e}`).join(',')}
            onChange={onInputChange}
            hidden
          />
          <div className="ut__dropzone-icon">
            <UploadCloud size={26} strokeWidth={1.75} />
          </div>
          <div className="ut__dropzone-title">
            Drag &amp; drop your project here
          </div>
          <div className="ut__dropzone-sub">
            or <span className="ut__dropzone-link">browse files</span> — accepts a single
            <strong> .zip</strong> archive, or individual / multiple source files
          </div>
          <div className="ut__dropzone-formats">
            {['.zip', '.c/.cpp', '.py', '.js/.ts', '.java', '.go', '.rs', '+more'].map((f) => (
              <span key={f} className="tag">{f}</span>
            ))}
          </div>
        </div>
      </motion.div>

      {/* File list + summary */}
      {files.length > 0 && (
        <motion.div className="grid-3-2 section-gap--sm" {...anim(0.1)}>
          <div className="card card--flush ut__filelist-card">
            <div className="card-header" style={{ padding: '16px 20px', marginBottom: 0 }}>
              <span className="card-title">
                <FileCode2 size={15} /> Staged Files
                <span className="badge badge--neutral" style={{ marginLeft: 8 }}>
                  {files.length}
                </span>
              </span>
              <button className="btn btn--ghost" onClick={clearAll} style={{ minHeight: 30, padding: '6px 12px' }}>
                <Trash2 size={13} /> Clear All
              </button>
            </div>

            <div className="ut__filelist">
              {files.map((f) => {
                const Icon = iconFor(f.ext);
                return (
                  <div key={f.id} className="ut__file-row">
                    <Icon size={15} className={f.isArchive ? 'text-signal' : 'text-cyan'} />
                    <span className="ut__file-name truncate" title={f.name}>{f.name}</span>
                    {f.isArchive ? (
                      <span className="tag">ARCHIVE</span>
                    ) : (
                      <span className="tag">{LANGUAGE_MAP[f.ext] || f.ext.toUpperCase()}</span>
                    )}
                    <span className="ut__file-size mono">{formatBytes(f.size)}</span>
                    <button
                      className="ut__file-remove"
                      onClick={() => removeFile(f.id)}
                      title="Remove file"
                    >
                      <X size={14} />
                    </button>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Summary panel */}
          <div className="stack">
            <div className="card">
              <div className="card-title mb-4"><ShieldAlert size={15} /> Ingestion Summary</div>
              <div className="stat-row">
                <span className="stat-row__label">Files staged</span>
                <span className="stat-row__value">{files.length}</span>
              </div>
              <div className="stat-row">
                <span className="stat-row__label">Total size</span>
                <span className="stat-row__value">{formatBytes(totalSize)}</span>
              </div>
              <div className="stat-row">
                <span className="stat-row__label">Source type</span>
                <span className="stat-row__value">
                  {hasArchive ? 'Zipped project' : 'Loose source files'}
                </span>
              </div>
              {languages.length > 0 && (
                <div className="mt-4">
                  <div className="text-xs text-muted mono uppercase tracking-wider mb-2">
                    Detected languages
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {languages.map((l) => (
                      <span key={l} className="badge badge--info">{l}</span>
                    ))}
                  </div>
                </div>
              )}
            </div>

            <button
              className="btn btn--primary btn--xl w-full"
              onClick={beginAnalysis}
              disabled={status === 'uploading'}
            >
              {status === 'uploading' ? (
                <>
                  <Loader2 size={16} className="ut__spin" /> Ingesting Target…
                </>
              ) : (
                <>
                  <CheckCircle2 size={16} /> Begin Autonomous Analysis <ArrowRight size={16} />
                </>
              )}
            </button>
          </div>
        </motion.div>
      )}
    </div>
  );
}
