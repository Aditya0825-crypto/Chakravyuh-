import React from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { Toaster } from 'react-hot-toast';

// Landing page
import LandingPage from './pages/LandingPage';

// Console layout + pages
import Sidebar from './components/layout/Sidebar';
import TopBar from './components/layout/TopBar';
import Dashboard from './pages/Dashboard';
import UploadTarget from './pages/UploadTarget';
import ReconEngine from './pages/ReconEngine';
import BugFinding from './pages/BugFinding';
import PovVerifier from './pages/PovVerifier';
import VulnDNA from './pages/VulnDNA';
import PatchEngine from './pages/PatchEngine';
import SecurityReport from './pages/SecurityReport';
import LearningLog from './pages/LearningLog';

// Console shell — wraps Sidebar + TopBar + nested routes
// global.css is imported here so it only applies inside the console, not on the landing page
import './styles/global.css';

function ConsoleShell() {
  return (
    <div className="app-layout">
      <Sidebar />
      <div className="app-main">
        <TopBar />
        <main className="app-content">
          <Routes>
            <Route path="/"         element={<Dashboard />} />
            <Route path="upload"    element={<UploadTarget />} />
            <Route path="recon"     element={<ReconEngine />} />
            <Route path="bugfinding" element={<BugFinding />} />
            <Route path="verifier"  element={<PovVerifier />} />
            <Route path="vulndna"   element={<VulnDNA />} />
            <Route path="patch"     element={<PatchEngine />} />
            <Route path="report"    element={<SecurityReport />} />
            <Route path="learning"  element={<LearningLog />} />
          </Routes>
        </main>
      </div>
      <Toaster
        position="bottom-right"
        toastOptions={{
          style: {
            background: '#141B2E',
            color: '#E8EDF8',
            border: '1px solid #253558',
            fontFamily: 'Space Grotesk, sans-serif',
            fontSize: '13px',
          },
        }}
      />
    </div>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        {/* Landing page — no chrome */}
        <Route path="/" element={<LandingPage />} />

        {/* Console app — full sidebar + topbar */}
        <Route path="/console/*" element={<ConsoleShell />} />
      </Routes>
    </BrowserRouter>
  );
}
