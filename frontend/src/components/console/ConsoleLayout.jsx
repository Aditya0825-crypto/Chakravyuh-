import { useState } from "react";
import { NavLink, Outlet, Link } from "react-router-dom";
import {
  LayoutDashboard,
  Radar,
  Dna,
  ShieldCheck,
  SlidersHorizontal,
  ArrowLeft,
  Menu,
  X,
} from "lucide-react";
import { scans, pendingGateScans } from "../../data/scans";

const navItems = [
  { to: "/console", label: "Dashboard", icon: LayoutDashboard, end: true },
  { to: "/console/scans", label: "Scans", icon: Radar },
  { to: "/console/vulndna", label: "VulnDNA", icon: Dna },
  { to: "/console/approvals", label: "Approvals", icon: ShieldCheck, badge: true },
  { to: "/console/settings", label: "Settings", icon: SlidersHorizontal },
];

export default function ConsoleLayout() {
  const pendingCount = pendingGateScans().length;
  const runningCount = scans.filter((s) => s.status === "running").length;
  const [drawerOpen, setDrawerOpen] = useState(false);

  const NavList = ({ onNavigate }) => (
    <>
      {navItems.map((item) => (
        <NavLink
          key={item.to}
          to={item.to}
          end={item.end}
          onClick={onNavigate}
          className={({ isActive }) =>
            `flex items-center justify-between gap-2 px-3 py-2.5 font-mono text-xs uppercase tracking-widest transition-colors ${
              isActive
                ? "bg-signal/10 text-signal border-l-2 border-signal"
                : "text-ink-2 hover:text-ink-1 hover:bg-panel-2 border-l-2 border-transparent"
            }`
          }
        >
          <span className="flex items-center gap-2.5">
            <item.icon size={15} strokeWidth={1.8} />
            {item.label}
          </span>
          {item.badge && pendingCount > 0 && (
            <span className="w-4 h-4 flex items-center justify-center rounded-full bg-red/90 text-void text-[9px] font-bold">
              {pendingCount}
            </span>
          )}
        </NavLink>
      ))}
    </>
  );

  return (
    <div className="min-h-screen bg-void text-ink-1 flex">
      {/* Desktop sidebar */}
      <aside className="hidden md:flex w-60 shrink-0 flex-col border-r border-line bg-panel-1/60">
        <div className="h-16 flex items-center gap-2.5 px-5 border-b border-line">
          <span className="relative w-4 h-4 flex items-center justify-center">
            <span className="absolute inset-0 rounded-full border border-signal/70" />
            <span className="w-1 h-1 rounded-full bg-signal" />
          </span>
          <span className="font-display font-semibold text-sm tracking-tight">CHAKRAVYUH</span>
        </div>

        <nav className="flex-1 py-6 px-3 space-y-1">
          <NavList />
        </nav>

        <div className="p-3 border-t border-line">
          <Link
            to="/"
            className="flex items-center gap-2 px-3 py-2.5 font-mono text-xs uppercase tracking-widest text-ink-3 hover:text-signal transition-colors"
          >
            <ArrowLeft size={14} />
            Back to Site
          </Link>
        </div>
      </aside>

      {/* Mobile drawer */}
      {drawerOpen && (
        <div className="md:hidden fixed inset-0 z-40 flex">
          <div
            className="absolute inset-0 bg-void/80 backdrop-blur-sm"
            onClick={() => setDrawerOpen(false)}
          />
          <aside className="relative w-64 h-full bg-panel-1 border-r border-line flex flex-col">
            <div className="h-16 flex items-center justify-between gap-2.5 px-5 border-b border-line">
              <span className="font-display font-semibold text-sm tracking-tight">CHAKRAVYUH</span>
              <button onClick={() => setDrawerOpen(false)} className="text-ink-3">
                <X size={18} />
              </button>
            </div>
            <nav className="flex-1 py-6 px-3 space-y-1">
              <NavList onNavigate={() => setDrawerOpen(false)} />
            </nav>
            <div className="p-3 border-t border-line">
              <Link
                to="/"
                onClick={() => setDrawerOpen(false)}
                className="flex items-center gap-2 px-3 py-2.5 font-mono text-xs uppercase tracking-widest text-ink-3 hover:text-signal transition-colors"
              >
                <ArrowLeft size={14} />
                Back to Site
              </Link>
            </div>
          </aside>
        </div>
      )}

      <div className="flex-1 min-w-0 flex flex-col">
        <header className="h-16 border-b border-line flex items-center justify-between px-4 md:px-8 bg-void/90 backdrop-blur sticky top-0 z-20">
          <div className="flex items-center gap-3">
            <button
              onClick={() => setDrawerOpen(true)}
              className="md:hidden text-ink-2 hover:text-signal transition-colors"
              aria-label="Open navigation"
            >
              <Menu size={20} />
            </button>
            <div className="flex items-center gap-3 font-mono text-[11px] uppercase tracking-widest text-ink-3">
              <span className="text-ink-1">Console</span>
              <span className="hidden sm:inline">/</span>
              <span className="text-signal hidden sm:inline">v4.1</span>
            </div>
          </div>
          <div className="flex items-center gap-3 md:gap-5 font-mono text-[10px] uppercase tracking-widest text-ink-3">
            <span className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-steel animate-pulse-slow" />
              <span className="hidden sm:inline">{runningCount} Running</span>
              <span className="sm:hidden">{runningCount}</span>
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-red" />
              <span className="hidden sm:inline">{pendingCount} Pending Gate</span>
              <span className="sm:hidden">{pendingCount}</span>
            </span>
          </div>
        </header>

        <main className="flex-1 p-5 md:p-8">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
