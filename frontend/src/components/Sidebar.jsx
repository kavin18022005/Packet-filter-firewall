import React from 'react';
import {
  LayoutDashboard,
  Activity,
  ShieldCheck,
  AlertTriangle,
  FileSearch,
  Settings
} from 'lucide-react';

export function Sidebar({ currentTab, onSelectTab, alertCount = 0 }) {
  const navItems = [
    { id: 'dashboard', label: 'SOC Dashboard', icon: LayoutDashboard },
    { id: 'packets', label: 'Packet Logs', icon: Activity },
    { id: 'rules', label: 'Firewall Rules', icon: ShieldCheck },
    { id: 'alerts', label: 'Security Alerts', icon: AlertTriangle, badge: alertCount },
    { id: 'pcap', label: 'PCAP Analysis', icon: FileSearch },
    { id: 'settings', label: 'Engine Settings', icon: Settings },
  ];

  return (
    <aside className="w-full md:w-64 bg-[#0A0F1D] border-r border-slate-800/80 flex flex-col shrink-0">
      <nav className="p-3 space-y-1">
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = currentTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onSelectTab(item.id)}
              className={`w-full flex items-center justify-between px-3.5 py-2.5 rounded-xl text-sm font-medium transition-all ${
                isActive
                  ? 'bg-gradient-to-r from-cyan-950/80 to-slate-900 text-cyan-300 border border-cyan-500/40 shadow-sm shadow-cyan-950/50'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60 border border-transparent'
              }`}
            >
              <div className="flex items-center gap-3">
                <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
                <span>{item.label}</span>
              </div>
              {item.badge > 0 && (
                <span className="px-2 py-0.5 rounded-full text-[11px] font-bold bg-rose-950 text-rose-400 border border-rose-600/50 animate-pulse">
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      {/* Security Architecture Tag */}
      <div className="mt-auto p-4 m-3 rounded-xl bg-slate-900/60 border border-slate-800/80 text-xs">
        <div className="flex items-center gap-2 mb-1.5 text-cyan-400 font-bold uppercase tracking-wider text-[10px]">
          <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
          Active Defense
        </div>
        <p className="text-slate-400 text-[11px] leading-relaxed">
          Stateful metadata inspection with CIDR subnet matching, Scapy offline parser, and live heuristic threat mitigation.
        </p>
      </div>
    </aside>
  );
}
