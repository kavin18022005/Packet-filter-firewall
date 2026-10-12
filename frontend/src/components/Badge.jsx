import React from 'react';

export function ActionBadge({ action }) {
  const isAllow = action?.toUpperCase() === 'ALLOW';
  return (
    <span
      className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold tracking-wide uppercase border ${
        isAllow
          ? 'bg-emerald-950/70 text-emerald-400 border-emerald-500/40 shadow-sm shadow-emerald-900/30'
          : 'bg-rose-950/70 text-rose-400 border-rose-500/40 shadow-sm shadow-rose-900/30'
      }`}
    >
      <span className={`w-1.5 h-1.5 rounded-full mr-1.5 ${isAllow ? 'bg-emerald-400' : 'bg-rose-400'}`} />
      {action}
    </span>
  );
}

export function ProtocolBadge({ protocol }) {
  const proto = protocol?.toUpperCase() || 'OTHER';
  let styles = 'bg-slate-800 text-slate-300 border-slate-700';

  if (proto === 'TCP') styles = 'bg-cyan-950/60 text-cyan-400 border-cyan-800/60';
  else if (proto === 'UDP') styles = 'bg-purple-950/60 text-purple-400 border-purple-800/60';
  else if (proto === 'ICMP') styles = 'bg-amber-950/60 text-amber-400 border-amber-800/60';

  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-medium border ${styles}`}>
      {proto}
    </span>
  );
}

export function SeverityBadge({ severity }) {
  const sev = severity?.toUpperCase() || 'LOW';
  let styles = 'bg-blue-950/80 text-blue-400 border-blue-700/50';

  if (sev === 'CRITICAL') styles = 'bg-red-950 text-red-400 border-red-600 animate-pulse';
  else if (sev === 'HIGH') styles = 'bg-orange-950/80 text-orange-400 border-orange-700/60';
  else if (sev === 'MEDIUM') styles = 'bg-amber-950/80 text-amber-400 border-amber-700/60';

  return (
    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold uppercase tracking-wider border ${styles}`}>
      {sev}
    </span>
  );
}

export function StatusBadge({ status }) {
  const stat = status?.toUpperCase() || 'NEW';
  let styles = 'bg-rose-950/60 text-rose-400 border-rose-800/60';

  if (stat === 'RESOLVED') styles = 'bg-emerald-950/60 text-emerald-400 border-emerald-800/60';
  else if (stat === 'ACKNOWLEDGED') styles = 'bg-amber-950/60 text-amber-400 border-amber-800/60';

  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${styles}`}>
      {stat}
    </span>
  );
}
