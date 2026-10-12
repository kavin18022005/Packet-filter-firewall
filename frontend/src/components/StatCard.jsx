import React from 'react';

export function StatCard({ title, value, subtitle, icon: Icon, color = 'cyan', trend }) {
  const colorMap = {
    cyan: 'border-cyan-500/30 text-cyan-400 bg-cyan-950/20',
    emerald: 'border-emerald-500/30 text-emerald-400 bg-emerald-950/20',
    rose: 'border-rose-500/30 text-rose-400 bg-rose-950/20',
    amber: 'border-amber-500/30 text-amber-400 bg-amber-950/20',
    purple: 'border-purple-500/30 text-purple-400 bg-purple-950/20',
  };

  const iconStyle = colorMap[color] || colorMap.cyan;

  return (
    <div className="cyber-card p-5 relative overflow-hidden group">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-xs font-semibold uppercase tracking-wider text-slate-400">{title}</p>
          <h3 className="text-2xl lg:text-3xl font-extrabold text-white mt-1 font-mono tracking-tight">
            {value}
          </h3>
          {subtitle && (
            <p className="text-xs text-slate-400 mt-1 flex items-center gap-1">
              {trend && <span className="font-semibold text-slate-300">{trend}</span>}
              <span>{subtitle}</span>
            </p>
          )}
        </div>
        <div className={`p-3 rounded-xl border ${iconStyle} transition-transform group-hover:scale-110`}>
          {Icon && <Icon className="w-6 h-6" />}
        </div>
      </div>
      {/* Decorative gradient glow on card edge */}
      <div className="absolute inset-x-0 bottom-0 h-[2px] bg-gradient-to-r from-transparent via-cyan-500/30 to-transparent opacity-0 group-hover:opacity-100 transition-opacity" />
    </div>
  );
}
