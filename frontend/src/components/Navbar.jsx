import React from 'react';
import { Shield, Play, Square, Zap, RefreshCw } from 'lucide-react';

export function Navbar({
  defaultPolicy = 'BLOCK',
  simStatus,
  onToggleSimulator,
  onGenerateBatch,
  autoRefresh,
  onToggleAutoRefresh,
  isRefreshing,
  onManualRefresh
}) {
  const isRunning = simStatus?.is_running;

  return (
    <header className="h-16 bg-[#0B1120]/95 backdrop-blur border-b border-slate-800/80 px-4 lg:px-8 flex items-center justify-between sticky top-0 z-40">
      {/* Brand & SOC Indicator */}
      <div className="flex items-center gap-3">
        <div className="p-2 bg-cyan-950/60 border border-cyan-500/40 rounded-xl shadow-lg shadow-cyan-900/30">
          <Shield className="w-5 h-5 text-cyan-400" />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <h1 className="font-extrabold text-base lg:text-lg tracking-wide text-white uppercase flex items-center gap-1.5">
              <span>CyberWall</span>
              <span className="text-cyan-400 font-mono text-xs px-2 py-0.5 rounded bg-cyan-950/80 border border-cyan-800/60 font-semibold">
                v1.0
              </span>
            </h1>
          </div>
          <p className="text-[11px] text-slate-400 hidden sm:block">
            Data-Driven Packet Filtering Firewall &amp; Anomaly Engine
          </p>
        </div>
      </div>

      {/* Global Status & Quick Controls */}
      <div className="flex items-center gap-2 sm:gap-3">
        {/* Default Policy Pill */}
        <div className="hidden md:flex items-center gap-1.5 px-3 py-1 rounded-full bg-slate-900/90 border border-slate-700/80 text-xs">
          <span className="text-slate-400">Policy:</span>
          <span className={`font-mono font-bold ${defaultPolicy === 'BLOCK' ? 'text-rose-400' : 'text-emerald-400'}`}>
            DEFAULT-{defaultPolicy}
          </span>
        </div>

        {/* Generate Instant Batch Button */}
        <button
          onClick={onGenerateBatch}
          className="flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-semibold rounded-lg bg-slate-800/90 hover:bg-slate-700 border border-slate-700 text-cyan-300 transition"
          title="Inject 5 simulated packets into firewall engine"
        >
          <Zap className="w-3.5 h-3.5 text-cyan-400" />
          <span className="hidden sm:inline">Inject</span> +5
        </button>

        {/* Simulator Toggle Button */}
        <button
          onClick={onToggleSimulator}
          className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg border transition ${
            isRunning
              ? 'bg-emerald-950/60 hover:bg-emerald-900/70 border-emerald-500/50 text-emerald-300'
              : 'bg-slate-800 hover:bg-slate-700 border-slate-600 text-slate-300'
          }`}
          title={isRunning ? 'Pause synthetic traffic generator' : 'Start synthetic traffic generator'}
        >
          {isRunning ? (
            <>
              <Square className="w-3 h-3 fill-emerald-400 text-emerald-400 animate-pulse" />
              <span>Sim Active</span>
            </>
          ) : (
            <>
              <Play className="w-3 h-3 fill-slate-300 text-slate-300" />
              <span>Sim Paused</span>
            </>
          )}
        </button>

        {/* Auto Refresh & Manual Sync */}
        <div className="flex items-center border border-slate-700/70 rounded-lg overflow-hidden bg-slate-900/80">
          <button
            onClick={onToggleAutoRefresh}
            className={`px-2.5 py-1.5 text-xs font-medium transition ${
              autoRefresh ? 'bg-cyan-950/60 text-cyan-300 font-semibold' : 'text-slate-400 hover:text-white'
            }`}
            title="Auto-refresh every 3 seconds"
          >
            Auto (3s)
          </button>
          <button
            onClick={onManualRefresh}
            className="p-1.5 text-slate-400 hover:text-cyan-400 hover:bg-slate-800 border-l border-slate-700/60 transition"
            title="Manual sync now"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin text-cyan-400' : ''}`} />
          </button>
        </div>
      </div>
    </header>
  );
}
