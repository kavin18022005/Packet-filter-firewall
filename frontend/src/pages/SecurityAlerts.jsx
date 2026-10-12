import React, { useState, useEffect } from 'react';
import {
  AlertTriangle,
  ShieldAlert,
  CheckCircle,
  Eye,
  Filter,
  Trash2,
  Lock,
  Search,
  ExternalLink
} from 'lucide-react';
import { api } from '../api';
import { SeverityBadge, StatusBadge } from '../components/Badge';

export function SecurityAlerts({ onNavigate }) {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(false);
  const [severityFilter, setSeverityFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [search, setSearch] = useState('');
  const [successMsg, setSuccessMsg] = useState('');

  const loadAlerts = async () => {
    setLoading(true);
    try {
      const data = await api.getAlerts({
        severity: severityFilter,
        status: statusFilter,
        search,
      });
      setAlerts(data || []);
    } catch (err) {
      console.error('Failed to load alerts:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAlerts();
  }, [severityFilter, statusFilter]);

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    loadAlerts();
  };

  const handleUpdateStatus = async (id, newStatus) => {
    try {
      await api.updateAlertStatus(id, newStatus);
      loadAlerts();
    } catch (err) {
      alert(err.message);
    }
  };

  const handleBlockIp = async (alertItem) => {
    try {
      const createdRule = await api.blockOffendingIp(alertItem.id);
      setSuccessMsg(`Host ${alertItem.src_ip} successfully mitigated! High-priority rule "${createdRule.name}" created.`);
      setTimeout(() => setSuccessMsg(''), 6000);
      loadAlerts();
    } catch (err) {
      alert(err.message);
    }
  };

  const handleClearAlerts = async () => {
    if (window.confirm('Clear all security threat alerts?')) {
      try {
        await api.clearAlerts();
        loadAlerts();
      } catch (err) {
        alert(err.message);
      }
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-2xl font-extrabold text-white tracking-tight flex items-center gap-2">
            Heuristic Anomaly Alerts &amp; Threats
          </h2>
          <p className="text-sm text-slate-400">
            Real-time detection of stealth port scans, SYN flood bursts, and sensitive reconnaissance probes.
          </p>
        </div>
        <button
          onClick={handleClearAlerts}
          className="flex items-center gap-1.5 px-3 py-2 text-xs font-semibold rounded-lg bg-rose-950/40 hover:bg-rose-900/60 border border-rose-800/50 text-rose-300 transition"
        >
          <Trash2 className="w-4 h-4" />
          Clear Alerts
        </button>
      </div>

      {/* Success Notification */}
      {successMsg && (
        <div className="p-4 rounded-xl bg-emerald-950/80 border border-emerald-500/60 text-emerald-300 text-xs font-semibold flex items-center justify-between shadow-lg shadow-emerald-950/50">
          <div className="flex items-center gap-2">
            <CheckCircle className="w-4 h-4 text-emerald-400" />
            <span>{successMsg}</span>
          </div>
          <button
            onClick={() => onNavigate('rules')}
            className="underline hover:text-emerald-200 flex items-center gap-1"
          >
            <span>Inspect Rules</span>
            <ExternalLink className="w-3 h-3" />
          </button>
        </div>
      )}

      {/* Filter Toolbar */}
      <div className="cyber-card p-4 space-y-3">
        <form onSubmit={handleSearchSubmit} className="flex flex-col md:flex-row gap-3">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-3" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search by attacker IP or pattern..."
              className="w-full bg-[#0F172A] border border-slate-700/80 rounded-xl pl-9 pr-4 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500"
            />
          </div>
          <button
            type="submit"
            className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-xl text-xs font-semibold transition"
          >
            Search
          </button>
        </form>

        <div className="flex flex-wrap items-center gap-3 pt-2 border-t border-slate-800 text-xs">
          <div className="flex items-center gap-1.5 text-slate-400">
            <Filter className="w-3.5 h-3.5" />
            <span>Filter by:</span>
          </div>

          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="bg-[#0F172A] border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
          >
            <option value="">All Severities</option>
            <option value="CRITICAL">CRITICAL</option>
            <option value="HIGH">HIGH</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="LOW">LOW</option>
          </select>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="bg-[#0F172A] border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
          >
            <option value="">All Statuses</option>
            <option value="NEW">NEW</option>
            <option value="ACKNOWLEDGED">ACKNOWLEDGED</option>
            <option value="RESOLVED">RESOLVED</option>
          </select>

          <span className="text-slate-500 ml-auto font-mono text-[11px]">
            {alerts.length} alerts loaded
          </span>
        </div>
      </div>

      {/* Alerts Feed */}
      <div className="space-y-3">
        {alerts.map((item) => (
          <div
            key={item.id}
            className={`cyber-card p-5 flex flex-col md:flex-row md:items-center justify-between gap-4 border-l-4 ${
              item.severity === 'CRITICAL'
                ? 'border-l-rose-500 bg-rose-950/10'
                : item.severity === 'HIGH'
                ? 'border-l-orange-500 bg-orange-950/10'
                : 'border-l-cyan-500'
            }`}
          >
            <div className="space-y-1.5">
              <div className="flex items-center gap-3">
                <SeverityBadge severity={item.severity} />
                <span className="text-xs font-mono font-bold text-white tracking-wide">
                  {item.alert_type}
                </span>
                <StatusBadge status={item.status} />
                <span className="text-xs text-slate-400 font-mono">
                  {new Date(item.timestamp).toLocaleString()}
                </span>
              </div>
              <p className="text-sm text-slate-200 font-medium">
                {item.description}
              </p>
              <div className="flex items-center gap-4 text-xs font-mono text-slate-400 pt-1">
                <span>Offending Source IP: <strong className="text-rose-400">{item.src_ip}</strong></span>
                {item.dst_ip && (
                  <span>Target IP: <strong className="text-slate-300">{item.dst_ip}</strong></span>
                )}
                <span>Probe Packets: <strong className="text-cyan-400">{item.packet_count}</strong></span>
              </div>
            </div>

            {/* Quick Actions */}
            <div className="flex flex-wrap items-center gap-2 shrink-0">
              {item.status === 'NEW' && (
                <button
                  onClick={() => handleUpdateStatus(item.id, 'ACKNOWLEDGED')}
                  className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium transition"
                >
                  Acknowledge
                </button>
              )}
              {item.status !== 'RESOLVED' && (
                <button
                  onClick={() => handleUpdateStatus(item.id, 'RESOLVED')}
                  className="px-3 py-1.5 rounded-lg bg-emerald-950/70 hover:bg-emerald-900 border border-emerald-600/50 text-emerald-300 text-xs font-medium transition"
                >
                  Resolve
                </button>
              )}
              {/* 1-Click Auto Block IP Mitigation */}
              <button
                onClick={() => handleBlockIp(item)}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-white text-xs font-bold shadow-md shadow-rose-950/50 transition"
                title={`Generate rule to immediately drop all traffic from ${item.src_ip}`}
              >
                <Lock className="w-3.5 h-3.5" />
                <span>Auto-Block IP</span>
              </button>
            </div>
          </div>
        ))}

        {alerts.length === 0 && !loading && (
          <div className="cyber-card p-12 text-center text-slate-500">
            <ShieldAlert className="w-10 h-10 mx-auto text-slate-600 mb-2" />
            <p className="text-sm font-medium">No security anomalies detected.</p>
            <p className="text-xs text-slate-600 mt-1">
              Any stealth scans, SYN floods, or unauthorized port probes will appear here immediately.
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
