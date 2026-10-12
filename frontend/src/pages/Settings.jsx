import React, { useState, useEffect } from 'react';
import {
  Settings as SettingsIcon,
  Save,
  RotateCcw,
  CheckCircle,
  AlertTriangle,
  Sliders,
  ShieldAlert,
  Gauge
} from 'lucide-react';
import { api } from '../api';

export function Settings() {
  const [settings, setSettings] = useState({});
  const [loading, setLoading] = useState(false);
  const [savingKey, setSavingKey] = useState(null);
  const [feedback, setFeedback] = useState('');

  // Local state for edits
  const [defaultPolicy, setDefaultPolicy] = useState('BLOCK');
  const [portScanThreshold, setPortScanThreshold] = useState(5);
  const [portScanWindow, setPortScanWindow] = useState(30);
  const [synFloodThreshold, setSynFloodThreshold] = useState(15);
  const [simRate, setSimRate] = useState(1000);
  const [simBatch, setSimBatch] = useState(3);

  const loadSettings = async () => {
    setLoading(true);
    try {
      const data = await api.getSettings();
      const settingsMap = {};
      data.forEach((s) => {
        settingsMap[s.key] = s.value;
      });
      setSettings(settingsMap);

      if (settingsMap.DEFAULT_POLICY) setDefaultPolicy(settingsMap.DEFAULT_POLICY);
      if (settingsMap.PORT_SCAN_THRESHOLD) setPortScanThreshold(Number(settingsMap.PORT_SCAN_THRESHOLD));
      if (settingsMap.PORT_SCAN_WINDOW_SECONDS) setPortScanWindow(Number(settingsMap.PORT_SCAN_WINDOW_SECONDS));
      if (settingsMap.SYN_FLOOD_THRESHOLD) setSynFloodThreshold(Number(settingsMap.SYN_FLOOD_THRESHOLD));
      if (settingsMap.SIMULATOR_RATE_MS) setSimRate(Number(settingsMap.SIMULATOR_RATE_MS));
      if (settingsMap.SIMULATOR_BATCH_SIZE) setSimBatch(Number(settingsMap.SIMULATOR_BATCH_SIZE));
    } catch (err) {
      console.error('Failed to load settings:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadSettings();
  }, []);

  const handleSaveSetting = async (key, val) => {
    setSavingKey(key);
    setFeedback('');
    try {
      await api.updateSetting(key, String(val));
      setFeedback(`Setting "${key}" updated successfully!`);
      setTimeout(() => setFeedback(''), 4000);
      loadSettings();
    } catch (err) {
      alert(err.message);
    } finally {
      setSavingKey(null);
    }
  };

  const handleUpdateSimulatorConfig = async () => {
    try {
      await api.updateSimulatorConfig({
        rate_ms: simRate,
        batch_size: simBatch,
      });
      setFeedback('Simulator speed and batch settings updated!');
      setTimeout(() => setFeedback(''), 4000);
    } catch (err) {
      alert(err.message);
    }
  };

  const handleResetDefaults = async () => {
    if (window.confirm('Reset all firewall rules, settings, and thresholds back to default factory baseline?')) {
      try {
        await api.resetDefaults();
        setFeedback('Firewall restored to default factory security policies.');
        setTimeout(() => setFeedback(''), 5000);
        loadSettings();
      } catch (err) {
        alert(err.message);
      }
    }
  };

  return (
    <div className="space-y-6 max-w-4xl">
      {/* Header */}
      <div>
        <h2 className="text-2xl font-extrabold text-white tracking-tight flex items-center gap-2">
          Firewall Engine &amp; Anomaly Settings
        </h2>
        <p className="text-sm text-slate-400">
          Configure default fallback security policies, heuristic anomaly thresholds, and synthetic generator frequencies.
        </p>
      </div>

      {feedback && (
        <div className="p-4 rounded-xl bg-cyan-950/80 border border-cyan-500/60 text-cyan-300 text-xs font-semibold flex items-center gap-2 shadow-lg shadow-cyan-950/40">
          <CheckCircle className="w-4 h-4 text-cyan-400" />
          <span>{feedback}</span>
        </div>
      )}

      {/* Default Fallback Policy */}
      <div className="cyber-card p-6 space-y-4">
        <div className="flex items-center gap-2 text-cyan-400 font-bold uppercase text-xs">
          <ShieldAlert className="w-4 h-4" />
          <span>Default Firewall Policy</span>
        </div>
        <div>
          <h4 className="text-base font-bold text-white">Fallback Action When No Rule Matches</h4>
          <p className="text-xs text-slate-400 mt-1">
            Industry best-practice is <strong>DEFAULT-DENY (BLOCK)</strong>, ensuring that any unclassified packets are discarded immediately.
          </p>
        </div>

        <div className="flex items-center gap-4 pt-2">
          <label className="flex items-center gap-2 text-xs font-mono font-medium cursor-pointer">
            <input
              type="radio"
              name="defaultPolicy"
              value="BLOCK"
              checked={defaultPolicy === 'BLOCK'}
              onChange={() => {
                setDefaultPolicy('BLOCK');
                handleSaveSetting('DEFAULT_POLICY', 'BLOCK');
              }}
              className="text-rose-500 focus:ring-0 bg-[#0B1120] border-slate-700"
            />
            <span className="text-rose-400 font-bold">DEFAULT-DENY (BLOCK)</span>
          </label>

          <label className="flex items-center gap-2 text-xs font-mono font-medium cursor-pointer">
            <input
              type="radio"
              name="defaultPolicy"
              value="ALLOW"
              checked={defaultPolicy === 'ALLOW'}
              onChange={() => {
                setDefaultPolicy('ALLOW');
                handleSaveSetting('DEFAULT_POLICY', 'ALLOW');
              }}
              className="text-emerald-500 focus:ring-0 bg-[#0B1120] border-slate-700"
            />
            <span className="text-emerald-400 font-bold">DEFAULT-ALLOW (PERMISSIVE)</span>
          </label>
        </div>
      </div>

      {/* Heuristic Anomaly Detector Thresholds */}
      <div className="cyber-card p-6 space-y-4">
        <div className="flex items-center gap-2 text-amber-400 font-bold uppercase text-xs">
          <AlertTriangle className="w-4 h-4" />
          <span>Anomaly Heuristic Thresholds</span>
        </div>
        <div>
          <h4 className="text-base font-bold text-white">Sliding-Window Threat Parameters</h4>
          <p className="text-xs text-slate-400 mt-1">
            Tune threshold sensitivity to prevent false alarms while catching stealthy reconnaissance.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2 text-xs">
          <div className="p-4 bg-slate-900/60 rounded-xl border border-slate-800 space-y-2">
            <label className="block text-slate-300 font-medium">Port Scan Threshold (Distinct Ports)</label>
            <div className="flex items-center gap-3">
              <input
                type="number"
                min="2"
                max="50"
                value={portScanThreshold}
                onChange={(e) => setPortScanThreshold(Number(e.target.value))}
                className="w-24 bg-[#0B1120] border border-slate-700 rounded-lg px-3 py-1.5 text-white font-mono"
              />
              <button
                onClick={() => handleSaveSetting('PORT_SCAN_THRESHOLD', portScanThreshold)}
                className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-cyan-300 rounded-lg font-semibold transition"
              >
                Save
              </button>
            </div>
            <span className="text-[11px] text-slate-500 block">Trigger alert after N ports probed from single IP</span>
          </div>

          <div className="p-4 bg-slate-900/60 rounded-xl border border-slate-800 space-y-2">
            <label className="block text-slate-300 font-medium">SYN Flood Burst Threshold (Packets)</label>
            <div className="flex items-center gap-3">
              <input
                type="number"
                min="5"
                max="100"
                value={synFloodThreshold}
                onChange={(e) => setSynFloodThreshold(Number(e.target.value))}
                className="w-24 bg-[#0B1120] border border-slate-700 rounded-lg px-3 py-1.5 text-white font-mono"
              />
              <button
                onClick={() => handleSaveSetting('SYN_FLOOD_THRESHOLD', synFloodThreshold)}
                className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-cyan-300 rounded-lg font-semibold transition"
              >
                Save
              </button>
            </div>
            <span className="text-[11px] text-slate-500 block">Trigger alert when burst of SYN flags exceeds threshold</span>
          </div>
        </div>
      </div>

      {/* Traffic Simulator Controls */}
      <div className="cyber-card p-6 space-y-4">
        <div className="flex items-center gap-2 text-purple-400 font-bold uppercase text-xs">
          <Gauge className="w-4 h-4" />
          <span>Traffic Simulator Configuration</span>
        </div>
        <div>
          <h4 className="text-base font-bold text-white">Synthetic Packet Frequency</h4>
          <p className="text-xs text-slate-400 mt-1">
            Controls synthetic traffic generation rate and batch volume per cycle.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2 text-xs">
          <div>
            <label className="block text-slate-300 font-medium mb-1">
              Interval: <strong className="text-cyan-400 font-mono">{simRate} ms</strong>
            </label>
            <input
              type="range"
              min="200"
              max="5000"
              step="100"
              value={simRate}
              onChange={(e) => setSimRate(Number(e.target.value))}
              className="w-full accent-cyan-500"
            />
            <div className="flex justify-between text-[10px] text-slate-500 mt-1">
              <span>Fast (200ms)</span>
              <span>Default (1000ms)</span>
              <span>Slow (5000ms)</span>
            </div>
          </div>

          <div>
            <label className="block text-slate-300 font-medium mb-1">
              Batch Size: <strong className="text-purple-400 font-mono">{simBatch} pkts / cycle</strong>
            </label>
            <input
              type="range"
              min="1"
              max="20"
              value={simBatch}
              onChange={(e) => setSimBatch(Number(e.target.value))}
              className="w-full accent-purple-500"
            />
            <div className="flex justify-between text-[10px] text-slate-500 mt-1">
              <span>1 packet</span>
              <span>10 packets</span>
              <span>20 packets</span>
            </div>
          </div>
        </div>

        <div className="flex justify-end pt-2">
          <button
            onClick={handleUpdateSimulatorConfig}
            className="px-4 py-2 bg-purple-600 hover:bg-purple-500 text-white rounded-xl text-xs font-bold transition shadow-lg shadow-purple-950/40"
          >
            Apply Simulator Settings
          </button>
        </div>
      </div>

      {/* Factory Reset */}
      <div className="cyber-card p-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-rose-900/40 bg-rose-950/10">
        <div>
          <h4 className="text-sm font-bold text-rose-300">Reset Engine to Factory Baseline</h4>
          <p className="text-xs text-slate-400 mt-0.5">
            Restores default firewall rules, clears packet history, and re-enables default-deny.
          </p>
        </div>
        <button
          onClick={handleResetDefaults}
          className="flex items-center gap-1.5 px-4 py-2 bg-rose-950 hover:bg-rose-900 border border-rose-700 text-rose-200 rounded-xl text-xs font-bold transition"
        >
          <RotateCcw className="w-4 h-4" />
          <span>Restore Factory Baseline</span>
        </button>
      </div>
    </div>
  );
}
