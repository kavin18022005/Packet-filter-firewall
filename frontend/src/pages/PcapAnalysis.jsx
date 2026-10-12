import React, { useState } from 'react';
import {
  FileSearch,
  UploadCloud,
  CheckCircle,
  AlertTriangle,
  Play,
  FileCode,
  ShieldCheck,
  ShieldAlert,
  Clock,
  Layers
} from 'lucide-react';
import { api } from '../api';
import { ActionBadge, ProtocolBadge } from '../components/Badge';

export function PcapAnalysis({ onNavigate }) {
  const [file, setFile] = useState(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0]);
      setError('');
    }
  };

  const handleUpload = async () => {
    if (!file) {
      setError('Please choose a .pcap or .pcapng file to upload.');
      return;
    }
    setAnalyzing(true);
    setError('');
    setResult(null);
    try {
      const res = await api.uploadPcap(file);
      setResult(res);
    } catch (err) {
      setError(err.message);
    } finally {
      setAnalyzing(false);
    }
  };

  const handleRunSample = async () => {
    setAnalyzing(true);
    setError('');
    setResult(null);
    try {
      const res = await api.runSamplePcap();
      setResult(res);
    } catch (err) {
      setError(err.message);
    } finally {
      setAnalyzing(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-2xl font-extrabold text-white tracking-tight flex items-center gap-2">
          Scapy Offline PCAP Packet Ingestion &amp; Dissection
        </h2>
        <p className="text-sm text-slate-400">
          Upload packet captures (.pcap) captured via Wireshark/tcpdump. Scapy dissects every frame and validates against active firewall policies and heuristic anomaly detectors.
        </p>
      </div>

      {/* Upload Zone & Quick Sample Trigger */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Upload Card */}
        <div className="lg:col-span-2 cyber-card p-6 flex flex-col justify-between">
          <div>
            <h3 className="text-sm font-bold text-white uppercase tracking-wider mb-2 flex items-center gap-2">
              <UploadCloud className="w-4 h-4 text-cyan-400" />
              <span>Upload Custom PCAP Capture</span>
            </h3>
            <p className="text-xs text-slate-400 mb-4">
              Supports standard libpcap format files up to 25MB.
            </p>

            <div className="border-2 border-dashed border-slate-700/80 hover:border-cyan-500/60 rounded-2xl p-6 text-center cursor-pointer transition bg-slate-900/30">
              <input
                type="file"
                accept=".pcap,.pcapng,.cap"
                onChange={handleFileChange}
                className="hidden"
                id="pcapFileInput"
              />
              <label htmlFor="pcapFileInput" className="cursor-pointer block">
                <FileCode className="w-10 h-10 mx-auto text-cyan-400/80 mb-2" />
                <span className="text-xs text-slate-300 font-medium block">
                  {file ? file.name : 'Click to select or drag & drop .pcap file'}
                </span>
                <span className="text-[10px] text-slate-500 mt-1 block">
                  {file ? `${(file.size / 1024).toFixed(1)} KB` : 'Wireshark, tcpdump, or Zeek pcap files'}
                </span>
              </label>
            </div>
          </div>

          {error && (
            <div className="mt-4 p-3 rounded-lg bg-rose-950/80 border border-rose-600 text-rose-300 text-xs">
              {error}
            </div>
          )}

          <div className="mt-4 flex justify-end">
            <button
              onClick={handleUpload}
              disabled={!file || analyzing}
              className="px-5 py-2.5 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white rounded-xl text-xs font-bold transition shadow-lg shadow-cyan-950/50 flex items-center gap-2"
            >
              <FileSearch className="w-4 h-4" />
              <span>{analyzing ? 'Dissecting Packets...' : 'Dissect & Ingest PCAP'}</span>
            </button>
          </div>
        </div>

        {/* 1-Click Sample Ingestion Card */}
        <div className="cyber-card p-6 flex flex-col justify-between bg-gradient-to-br from-slate-900 to-[#0A1124]">
          <div>
            <div className="flex items-center gap-2 text-cyan-400 font-bold uppercase text-xs mb-2">
              <Layers className="w-4 h-4" />
              <span>Pre-packaged Evaluation PCAP</span>
            </div>
            <h4 className="text-base font-bold text-white mb-1">
              Sample Multi-vector Attack Capture
            </h4>
            <p className="text-xs text-slate-400 leading-relaxed">
              Includes pre-generated Scapy packets featuring DNS queries, HTTPS traffic, stealth port scanning, Telnet probes, and SYN bursts.
            </p>
          </div>

          <div className="mt-6 pt-4 border-t border-slate-800">
            <button
              onClick={handleRunSample}
              disabled={analyzing}
              className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl bg-purple-600 hover:bg-purple-500 text-white text-xs font-bold transition shadow-lg shadow-purple-950/50"
            >
              <Play className="w-4 h-4" />
              <span>{analyzing ? 'Analyzing Sample...' : 'Run Bundled Sample PCAP'}</span>
            </button>
          </div>
        </div>
      </div>

      {/* Analysis Results Display */}
      {result && (
        <div className="cyber-card p-6 space-y-6">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-slate-800 gap-2">
            <div>
              <span className="text-xs font-mono text-cyan-400 uppercase font-bold tracking-wider">
                Scapy Dissection Complete
              </span>
              <h3 className="text-lg font-bold text-white mt-0.5">
                Processed: <span className="text-cyan-300 font-mono">{result.filename}</span>
              </h3>
            </div>
            <button
              onClick={() => onNavigate('packets')}
              className="text-xs text-cyan-400 hover:text-cyan-300 underline font-medium self-start sm:self-auto"
            >
              View in Packet Logs &rarr;
            </button>
          </div>

          {/* Quick Metrics */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 font-mono text-xs">
            <div className="p-3.5 bg-slate-900/80 rounded-xl border border-slate-800">
              <span className="text-slate-400 font-sans block text-[11px]">Total Dissected</span>
              <span className="text-xl font-bold text-white mt-1 block">{result.total_packets}</span>
            </div>
            <div className="p-3.5 bg-emerald-950/30 rounded-xl border border-emerald-800/40">
              <span className="text-emerald-400 font-sans block text-[11px]">Allowed Packets</span>
              <span className="text-xl font-bold text-emerald-300 mt-1 block">{result.allowed_count}</span>
            </div>
            <div className="p-3.5 bg-rose-950/30 rounded-xl border border-rose-800/40">
              <span className="text-rose-400 font-sans block text-[11px]">Blocked Packets</span>
              <span className="text-xl font-bold text-rose-300 mt-1 block">{result.blocked_count}</span>
            </div>
            <div className="p-3.5 bg-amber-950/30 rounded-xl border border-amber-800/40">
              <span className="text-amber-400 font-sans block text-[11px]">Alerts Generated</span>
              <span className="text-xl font-bold text-amber-300 mt-1 block">{result.alerts_generated}</span>
            </div>
          </div>

          {/* Sample Dissected Packets Table */}
          {result.packets_preview && result.packets_preview.length > 0 && (
            <div>
              <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">
                Evaluated Packet Breakdown
              </h4>
              <div className="overflow-x-auto border border-slate-800 rounded-xl">
                <table className="w-full text-left text-xs font-mono">
                  <thead>
                    <tr className="bg-slate-900 text-slate-400 border-b border-slate-800 text-[10px] uppercase">
                      <th className="p-2.5">Source</th>
                      <th className="p-2.5">Destination</th>
                      <th className="p-2.5">Proto</th>
                      <th className="p-2.5">Flags</th>
                      <th className="p-2.5">Decision</th>
                      <th className="p-2.5">Enforcement Reason</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {result.packets_preview.map((pkt) => (
                      <tr key={pkt.id} className="hover:bg-slate-800/30">
                        <td className="p-2.5 text-cyan-300">{pkt.src_ip}:{pkt.src_port || '*'}</td>
                        <td className="p-2.5 text-slate-300">{pkt.dst_ip}:{pkt.dst_port || '*'}</td>
                        <td className="p-2.5"><ProtocolBadge protocol={pkt.protocol} /></td>
                        <td className="p-2.5 text-slate-400">{pkt.tcp_flags || '-'}</td>
                        <td className="p-2.5"><ActionBadge action={pkt.action} /></td>
                        <td className="p-2.5 text-slate-300 font-sans truncate max-w-xs">{pkt.decision_reason}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
