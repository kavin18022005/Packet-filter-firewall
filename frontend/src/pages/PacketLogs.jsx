import React, { useState, useEffect } from 'react';
import {
  Search,
  Filter,
  Trash2,
  ChevronLeft,
  ChevronRight,
  Eye,
  Info,
  Radio,
  FileCode
} from 'lucide-react';
import { api } from '../api';
import { ActionBadge, ProtocolBadge } from '../components/Badge';
import { Modal } from '../components/Modal';

export function PacketLogs({ initialSelectedId }) {
  const [logs, setLogs] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [totalPages, setTotalPages] = useState(1);
  const [loading, setLoading] = useState(false);

  // Filters
  const [search, setSearch] = useState('');
  const [actionFilter, setActionFilter] = useState('');
  const [protocolFilter, setProtocolFilter] = useState('');
  const [simulatedFilter, setSimulatedFilter] = useState('');

  // Selected Packet for Inspection
  const [selectedPacket, setSelectedPacket] = useState(null);
  const [isModalOpen, setIsModalOpen] = useState(false);

  const loadPackets = async () => {
    setLoading(true);
    try {
      const data = await api.getPackets({
        page,
        page_size: pageSize,
        search,
        action: actionFilter,
        protocol: protocolFilter,
        is_simulated: simulatedFilter
      });
      setLogs(data.items || []);
      setTotal(data.total);
      setTotalPages(data.total_pages);
    } catch (err) {
      console.error('Failed to load packets:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadPackets();
  }, [page, pageSize, actionFilter, protocolFilter, simulatedFilter]);

  // Handle Enter key for search
  const handleSearchSubmit = (e) => {
    e.preventDefault();
    setPage(1);
    loadPackets();
  };

  const handleInspect = async (id) => {
    try {
      const pkt = await api.getPacketDetail(id);
      setSelectedPacket(pkt);
      setIsModalOpen(true);
    } catch (err) {
      console.error('Failed to load packet detail:', err);
    }
  };

  const handleClearLogs = async () => {
    if (window.confirm('Are you sure you want to clear all packet history?')) {
      try {
        await api.clearPackets();
        loadPackets();
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
          <h2 className="text-2xl font-extrabold text-white tracking-tight">Packet Logs &amp; Metadata Inspection</h2>
          <p className="text-sm text-slate-400">
            Granular inspection of every evaluated network packet, matched rule, and decision reason.
          </p>
        </div>
        <button
          onClick={handleClearLogs}
          className="flex items-center gap-1.5 px-3 py-2 text-xs font-semibold rounded-lg bg-rose-950/40 hover:bg-rose-900/60 border border-rose-800/50 text-rose-300 transition"
        >
          <Trash2 className="w-4 h-4" />
          Clear Logs
        </button>
      </div>

      {/* Search and Filters Bar */}
      <div className="cyber-card p-4 space-y-3">
        <form onSubmit={handleSearchSubmit} className="flex flex-col md:flex-row gap-3">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-3" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search by IP, port, reason, or packet summary..."
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
            <span>Filters:</span>
          </div>

          {/* Action Filter */}
          <select
            value={actionFilter}
            onChange={(e) => { setActionFilter(e.target.value); setPage(1); }}
            className="bg-[#0F172A] border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
          >
            <option value="">All Actions</option>
            <option value="ALLOW">ALLOW only</option>
            <option value="BLOCK">BLOCK only</option>
          </select>

          {/* Protocol Filter */}
          <select
            value={protocolFilter}
            onChange={(e) => { setProtocolFilter(e.target.value); setPage(1); }}
            className="bg-[#0F172A] border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
          >
            <option value="">All Protocols</option>
            <option value="TCP">TCP</option>
            <option value="UDP">UDP</option>
            <option value="ICMP">ICMP</option>
          </select>

          {/* Traffic Source Filter */}
          <select
            value={simulatedFilter}
            onChange={(e) => { setSimulatedFilter(e.target.value); setPage(1); }}
            className="bg-[#0F172A] border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
          >
            <option value="">All Traffic Sources</option>
            <option value="true">Simulated Traffic</option>
            <option value="false">PCAP Captured Traffic</option>
          </select>

          <span className="text-slate-500 ml-auto font-mono text-[11px]">
            {total.toLocaleString()} total entries
          </span>
        </div>
      </div>

      {/* Table */}
      <div className="cyber-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-900/80 text-slate-400 font-semibold uppercase tracking-wider text-[11px]">
                <th className="py-3 px-4">Time</th>
                <th className="py-3 px-4">Source</th>
                <th className="py-3 px-4">Destination</th>
                <th className="py-3 px-4">Proto</th>
                <th className="py-3 px-4">Flags</th>
                <th className="py-3 px-4">Size</th>
                <th className="py-3 px-4">Decision</th>
                <th className="py-3 px-4">Reason</th>
                <th className="py-3 px-4">Source</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {logs.map((pkt) => (
                <tr key={pkt.id} className="hover:bg-slate-800/40 transition-colors">
                  <td className="py-2.5 px-4 text-slate-400 whitespace-nowrap">
                    {new Date(pkt.timestamp).toLocaleTimeString()}
                  </td>
                  <td className="py-2.5 px-4 text-cyan-300 font-medium">
                    {pkt.src_ip}{pkt.src_port ? `:${pkt.src_port}` : ''}
                  </td>
                  <td className="py-2.5 px-4 text-slate-300">
                    {pkt.dst_ip}{pkt.dst_port ? `:${pkt.dst_port}` : ''}
                  </td>
                  <td className="py-2.5 px-4">
                    <ProtocolBadge protocol={pkt.protocol} />
                  </td>
                  <td className="py-2.5 px-4 text-slate-400 text-[11px]">
                    {pkt.tcp_flags || '-'}
                  </td>
                  <td className="py-2.5 px-4 text-slate-400 text-[11px]">
                    {pkt.packet_size} B
                  </td>
                  <td className="py-2.5 px-4">
                    <ActionBadge action={pkt.action} />
                  </td>
                  <td className="py-2.5 px-4 text-slate-300 truncate max-w-xs font-sans" title={pkt.decision_reason}>
                    {pkt.decision_reason}
                  </td>
                  <td className="py-2.5 px-4">
                    {pkt.is_simulated ? (
                      <span className="inline-flex items-center gap-1 text-[10px] font-mono text-purple-400 bg-purple-950/60 px-2 py-0.5 rounded border border-purple-800/40">
                        <Radio className="w-2.5 h-2.5" /> Sim
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 text-[10px] font-mono text-cyan-400 bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-800/40">
                        <FileCode className="w-2.5 h-2.5" /> PCAP
                      </span>
                    )}
                  </td>
                  <td className="py-2.5 px-4 text-right">
                    <button
                      onClick={() => handleInspect(pkt.id)}
                      className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-cyan-400 transition"
                      title="Inspect Packet Metadata"
                    >
                      <Eye className="w-4 h-4" />
                    </button>
                  </td>
                </tr>
              ))}
              {logs.length === 0 && !loading && (
                <tr>
                  <td colSpan={10} className="py-10 text-center text-slate-500 font-sans">
                    No packet records matched the active filters.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Footer */}
        <div className="p-4 border-t border-slate-800 flex items-center justify-between text-xs bg-slate-900/40">
          <div className="text-slate-400">
            Page <span className="font-semibold text-white">{page}</span> of{' '}
            <span className="font-semibold text-white">{totalPages}</span>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page <= 1}
              className="p-1.5 rounded-lg border border-slate-700 bg-slate-800 text-slate-300 hover:bg-slate-700 disabled:opacity-40 disabled:pointer-events-none transition"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <button
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              disabled={page >= totalPages}
              className="p-1.5 rounded-lg border border-slate-700 bg-slate-800 text-slate-300 hover:bg-slate-700 disabled:opacity-40 disabled:pointer-events-none transition"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Packet Inspection Modal */}
      <Modal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        title="Packet Metadata Inspection Drawer"
      >
        {selectedPacket && (
          <div className="space-y-4 text-xs font-mono">
            {/* Decision Banner */}
            <div className={`p-4 rounded-xl border flex items-center justify-between ${
              selectedPacket.action === 'ALLOW'
                ? 'bg-emerald-950/40 border-emerald-500/40 text-emerald-300'
                : 'bg-rose-950/40 border-rose-500/40 text-rose-300'
            }`}>
              <div>
                <span className="text-[10px] uppercase font-bold tracking-wider">Firewall Decision</span>
                <h4 className="text-lg font-bold">{selectedPacket.action}</h4>
              </div>
              <div className="text-right">
                <span className="text-[10px] text-slate-400">Enforcement</span>
                <p className="font-sans text-xs">{selectedPacket.decision_reason}</p>
              </div>
            </div>

            {/* Headers Grid */}
            <div className="grid grid-cols-2 gap-3">
              <div className="p-3 bg-slate-900/80 rounded-xl border border-slate-800">
                <span className="text-[10px] text-slate-500 uppercase">Source IP : Port</span>
                <p className="text-cyan-300 font-bold mt-0.5">
                  {selectedPacket.src_ip}{selectedPacket.src_port ? ` : ${selectedPacket.src_port}` : ''}
                </p>
              </div>
              <div className="p-3 bg-slate-900/80 rounded-xl border border-slate-800">
                <span className="text-[10px] text-slate-500 uppercase">Destination IP : Port</span>
                <p className="text-white font-bold mt-0.5">
                  {selectedPacket.dst_ip}{selectedPacket.dst_port ? ` : ${selectedPacket.dst_port}` : ''}
                </p>
              </div>
              <div className="p-3 bg-slate-900/80 rounded-xl border border-slate-800">
                <span className="text-[10px] text-slate-500 uppercase">Transport Protocol</span>
                <p className="text-purple-300 font-bold mt-0.5">{selectedPacket.protocol}</p>
              </div>
              <div className="p-3 bg-slate-900/80 rounded-xl border border-slate-800">
                <span className="text-[10px] text-slate-500 uppercase">TCP Flags</span>
                <p className="text-amber-300 font-bold mt-0.5">{selectedPacket.tcp_flags || 'None / N/A'}</p>
              </div>
              <div className="p-3 bg-slate-900/80 rounded-xl border border-slate-800">
                <span className="text-[10px] text-slate-500 uppercase">Packet Size</span>
                <p className="text-slate-300 font-bold mt-0.5">{selectedPacket.packet_size} bytes</p>
              </div>
              <div className="p-3 bg-slate-900/80 rounded-xl border border-slate-800">
                <span className="text-[10px] text-slate-500 uppercase">Traffic Class</span>
                <p className="text-slate-300 font-bold mt-0.5">
                  {selectedPacket.is_simulated ? 'Synthetic Simulation' : 'PCAP Offline Ingestion'}
                </p>
              </div>
            </div>

            {/* Raw Summary */}
            <div className="p-3 bg-slate-900/80 rounded-xl border border-slate-800">
              <span className="text-[10px] text-slate-500 uppercase">Scapy Dissection Summary</span>
              <p className="text-slate-300 mt-1 break-all bg-black/40 p-2 rounded">
                {selectedPacket.raw_summary || 'No payload details available.'}
              </p>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}
