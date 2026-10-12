import React from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Activity,
  AlertTriangle,
  Zap,
  ArrowUpRight,
  TrendingDown
} from 'lucide-react';
import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Tooltip,
  Legend,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  BarChart,
  Bar
} from 'recharts';
import { StatCard } from '../components/StatCard';
import { ActionBadge, ProtocolBadge } from '../components/Badge';

const PROTO_COLORS = {
  TCP: '#06B6D4',
  UDP: '#8B5CF6',
  ICMP: '#F59E0B',
  OTHER: '#64748B'
};

export function Dashboard({ stats, timeline, onSelectPacket, onNavigate }) {
  if (!stats) {
    return (
      <div className="flex items-center justify-center h-64 text-slate-400">
        <Activity className="w-6 h-6 animate-spin text-cyan-400 mr-2" />
        Loading SOC telemetry...
      </div>
    );
  }

  // Format data for Recharts PieChart
  const protocolData = Object.entries(stats.protocol_distribution || {}).map(([name, value]) => ({
    name,
    value,
  }));

  // Format data for Decision BarChart
  const decisionData = [
    { name: 'Allowed', count: stats.allowed_packets || 0, fill: '#10B981' },
    { name: 'Blocked', count: stats.blocked_packets || 0, fill: '#EF4444' }
  ];

  return (
    <div className="space-y-6">
      {/* Top Banner / Heading */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-2xl font-extrabold text-white tracking-tight flex items-center gap-2">
            Security Operations Center (SOC)
          </h2>
          <p className="text-sm text-slate-400">
            Real-time traffic telemetry, automated rule enforcement, and anomaly detection.
          </p>
        </div>
      </div>

      {/* KPI Cards Grid */}
      <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-4">
        <StatCard
          title="Total Packets"
          value={stats.total_packets.toLocaleString()}
          subtitle="Processed"
          icon={Activity}
          color="cyan"
        />
        <StatCard
          title="Allowed"
          value={stats.allowed_packets.toLocaleString()}
          subtitle="Permitted"
          icon={ShieldCheck}
          color="emerald"
        />
        <StatCard
          title="Blocked"
          value={stats.blocked_packets.toLocaleString()}
          subtitle="Enforced"
          icon={ShieldAlert}
          color="rose"
        />
        <StatCard
          title="Block Rate"
          value={`${stats.block_rate_percent}%`}
          subtitle="Drop ratio"
          icon={TrendingDown}
          color="amber"
        />
        <StatCard
          title="Active Alerts"
          value={stats.active_alerts}
          subtitle={`Total: ${stats.total_alerts}`}
          icon={AlertTriangle}
          color="rose"
        />
        <StatCard
          title="Firewall Rules"
          value={stats.active_rules_count}
          subtitle="Active filters"
          icon={Zap}
          color="purple"
        />
      </div>

      {/* Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Protocol Distribution Donut Chart */}
        <div className="cyber-card p-5 flex flex-col">
          <h3 className="text-sm font-bold text-white uppercase tracking-wider mb-2 flex items-center justify-between">
            <span>Protocol Distribution</span>
            <span className="text-xs text-slate-400 font-normal font-mono">L4 Telemetry</span>
          </h3>
          <div className="h-64 w-full">
            {protocolData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={protocolData}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    innerRadius={55}
                    outerRadius={80}
                    paddingAngle={4}
                  >
                    {protocolData.map((entry) => (
                      <Cell
                        key={`cell-${entry.name}`}
                        fill={PROTO_COLORS[entry.name] || PROTO_COLORS.OTHER}
                        stroke="#0D1527"
                        strokeWidth={2}
                      />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{ backgroundColor: '#0F172A', borderColor: '#334155', borderRadius: '8px' }}
                    itemStyle={{ color: '#F8FAFC' }}
                  />
                  <Legend verticalAlign="bottom" height={36} iconType="circle" />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-xs text-slate-500">
                Awaiting packet stream...
              </div>
            )}
          </div>
        </div>

        {/* Traffic Volume Timeline Area Chart */}
        <div className="cyber-card p-5 flex flex-col">
          <h3 className="text-sm font-bold text-white uppercase tracking-wider mb-2 flex items-center justify-between">
            <span>Traffic Volume Over Time</span>
            <span className="text-xs text-slate-400 font-normal font-mono">Stream Log</span>
          </h3>
          <div className="h-64 w-full">
            {timeline && timeline.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={timeline}>
                  <defs>
                    <linearGradient id="colorAllowed" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#10B981" stopOpacity={0.5}/>
                      <stop offset="95%" stopColor="#10B981" stopOpacity={0}/>
                    </linearGradient>
                    <linearGradient id="colorBlocked" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#EF4444" stopOpacity={0.5}/>
                      <stop offset="95%" stopColor="#EF4444" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="time" stroke="#475569" fontSize={10} tickLine={false} />
                  <YAxis stroke="#475569" fontSize={10} tickLine={false} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#0F172A', borderColor: '#334155', borderRadius: '8px' }}
                  />
                  <Area type="monotone" dataKey="allowed" stroke="#10B981" fillOpacity={1} fill="url(#colorAllowed)" />
                  <Area type="monotone" dataKey="blocked" stroke="#EF4444" fillOpacity={1} fill="url(#colorBlocked)" />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-xs text-slate-500">
                Generating traffic telemetry...
              </div>
            )}
          </div>
        </div>

        {/* Action Decision Breakdown BarChart */}
        <div className="cyber-card p-5 flex flex-col">
          <h3 className="text-sm font-bold text-white uppercase tracking-wider mb-2 flex items-center justify-between">
            <span>Filtering Actions Ratio</span>
            <span className="text-xs text-slate-400 font-normal font-mono">Enforcement</span>
          </h3>
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={decisionData}>
                <XAxis dataKey="name" stroke="#475569" fontSize={11} tickLine={false} />
                <YAxis stroke="#475569" fontSize={11} tickLine={false} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0F172A', borderColor: '#334155', borderRadius: '8px' }}
                />
                <Bar dataKey="count" radius={[6, 6, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Live Recent Activity Stream Table */}
      <div className="cyber-card overflow-hidden">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-900/40">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
            <h3 className="text-sm font-bold text-white uppercase tracking-wider">
              Real-time Packet Evaluation Stream
            </h3>
          </div>
          <button
            onClick={() => onNavigate('packets')}
            className="text-xs text-cyan-400 hover:text-cyan-300 font-medium flex items-center gap-1 transition"
          >
            <span>View Full Packet Logs</span>
            <ArrowUpRight className="w-3.5 h-3.5" />
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-900/70 text-slate-400 font-semibold uppercase tracking-wider text-[11px]">
                <th className="py-3 px-4">Time</th>
                <th className="py-3 px-4">Source IP</th>
                <th className="py-3 px-4">Destination IP</th>
                <th className="py-3 px-4">Protocol</th>
                <th className="py-3 px-4">Decision</th>
                <th className="py-3 px-4">Enforcement Reason</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {(stats.recent_activity || []).map((pkt) => (
                <tr
                  key={pkt.id}
                  onClick={() => onSelectPacket && onSelectPacket(pkt.id)}
                  className="hover:bg-slate-800/40 transition-colors cursor-pointer"
                >
                  <td className="py-2.5 px-4 text-slate-400">{pkt.timestamp}</td>
                  <td className="py-2.5 px-4 text-cyan-300 font-medium">{pkt.src_ip}</td>
                  <td className="py-2.5 px-4 text-slate-300">{pkt.dst_ip}</td>
                  <td className="py-2.5 px-4">
                    <ProtocolBadge protocol={pkt.protocol} />
                  </td>
                  <td className="py-2.5 px-4">
                    <ActionBadge action={pkt.action} />
                  </td>
                  <td className="py-2.5 px-4 text-slate-300 truncate max-w-xs" title={pkt.decision_reason}>
                    {pkt.decision_reason}
                  </td>
                </tr>
              ))}
              {(!stats.recent_activity || stats.recent_activity.length === 0) && (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-500 font-sans">
                    No packet logs yet. Click 'Inject +5' or start the simulator above!
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
