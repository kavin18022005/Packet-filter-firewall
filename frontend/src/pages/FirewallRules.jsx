import React, { useState, useEffect } from 'react';
import {
  Plus,
  Edit2,
  Trash2,
  CheckCircle2,
  XCircle,
  ArrowUp,
  ArrowDown,
  RotateCcw,
  Shield,
  HelpCircle
} from 'lucide-react';
import { api } from '../api';
import { ActionBadge, ProtocolBadge } from '../components/Badge';
import { Modal } from '../components/Modal';

export function FirewallRules() {
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(false);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [editingRule, setEditingRule] = useState(null);
  const [formError, setFormError] = useState('');

  // Form State
  const initialForm = {
    name: '',
    priority: 100,
    action: 'BLOCK',
    protocol: 'ANY',
    src_ip: 'ANY',
    dst_ip: 'ANY',
    src_port: 'ANY',
    dst_port: 'ANY',
    enabled: true,
    description: ''
  };
  const [formData, setFormData] = useState(initialForm);

  const loadRules = async () => {
    setLoading(true);
    try {
      const data = await api.getRules();
      setRules(data || []);
    } catch (err) {
      console.error('Failed to load rules:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadRules();
  }, []);

  const handleOpenAddModal = () => {
    setEditingRule(null);
    setFormData(initialForm);
    setFormError('');
    setIsModalOpen(true);
  };

  const handleOpenEditModal = (rule) => {
    setEditingRule(rule);
    setFormData({
      name: rule.name,
      priority: rule.priority,
      action: rule.action,
      protocol: rule.protocol,
      src_ip: rule.src_ip,
      dst_ip: rule.dst_ip,
      src_port: rule.src_port,
      dst_port: rule.dst_port,
      enabled: rule.enabled,
      description: rule.description || ''
    });
    setFormError('');
    setIsModalOpen(true);
  };

  const handleSubmitForm = async (e) => {
    e.preventDefault();
    setFormError('');
    try {
      if (editingRule) {
        await api.updateRule(editingRule.id, formData);
      } else {
        await api.createRule(formData);
      }
      setIsModalOpen(false);
      loadRules();
    } catch (err) {
      setFormError(err.message);
    }
  };

  const handleToggle = async (id) => {
    try {
      await api.toggleRule(id);
      loadRules();
    } catch (err) {
      alert(err.message);
    }
  };

  const handleAdjustPriority = async (id, currentPriority, delta) => {
    const newPriority = Math.max(1, Math.min(10000, currentPriority + delta));
    try {
      await api.updateRulePriority(id, newPriority);
      loadRules();
    } catch (err) {
      alert(err.message);
    }
  };

  const handleDelete = async (id, name) => {
    if (window.confirm(`Are you sure you want to delete rule "${name}"?`)) {
      try {
        await api.deleteRule(id);
        loadRules();
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
            Firewall Rule Engine Policy
          </h2>
          <p className="text-sm text-slate-400">
            Rules are evaluated in strict priority order (lowest integer first). First matching enabled rule wins.
          </p>
        </div>
        <button
          onClick={handleOpenAddModal}
          className="flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-cyan-600 to-cyan-500 hover:from-cyan-500 hover:to-cyan-400 text-white rounded-xl text-xs font-bold shadow-lg shadow-cyan-900/30 transition"
        >
          <Plus className="w-4 h-4" />
          Add Firewall Rule
        </button>
      </div>

      {/* Rules Table */}
      <div className="cyber-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-900/80 text-slate-400 font-semibold uppercase tracking-wider text-[11px]">
                <th className="py-3 px-4 w-24">Priority</th>
                <th className="py-3 px-4 w-20">Status</th>
                <th className="py-3 px-4">Rule Name</th>
                <th className="py-3 px-4">Action</th>
                <th className="py-3 px-4">Proto</th>
                <th className="py-3 px-4">Source IP</th>
                <th className="py-3 px-4">Destination IP</th>
                <th className="py-3 px-4">Dst Port</th>
                <th className="py-3 px-4">Description</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {rules.map((rule) => (
                <tr
                  key={rule.id}
                  className={`hover:bg-slate-800/40 transition-colors ${!rule.enabled ? 'opacity-50' : ''}`}
                >
                  {/* Priority with Up/Down Controls */}
                  <td className="py-3 px-4 whitespace-nowrap">
                    <div className="flex items-center gap-1">
                      <span className="font-bold text-cyan-300 w-8">{rule.priority}</span>
                      <div className="flex flex-col">
                        <button
                          onClick={() => handleAdjustPriority(rule.id, rule.priority, -5)}
                          className="p-0.5 hover:text-cyan-400 transition"
                          title="Increase Priority (lower number)"
                        >
                          <ArrowUp className="w-3 h-3" />
                        </button>
                        <button
                          onClick={() => handleAdjustPriority(rule.id, rule.priority, 5)}
                          className="p-0.5 hover:text-cyan-400 transition"
                          title="Decrease Priority (higher number)"
                        >
                          <ArrowDown className="w-3 h-3" />
                        </button>
                      </div>
                    </div>
                  </td>

                  {/* Enabled Toggle Switch */}
                  <td className="py-3 px-4">
                    <button
                      onClick={() => handleToggle(rule.id)}
                      className={`relative inline-flex h-5 w-9 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none ${
                        rule.enabled ? 'bg-cyan-600' : 'bg-slate-700'
                      }`}
                      title={rule.enabled ? 'Click to disable rule' : 'Click to enable rule'}
                    >
                      <span
                        className={`pointer-events-none inline-block h-4 w-4 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${
                          rule.enabled ? 'translate-x-4' : 'translate-x-0'
                        }`}
                      />
                    </button>
                  </td>

                  <td className="py-3 px-4 font-bold text-white font-sans whitespace-nowrap">
                    {rule.name}
                  </td>
                  <td className="py-3 px-4">
                    <ActionBadge action={rule.action} />
                  </td>
                  <td className="py-3 px-4">
                    <ProtocolBadge protocol={rule.protocol} />
                  </td>
                  <td className="py-3 px-4 text-cyan-400">{rule.src_ip}</td>
                  <td className="py-3 px-4 text-slate-300">{rule.dst_ip}</td>
                  <td className="py-3 px-4 text-purple-300">{rule.dst_port}</td>
                  <td className="py-3 px-4 text-slate-400 font-sans truncate max-w-xs" title={rule.description}>
                    {rule.description || '-'}
                  </td>
                  <td className="py-3 px-4 text-right whitespace-nowrap">
                    <div className="flex items-center justify-end gap-1.5 font-sans">
                      <button
                        onClick={() => handleOpenEditModal(rule)}
                        className="p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-cyan-400 transition"
                        title="Edit rule"
                      >
                        <Edit2 className="w-3.5 h-3.5" />
                      </button>
                      <button
                        onClick={() => handleDelete(rule.id, rule.name)}
                        className="p-1.5 rounded bg-slate-800 hover:bg-rose-950/60 text-slate-300 hover:text-rose-400 transition"
                        title="Delete rule"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
              {rules.length === 0 && !loading && (
                <tr>
                  <td colSpan={10} className="py-12 text-center text-slate-500 font-sans">
                    No firewall rules configured.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Add / Edit Rule Modal */}
      <Modal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        title={editingRule ? `Edit Rule: ${editingRule.name}` : 'Create New Firewall Rule'}
        maxWidth="max-w-2xl"
      >
        <form onSubmit={handleSubmitForm} className="space-y-4 text-xs font-sans">
          {formError && (
            <div className="p-3 rounded-lg bg-rose-950/80 border border-rose-600 text-rose-300 font-medium">
              {formError}
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-slate-400 font-medium mb-1">Rule Name *</label>
              <input
                type="text"
                required
                value={formData.name}
                onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                placeholder="e.g. Block Ransomware Port"
                className="w-full bg-[#0B1120] border border-slate-700 rounded-lg px-3 py-2 text-white focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div>
              <label className="block text-slate-400 font-medium mb-1">
                Priority * <span className="text-slate-500 font-normal">(Lower = Higher evaluation precedence)</span>
              </label>
              <input
                type="number"
                min="1"
                max="10000"
                required
                value={formData.priority}
                onChange={(e) => setFormData({ ...formData, priority: parseInt(e.target.value) || 100 })}
                className="w-full bg-[#0B1120] border border-slate-700 rounded-lg px-3 py-2 text-white focus:outline-none focus:border-cyan-500 font-mono"
              />
            </div>

            <div>
              <label className="block text-slate-400 font-medium mb-1">Action *</label>
              <select
                value={formData.action}
                onChange={(e) => setFormData({ ...formData, action: e.target.value })}
                className="w-full bg-[#0B1120] border border-slate-700 rounded-lg px-3 py-2 text-white focus:outline-none focus:border-cyan-500 font-semibold"
              >
                <option value="ALLOW">ALLOW</option>
                <option value="BLOCK">BLOCK</option>
              </select>
            </div>

            <div>
              <label className="block text-slate-400 font-medium mb-1">Protocol *</label>
              <select
                value={formData.protocol}
                onChange={(e) => setFormData({ ...formData, protocol: e.target.value })}
                className="w-full bg-[#0B1120] border border-slate-700 rounded-lg px-3 py-2 text-white focus:outline-none focus:border-cyan-500 font-mono"
              >
                <option value="ANY">ANY</option>
                <option value="TCP">TCP</option>
                <option value="UDP">UDP</option>
                <option value="ICMP">ICMP</option>
              </select>
            </div>

            <div>
              <label className="block text-slate-400 font-medium mb-1">
                Source IP / CIDR <span className="text-slate-500 font-normal">(e.g. 192.168.1.0/24, ANY)</span>
              </label>
              <input
                type="text"
                value={formData.src_ip}
                onChange={(e) => setFormData({ ...formData, src_ip: e.target.value })}
                className="w-full bg-[#0B1120] border border-slate-700 rounded-lg px-3 py-2 text-white focus:outline-none focus:border-cyan-500 font-mono"
              />
            </div>

            <div>
              <label className="block text-slate-400 font-medium mb-1">
                Destination IP / CIDR <span className="text-slate-500 font-normal">(e.g. 10.0.0.0/8, ANY)</span>
              </label>
              <input
                type="text"
                value={formData.dst_ip}
                onChange={(e) => setFormData({ ...formData, dst_ip: e.target.value })}
                className="w-full bg-[#0B1120] border border-slate-700 rounded-lg px-3 py-2 text-white focus:outline-none focus:border-cyan-500 font-mono"
              />
            </div>

            <div>
              <label className="block text-slate-400 font-medium mb-1">
                Source Port <span className="text-slate-500 font-normal">(e.g. ANY, 1024-65535)</span>
              </label>
              <input
                type="text"
                value={formData.src_port}
                onChange={(e) => setFormData({ ...formData, src_port: e.target.value })}
                className="w-full bg-[#0B1120] border border-slate-700 rounded-lg px-3 py-2 text-white focus:outline-none focus:border-cyan-500 font-mono"
              />
            </div>

            <div>
              <label className="block text-slate-400 font-medium mb-1">
                Destination Port <span className="text-slate-500 font-normal">(e.g. 80,443, 8000-8080, ANY)</span>
              </label>
              <input
                type="text"
                value={formData.dst_port}
                onChange={(e) => setFormData({ ...formData, dst_port: e.target.value })}
                className="w-full bg-[#0B1120] border border-slate-700 rounded-lg px-3 py-2 text-white focus:outline-none focus:border-cyan-500 font-mono"
              />
            </div>
          </div>

          <div>
            <label className="block text-slate-400 font-medium mb-1">Description / Security Rationale</label>
            <input
              type="text"
              value={formData.description}
              onChange={(e) => setFormData({ ...formData, description: e.target.value })}
              placeholder="e.g. Restrict unauthorized admin access"
              className="w-full bg-[#0B1120] border border-slate-700 rounded-lg px-3 py-2 text-white focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div className="flex items-center gap-2 pt-2">
            <input
              type="checkbox"
              id="ruleEnabledCheckbox"
              checked={formData.enabled}
              onChange={(e) => setFormData({ ...formData, enabled: e.target.checked })}
              className="rounded bg-[#0B1120] border-slate-700 text-cyan-600 focus:ring-0"
            />
            <label htmlFor="ruleEnabledCheckbox" className="text-slate-300 font-medium cursor-pointer">
              Enable this rule immediately upon saving
            </label>
          </div>

          <div className="flex justify-end gap-3 pt-4 border-t border-slate-800">
            <button
              type="button"
              onClick={() => setIsModalOpen(false)}
              className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 transition"
            >
              Cancel
            </button>
            <button
              type="submit"
              className="px-5 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white font-bold transition shadow-lg shadow-cyan-950/50"
            >
              {editingRule ? 'Save Changes' : 'Create Rule'}
            </button>
          </div>
        </form>
      </Modal>
    </div>
  );
}
