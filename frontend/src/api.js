// API Client for Data-Driven Packet Filtering Firewall Backend

const BASE_URL = ''; // Relative path leverages Vite dev server proxy

async function request(endpoint, options = {}) {
  const url = `${BASE_URL}${endpoint}`;
  const response = await fetch(url, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...options.headers,
    },
  });

  if (!response.ok) {
    let errorMsg = `HTTP Error ${response.status}`;
    try {
      const errorData = await response.json();
      if (errorData.detail) {
        errorMsg = typeof errorData.detail === 'string' ? errorData.detail : JSON.stringify(errorData.detail);
      }
    } catch (_) {}
    throw new Error(errorMsg);
  }

  return response.json();
}

export const api = {
  // Health & Dashboard
  getHealth: () => request('/api/health'),
  getDashboardStats: () => request('/api/dashboard/stats'),
  getTrafficTimeline: () => request('/api/dashboard/timeline'),

  // Firewall Rules
  getRules: (enabledOnly = false) => request(`/api/rules${enabledOnly ? '?enabled_only=true' : ''}`),
  createRule: (rule) => request('/api/rules', { method: 'POST', body: JSON.stringify(rule) }),
  updateRule: (id, rule) => request(`/api/rules/${id}`, { method: 'PUT', body: JSON.stringify(rule) }),
  toggleRule: (id) => request(`/api/rules/${id}/toggle`, { method: 'PATCH' }),
  updateRulePriority: (id, priority) => request(`/api/rules/${id}/priority?priority=${priority}`, { method: 'PATCH' }),
  deleteRule: (id) => request(`/api/rules/${id}`, { method: 'DELETE' }),

  // Packet Logs
  getPackets: (params = {}) => {
    const query = new URLSearchParams();
    if (params.page) query.append('page', params.page);
    if (params.page_size) query.append('page_size', params.page_size);
    if (params.search) query.append('search', params.search);
    if (params.action) query.append('action', params.action);
    if (params.protocol) query.append('protocol', params.protocol);
    if (params.is_simulated !== undefined && params.is_simulated !== '') {
      query.append('is_simulated', params.is_simulated);
    }
    return request(`/api/packets?${query.toString()}`);
  },
  getPacketDetail: (id) => request(`/api/packets/${id}`),
  ingestPacket: (pkt) => request('/api/packets/ingest', { method: 'POST', body: JSON.stringify(pkt) }),
  clearPackets: () => request('/api/packets/clear', { method: 'DELETE' }),

  // Security Alerts
  getAlerts: (params = {}) => {
    const query = new URLSearchParams();
    if (params.severity) query.append('severity', params.severity);
    if (params.status) query.append('status', params.status);
    if (params.search) query.append('search', params.search);
    if (params.limit) query.append('limit', params.limit);
    return request(`/api/alerts?${query.toString()}`);
  },
  updateAlertStatus: (id, status) => request(`/api/alerts/${id}/status`, {
    method: 'PATCH',
    body: JSON.stringify({ status })
  }),
  blockOffendingIp: (id) => request(`/api/alerts/${id}/block-ip`, { method: 'POST' }),
  clearAlerts: () => request('/api/alerts/clear', { method: 'DELETE' }),

  // Simulator
  getSimulatorStatus: () => request('/api/simulator/status'),
  startSimulator: () => request('/api/simulator/start', { method: 'POST' }),
  stopSimulator: () => request('/api/simulator/stop', { method: 'POST' }),
  updateSimulatorConfig: (cfg) => request('/api/simulator/config', {
    method: 'POST',
    body: JSON.stringify(cfg)
  }),
  generateBatch: (count = 5) => request(`/api/simulator/generate?count=${count}`, { method: 'POST' }),

  // PCAP Offline Ingestion
  uploadPcap: async (file) => {
    const formData = new FormData();
    formData.append('file', file);
    const response = await fetch('/api/pcap/upload', {
      method: 'POST',
      body: formData,
    });
    if (!response.ok) {
      const err = await response.json();
      throw new Error(err.detail || 'PCAP upload failed');
    }
    return response.json();
  },
  runSamplePcap: () => request('/api/pcap/sample', { method: 'POST' }),
  getSampleInfo: () => request('/api/pcap/sample-info'),

  // Settings
  getSettings: () => request('/api/settings'),
  updateSetting: (key, value) => request(`/api/settings/${key}`, {
    method: 'PUT',
    body: JSON.stringify({ value })
  }),
  resetDefaults: () => request('/api/settings/reset-to-defaults', { method: 'POST' }),
};
