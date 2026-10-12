import React, { useState, useEffect, useRef } from 'react';
import { Navbar } from './components/Navbar';
import { Sidebar } from './components/Sidebar';
import { Dashboard } from './pages/Dashboard';
import { PacketLogs } from './pages/PacketLogs';
import { FirewallRules } from './pages/FirewallRules';
import { SecurityAlerts } from './pages/SecurityAlerts';
import { PcapAnalysis } from './pages/PcapAnalysis';
import { Settings } from './pages/Settings';
import { api } from './api';

export function App() {
  const [currentTab, setCurrentTab] = useState('dashboard');
  const [stats, setStats] = useState(null);
  const [timeline, setTimeline] = useState([]);
  const [simStatus, setSimStatus] = useState(null);
  const [defaultPolicy, setDefaultPolicy] = useState('BLOCK');
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [inspectedPacketId, setInspectedPacketId] = useState(null);

  const refreshIntervalRef = useRef(null);

  const fetchSOCData = async (showSpinner = false) => {
    if (showSpinner) setIsRefreshing(true);
    try {
      const [statsData, timelineData, simData, healthData] = await Promise.all([
        api.getDashboardStats().catch(() => null),
        api.getTrafficTimeline().catch(() => []),
        api.getSimulatorStatus().catch(() => null),
        api.getHealth().catch(() => null),
      ]);

      if (statsData) setStats(statsData);
      if (timelineData) setTimeline(timelineData);
      if (simData) setSimStatus(simData);
      if (healthData && healthData.default_policy) {
        setDefaultPolicy(healthData.default_policy);
      }
    } catch (err) {
      console.error('Data refresh error:', err);
    } finally {
      if (showSpinner) setIsRefreshing(false);
    }
  };

  useEffect(() => {
    fetchSOCData(true);
  }, []);

  useEffect(() => {
    if (autoRefresh) {
      refreshIntervalRef.current = setInterval(() => {
        fetchSOCData(false);
      }, 3000);
    } else {
      if (refreshIntervalRef.current) clearInterval(refreshIntervalRef.current);
    }
    return () => {
      if (refreshIntervalRef.current) clearInterval(refreshIntervalRef.current);
    };
  }, [autoRefresh]);

  const handleToggleSimulator = async () => {
    try {
      if (simStatus?.is_running) {
        await api.stopSimulator();
      } else {
        await api.startSimulator();
      }
      const updatedStatus = await api.getSimulatorStatus();
      setSimStatus(updatedStatus);
      fetchSOCData();
    } catch (err) {
      alert(err.message);
    }
  };

  const handleGenerateBatch = async () => {
    try {
      await api.generateBatch(5);
      fetchSOCData();
    } catch (err) {
      alert(err.message);
    }
  };

  const handleSelectPacketFromDashboard = (packetId) => {
    setInspectedPacketId(packetId);
    setCurrentTab('packets');
  };

  return (
    <div className="min-h-screen bg-[#070B14] text-slate-100 flex flex-col font-sans">
      {/* Top Navbar */}
      <Navbar
        defaultPolicy={defaultPolicy}
        simStatus={simStatus}
        onToggleSimulator={handleToggleSimulator}
        onGenerateBatch={handleGenerateBatch}
        autoRefresh={autoRefresh}
        onToggleAutoRefresh={() => setAutoRefresh(!autoRefresh)}
        isRefreshing={isRefreshing}
        onManualRefresh={() => fetchSOCData(true)}
      />

      {/* Main Layout */}
      <div className="flex-1 flex flex-col md:flex-row overflow-hidden">
        {/* Navigation Sidebar */}
        <Sidebar
          currentTab={currentTab}
          onSelectTab={setCurrentTab}
          alertCount={stats?.active_alerts || 0}
        />

        {/* Dynamic Page View */}
        <main className="flex-1 overflow-y-auto p-4 lg:p-8 bg-gradient-to-b from-[#090E1B] to-[#070B14]">
          {currentTab === 'dashboard' && (
            <Dashboard
              stats={stats}
              timeline={timeline}
              onSelectPacket={handleSelectPacketFromDashboard}
              onNavigate={setCurrentTab}
            />
          )}

          {currentTab === 'packets' && (
            <PacketLogs initialSelectedId={inspectedPacketId} />
          )}

          {currentTab === 'rules' && (
            <FirewallRules />
          )}

          {currentTab === 'alerts' && (
            <SecurityAlerts onNavigate={setCurrentTab} />
          )}

          {currentTab === 'pcap' && (
            <PcapAnalysis onNavigate={setCurrentTab} />
          )}

          {currentTab === 'settings' && (
            <Settings />
          )}
        </main>
      </div>
    </div>
  );
}

export default App;
