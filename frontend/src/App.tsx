import React, { useState, useEffect, useCallback } from 'react';
import { api } from './api/client';
import type {
  Scope,
  ScanRun,
  DiscoveredAsset,
  ScanFinding,
  StatsOverview,
  ScanConfig,
} from './api/types';

import { Sidebar } from './components/layout/Sidebar';
import type { NavTab } from './components/layout/Sidebar';
import { Header } from './components/layout/Header';
import { OverviewView } from './components/overview/OverviewView';
import { InventoryView } from './components/inventory/InventoryView';
import { DiscoveryView } from './components/discovery/DiscoveryView';
import { ScopeView } from './components/scope/ScopeView';
import { ChangesView } from './components/changes/ChangesView';
import { FindingsView } from './components/findings/FindingsView';
import { ReportsAlertsView } from './components/reports/ReportsAlertsView';
import { ScheduledDiscoveryView } from './components/schedules/ScheduledDiscoveryView';
import { AssetDetailDrawer } from './components/inventory/AssetDetailDrawer';
import { NewScanModal } from './components/discovery/NewScanModal';
import { ScopeModal } from './components/scope/ScopeModal';

export const App: React.FC = () => {
  const [currentTab, setCurrentTab] = useState<NavTab>('overview');
  const [stats, setStats] = useState<StatsOverview | null>(null);
  const [scopes, setScopes] = useState<Scope[]>([]);
  const [scans, setScans] = useState<ScanRun[]>([]);
  const [assets, setAssets] = useState<DiscoveredAsset[]>([]);
  const [activeScan, setActiveScan] = useState<ScanRun | null>(null);

  // Asset detail inspection
  const [selectedAsset, setSelectedAsset] = useState<DiscoveredAsset | null>(null);
  const [findingsMap, setFindingsMap] = useState<Record<string, ScanFinding[]>>({});
  const [isDrawerOpen, setIsDrawerOpen] = useState(false);

  // Modals
  const [isNewScanModalOpen, setIsNewScanModalOpen] = useState(false);
  const [modalScopeId, setModalScopeId] = useState<string | undefined>(undefined);
  const [isNewScopeModalOpen, setIsNewScopeModalOpen] = useState(false);

  // Health and state
  const [backendHealthy, setBackendHealthy] = useState(false);
  const [isRefreshing, setIsRefreshing] = useState(false);

  // Load all foundational data
  const fetchData = useCallback(async () => {
    setIsRefreshing(true);
    try {
      const [healthRes, statsRes, scopesRes, scansRes, assetsRes] = await Promise.all([
        api.getHealth().catch(() => null),
        api.getStatsOverview().catch(() => null),
        api.getScopes().catch(() => []),
        api.getScans().catch(() => []),
        api.getAssets().catch(() => []),
      ]);

      setBackendHealthy(Boolean(healthRes && healthRes.status === 'healthy'));
      if (statsRes) setStats(statsRes);
      setScopes(scopesRes);
      setScans(scansRes);
      setAssets(assetsRes);

      // Track ongoing in-progress scan if any
      const runningScan = scansRes.find((s) => s.status === 'IN_PROGRESS');
      if (runningScan) {
        setActiveScan(runningScan);
      } else if (!activeScan && scansRes.length > 0) {
        setActiveScan(scansRes[0]);
      }
    } catch {
      setBackendHealthy(false);
    } finally {
      setIsRefreshing(false);
    }
  }, [activeScan]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  // Real-time polling when an active scan is running
  useEffect(() => {
    if (!activeScan || activeScan.status !== 'IN_PROGRESS') return;

    const interval = setInterval(async () => {
      try {
        const updated = await api.getScan(activeScan.id);
        setActiveScan(updated);
        // If scan completed, reload assets and stats
        if (updated.status !== 'IN_PROGRESS') {
          const [updatedStats, updatedAssets, updatedScans] = await Promise.all([
            api.getStatsOverview(),
            api.getAssets(),
            api.getScans(),
          ]);
          setStats(updatedStats);
          setAssets(updatedAssets);
          setScans(updatedScans);
        }
      } catch {
        // ignore polling errors
      }
    }, 1500);

    return () => clearInterval(interval);
  }, [activeScan]);

  const isDemoActive = scopes.some((s) => s.name.includes('[DEMO / SYNTHETIC]'));

  // Toggle demo mode
  const handleToggleDemo = async () => {
    try {
      if (isDemoActive) {
        await api.clearDemoMode();
      } else {
        await api.seedDemoMode();
      }
      await fetchData();
    } catch (err: any) {
      alert(`Error toggling demo mode: ${err.message}`);
    }
  };

  // Launch scan
  const handleLaunchScan = async (scopeId: string, config: ScanConfig) => {
    const newScan = await api.launchScan(scopeId, config);
    setActiveScan(newScan);
    setCurrentTab('discovery');
    fetchData();
  };

  // Cancel scan
  const handleCancelScan = async (scanId: string) => {
    await api.cancelScan(scanId);
    if (activeScan && activeScan.id === scanId) {
      const refreshed = await api.getScan(scanId);
      setActiveScan(refreshed);
    }
    fetchData();
  };

  // Delete asset
  const handleDeleteAsset = async (assetId: string) => {
    if (!confirm('Are you sure you want to remove this asset from inventory?')) return;
    await api.deleteAsset(assetId);
    if (selectedAsset?.id === assetId) {
      setIsDrawerOpen(false);
      setSelectedAsset(null);
    }
    fetchData();
  };

  // Delete scope
  const handleDeleteScope = async (scopeId: string) => {
    if (!confirm('Delete this scope? All associated scan runs and discovered assets will also be removed.')) return;
    await api.deleteScope(scopeId);
    fetchData();
  };

  // Inspect asset
  const handleInspectAsset = async (asset: DiscoveredAsset) => {
    setSelectedAsset(asset);
    setIsDrawerOpen(true);
    if (!findingsMap[asset.id]) {
      try {
        const findings = await api.getAssetFindings(asset.id);
        setFindingsMap((prev) => ({ ...prev, [asset.id]: findings }));
      } catch {
        // ignore
      }
    }
  };

  const titles: Record<NavTab, { title: string; subtitle: string }> = {
    overview: {
      title: 'Attack Surface Overview',
      subtitle: 'Phase 1 inventory posture, live scan metrics, and service breakdowns',
    },
    inventory: {
      title: 'Discovered Asset Inventory',
      subtitle: 'Comprehensive inventory of authorized domains, IPs, services, and TLS certificates',
    },
    changes: {
      title: 'Asset Change History & Baseline Monitoring',
      subtitle: 'Phase 2 detected additions, removals, service state shifts, and TLS certificate updates',
    },
    findings: {
      title: 'Findings & Explainable Risk Classification',
      subtitle: 'Deterministic risk analysis, exposed service assessments, and review status triage',
    },
    discovery: {
      title: 'Discovery Runs & Engine Monitor',
      subtitle: 'Real-time progress, live execution console, and bounded probe logs',
    },
    schedules: {
      title: 'Automated & Scheduled Discovery',
      subtitle: 'Phase 6 recurring scans, automated baseline comparison, and continuous attack-surface monitoring',
    },
    scopes: {
      title: 'Authorised Scope Settings',
      subtitle: 'Explicit target boundaries, local lab policies, and verified authorization records',
    },
    reports: {
      title: 'Alerts, Notifications & Audit Telemetry',
      subtitle: 'Phase 5 configurable alert rules, bounded delivery, sanitized reports, and audit trail',
    },
  };

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-background text-foreground cyber-grid">
      {/* Sidebar Navigation */}
      <Sidebar
        currentTab={currentTab}
        onSelectTab={setCurrentTab}
        isDemoActive={isDemoActive}
        onToggleDemo={handleToggleDemo}
        onOpenQuickScan={() => setIsNewScanModalOpen(true)}
        backendHealthy={backendHealthy}
      />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col h-full overflow-hidden">
        <Header
          title={titles[currentTab].title}
          subtitle={titles[currentTab].subtitle}
          isDemoActive={isDemoActive}
          onRefresh={fetchData}
          onOpenNewScope={() => setIsNewScopeModalOpen(true)}
          onOpenQuickScan={() => setIsNewScanModalOpen(true)}
          isRefreshing={isRefreshing}
        />

        {/* View Body */}
        <main className="flex-1 overflow-y-auto p-8">
          {currentTab === 'overview' && (
            <OverviewView
              stats={stats}
              recentScans={scans}
              onNavigate={setCurrentTab}
              onOpenNewScope={() => setIsNewScopeModalOpen(true)}
              onOpenQuickScan={() => setIsNewScanModalOpen(true)}
              onToggleDemo={handleToggleDemo}
              isDemoActive={isDemoActive}
            />
          )}

          {currentTab === 'inventory' && (
            <InventoryView
              assets={assets}
              scopes={scopes}
              findingsMap={findingsMap}
              onInspectAsset={handleInspectAsset}
              onDeleteAsset={handleDeleteAsset}
              onRefresh={fetchData}
              selectedAsset={selectedAsset}
              onCloseDrawer={() => setIsDrawerOpen(false)}
              isDrawerOpen={isDrawerOpen}
            />
          )}

          {currentTab === 'changes' && (
            <ChangesView
              scopes={scopes}
              onInspectAsset={(host) => {
                const found = assets.find((a) => a.host_or_ip === host);
                if (found) {
                  handleInspectAsset(found);
                }
              }}
            />
          )}

          {currentTab === 'findings' && (
            <FindingsView
              scopes={scopes}
              onInspectAsset={(host) => {
                const found = assets.find((a) => a.host_or_ip === host);
                if (found) {
                  handleInspectAsset(found);
                } else {
                  setCurrentTab('inventory');
                }
              }}
            />
          )}

          {currentTab === 'discovery' && (
            <DiscoveryView
              scans={scans}
              activeScan={activeScan}
              scopes={scopes}
              onOpenNewScan={() => setIsNewScanModalOpen(true)}
              onCancelScan={handleCancelScan}
              onSelectScan={(s) => setActiveScan(s)}
            />
          )}

          {currentTab === 'schedules' && (
            <ScheduledDiscoveryView
              scopes={scopes}
              onNavigateToScan={(scanId) => {
                const found = scans.find((s) => s.id === scanId);
                if (found) setActiveScan(found);
                setCurrentTab('discovery');
              }}
            />
          )}

          {currentTab === 'scopes' && (
            <ScopeView
              scopes={scopes}
              onOpenNewScope={() => setIsNewScopeModalOpen(true)}
              onDeleteScope={handleDeleteScope}
              onLaunchScanForScope={(scopeId) => {
                setModalScopeId(scopeId);
                setIsNewScanModalOpen(true);
              }}
            />
          )}

          {currentTab === 'reports' && (
            <ReportsAlertsView scopes={scopes} />
          )}
        </main>
      </div>

      {/* New Scan Modal */}
      <NewScanModal
        isOpen={isNewScanModalOpen}
        onClose={() => {
          setIsNewScanModalOpen(false);
          setModalScopeId(undefined);
        }}
        scopes={scopes}
        onLaunchScan={handleLaunchScan}
        initialScopeId={modalScopeId}
      />

      {/* New Scope Modal */}
      <ScopeModal
        isOpen={isNewScopeModalOpen}
        onClose={() => setIsNewScopeModalOpen(false)}
        onScopeCreated={fetchData}
      />

      {/* Global Asset Detail Inspection Drawer */}
      <AssetDetailDrawer
        asset={selectedAsset}
        findings={selectedAsset ? findingsMap[selectedAsset.id] || [] : []}
        isOpen={isDrawerOpen}
        onClose={() => setIsDrawerOpen(false)}
      />
    </div>
  );
};

export default App;
