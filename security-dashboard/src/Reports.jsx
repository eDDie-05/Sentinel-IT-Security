import { useEffect, useMemo, useState } from "react";

const API = "http://localhost:5000/api";

const defaultPolicy = {
  antivirus_required: true,
  firewall_required: true,
  backup_required: true,
};

function getToken() {
  return localStorage.getItem("token");
}

async function apiFetch(path, options = {}) {
  const token = getToken();

  const response = await fetch(`${API}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(options.headers || {}),
    },
  });

  let data = null;

  try {
    data = await response.json();
  } catch {
    data = null;
  }

  if (!response.ok) {
    throw new Error(
      data?.error ||
        data?.message ||
        `Request failed with status ${response.status}`
    );
  }

  return data;
}

function normalizeArray(data) {
  if (Array.isArray(data)) return data;

  if (Array.isArray(data?.devices)) return data.devices;
  if (Array.isArray(data?.logs)) return data.logs;
  if (Array.isArray(data?.alerts)) return data.alerts;
  if (Array.isArray(data?.users)) return data.users;
  if (Array.isArray(data?.data)) return data.data;

  return [];
}

function isTrue(value) {
  return (
    value === true ||
    value === 1 ||
    value === "1" ||
    value === "true" ||
    value === "enabled" ||
    value === "ENABLED"
  );
}

function securityState(device, policy) {
  const antivirusRequired =
    policy?.antivirus_required ?? policy?.antivirusRequired ?? true;

  const firewallRequired =
    policy?.firewall_required ?? policy?.firewallRequired ?? true;

  const backupRequired =
    policy?.backup_required ?? policy?.backupRequired ?? true;

  const checks = [];

  if (antivirusRequired) {
    checks.push(isTrue(device.antivirus));
  }

  if (firewallRequired) {
    checks.push(isTrue(device.firewall));
  }

  if (backupRequired) {
    checks.push(isTrue(device.backup));
  }

  if (!checks.length) {
    return "SECURE";
  }

  if (checks.every(Boolean)) {
    return "SECURE";
  }

  return "AT RISK";
}

function onlineState(device) {
  if (device.online === true || device.online === 1) {
    return true;
  }

  if (device.online === "true" || device.online === "1") {
    return true;
  }

  return false;
}

function formatDate(value) {
  if (!value) return "—";

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return String(value);
  }

  return date.toLocaleString();
}

function StatCard({ title, value, subtitle, icon }) {
  return (
    <div className="report-stat-card">
      <div className="report-stat-icon">{icon}</div>

      <div className="report-stat-content">
        <div className="report-stat-title">{title}</div>
        <div className="report-stat-value">{value}</div>
        <div className="report-stat-subtitle">{subtitle}</div>
      </div>
    </div>
  );
}

function ProgressBar({ label, value, total }) {
  const percentage =
    total > 0 ? Math.round((Number(value) / Number(total)) * 100) : 0;

  return (
    <div className="report-progress-row">
      <div className="report-progress-header">
        <span>{label}</span>
        <strong>
          {value} / {total}
        </strong>
      </div>

      <div className="report-progress-track">
        <div
          className="report-progress-fill"
          style={{ width: `${percentage}%` }}
        />
      </div>

      <div className="report-progress-percent">{percentage}%</div>
    </div>
  );
}

export default function Reports() {
  const [devices, setDevices] = useState([]);
  const [policy, setPolicy] = useState(defaultPolicy);
  const [auditLogs, setAuditLogs] = useState([]);
  const [alerts, setAlerts] = useState([]);

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const [lastUpdated, setLastUpdated] = useState(null);

  async function loadReports() {
    setLoading(true);
    setError("");

    try {
      const [devicesResult, policyResult, logsResult, alertsResult] =
        await Promise.all([
          apiFetch("/devices"),
          apiFetch("/security-policy"),
          apiFetch("/audit-logs").catch(() => []),
          apiFetch("/security-alerts").catch(() => []),
        ]);

      const loadedDevices = normalizeArray(devicesResult);

      setDevices(loadedDevices);

      if (policyResult) {
        if (Array.isArray(policyResult)) {
          setPolicy(policyResult[0] || defaultPolicy);
        } else {
          setPolicy({
            ...defaultPolicy,
            ...(policyResult.policy || policyResult),
          });
        }
      }

      setAuditLogs(normalizeArray(logsResult));
      setAlerts(normalizeArray(alertsResult));

      setLastUpdated(new Date());
    } catch (err) {
      console.error("Reports loading error:", err);
      setError(err.message || "Unable to load reports.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadReports();

    const interval = setInterval(() => {
      loadReports();
    }, 30000);

    return () => clearInterval(interval);
  }, []);

  const statistics = useMemo(() => {
    const total = devices.length;

    const online = devices.filter((device) => onlineState(device)).length;

    const offline = total - online;

    const secure = devices.filter(
      (device) => securityState(device, policy) === "SECURE"
    ).length;

    const atRisk = devices.filter(
      (device) => securityState(device, policy) === "AT RISK"
    ).length;

    const antivirusEnabled = devices.filter((device) =>
      isTrue(device.antivirus)
    ).length;

    const firewallEnabled = devices.filter((device) =>
      isTrue(device.firewall)
    ).length;

    const backupEnabled = devices.filter((device) =>
      isTrue(device.backup)
    ).length;

    return {
      total,
      online,
      offline,
      secure,
      atRisk,
      antivirusEnabled,
      firewallEnabled,
      backupEnabled,
    };
  }, [devices, policy]);

  const departmentStats = useMemo(() => {
    const departments = {};

    devices.forEach((device) => {
      const department = device.department || "Unassigned";

      if (!departments[department]) {
        departments[department] = {
          total: 0,
          secure: 0,
          atRisk: 0,
          online: 0,
        };
      }

      departments[department].total += 1;

      if (securityState(device, policy) === "SECURE") {
        departments[department].secure += 1;
      } else {
        departments[department].atRisk += 1;
      }

      if (onlineState(device)) {
        departments[department].online += 1;
      }
    });

    return Object.entries(departments)
      .map(([name, values]) => ({
        name,
        ...values,
      }))
      .sort((a, b) => b.total - a.total);
  }, [devices, policy]);

  const recentDevices = useMemo(() => {
    return [...devices]
      .sort((a, b) => {
        const first = new Date(a.last_seen || 0).getTime();
        const second = new Date(b.last_seen || 0).getTime();

        return second - first;
      })
      .slice(0, 8);
  }, [devices]);

  const alertSummary = useMemo(() => {
    const result = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
    };

    alerts.forEach((alert) => {
      const severity = String(alert.severity || "").toLowerCase();

      if (severity === "critical") result.critical += 1;
      else if (severity === "high") result.high += 1;
      else if (severity === "medium") result.medium += 1;
      else if (severity === "low") result.low += 1;
    });

    return result;
  }, [alerts]);

  if (loading) {
    return (
      <div className="reports-page">
        <div className="reports-loading">
          <div className="reports-spinner" />
          <h2>Loading Reports & Analytics</h2>
          <p>Collecting security information from Sentinel.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="reports-page">
      <div className="reports-header">
        <div>
          <div className="reports-eyebrow">SENTINEL SECURITY MANAGEMENT</div>

          <h1>Reports & Analytics</h1>

          <p>
            Security posture, device health, compliance and operational
            activity across the company.
          </p>
        </div>

        <div className="reports-header-actions">
          <div className="reports-last-updated">
            <span className="status-dot" />
            <span>
              Updated{" "}
              {lastUpdated ? lastUpdated.toLocaleTimeString() : "just now"}
            </span>
          </div>

          <button
            type="button"
            className="reports-refresh-button"
            onClick={loadReports}
          >
            ↻ Refresh
          </button>
        </div>
      </div>

      {error && (
        <div className="reports-error">
          <div className="reports-error-icon">!</div>

          <div>
            <strong>Unable to load some report data</strong>
            <p>{error}</p>
          </div>

          <button type="button" onClick={loadReports}>
            Retry
          </button>
        </div>
      )}

      <div className="reports-stat-grid">
        <StatCard
          title="Total Devices"
          value={statistics.total}
          subtitle="Registered endpoints"
          icon="▣"
        />

        <StatCard
          title="Secure Devices"
          value={statistics.secure}
          subtitle="Meeting security policy"
          icon="✓"
        />

        <StatCard
          title="At Risk"
          value={statistics.atRisk}
          subtitle="Require attention"
          icon="!"
        />

        <StatCard
          title="Online"
          value={statistics.online}
          subtitle={`${statistics.offline} offline`}
          icon="●"
        />
      </div>

      <div className="reports-main-grid">
        <section className="reports-panel reports-security-panel">
          <div className="reports-panel-heading">
            <div>
              <span className="panel-kicker">SECURITY POSTURE</span>
              <h2>Security Controls</h2>
            </div>

            <span className="panel-badge">
              {statistics.total > 0
                ? Math.round(
                    (statistics.secure / statistics.total) * 100
                  )
                : 0}
              % secure
            </span>
          </div>

          <div className="security-control-list">
            <ProgressBar
              label="Antivirus Enabled"
              value={statistics.antivirusEnabled}
              total={statistics.total}
            />

            <ProgressBar
              label="Firewall Enabled"
              value={statistics.firewallEnabled}
              total={statistics.total}
            />

            <ProgressBar
              label="Backup Enabled"
              value={statistics.backupEnabled}
              total={statistics.total}
            />
          </div>

          <div className="policy-box">
            <div className="policy-box-title">Active Security Policy</div>

            <div className="policy-items">
              <span
                className={
                  policy.antivirus_required
                    ? "policy-item enabled"
                    : "policy-item disabled"
                }
              >
                <span>
                  {policy.antivirus_required ? "✓" : "×"}
                </span>
                Antivirus required
              </span>

              <span
                className={
                  policy.firewall_required
                    ? "policy-item enabled"
                    : "policy-item disabled"
                }
              >
                <span>{policy.firewall_required ? "✓" : "×"}</span>
                Firewall required
              </span>

              <span
                className={
                  policy.backup_required
                    ? "policy-item enabled"
                    : "policy-item disabled"
                }
              >
                <span>{policy.backup_required ? "✓" : "×"}</span>
                Backup required
              </span>
            </div>
          </div>
        </section>

        <section className="reports-panel">
          <div className="reports-panel-heading">
            <div>
              <span className="panel-kicker">ENDPOINT STATUS</span>
              <h2>Device Health</h2>
            </div>
          </div>

          <div className="health-overview">
            <div className="health-circle">
              <div className="health-circle-inner">
                <strong>
                  {statistics.total > 0
                    ? Math.round(
                        (statistics.secure / statistics.total) * 100
                      )
                    : 0}
                  %
                </strong>
                <span>Secure</span>
              </div>
            </div>

            <div className="health-legend">
              <div>
                <span className="legend-dot secure" />
                <span>Secure</span>
                <strong>{statistics.secure}</strong>
              </div>

              <div>
                <span className="legend-dot risk" />
                <span>At Risk</span>
                <strong>{statistics.atRisk}</strong>
              </div>

              <div>
                <span className="legend-dot offline" />
                <span>Offline</span>
                <strong>{statistics.offline}</strong>
              </div>
            </div>
          </div>
        </section>
      </div>

      <div className="reports-main-grid">
        <section className="reports-panel">
          <div className="reports-panel-heading">
            <div>
              <span className="panel-kicker">ORGANIZATION</span>
              <h2>Department Security</h2>
            </div>
          </div>

          {departmentStats.length === 0 ? (
            <div className="reports-empty">
              No department data available.
            </div>
          ) : (
            <div className="department-table-wrapper">
              <table className="department-table">
                <thead>
                  <tr>
                    <th>Department</th>
                    <th>Devices</th>
                    <th>Secure</th>
                    <th>At Risk</th>
                    <th>Online</th>
                  </tr>
                </thead>

                <tbody>
                  {departmentStats.map((department) => (
                    <tr key={department.name}>
                      <td>
                        <strong>{department.name}</strong>
                      </td>

                      <td>{department.total}</td>

                      <td>
                        <span className="table-status secure">
                          {department.secure}
                        </span>
                      </td>

                      <td>
                        <span className="table-status risk">
                          {department.atRisk}
                        </span>
                      </td>

                      <td>
                        <span className="table-status online">
                          {department.online}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        <section className="reports-panel">
          <div className="reports-panel-heading">
            <div>
              <span className="panel-kicker">SECURITY EVENTS</span>
              <h2>Alert Summary</h2>
            </div>

            <span className="panel-badge">{alerts.length} total</span>
          </div>

          <div className="alert-summary-grid">
            <div className="alert-summary-card critical">
              <span>Critical</span>
              <strong>{alertSummary.critical}</strong>
            </div>

            <div className="alert-summary-card high">
              <span>High</span>
              <strong>{alertSummary.high}</strong>
            </div>

            <div className="alert-summary-card medium">
              <span>Medium</span>
              <strong>{alertSummary.medium}</strong>
            </div>

            <div className="alert-summary-card low">
              <span>Low</span>
              <strong>{alertSummary.low}</strong>
            </div>
          </div>

          <div className="alert-total">
            <span>Total security alerts</span>
            <strong>{alerts.length}</strong>
          </div>
        </section>
      </div>

      <section className="reports-panel reports-devices-panel">
        <div className="reports-panel-heading">
          <div>
            <span className="panel-kicker">LIVE ENDPOINTS</span>
            <h2>Recent Device Activity</h2>
          </div>

          <span className="panel-badge">
            {recentDevices.length} shown
          </span>
        </div>

        {recentDevices.length === 0 ? (
          <div className="reports-empty">
            No devices have been registered yet.
          </div>
        ) : (
          <div className="recent-devices-grid">
            {recentDevices.map((device) => {
              const secureStatus = securityState(device, policy);
              const online = onlineState(device);

              return (
                <div
                  className="recent-device-card"
                  key={device.id || device.device_id || device.name}
                >
                  <div className="recent-device-top">
                    <div className="device-avatar">
                      {(device.name || device.device_id || "D")
                        .charAt(0)
                        .toUpperCase()}
                    </div>

                    <div className="device-name-wrapper">
                      <strong>
                        {device.name ||
                          device.device_id ||
                          "Unnamed Device"}
                      </strong>

                      <span>
                        {device.operating_system || "Unknown OS"}
                      </span>
                    </div>

                    <span
                      className={
                        online
                          ? "device-online-badge"
                          : "device-offline-badge"
                      }
                    >
                      {online ? "ONLINE" : "OFFLINE"}
                    </span>
                  </div>

                  <div className="recent-device-details">
                    <div>
                      <span>Employee</span>
                      <strong>{device.employee || "Unknown"}</strong>
                    </div>

                    <div>
                      <span>Department</span>
                      <strong>
                        {device.department || "Unassigned"}
                      </strong>
                    </div>

                    <div>
                      <span>CPU</span>
                      <strong>{device.cpu || "Unknown"}</strong>
                    </div>

                    <div>
                      <span>RAM</span>
                      <strong>
                        {device.ram_gb
                          ? `${device.ram_gb} GB`
                          : "Unknown"}
                      </strong>
                    </div>
                  </div>

                  <div className="recent-device-footer">
                    <span
                      className={
                        secureStatus === "SECURE"
                          ? "security-badge secure"
                          : "security-badge risk"
                      }
                    >
                      {secureStatus}
                    </span>

                    <span className="last-seen">
                      Last seen: {formatDate(device.last_seen)}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </section>

      <section className="reports-panel reports-audit-panel">
        <div className="reports-panel-heading">
          <div>
            <span className="panel-kicker">AUDIT TRAIL</span>
            <h2>Recent Activity</h2>
          </div>

          <span className="panel-badge">
            {auditLogs.length} records
          </span>
        </div>

        {auditLogs.length === 0 ? (
          <div className="reports-empty">
            No audit activity is currently available.
          </div>
        ) : (
          <div className="audit-list">
            {auditLogs.slice(0, 10).map((log, index) => (
              <div
                className="audit-item"
                key={log.id || `${log.created_at}-${index}`}
              >
                <div className="audit-icon">•</div>

                <div className="audit-content">
                  <strong>
                    {log.action ||
                      log.event ||
                      log.activity ||
                      "Security activity"}
                  </strong>

                  <span>
                    {log.message ||
                      log.description ||
                      log.details ||
                      "System activity recorded."}
                  </span>
                </div>

                <time>{formatDate(log.created_at)}</time>
              </div>
            ))}
          </div>
        )}
      </section>

      <div className="reports-footer">
        <span>Sentinel IT Security Management</span>
        <span>Automated security analytics</span>
      </div>

      <style>{`
        .reports-page {
          width: 100%;
          min-height: 100%;
          padding: 28px;
          background: #f5f7fb;
          color: #172033;
        }

        .reports-header {
          display: flex;
          justify-content: space-between;
          gap: 24px;
          align-items: flex-start;
          margin-bottom: 24px;
        }

        .reports-eyebrow,
        .panel-kicker {
          font-size: 11px;
          font-weight: 800;
          letter-spacing: 0.12em;
          color: #6b7280;
        }

        .reports-header h1 {
          margin: 7px 0 7px;
          font-size: 30px;
          line-height: 1.15;
          letter-spacing: -0.03em;
        }

        .reports-header p {
          margin: 0;
          color: #667085;
          max-width: 720px;
          line-height: 1.6;
        }

        .reports-header-actions {
          display: flex;
          align-items: center;
          gap: 12px;
        }

        .reports-last-updated {
          display: flex;
          align-items: center;
          gap: 8px;
          white-space: nowrap;
          font-size: 12px;
          color: #667085;
        }

        .status-dot {
          width: 8px;
          height: 8px;
          border-radius: 50%;
          background: #16a34a;
          display: inline-block;
        }

        .reports-refresh-button {
          border: 1px solid #d8dee9;
          background: #ffffff;
          border-radius: 10px;
          padding: 10px 15px;
          font-weight: 700;
          cursor: pointer;
          color: #172033;
        }

        .reports-refresh-button:hover {
          background: #f8fafc;
        }

        .reports-stat-grid {
          display: grid;
          grid-template-columns: repeat(4, minmax(0, 1fr));
          gap: 16px;
          margin-bottom: 18px;
        }

        .report-stat-card {
          background: #ffffff;
          border: 1px solid #e4e8ef;
          border-radius: 15px;
          padding: 19px;
          display: flex;
          gap: 14px;
          align-items: center;
          min-height: 118px;
          box-shadow: 0 4px 14px rgba(15, 23, 42, 0.035);
        }

        .report-stat-icon {
          width: 45px;
          height: 45px;
          display: grid;
          place-items: center;
          border-radius: 12px;
          background: #eef2ff;
          font-size: 19px;
          font-weight: 800;
        }

        .report-stat-title {
          font-size: 12px;
          color: #667085;
          margin-bottom: 4px;
        }

        .report-stat-value {
          font-size: 27px;
          line-height: 1;
          font-weight: 800;
          letter-spacing: -0.03em;
        }

        .report-stat-subtitle {
          margin-top: 7px;
          font-size: 11px;
          color: #98a2b3;
        }

        .reports-main-grid {
          display: grid;
          grid-template-columns: minmax(0, 1.25fr) minmax(330px, 0.75fr);
          gap: 18px;
          margin-bottom: 18px;
        }

        .reports-panel {
          background: #ffffff;
          border: 1px solid #e4e8ef;
          border-radius: 15px;
          padding: 21px;
          box-shadow: 0 4px 14px rgba(15, 23, 42, 0.035);
        }

        .reports-panel-heading {
          display: flex;
          justify-content: space-between;
          align-items: flex-start;
          gap: 15px;
          margin-bottom: 20px;
        }

        .reports-panel-heading h2 {
          margin: 5px 0 0;
          font-size: 18px;
          letter-spacing: -0.02em;
        }

        .panel-badge {
          border: 1px solid #e1e6ee;
          border-radius: 999px;
          padding: 6px 10px;
          font-size: 11px;
          font-weight: 800;
          color: #475467;
          white-space: nowrap;
        }

        .security-control-list {
          display: grid;
          gap: 19px;
        }

        .report-progress-header {
          display: flex;
          justify-content: space-between;
          gap: 15px;
          font-size: 12px;
          margin-bottom: 7px;
        }

        .report-progress-header span {
          color: #667085;
        }

        .report-progress-track {
          height: 9px;
          border-radius: 999px;
          overflow: hidden;
          background: #edf0f5;
        }

        .report-progress-fill {
          height: 100%;
          border-radius: inherit;
          background: #334155;
          transition: width 0.3s ease;
        }

        .report-progress-percent {
          margin-top: 5px;
          font-size: 10px;
          color: #98a2b3;
        }

        .policy-box {
          margin-top: 22px;
          padding: 15px;
          border-radius: 12px;
          background: #f8fafc;
          border: 1px solid #e8edf3;
        }

        .policy-box-title {
          font-size: 12px;
          font-weight: 800;
          margin-bottom: 12px;
        }

        .policy-items {
          display: flex;
          flex-wrap: wrap;
          gap: 9px;
        }

        .policy-item {
          display: inline-flex;
          align-items: center;
          gap: 6px;
          padding: 6px 9px;
          border-radius: 8px;
          font-size: 11px;
          font-weight: 700;
        }

        .policy-item.enabled {
          background: #ecfdf3;
          color: #027a48;
        }

        .policy-item.disabled {
          background: #fef3f2;
          color: #b42318;
        }

        .health-overview {
          display: flex;
          align-items: center;
          justify-content: center;
          gap: 35px;
          min-height: 210px;
        }

        .health-circle {
          width: 150px;
          height: 150px;
          border-radius: 50%;
          display: grid;
          place-items: center;
          background: conic-gradient(
            #334155
              ${
                statistics.total > 0
                  ? Math.round(
                      (statistics.secure / statistics.total) * 100
                    )
                  : 0
              }%,
            #e8ecf2 0
          );
        }

        .health-circle-inner {
          width: 112px;
          height: 112px;
          border-radius: 50%;
          background: #ffffff;
          display: flex;
          flex-direction: column;
          justify-content: center;
          align-items: center;
        }

        .health-circle-inner strong {
          font-size: 25px;
          letter-spacing: -0.03em;
        }

        .health-circle-inner span {
          margin-top: 3px;
          font-size: 11px;
          color: #667085;
        }

        .health-legend {
          display: grid;
          gap: 14px;
          min-width: 150px;
        }

        .health-legend > div {
          display: grid;
          grid-template-columns: 9px 1fr auto;
          gap: 8px;
          align-items: center;
          font-size: 12px;
        }

        .legend-dot {
          width: 8px;
          height: 8px;
          border-radius: 50%;
          display: block;
        }

        .legend-dot.secure {
          background: #16a34a;
        }

        .legend-dot.risk {
          background: #dc2626;
        }

        .legend-dot.offline {
          background: #94a3b8;
        }

        .department-table-wrapper {
          overflow-x: auto;
        }

        .department-table {
          width: 100%;
          border-collapse: collapse;
          font-size: 12px;
        }

        .department-table th {
          text-align: left;
          padding: 10px 8px;
          border-bottom: 1px solid #e7ebf1;
          color: #667085;
          font-weight: 700;
        }

        .department-table td {
          padding: 13px 8px;
          border-bottom: 1px solid #eef1f5;
        }

        .table-status {
          display: inline-flex;
          min-width: 28px;
          justify-content: center;
          border-radius: 999px;
          padding: 4px 7px;
          font-weight: 800;
        }

        .table-status.secure {
          background: #ecfdf3;
          color: #027a48;
        }

        .table-status.risk {
          background: #fef3f2;
          color: #b42318;
        }

        .table-status.online {
          background: #eff6ff;
          color: #175cd3;
        }

        .alert-summary-grid {
          display: grid;
          grid-template-columns: repeat(2, 1fr);
          gap: 10px;
        }

        .alert-summary-card {
          padding: 15px;
          border-radius: 11px;
          border: 1px solid #e8ebf0;
          display: flex;
          justify-content: space-between;
          align-items: center;
        }

        .alert-summary-card span {
          font-size: 11px;
          font-weight: 700;
        }

        .alert-summary-card strong {
          font-size: 20px;
        }

        .alert-summary-card.critical {
          background: #fff5f5;
        }

        .alert-summary-card.high {
          background: #fff7ed;
        }

        .alert-summary-card.medium {
          background: #fffbeb;
        }

        .alert-summary-card.low {
          background: #f8fafc;
        }

        .alert-total {
          margin-top: 14px;
          padding-top: 14px;
          border-top: 1px solid #e8ebf0;
          display: flex;
          justify-content: space-between;
          font-size: 12px;
          color: #667085;
        }

        .alert-total strong {
          color: #172033;
        }

        .reports-devices-panel {
          margin-bottom: 18px;
        }

        .recent-devices-grid {
          display: grid;
          grid-template-columns: repeat(2, minmax(0, 1fr));
          gap: 13px;
        }

        .recent-device-card {
          border: 1px solid #e7ebf1;
          border-radius: 13px;
          padding: 15px;
          background: #fcfdff;
        }

        .recent-device-top {
          display: flex;
          align-items: center;
          gap: 10px;
        }

        .device-avatar {
          width: 39px;
          height: 39px;
          border-radius: 10px;
          background: #eef2ff;
          display: grid;
          place-items: center;
          font-weight: 800;
        }

        .device-name-wrapper {
          flex: 1;
          min-width: 0;
          display: flex;
          flex-direction: column;
          gap: 3px;
        }

        .device-name-wrapper strong {
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
          font-size: 13px;
        }

        .device-name-wrapper span {
          font-size: 10px;
          color: #667085;
        }

        .device-online-badge,
        .device-offline-badge,
        .security-badge {
          font-size: 9px;
          font-weight: 900;
          border-radius: 999px;
          padding: 5px 7px;
          white-space: nowrap;
        }

        .device-online-badge {
          background: #ecfdf3;
          color: #027a48;
        }

        .device-offline-badge {
          background: #f2f4f7;
          color: #667085;
        }

        .recent-device-details {
          display: grid;
          grid-template-columns: repeat(2, 1fr);
          gap: 10px;
          margin-top: 15px;
          padding-top: 13px;
          border-top: 1px solid #edf0f4;
        }

        .recent-device-details div {
          display: flex;
          flex-direction: column;
          gap: 3px;
          min-width: 0;
        }

        .recent-device-details span {
          font-size: 9px;
          color: #98a2b3;
          text-transform: uppercase;
          letter-spacing: 0.04em;
        }

        .recent-device-details strong {
          font-size: 11px;
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
        }

        .recent-device-footer {
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 10px;
          margin-top: 13px;
        }

        .security-badge.secure {
          background: #ecfdf3;
          color: #027a48;
        }

        .security-badge.risk {
          background: #fef3f2;
          color: #b42318;
        }

        .last-seen {
          color: #98a2b3;
          font-size: 9px;
          text-align: right;
        }

        .audit-list {
          display: grid;
        }

        .audit-item {
          display: flex;
          align-items: flex-start;
          gap: 12px;
          padding: 13px 0;
          border-bottom: 1px solid #edf0f4;
        }

        .audit-item:last-child {
          border-bottom: 0;
        }

        .audit-icon {
          width: 27px;
          height: 27px;
          border-radius: 50%;
          background: #eef2ff;
          display: grid;
          place-items: center;
          font-weight: 900;
        }

        .audit-content {
          flex: 1;
          min-width: 0;
          display: flex;
          flex-direction: column;
          gap: 4px;
        }

        .audit-content strong {
          font-size: 12px;
        }

        .audit-content span {
          font-size: 11px;
          color: #667085;
        }

        .audit-item time {
          font-size: 10px;
          color: #98a2b3;
          white-space: nowrap;
        }

        .reports-empty {
          padding: 30px 10px;
          text-align: center;
          color: #98a2b3;
          font-size: 12px;
        }

        .reports-error {
          display: flex;
          align-items: center;
          gap: 12px;
          margin-bottom: 18px;
          padding: 14px 16px;
          border: 1px solid #f3c7c3;
          border-radius: 12px;
          background: #fff8f7;
          color: #8a1c13;
        }

        .reports-error-icon {
          width: 28px;
          height: 28px;
          border-radius: 50%;
          display: grid;
          place-items: center;
          background: #fee4e2;
          font-weight: 900;
        }

        .reports-error strong {
          font-size: 12px;
        }

        .reports-error p {
          margin: 3px 0 0;
          font-size: 11px;
        }

        .reports-error button {
          margin-left: auto;
          border: 1px solid #efb8b2;
          border-radius: 8px;
          background: #ffffff;
          padding: 7px 10px;
          font-size: 11px;
          font-weight: 800;
          cursor: pointer;
        }

        .reports-loading {
          min-height: 60vh;
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          text-align: center;
        }

        .reports-loading h2 {
          margin: 15px 0 5px;
          font-size: 18px;
        }

        .reports-loading p {
          margin: 0;
          color: #667085;
          font-size: 12px;
        }

        .reports-spinner {
          width: 34px;
          height: 34px;
          border: 3px solid #e5e7eb;
          border-top-color: #334155;
          border-radius: 50%;
          animation: reports-spin 0.8s linear infinite;
        }

        @keyframes reports-spin {
          to {
            transform: rotate(360deg);
          }
        }

        .reports-footer {
          display: flex;
          justify-content: space-between;
          margin-top: 18px;
          padding: 5px 2px 20px;
          color: #98a2b3;
          font-size: 10px;
        }

        @media (max-width: 1100px) {
          .reports-stat-grid {
            grid-template-columns: repeat(2, 1fr);
          }

          .reports-main-grid {
            grid-template-columns: 1fr;
          }
        }

        @media (max-width: 700px) {
          .reports-page {
            padding: 17px;
          }

          .reports-header {
            flex-direction: column;
          }

          .reports-header-actions {
            width: 100%;
            justify-content: space-between;
          }

          .reports-stat-grid {
            grid-template-columns: 1fr;
          }

          .recent-devices-grid {
            grid-template-columns: 1fr;
          }

          .health-overview {
            flex-direction: column;
            gap: 20px;
          }

          .reports-footer {
            flex-direction: column;
            gap: 5px;
          }
        }
      `}</style>
    </div>
  );
}