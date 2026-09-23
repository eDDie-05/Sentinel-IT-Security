import { useEffect, useMemo, useState } from "react";

const API = "http://localhost:5000/api";

function getToken() {
  return localStorage.getItem("token");
}

async function apiFetch(path) {
  const token = getToken();

  const response = await fetch(`${API}${path}`, {
    headers: {
      "Content-Type": "application/json",
      ...(token
        ? {
            Authorization: `Bearer ${token}`,
          }
        : {}),
    },
  });

  let data = {};

  try {
    data = await response.json();
  } catch {
    data = {};
  }

  if (!response.ok) {
    throw new Error(
      data.message ||
        data.error ||
        `Request failed: ${response.status}`
    );
  }

  return data;
}

function normalize(value) {
  return String(value || "")
    .trim()
    .toUpperCase();
}

function formatDate(value) {
  if (!value) return "Unknown";

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return "Unknown";
  }

  return date.toLocaleString();
}

function relativeTime(value) {
  if (!value) return "Unknown";

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return "Unknown";
  }

  const seconds = Math.floor(
    (Date.now() - date.getTime()) / 1000
  );

  if (seconds < 10) return "Just now";
  if (seconds < 60) return `${seconds}s ago`;

  const minutes = Math.floor(seconds / 60);

  if (minutes < 60) {
    return `${minutes}m ago`;
  }

  const hours = Math.floor(minutes / 60);

  if (hours < 24) {
    return `${hours}h ago`;
  }

  const days = Math.floor(hours / 24);

  return `${days}d ago`;
}

function deviceName(device) {
  return (
    device.name ||
    device.hostname ||
    device.device_id ||
    "Unknown Device"
  );
}

function securityStatus(device) {
  return normalize(
    device.security_status ||
      device.securityStatus
  );
}

function connectionStatus(device) {
  return device.online === true
    ? "ONLINE"
    : "OFFLINE";
}

function controlStatus(device, type) {
  const value =
    device[`${type}_status`];

  if (value) {
    return normalize(value);
  }

  const booleanValue =
    device[type];

  if (booleanValue === true) {
    return "ENABLED";
  }

  if (booleanValue === false) {
    return "DISABLED";
  }

  return "UNKNOWN";
}

export default function Dashboard() {
  const [devices, setDevices] = useState([]);
  const [alerts, setAlerts] = useState([]);

  const [loading, setLoading] =
    useState(true);

  const [refreshing, setRefreshing] =
    useState(false);

  const [error, setError] = useState("");

  async function loadDashboard(
    initial = false
  ) {
    try {
      if (initial) {
        setLoading(true);
      } else {
        setRefreshing(true);
      }

      setError("");

      const [devicesData, alertsData] =
        await Promise.all([
          apiFetch("/devices"),
          apiFetch("/security-alerts"),
        ]);

      const deviceRows =
        Array.isArray(devicesData)
          ? devicesData
          : Array.isArray(
              devicesData.devices
            )
          ? devicesData.devices
          : [];

      const alertRows =
        Array.isArray(alertsData)
          ? alertsData
          : Array.isArray(
              alertsData.alerts
            )
          ? alertsData.alerts
          : [];

      setDevices(deviceRows);
      setAlerts(alertRows);
    } catch (err) {
      console.error(
        "Dashboard loading error:",
        err
      );

      setError(
        err.message ||
          "Failed to load dashboard data."
      );
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }

  useEffect(() => {
    loadDashboard(true);

    const interval = setInterval(() => {
      loadDashboard(false);
    }, 15000);

    return () =>
      clearInterval(interval);
  }, []);

  const statistics = useMemo(() => {
    let online = 0;
    let offline = 0;

    let secure = 0;
    let atRisk = 0;
    let unknown = 0;

    for (const device of devices) {
      if (device.online === true) {
        online++;
      } else {
        offline++;
      }

      const status =
        securityStatus(device);

      if (status === "SECURE") {
        secure++;
      } else if (
        status === "AT RISK"
      ) {
        atRisk++;
      } else {
        unknown++;
      }
    }

    const activeAlerts =
      alerts.filter((alert) => {
        const status = normalize(
          alert.status
        );

        return (
          status === "OPEN" ||
          status === "ACKNOWLEDGED"
        );
      });

    const openAlerts =
      alerts.filter(
        (alert) =>
          normalize(alert.status) ===
          "OPEN"
      );

    const criticalAlerts =
      activeAlerts.filter((alert) => {
        const severity =
          normalize(alert.severity);

        return (
          severity === "CRITICAL" ||
          severity === "HIGH"
        );
      });

    return {
      total: devices.length,
      online,
      offline,
      secure,
      atRisk,
      unknown,
      activeAlerts:
        activeAlerts.length,
      openAlerts: openAlerts.length,
      criticalAlerts:
        criticalAlerts.length,
    };
  }, [devices, alerts]);

  const securityBreakdown = useMemo(() => {
    let antivirusEnabled = 0;
    let antivirusDisabled = 0;
    let antivirusUnknown = 0;

    let firewallEnabled = 0;
    let firewallDisabled = 0;
    let firewallUnknown = 0;

    let backupEnabled = 0;
    let backupDisabled = 0;
    let backupUnknown = 0;

    for (const device of devices) {
      const antivirus =
        controlStatus(
          device,
          "antivirus"
        );

      const firewall =
        controlStatus(
          device,
          "firewall"
        );

      const backup =
        controlStatus(
          device,
          "backup"
        );

      if (antivirus === "ENABLED") {
        antivirusEnabled++;
      } else if (
        antivirus === "DISABLED"
      ) {
        antivirusDisabled++;
      } else {
        antivirusUnknown++;
      }

      if (firewall === "ENABLED") {
        firewallEnabled++;
      } else if (
        firewall === "DISABLED"
      ) {
        firewallDisabled++;
      } else {
        firewallUnknown++;
      }

      if (backup === "ENABLED") {
        backupEnabled++;
      } else if (
        backup === "DISABLED"
      ) {
        backupDisabled++;
      } else {
        backupUnknown++;
      }
    }

    return {
      antivirusEnabled,
      antivirusDisabled,
      antivirusUnknown,
      firewallEnabled,
      firewallDisabled,
      firewallUnknown,
      backupEnabled,
      backupDisabled,
      backupUnknown,
    };
  }, [devices]);

  const recentAlerts = useMemo(() => {
    return [...alerts]
      .sort((a, b) => {
        const aTime =
          new Date(
            a.last_detected ||
              a.updated_at ||
              a.created_at ||
              0
          ).getTime();

        const bTime =
          new Date(
            b.last_detected ||
              b.updated_at ||
              b.created_at ||
              0
          ).getTime();

        return bTime - aTime;
      })
      .slice(0, 6);
  }, [alerts]);

  const riskDevices = useMemo(() => {
    return devices
      .filter(
        (device) =>
          securityStatus(device) ===
          "AT RISK"
      )
      .slice(0, 6);
  }, [devices]);

  if (loading) {
    return (
      <div className="sd-page">
        <style>{styles}</style>

        <div className="sd-loading">
          <div className="sd-spinner" />

          <div>
            <strong>
              Loading Sentinel Dashboard
            </strong>

            <span>
              Collecting live device and
              security information...
            </span>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="sd-page">
      <style>{styles}</style>

      <div className="sd-header">
        <div>
          <div className="sd-eyebrow">
            SENTINEL IT SECURITY PLATFORM
          </div>

          <h1>Security Overview</h1>

          <p>
            Real-time visibility into company
            devices, security controls and
            active incidents.
          </p>
        </div>

        <div className="sd-header-actions">
          <div className="sd-live-indicator">
            <span />
            Live monitoring
          </div>

          <button
            className="sd-refresh"
            onClick={() =>
              loadDashboard(false)
            }
            disabled={refreshing}
          >
            <span
              className={
                refreshing
                  ? "sd-refresh-icon sd-spin"
                  : "sd-refresh-icon"
              }
            >
              ↻
            </span>

            {refreshing
              ? "Refreshing..."
              : "Refresh"}
          </button>
        </div>
      </div>

      {error && (
        <div className="sd-error">
          <div>
            <strong>
              Dashboard connection problem
            </strong>

            <span>{error}</span>
          </div>

          <button
            onClick={() => setError("")}
          >
            ×
          </button>
        </div>
      )}

      <div className="sd-stat-grid">
        <StatCard
          label="Total Devices"
          value={statistics.total}
          icon="▣"
          className="blue"
        />

        <StatCard
          label="Online"
          value={statistics.online}
          icon="●"
          className="green"
        />

        <StatCard
          label="Offline"
          value={statistics.offline}
          icon="○"
          className="gray"
        />

        <StatCard
          label="Secure"
          value={statistics.secure}
          icon="✓"
          className="green"
        />

        <StatCard
          label="At Risk"
          value={statistics.atRisk}
          icon="!"
          className="red"
        />

        <StatCard
          label="Critical Alerts"
          value={statistics.criticalAlerts}
          icon="!"
          className="orange"
        />
      </div>

      <div className="sd-main-grid">
        <section className="sd-panel">
          <div className="sd-panel-header">
            <div>
              <h2>
                Security Controls
              </h2>

              <p>
                Current protection state across
                monitored devices.
              </p>
            </div>

            <div className="sd-device-count">
              {devices.length} devices
            </div>
          </div>

          <div className="sd-control-list">
            <SecurityControl
              name="Antivirus"
              enabled={
                securityBreakdown
                  .antivirusEnabled
              }
              disabled={
                securityBreakdown
                  .antivirusDisabled
              }
              unknown={
                securityBreakdown
                  .antivirusUnknown
              }
            />

            <SecurityControl
              name="Firewall"
              enabled={
                securityBreakdown
                  .firewallEnabled
              }
              disabled={
                securityBreakdown
                  .firewallDisabled
              }
              unknown={
                securityBreakdown
                  .firewallUnknown
              }
            />

            <SecurityControl
              name="Backup"
              enabled={
                securityBreakdown
                  .backupEnabled
              }
              disabled={
                securityBreakdown
                  .backupDisabled
              }
              unknown={
                securityBreakdown
                  .backupUnknown
              }
            />
          </div>
        </section>

        <section className="sd-panel">
          <div className="sd-panel-header">
            <div>
              <h2>
                Alert Summary
              </h2>

              <p>
                Current security incident
                status.
              </p>
            </div>
          </div>

          <div className="sd-alert-summary">
            <SummaryRow
              label="Open alerts"
              value={statistics.openAlerts}
              className="danger"
            />

            <SummaryRow
              label="Active alerts"
              value={statistics.activeAlerts}
              className="warning"
            />

            <SummaryRow
              label="Critical alerts"
              value={
                statistics.criticalAlerts
              }
              className="critical"
            />

            <SummaryRow
              label="Resolved alerts"
              value={
                alerts.filter(
                  (alert) =>
                    normalize(
                      alert.status
                    ) === "RESOLVED"
                ).length
              }
              className="success"
            />
          </div>
        </section>
      </div>

      <div className="sd-content-grid">
        <section className="sd-panel sd-wide">
          <div className="sd-panel-header">
            <div>
              <h2>
                Recent Security Events
              </h2>

              <p>
                Latest events detected by
                Sentinel.
              </p>
            </div>

            <span className="sd-auto">
              Auto-refresh 15s
            </span>
          </div>

          {recentAlerts.length === 0 ? (
            <EmptyState
              title="No security events"
              text="Sentinel has not detected any security alerts."
            />
          ) : (
            <div className="sd-event-list">
              {recentAlerts.map(
                (alert) => {
                  const severity =
                    normalize(
                      alert.severity
                    );

                  const status =
                    normalize(
                      alert.status
                    );

                  return (
                    <div
                      className="sd-event"
                      key={alert.id}
                    >
                      <div
                        className={`sd-event-icon ${severity.toLowerCase()}`}
                      >
                        !
                      </div>

                      <div className="sd-event-content">
                        <div className="sd-event-top">
                          <strong>
                            {String(
                              alert.alert_type ||
                                "Security Alert"
                            )
                              .replaceAll(
                                "_",
                                " "
                              )
                              .replace(
                                /\b\w/g,
                                (letter) =>
                                  letter.toUpperCase()
                              )}
                          </strong>

                          <span
                            className={`sd-badge ${severity === "CRITICAL" || severity === "HIGH"
                                ? "critical"
                                : "warning"
                            }`}
                          >
                            {severity ||
                              "WARNING"}
                          </span>
                        </div>

                        <p>
                          {alert.message ||
                            alert.details ||
                            "Security condition requires attention."}
                        </p>

                        <div className="sd-event-meta">
                          <span>
                            {alert.device_name ||
                              alert.device_hostname ||
                              alert.hostname ||
                              alert.device_id ||
                              "Unknown device"}
                          </span>

                          <span>
                            {relativeTime(
                              alert.last_detected ||
                                alert.updated_at ||
                                alert.created_at
                            )}
                          </span>

                          <span
                            className={`sd-status ${status.toLowerCase()}`}
                          >
                            {status ||
                              "UNKNOWN"}
                          </span>
                        </div>
                      </div>
                    </div>
                  );
                }
              )}
            </div>
          )}
        </section>

        <section className="sd-panel">
          <div className="sd-panel-header">
            <div>
              <h2>
                Devices At Risk
              </h2>

              <p>
                Devices requiring attention.
              </p>
            </div>
          </div>

          {riskDevices.length === 0 ? (
            <EmptyState
              title="No devices at risk"
              text="All currently evaluated devices are not reporting an at-risk state."
            />
          ) : (
            <div className="sd-risk-list">
              {riskDevices.map(
                (device) => (
                  <div
                    className="sd-risk-device"
                    key={
                      device.id ||
                      device.device_id ||
                      device.name
                    }
                  >
                    <div className="sd-risk-icon">
                      !
                    </div>

                    <div className="sd-risk-info">
                      <strong>
                        {deviceName(
                          device
                        )}
                      </strong>

                      <span>
                        {device.operating_system ||
                          device.os ||
                          "Operating system unknown"}
                      </span>
                    </div>

                    <span className="sd-badge critical">
                      AT RISK
                    </span>
                  </div>
                )
              )}
            </div>
          )}
        </section>
      </div>

      <section className="sd-panel sd-devices-panel">
        <div className="sd-panel-header">
          <div>
            <h2>
              Device Monitoring
            </h2>

            <p>
              Live status of monitored company
              computers.
            </p>
          </div>

          <div className="sd-monitor-count">
            <span />
            Monitoring {devices.length}
          </div>
        </div>

        {devices.length === 0 ? (
          <EmptyState
            title="No devices registered"
            text="Install and start the Sentinel agent on a company computer to register it."
          />
        ) : (
          <div className="sd-device-grid">
            {devices.map((device) => {
              const security =
                securityStatus(
                  device
                );

              const online =
                connectionStatus(
                  device
                );

              return (
                <div
                  className="sd-device-card"
                  key={
                    device.id ||
                    device.device_id ||
                    device.name
                  }
                >
                  <div className="sd-device-card-top">
                    <div className="sd-computer-icon">
                      ▣
                    </div>

                    <div>
                      <strong>
                        {deviceName(
                          device
                        )}
                      </strong>

                      <span>
                        {device.employee ||
                          device.username ||
                          "Unassigned"}
                      </span>
                    </div>
                  </div>

                  <div className="sd-device-status-row">
                    <span
                      className={
                        online === "ONLINE"
                          ? "sd-online"
                          : "sd-offline"
                      }
                    >
                      <i />
                      {online}
                    </span>

                    <span
                      className={
                        security ===
                        "SECURE"
                          ? "sd-secure"
                          : security ===
                            "AT RISK"
                          ? "sd-at-risk"
                          : "sd-unknown"
                      }
                    >
                      {security ||
                        "UNKNOWN"}
                    </span>
                  </div>

                  <div className="sd-mini-controls">
                    <MiniControl
                      label="AV"
                      status={controlStatus(
                        device,
                        "antivirus"
                      )}
                    />

                    <MiniControl
                      label="FW"
                      status={controlStatus(
                        device,
                        "firewall"
                      )}
                    />

                    <MiniControl
                      label="Backup"
                      status={controlStatus(
                        device,
                        "backup"
                      )}
                    />
                  </div>

                  <div className="sd-device-footer">
                    <span>
                      {device.operating_system ||
                        device.os ||
                        "OS unknown"}
                    </span>

                    <span>
                      {device.last_seen
                        ? `Seen ${relativeTime(
                            device.last_seen
                          )}`
                        : "No heartbeat"}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </section>

      <div className="sd-footer">
        <span>
          Sentinel monitoring active
        </span>

        <span>
          Last dashboard update:{" "}
          {new Date().toLocaleTimeString()}
        </span>
      </div>
    </div>
  );
}

function StatCard({
  label,
  value,
  icon,
  className,
}) {
  return (
    <div className="sd-stat-card">
      <div
        className={`sd-stat-icon ${className}`}
      >
        {icon}
      </div>

      <div>
        <span>{label}</span>
        <strong>{value}</strong>
      </div>
    </div>
  );
}

function SecurityControl({
  name,
  enabled,
  disabled,
  unknown,
}) {
  const total =
    enabled + disabled + unknown;

  const enabledPercent =
    total > 0
      ? (enabled / total) * 100
      : 0;

  return (
    <div className="sd-control">
      <div className="sd-control-header">
        <strong>{name}</strong>

        <span>
          {enabled} enabled
        </span>
      </div>

      <div className="sd-progress">
        <div
          className="sd-progress-fill"
          style={{
            width: `${enabledPercent}%`,
          }}
        />
      </div>

      <div className="sd-control-legend">
        <span className="enabled">
          <i />
          Enabled {enabled}
        </span>

        <span className="disabled">
          <i />
          Disabled {disabled}
        </span>

        <span className="unknown">
          <i />
          Unknown {unknown}
        </span>
      </div>
    </div>
  );
}

function SummaryRow({
  label,
  value,
  className,
}) {
  return (
    <div className="sd-summary-row">
      <div>
        <span
          className={`sd-summary-dot ${className}`}
        />
        <strong>{label}</strong>
      </div>

      <span className="sd-summary-value">
        {value}
      </span>
    </div>
  );
}

function MiniControl({
  label,
  status,
}) {
  const normalized =
    normalize(status);

  let className = "unknown";

  if (normalized === "ENABLED") {
    className = "enabled";
  } else if (
    normalized === "DISABLED"
  ) {
    className = "disabled";
  }

  return (
    <div className="sd-mini-control">
      <span>{label}</span>

      <strong
        className={className}
      >
        {normalized === "ENABLED"
          ? "ON"
          : normalized === "DISABLED"
          ? "OFF"
          : "?"}
      </strong>
    </div>
  );
}

function EmptyState({
  title,
  text,
}) {
  return (
    <div className="sd-empty">
      <div className="sd-empty-icon">
        ✓
      </div>

      <h3>{title}</h3>

      <p>{text}</p>
    </div>
  );
}

const styles = `
.sd-page {
  width: 100%;
  min-height: 100%;
  padding: 28px;
  background: #f6f8fb;
  color: #172033;
  font-family:
    Inter,
    ui-sans-serif,
    system-ui,
    -apple-system,
    BlinkMacSystemFont,
    "Segoe UI",
    sans-serif;
}

.sd-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 20px;
  margin-bottom: 24px;
}

.sd-eyebrow {
  color: #64748b;
  font-size: 10px;
  font-weight: 900;
  letter-spacing: .14em;
  margin-bottom: 7px;
}

.sd-header h1 {
  margin: 0;
  font-size: 30px;
  line-height: 1.15;
  letter-spacing: -.035em;
}

.sd-header p {
  margin: 8px 0 0;
  color: #64748b;
  font-size: 13px;
}

.sd-header-actions {
  display: flex;
  align-items: center;
  gap: 12px;
}

.sd-live-indicator,
.sd-monitor-count {
  display: flex;
  align-items: center;
  gap: 8px;
  color: #4b5a70;
  font-size: 11px;
  font-weight: 800;
}

.sd-live-indicator span,
.sd-monitor-count span {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: #16a34a;
  box-shadow: 0 0 0 4px #dcfce7;
}

.sd-refresh {
  display: flex;
  align-items: center;
  gap: 8px;
  border: 1px solid #dbe2ea;
  background: #fff;
  color: #334155;
  padding: 9px 13px;
  border-radius: 9px;
  font-size: 11px;
  font-weight: 800;
  cursor: pointer;
}

.sd-refresh:hover {
  background: #f8fafc;
}

.sd-refresh:disabled {
  opacity: .6;
  cursor: default;
}

.sd-refresh-icon {
  font-size: 18px;
  line-height: 1;
}

.sd-spin {
  animation: sd-spin 0.8s linear infinite;
}

@keyframes sd-spin {
  to {
    transform: rotate(360deg);
  }
}

.sd-error {
  display: flex;
  justify-content: space-between;
  gap: 20px;
  padding: 13px 16px;
  margin-bottom: 18px;
  border: 1px solid #fecaca;
  background: #fff5f5;
  border-radius: 11px;
  color: #991b1b;
}

.sd-error div {
  display: flex;
  flex-direction: column;
  gap: 3px;
}

.sd-error strong {
  font-size: 12px;
}

.sd-error span {
  font-size: 11px;
}

.sd-error button {
  border: 0;
  background: transparent;
  color: #991b1b;
  font-size: 19px;
  cursor: pointer;
}

.sd-stat-grid {
  display: grid;
  grid-template-columns: repeat(6, minmax(0, 1fr));
  gap: 13px;
  margin-bottom: 18px;
}

.sd-stat-card {
  display: flex;
  align-items: center;
  gap: 12px;
  min-height: 96px;
  padding: 15px;
  border: 1px solid #e5eaf0;
  background: #fff;
  border-radius: 13px;
  box-shadow: 0 2px 5px rgba(15,23,42,.025);
}

.sd-stat-icon {
  width: 38px;
  height: 38px;
  flex-shrink: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: 10px;
  font-size: 16px;
  font-weight: 900;
}

.sd-stat-icon.blue {
  background: #eef4ff;
  color: #315ea8;
}

.sd-stat-icon.green {
  background: #ecfdf3;
  color: #16834b;
}

.sd-stat-icon.gray {
  background: #f1f5f9;
  color: #64748b;
}

.sd-stat-icon.red {
  background: #fff0f0;
  color: #c62828;
}

.sd-stat-icon.orange {
  background: #fff3e8;
  color: #c76516;
}

.sd-stat-card > div:last-child {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.sd-stat-card span {
  color: #718096;
  font-size: 10px;
  font-weight: 800;
  white-space: nowrap;
}

.sd-stat-card strong {
  font-size: 25px;
  line-height: 1;
}

.sd-main-grid {
  display: grid;
  grid-template-columns: 1.5fr 1fr;
  gap: 16px;
  margin-bottom: 16px;
}

.sd-content-grid {
  display: grid;
  grid-template-columns: 1.6fr 1fr;
  gap: 16px;
  margin-bottom: 16px;
}

.sd-panel {
  background: #fff;
  border: 1px solid #e5eaf0;
  border-radius: 14px;
  overflow: hidden;
  box-shadow: 0 2px 6px rgba(15,23,42,.025);
}

.sd-panel-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 16px;
  padding: 17px 19px;
  border-bottom: 1px solid #edf0f4;
}

.sd-panel-header h2 {
  margin: 0;
  font-size: 15px;
}

.sd-panel-header p {
  margin: 4px 0 0;
  color: #8490a2;
  font-size: 10px;
}

.sd-device-count,
.sd-auto {
  padding: 5px 8px;
  border-radius: 7px;
  background: #f1f5f9;
  color: #64748b;
  font-size: 9px;
  font-weight: 800;
  white-space: nowrap;
}

.sd-control-list {
  padding: 5px 19px 15px;
}

.sd-control {
  padding: 14px 0;
  border-bottom: 1px solid #eef1f5;
}

.sd-control:last-child {
  border-bottom: 0;
}

.sd-control-header {
  display: flex;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 8px;
}

.sd-control-header strong {
  font-size: 12px;
}

.sd-control-header span {
  color: #64748b;
  font-size: 10px;
  font-weight: 700;
}

.sd-progress {
  width: 100%;
  height: 6px;
  overflow: hidden;
  border-radius: 99px;
  background: #edf1f5;
}

.sd-progress-fill {
  height: 100%;
  border-radius: inherit;
  background: #22a05a;
  transition: width .4s ease;
}

.sd-control-legend {
  display: flex;
  gap: 15px;
  margin-top: 8px;
}

.sd-control-legend span {
  display: flex;
  align-items: center;
  gap: 5px;
  color: #8995a7;
  font-size: 9px;
  font-weight: 700;
}

.sd-control-legend i {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  display: inline-block;
}

.sd-control-legend .enabled i {
  background: #16a34a;
}

.sd-control-legend .disabled i {
  background: #dc2626;
}

.sd-control-legend .unknown i {
  background: #94a3b8;
}

.sd-alert-summary {
  padding: 8px 19px 14px;
}

.sd-summary-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 13px 0;
  border-bottom: 1px solid #eef1f5;
}

.sd-summary-row:last-child {
  border-bottom: 0;
}

.sd-summary-row > div {
  display: flex;
  align-items: center;
  gap: 9px;
}

.sd-summary-row strong {
  color: #475569;
  font-size: 11px;
}

.sd-summary-dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
}

.sd-summary-dot.danger {
  background: #dc2626;
}

.sd-summary-dot.warning {
  background: #f59e0b;
}

.sd-summary-dot.critical {
  background: #b91c1c;
}

.sd-summary-dot.success {
  background: #16a34a;
}

.sd-summary-value {
  color: #172033;
  font-size: 15px;
  font-weight: 900;
}

.sd-event-list {
  padding: 4px 19px;
}

.sd-event {
  display: flex;
  gap: 11px;
  padding: 13px 0;
  border-bottom: 1px solid #eef1f5;
}

.sd-event:last-child {
  border-bottom: 0;
}

.sd-event-icon {
  width: 31px;
  height: 31px;
  flex-shrink: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: 9px;
  background: #fff8e8;
  color: #b7791f;
  font-size: 13px;
  font-weight: 900;
}

.sd-event-icon.critical {
  background: #fff0f0;
  color: #c62828;
}

.sd-event-content {
  flex: 1;
  min-width: 0;
}

.sd-event-top {
  display: flex;
  align-items: center;
  gap: 8px;
}

.sd-event-top strong {
  color: #344054;
  font-size: 11px;
}

.sd-event p {
  margin: 4px 0;
  color: #667085;
  font-size: 10px;
  line-height: 1.45;
}

.sd-event-meta {
  display: flex;
  gap: 11px;
  flex-wrap: wrap;
  color: #98a2b3;
  font-size: 9px;
  font-weight: 700;
}

.sd-badge {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  padding: 4px 7px;
  border-radius: 999px;
  font-size: 8px;
  font-weight: 900;
}

.sd-badge.critical {
  color: #b42318;
  background: #fff0f0;
}

.sd-badge.warning {
  color: #946200;
  background: #fff8df;
}

.sd-status {
  padding: 2px 5px;
  border-radius: 5px;
  background: #f1f5f9;
}

.sd-status.open {
  color: #b42318;
  background: #fff0f0;
}

.sd-status.acknowledged {
  color: #6941a5;
  background: #f3edff;
}

.sd-status.resolved {
  color: #147a46;
  background: #ecfdf3;
}

.sd-risk-list {
  padding: 4px 17px;
}

.sd-risk-device {
  display: flex;
  align-items: center;
  gap: 9px;
  padding: 12px 2px;
  border-bottom: 1px solid #eef1f5;
}

.sd-risk-device:last-child {
  border-bottom: 0;
}

.sd-risk-icon {
  width: 30px;
  height: 30px;
  flex-shrink: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: 8px;
  background: #fff0f0;
  color: #c62828;
  font-weight: 900;
}

.sd-risk-info {
  flex: 1;
  min-width: 0;
  display: flex;
  flex-direction: column;
  gap: 3px;
}

.sd-risk-info strong {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  color: #344054;
  font-size: 11px;
}

.sd-risk-info span {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  color: #98a2b3;
  font-size: 9px;
}

.sd-devices-panel {
  margin-bottom: 14px;
}

.sd-device-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 12px;
  padding: 17px;
}

.sd-device-card {
  padding: 14px;
  border: 1px solid #e7ebf0;
  border-radius: 12px;
  background: #fbfcfe;
}

.sd-device-card-top {
  display: flex;
  align-items: center;
  gap: 9px;
  padding-bottom: 12px;
}

.sd-computer-icon {
  width: 34px;
  height: 34px;
  flex-shrink: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: 9px;
  background: #eef3f8;
  color: #46566e;
  font-size: 15px;
  font-weight: 900;
}

.sd-device-card-top > div:last-child {
  min-width: 0;
  display: flex;
  flex-direction: column;
  gap: 3px;
}

.sd-device-card-top strong {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  color: #344054;
  font-size: 11px;
}

.sd-device-card-top span {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  color: #98a2b3;
  font-size: 9px;
}

.sd-device-status-row {
  display: flex;
  justify-content: space-between;
  gap: 8px;
  padding: 9px 0;
  border-top: 1px solid #edf0f4;
  border-bottom: 1px solid #edf0f4;
}

.sd-online,
.sd-offline,
.sd-secure,
.sd-at-risk,
.sd-unknown {
  font-size: 9px;
  font-weight: 900;
}

.sd-online {
  color: #16834b;
}

.sd-offline {
  color: #64748b;
}

.sd-online i,
.sd-offline i {
  display: inline-block;
  width: 6px;
  height: 6px;
  margin-right: 5px;
  border-radius: 50%;
  background: currentColor;
}

.sd-secure {
  color: #16834b;
}

.sd-at-risk {
  color: #c62828;
}

.sd-unknown {
  color: #64748b;
}

.sd-mini-controls {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 6px;
  padding: 11px 0;
}

.sd-mini-control {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 3px;
  padding: 7px 3px;
  border-radius: 7px;
  background: #f1f5f9;
}

.sd-mini-control span {
  color: #8a95a6;
  font-size: 8px;
  font-weight: 800;
}

.sd-mini-control strong {
  font-size: 9px;
  font-weight: 900;
}

.sd-mini-control strong.enabled {
  color: #16834b;
}

.sd-mini-control strong.disabled {
  color: #c62828;
}

.sd-mini-control strong.unknown {
  color: #64748b;
}

.sd-device-footer {
  display: flex;
  justify-content: space-between;
  gap: 8px;
  color: #98a2b3;
  font-size: 8px;
}

.sd-device-footer span {
  max-width: 50%;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.sd-empty {
  min-height: 210px;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-direction: column;
  text-align: center;
  padding: 35px;
}

.sd-empty-icon {
  width: 43px;
  height: 43px;
  display: flex;
  align-items: center;
  justify-content: center;
  margin-bottom: 10px;
  border-radius: 50%;
  background: #ecfdf3;
  color: #16834b;
  font-weight: 900;
}

.sd-empty h3 {
  margin: 0 0 4px;
  font-size: 14px;
}

.sd-empty p {
  max-width: 430px;
  margin: 0;
  color: #8995a7;
  font-size: 10px;
  line-height: 1.5;
}

.sd-loading {
  min-height: 400px;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 12px;
}

.sd-loading > div:last-child {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.sd-loading strong {
  font-size: 13px;
}

.sd-loading span {
  color: #94a3b8;
  font-size: 10px;
}

.sd-spinner {
  width: 27px;
  height: 27px;
  border: 3px solid #e2e8f0;
  border-top-color: #475569;
  border-radius: 50%;
  animation: sd-spin .8s linear infinite;
}

.sd-footer {
  display: flex;
  justify-content: space-between;
  gap: 20px;
  padding: 4px 2px;
  color: #94a3b8;
  font-size: 9px;
}

@media (max-width: 1250px) {
  .sd-stat-grid {
    grid-template-columns: repeat(3, minmax(0, 1fr));
  }

  .sd-device-grid {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}

@media (max-width: 900px) {
  .sd-main-grid,
  .sd-content-grid {
    grid-template-columns: 1fr;
  }

  .sd-header {
    flex-direction: column;
  }

  .sd-header-actions {
    align-self: flex-start;
  }
}

@media (max-width: 650px) {
  .sd-page {
    padding: 17px;
  }

  .sd-stat-grid {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .sd-device-grid {
    grid-template-columns: 1fr;
  }

  .sd-control-legend {
    flex-direction: column;
    gap: 5px;
  }

  .sd-footer {
    flex-direction: column;
  }
}
`;