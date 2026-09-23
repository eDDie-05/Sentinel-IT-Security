import { useEffect, useMemo, useState } from "react";

const API = "http://localhost:5000/api";

function getToken() {
  return localStorage.getItem("token");
}

async function apiFetch(path, options = {}) {
  const token = getToken();

  const response = await fetch(`${API}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(token
        ? {
            Authorization: `Bearer ${token}`,
          }
        : {}),
      ...(options.headers || {}),
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
        `Request failed with status ${response.status}`
    );
  }

  return data;
}

function formatDate(value) {
  if (!value) return "Unknown";

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return "Unknown";
  }

  return date.toLocaleString();
}

function formatRelativeDate(value) {
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

  if (days < 30) {
    return `${days}d ago`;
  }

  return date.toLocaleDateString();
}

function normalizeStatus(value) {
  return String(value || "")
    .trim()
    .toUpperCase();
}

function severityClass(severity) {
  const value = normalizeStatus(severity);

  if (value === "CRITICAL") {
    return "sa-critical";
  }

  if (value === "HIGH") {
    return "sa-high";
  }

  if (value === "MEDIUM") {
    return "sa-medium";
  }

  return "sa-warning";
}

function statusClass(status) {
  const value = normalizeStatus(status);

  if (value === "OPEN") {
    return "sa-open";
  }

  if (value === "ACKNOWLEDGED") {
    return "sa-acknowledged";
  }

  if (value === "RESOLVED") {
    return "sa-resolved";
  }

  return "sa-unknown";
}

function prettyAlertType(type) {
  const value = String(type || "SECURITY_ALERT")
    .replaceAll("_", " ")
    .toLowerCase();

  return value.replace(/\b\w/g, (letter) =>
    letter.toUpperCase()
  );
}

function getDeviceName(alert) {
  return (
    alert.device_name ||
    alert.device_hostname ||
    alert.hostname ||
    alert.device_id ||
    "Unknown Device"
  );
}

function getMessage(alert) {
  return (
    alert.message ||
    alert.details ||
    "Security condition requires attention."
  );
}

export default function SecurityAlerts() {
  const [alerts, setAlerts] = useState([]);
  const [summary, setSummary] = useState(null);

  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const [error, setError] = useState("");

  const [filter, setFilter] = useState("ALL");
  const [severityFilter, setSeverityFilter] =
    useState("ALL");

  const [selectedAlert, setSelectedAlert] =
    useState(null);

  const [actionLoading, setActionLoading] =
    useState(false);

  const [resolveReason, setResolveReason] =
    useState("");

  const [showResolveBox, setShowResolveBox] =
    useState(false);

  async function loadAlerts(showLoading = false) {
    try {
      if (showLoading) {
        setLoading(true);
      } else {
        setRefreshing(true);
      }

      setError("");

      const [alertsData, summaryData] =
        await Promise.all([
          apiFetch("/security-alerts"),
          apiFetch("/security-alerts/summary"),
        ]);

      const alertRows = Array.isArray(alertsData)
        ? alertsData
        : Array.isArray(alertsData.alerts)
        ? alertsData.alerts
        : [];

      setAlerts(alertRows);

      setSummary(summaryData || null);
    } catch (err) {
      console.error(
        "Failed to load security alerts:",
        err
      );

      setError(
        err.message ||
          "Failed to load security alerts."
      );
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }

  useEffect(() => {
    loadAlerts(true);

    const interval = setInterval(() => {
      loadAlerts(false);
    }, 15000);

    return () => clearInterval(interval);
  }, []);

  async function acknowledgeAlert(alert) {
    if (!alert?.id) return;

    try {
      setActionLoading(true);
      setError("");

      await apiFetch(
        `/security-alerts/${alert.id}/acknowledge`,
        {
          method: "POST",
        }
      );

      setSelectedAlert(null);

      await loadAlerts(false);
    } catch (err) {
      console.error(
        "Failed to acknowledge alert:",
        err
      );

      setError(
        err.message ||
          "Failed to acknowledge alert."
      );
    } finally {
      setActionLoading(false);
    }
  }

  async function resolveAlert(alert) {
    if (!alert?.id) return;

    try {
      setActionLoading(true);
      setError("");

      await apiFetch(
        `/security-alerts/${alert.id}/resolve`,
        {
          method: "POST",
          body: JSON.stringify({
            reason:
              resolveReason.trim() ||
              "Resolved by administrator",
          }),
        }
      );

      setSelectedAlert(null);
      setShowResolveBox(false);
      setResolveReason("");

      await loadAlerts(false);
    } catch (err) {
      console.error(
        "Failed to resolve alert:",
        err
      );

      setError(
        err.message ||
          "Failed to resolve alert."
      );
    } finally {
      setActionLoading(false);
    }
  }

  const counts = useMemo(() => {
    const result = {
      all: alerts.length,
      open: 0,
      acknowledged: 0,
      resolved: 0,
      critical: 0,
      warning: 0,
    };

    for (const alert of alerts) {
      const status = normalizeStatus(
        alert.status
      );

      const severity = normalizeStatus(
        alert.severity
      );

      if (status === "OPEN") {
        result.open++;
      }

      if (status === "ACKNOWLEDGED") {
        result.acknowledged++;
      }

      if (status === "RESOLVED") {
        result.resolved++;
      }

      if (
        severity === "CRITICAL" ||
        severity === "HIGH"
      ) {
        result.critical++;
      }

      if (
        severity === "WARNING" ||
        severity === "MEDIUM"
      ) {
        result.warning++;
      }
    }

    return result;
  }, [alerts]);

  const filteredAlerts = useMemo(() => {
    return alerts.filter((alert) => {
      const status = normalizeStatus(
        alert.status
      );

      const severity = normalizeStatus(
        alert.severity
      );

      const statusMatch =
        filter === "ALL" ||
        status === filter;

      let severityMatch = true;

      if (severityFilter === "CRITICAL") {
        severityMatch =
          severity === "CRITICAL" ||
          severity === "HIGH";
      }

      if (severityFilter === "WARNING") {
        severityMatch =
          severity === "WARNING" ||
          severity === "MEDIUM";
      }

      return statusMatch && severityMatch;
    });
  }, [alerts, filter, severityFilter]);

  function openDetails(alert) {
    setSelectedAlert(alert);
    setShowResolveBox(false);
    setResolveReason("");
  }

  function closeDetails() {
    if (actionLoading) return;

    setSelectedAlert(null);
    setShowResolveBox(false);
    setResolveReason("");
  }

  if (loading) {
    return (
      <div className="sa-page">
        <style>{styles}</style>

        <div className="sa-loading">
          <div className="sa-spinner" />
          <div>
            <strong>Loading Security Alerts</strong>
            <span>
              Connecting to Sentinel monitoring
              service...
            </span>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="sa-page">
      <style>{styles}</style>

      <div className="sa-header">
        <div>
          <div className="sa-eyebrow">
            SENTINEL SECURITY CENTER
          </div>

          <h1>Security Alerts</h1>

          <p>
            Monitor, investigate and manage
            security events across company
            devices.
          </p>
        </div>

        <button
          className="sa-refresh"
          onClick={() => loadAlerts(false)}
          disabled={refreshing}
        >
          <span
            className={
              refreshing
                ? "sa-refresh-icon sa-spinning"
                : "sa-refresh-icon"
            }
          >
            ↻
          </span>

          {refreshing
            ? "Refreshing..."
            : "Refresh"}
        </button>
      </div>

      {error && (
        <div className="sa-error">
          <div>
            <strong>Unable to complete request</strong>
            <span>{error}</span>
          </div>

          <button
            onClick={() => setError("")}
          >
            ×
          </button>
        </div>
      )}

      <div className="sa-stat-grid">
        <div className="sa-stat-card">
          <div className="sa-stat-icon sa-blue">
            !
          </div>

          <div>
            <span>Total Alerts</span>
            <strong>
              {summary?.total ??
                counts.all}
            </strong>
          </div>
        </div>

        <div className="sa-stat-card">
          <div className="sa-stat-icon sa-red">
            !
          </div>

          <div>
            <span>Open</span>
            <strong>
              {summary?.open ??
                counts.open}
            </strong>
          </div>
        </div>

        <div className="sa-stat-card">
          <div className="sa-stat-icon sa-orange">
            !
          </div>

          <div>
            <span>Critical</span>
            <strong>
              {summary?.critical ??
                counts.critical}
            </strong>
          </div>
        </div>

        <div className="sa-stat-card">
          <div className="sa-stat-icon sa-yellow">
            !
          </div>

          <div>
            <span>Warnings</span>
            <strong>
              {summary?.warning ??
                counts.warning}
            </strong>
          </div>
        </div>

        <div className="sa-stat-card">
          <div className="sa-stat-icon sa-purple">
            ✓
          </div>

          <div>
            <span>Acknowledged</span>
            <strong>
              {summary?.acknowledged ??
                counts.acknowledged}
            </strong>
          </div>
        </div>

        <div className="sa-stat-card">
          <div className="sa-stat-icon sa-green">
            ✓
          </div>

          <div>
            <span>Resolved</span>
            <strong>
              {summary?.resolved ??
                counts.resolved}
            </strong>
          </div>
        </div>
      </div>

      <div className="sa-toolbar">
        <div className="sa-filter-group">
          {[
            ["ALL", "All Alerts"],
            ["OPEN", "Open"],
            ["ACKNOWLEDGED", "Acknowledged"],
            ["RESOLVED", "Resolved"],
          ].map(([value, label]) => (
            <button
              key={value}
              className={
                filter === value
                  ? "sa-filter active"
                  : "sa-filter"
              }
              onClick={() =>
                setFilter(value)
              }
            >
              {label}

              <span>
                {value === "ALL"
                  ? counts.all
                  : value === "OPEN"
                  ? counts.open
                  : value === "ACKNOWLEDGED"
                  ? counts.acknowledged
                  : counts.resolved}
              </span>
            </button>
          ))}
        </div>

        <div className="sa-severity-group">
          <button
            className={
              severityFilter === "ALL"
                ? "sa-severity active"
                : "sa-severity"
            }
            onClick={() =>
              setSeverityFilter("ALL")
            }
          >
            All severity
          </button>

          <button
            className={
              severityFilter === "CRITICAL"
                ? "sa-severity active critical"
                : "sa-severity critical"
            }
            onClick={() =>
              setSeverityFilter("CRITICAL")
            }
          >
            Critical
          </button>

          <button
            className={
              severityFilter === "WARNING"
                ? "sa-severity active warning"
                : "sa-severity warning"
            }
            onClick={() =>
              setSeverityFilter("WARNING")
            }
          >
            Warning
          </button>
        </div>
      </div>

      <div className="sa-table-card">
        <div className="sa-table-heading">
          <div>
            <h2>Alert Events</h2>
            <span>
              Showing{" "}
              {filteredAlerts.length} of{" "}
              {alerts.length} alerts
            </span>
          </div>

          <div className="sa-live">
            <span />
            Live monitoring
          </div>
        </div>

        {filteredAlerts.length === 0 ? (
          <div className="sa-empty">
            <div className="sa-empty-icon">
              ✓
            </div>

            <h3>No alerts found</h3>

            <p>
              There are no security alerts
              matching the selected filters.
            </p>
          </div>
        ) : (
          <div className="sa-table-wrap">
            <table className="sa-table">
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Device</th>
                  <th>Alert</th>
                  <th>Message</th>
                  <th>Occurrences</th>
                  <th>Last Detected</th>
                  <th>Status</th>
                  <th />
                </tr>
              </thead>

              <tbody>
                {filteredAlerts.map(
                  (alert) => {
                    const severity =
                      normalizeStatus(
                        alert.severity
                      );

                    const status =
                      normalizeStatus(
                        alert.status
                      );

                    return (
                      <tr key={alert.id}>
                        <td>
                          <span
                            className={`sa-badge ${severityClass(
                              severity
                            )}`}
                          >
                            {severity ||
                              "WARNING"}
                          </span>
                        </td>

                        <td>
                          <div className="sa-device">
                            <div className="sa-device-icon">
                              ▣
                            </div>

                            <div>
                              <strong>
                                {getDeviceName(
                                  alert
                                )}
                              </strong>

                              <span>
                                {alert.device_id ||
                                  "Device ID unavailable"}
                              </span>
                            </div>
                          </div>
                        </td>

                        <td>
                          <strong className="sa-alert-type">
                            {prettyAlertType(
                              alert.alert_type
                            )}
                          </strong>
                        </td>

                        <td>
                          <div className="sa-message">
                            {getMessage(alert)}
                          </div>
                        </td>

                        <td>
                          <span className="sa-occurrences">
                            {alert.occurrence_count ??
                              alert.occurrences ??
                              1}
                          </span>
                        </td>

                        <td>
                          <div className="sa-date">
                            <strong>
                              {formatRelativeDate(
                                alert.last_detected ||
                                  alert.updated_at ||
                                  alert.created_at
                              )}
                            </strong>

                            <span>
                              {formatDate(
                                alert.last_detected ||
                                  alert.updated_at ||
                                  alert.created_at
                              )}
                            </span>
                          </div>
                        </td>

                        <td>
                          <span
                            className={`sa-badge ${statusClass(
                              status
                            )}`}
                          >
                            {status ||
                              "UNKNOWN"}
                          </span>
                        </td>

                        <td>
                          <button
                            className="sa-view"
                            onClick={() =>
                              openDetails(
                                alert
                              )
                            }
                          >
                            View
                          </button>
                        </td>
                      </tr>
                    );
                  }
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {selectedAlert && (
        <div
          className="sa-modal-backdrop"
          onMouseDown={(event) => {
            if (
              event.target ===
              event.currentTarget
            ) {
              closeDetails();
            }
          }}
        >
          <div className="sa-modal">
            <div className="sa-modal-header">
              <div>
                <div className="sa-eyebrow">
                  SECURITY EVENT
                </div>

                <h2>
                  {prettyAlertType(
                    selectedAlert.alert_type
                  )}
                </h2>
              </div>

              <button
                className="sa-close"
                onClick={closeDetails}
                disabled={actionLoading}
              >
                ×
              </button>
            </div>

            <div className="sa-modal-badges">
              <span
                className={`sa-badge ${severityClass(
                  selectedAlert.severity
                )}`}
              >
                {normalizeStatus(
                  selectedAlert.severity
                ) || "WARNING"}
              </span>

              <span
                className={`sa-badge ${statusClass(
                  selectedAlert.status
                )}`}
              >
                {normalizeStatus(
                  selectedAlert.status
                ) || "UNKNOWN"}
              </span>
            </div>

            <div className="sa-detail-grid">
              <div>
                <span>Device</span>
                <strong>
                  {getDeviceName(
                    selectedAlert
                  )}
                </strong>
              </div>

              <div>
                <span>Device ID</span>
                <strong>
                  {selectedAlert.device_id ||
                    "Unavailable"}
                </strong>
              </div>

              <div>
                <span>First Detected</span>
                <strong>
                  {formatDate(
                    selectedAlert.first_detected ||
                      selectedAlert.created_at
                  )}
                </strong>
              </div>

              <div>
                <span>Last Detected</span>
                <strong>
                  {formatDate(
                    selectedAlert.last_detected ||
                      selectedAlert.updated_at ||
                      selectedAlert.created_at
                  )}
                </strong>
              </div>

              <div>
                <span>Occurrences</span>
                <strong>
                  {selectedAlert.occurrence_count ??
                    selectedAlert.occurrences ??
                    1}
                </strong>
              </div>

              <div>
                <span>Alert ID</span>
                <strong>
                  #{selectedAlert.id}
                </strong>
              </div>
            </div>

            <div className="sa-detail-message">
              <span>Alert Message</span>
              <p>
                {getMessage(
                  selectedAlert
                )}
              </p>
            </div>

            {selectedAlert.resolution_reason && (
              <div className="sa-resolution">
                <span>
                  Resolution Reason
                </span>

                <p>
                  {
                    selectedAlert.resolution_reason
                  }
                </p>
              </div>
            )}

            {showResolveBox && (
              <div className="sa-resolve-box">
                <label>
                  Resolution reason
                </label>

                <textarea
                  value={resolveReason}
                  onChange={(event) =>
                    setResolveReason(
                      event.target.value
                    )
                  }
                  placeholder="Explain why this alert is being resolved..."
                  rows={4}
                  disabled={actionLoading}
                />
              </div>
            )}

            <div className="sa-modal-actions">
              <button
                className="sa-secondary"
                onClick={closeDetails}
                disabled={actionLoading}
              >
                Close
              </button>

              {normalizeStatus(
                selectedAlert.status
              ) === "OPEN" && (
                <button
                  className="sa-ack"
                  onClick={() =>
                    acknowledgeAlert(
                      selectedAlert
                    )
                  }
                  disabled={actionLoading}
                >
                  {actionLoading
                    ? "Processing..."
                    : "Acknowledge"}
                </button>
              )}

              {(
                normalizeStatus(
                  selectedAlert.status
                ) === "OPEN" ||
                normalizeStatus(
                  selectedAlert.status
                ) === "ACKNOWLEDGED"
              ) &&
                !showResolveBox && (
                  <button
                    className="sa-resolve"
                    onClick={() =>
                      setShowResolveBox(true)
                    }
                    disabled={actionLoading}
                  >
                    Resolve Alert
                  </button>
                )}

              {showResolveBox && (
                <button
                  className="sa-resolve"
                  onClick={() =>
                    resolveAlert(
                      selectedAlert
                    )
                  }
                  disabled={actionLoading}
                >
                  {actionLoading
                    ? "Resolving..."
                    : "Confirm Resolution"}
                </button>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

const styles = `
.sa-page {
  width: 100%;
  min-height: 100%;
  color: #172033;
  background: #f6f8fb;
  padding: 28px;
  font-family:
    Inter,
    ui-sans-serif,
    system-ui,
    -apple-system,
    BlinkMacSystemFont,
    "Segoe UI",
    sans-serif;
}

.sa-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 24px;
  margin-bottom: 24px;
}

.sa-eyebrow {
  font-size: 11px;
  font-weight: 800;
  letter-spacing: 0.14em;
  color: #64748b;
  margin-bottom: 8px;
}

.sa-header h1 {
  margin: 0;
  font-size: 30px;
  line-height: 1.15;
  letter-spacing: -0.03em;
}

.sa-header p {
  margin: 8px 0 0;
  color: #64748b;
  font-size: 14px;
}

.sa-refresh {
  display: flex;
  align-items: center;
  gap: 9px;
  border: 1px solid #dbe2ea;
  background: #ffffff;
  color: #263449;
  border-radius: 10px;
  padding: 10px 15px;
  font-size: 13px;
  font-weight: 700;
  cursor: pointer;
}

.sa-refresh:hover {
  background: #f8fafc;
}

.sa-refresh:disabled {
  opacity: 0.65;
  cursor: default;
}

.sa-refresh-icon {
  font-size: 19px;
  line-height: 1;
}

.sa-spinning {
  animation: sa-spin 0.8s linear infinite;
}

@keyframes sa-spin {
  to {
    transform: rotate(360deg);
  }
}

.sa-error {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 20px;
  background: #fff5f5;
  border: 1px solid #fecaca;
  border-radius: 12px;
  padding: 13px 16px;
  margin-bottom: 20px;
  color: #991b1b;
}

.sa-error div {
  display: flex;
  flex-direction: column;
  gap: 3px;
}

.sa-error strong {
  font-size: 13px;
}

.sa-error span {
  font-size: 12px;
}

.sa-error button {
  border: 0;
  background: transparent;
  color: #991b1b;
  font-size: 20px;
  cursor: pointer;
}

.sa-stat-grid {
  display: grid;
  grid-template-columns:
    repeat(6, minmax(0, 1fr));
  gap: 14px;
  margin-bottom: 20px;
}

.sa-stat-card {
  min-height: 104px;
  display: flex;
  align-items: center;
  gap: 13px;
  background: #ffffff;
  border: 1px solid #e5eaf0;
  border-radius: 14px;
  padding: 16px;
  box-shadow:
    0 2px 5px rgba(15, 23, 42, 0.03);
}

.sa-stat-card > div:last-child {
  display: flex;
  flex-direction: column;
  gap: 4px;
  min-width: 0;
}

.sa-stat-card span {
  color: #64748b;
  font-size: 11px;
  font-weight: 700;
  white-space: nowrap;
}

.sa-stat-card strong {
  color: #111827;
  font-size: 27px;
  line-height: 1;
}

.sa-stat-icon {
  width: 38px;
  height: 38px;
  border-radius: 11px;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  font-size: 17px;
  font-weight: 900;
}

.sa-blue {
  background: #eef4ff;
  color: #315ea8;
}

.sa-red {
  background: #fff0f0;
  color: #c62828;
}

.sa-orange {
  background: #fff4e8;
  color: #c76516;
}

.sa-yellow {
  background: #fff9df;
  color: #9a7200;
}

.sa-purple {
  background: #f4efff;
  color: #6d43aa;
}

.sa-green {
  background: #ecfdf3;
  color: #16834b;
}

.sa-toolbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 16px;
  margin-bottom: 14px;
}

.sa-filter-group,
.sa-severity-group {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
}

.sa-filter,
.sa-severity {
  border: 1px solid transparent;
  background: transparent;
  color: #64748b;
  border-radius: 9px;
  padding: 8px 10px;
  font-size: 12px;
  font-weight: 700;
  cursor: pointer;
}

.sa-filter {
  display: flex;
  align-items: center;
  gap: 7px;
}

.sa-filter span {
  min-width: 20px;
  padding: 2px 5px;
  border-radius: 6px;
  background: #e9eef5;
  color: #475569;
  font-size: 10px;
}

.sa-filter.active,
.sa-severity.active {
  background: #ffffff;
  border-color: #dbe2ea;
  color: #172033;
  box-shadow:
    0 2px 4px rgba(15, 23, 42, 0.04);
}

.sa-severity {
  border-color: #dbe2ea;
  background: #ffffff;
}

.sa-severity.critical {
  color: #b42318;
}

.sa-severity.warning {
  color: #9a6700;
}

.sa-table-card {
  background: #ffffff;
  border: 1px solid #e5eaf0;
  border-radius: 15px;
  overflow: hidden;
  box-shadow:
    0 3px 8px rgba(15, 23, 42, 0.03);
}

.sa-table-heading {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 20px;
  padding: 18px 20px;
  border-bottom: 1px solid #edf0f4;
}

.sa-table-heading h2 {
  margin: 0 0 3px;
  font-size: 16px;
}

.sa-table-heading span {
  color: #7a8798;
  font-size: 11px;
}

.sa-live {
  display: flex;
  align-items: center;
  gap: 7px;
  font-weight: 700;
}

.sa-live > span {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: #16a34a;
  box-shadow:
    0 0 0 4px #dcfce7;
}

.sa-table-wrap {
  width: 100%;
  overflow-x: auto;
}

.sa-table {
  width: 100%;
  min-width: 1100px;
  border-collapse: collapse;
}

.sa-table th {
  text-align: left;
  padding: 11px 14px;
  background: #fafbfd;
  border-bottom: 1px solid #e8edf3;
  color: #748197;
  font-size: 10px;
  font-weight: 800;
  text-transform: uppercase;
  letter-spacing: 0.07em;
  white-space: nowrap;
}

.sa-table td {
  padding: 14px;
  border-bottom: 1px solid #eef1f5;
  vertical-align: middle;
  font-size: 12px;
}

.sa-table tbody tr:hover {
  background: #fbfcfe;
}

.sa-table tbody tr:last-child td {
  border-bottom: 0;
}

.sa-badge {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 74px;
  padding: 5px 8px;
  border-radius: 999px;
  font-size: 9px;
  font-weight: 900;
  letter-spacing: 0.04em;
  white-space: nowrap;
}

.sa-critical {
  color: #b42318;
  background: #fff0f0;
}

.sa-high {
  color: #b54708;
  background: #fff3e8;
}

.sa-medium {
  color: #9a6700;
  background: #fff8db;
}

.sa-warning {
  color: #8a6500;
  background: #fff8db;
}

.sa-open {
  color: #b42318;
  background: #fff0f0;
}

.sa-acknowledged {
  color: #6d43aa;
  background: #f3edff;
}

.sa-resolved {
  color: #147a46;
  background: #ecfdf3;
}

.sa-unknown {
  color: #64748b;
  background: #f1f5f9;
}

.sa-device {
  display: flex;
  align-items: center;
  gap: 9px;
  min-width: 155px;
}

.sa-device-icon {
  width: 31px;
  height: 31px;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: 8px;
  background: #eef3f8;
  color: #42526b;
  flex-shrink: 0;
}

.sa-device > div:last-child {
  display: flex;
  flex-direction: column;
  gap: 2px;
  min-width: 0;
}

.sa-device strong {
  max-width: 170px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  color: #263449;
}

.sa-device span {
  max-width: 170px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  color: #8995a7;
  font-size: 10px;
}

.sa-alert-type {
  color: #344054;
  white-space: nowrap;
}

.sa-message {
  max-width: 260px;
  color: #667085;
  line-height: 1.45;
}

.sa-occurrences {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 28px;
  height: 28px;
  padding: 0 7px;
  border-radius: 8px;
  background: #f1f5f9;
  color: #475569;
  font-weight: 800;
}

.sa-date {
  display: flex;
  flex-direction: column;
  gap: 2px;
  white-space: nowrap;
}

.sa-date strong {
  color: #344054;
  font-size: 11px;
}

.sa-date span {
  color: #98a2b3;
  font-size: 9px;
}

.sa-view {
  border: 1px solid #dbe2ea;
  background: #ffffff;
  color: #334155;
  border-radius: 8px;
  padding: 7px 10px;
  font-size: 11px;
  font-weight: 800;
  cursor: pointer;
}

.sa-view:hover {
  background: #f8fafc;
}

.sa-empty {
  min-height: 300px;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-direction: column;
  padding: 40px;
  text-align: center;
}

.sa-empty-icon {
  width: 50px;
  height: 50px;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: 50%;
  background: #ecfdf3;
  color: #16834b;
  font-size: 23px;
  font-weight: 900;
  margin-bottom: 14px;
}

.sa-empty h3 {
  margin: 0 0 5px;
  font-size: 16px;
}

.sa-empty p {
  margin: 0;
  color: #7a8798;
  font-size: 12px;
}

.sa-loading {
  min-height: 400px;
  display: flex;
  justify-content: center;
  align-items: center;
  gap: 13px;
  color: #475569;
}

.sa-loading > div:last-child {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.sa-loading span {
  color: #94a3b8;
  font-size: 12px;
}

.sa-spinner {
  width: 27px;
  height: 27px;
  border: 3px solid #e2e8f0;
  border-top-color: #475569;
  border-radius: 50%;
  animation: sa-spin 0.8s linear infinite;
}

.sa-modal-backdrop {
  position: fixed;
  inset: 0;
  z-index: 1000;
  background: rgba(15, 23, 42, 0.42);
  display: flex;
  justify-content: center;
  align-items: center;
  padding: 20px;
}

.sa-modal {
  width: min(650px, 100%);
  max-height: calc(100vh - 40px);
  overflow-y: auto;
  background: #ffffff;
  border-radius: 17px;
  box-shadow:
    0 25px 70px rgba(15, 23, 42, 0.22);
  padding: 24px;
}

.sa-modal-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 20px;
}

.sa-modal-header h2 {
  margin: 0;
  font-size: 22px;
}

.sa-close {
  width: 32px;
  height: 32px;
  border: 0;
  border-radius: 8px;
  background: #f1f5f9;
  color: #475569;
  font-size: 22px;
  cursor: pointer;
}

.sa-modal-badges {
  display: flex;
  gap: 7px;
  margin: 18px 0;
}

.sa-detail-grid {
  display: grid;
  grid-template-columns:
    repeat(2, minmax(0, 1fr));
  border: 1px solid #e8edf3;
  border-radius: 11px;
  overflow: hidden;
}

.sa-detail-grid > div {
  padding: 13px;
  border-bottom: 1px solid #edf0f4;
}

.sa-detail-grid > div:nth-child(odd) {
  border-right: 1px solid #edf0f4;
}

.sa-detail-grid > div:nth-last-child(-n + 2) {
  border-bottom: 0;
}

.sa-detail-grid span,
.sa-detail-message > span,
.sa-resolution > span {
  display: block;
  margin-bottom: 5px;
  color: #8995a7;
  font-size: 10px;
  font-weight: 800;
  text-transform: uppercase;
  letter-spacing: 0.06em;
}

.sa-detail-grid strong {
  display: block;
  color: #344054;
  font-size: 12px;
  word-break: break-word;
}

.sa-detail-message {
  margin-top: 15px;
  padding: 14px;
  border-radius: 11px;
  background: #f8fafc;
}

.sa-detail-message p,
.sa-resolution p {
  margin: 0;
  color: #475569;
  font-size: 12px;
  line-height: 1.55;
}

.sa-resolution {
  margin-top: 12px;
  padding: 14px;
  border-radius: 11px;
  background: #ecfdf3;
}

.sa-resolve-box {
  margin-top: 15px;
}

.sa-resolve-box label {
  display: block;
  margin-bottom: 7px;
  color: #344054;
  font-size: 11px;
  font-weight: 800;
}

.sa-resolve-box textarea {
  width: 100%;
  resize: vertical;
  border: 1px solid #dbe2ea;
  border-radius: 10px;
  padding: 11px;
  font: inherit;
  font-size: 12px;
  outline: none;
}

.sa-resolve-box textarea:focus {
  border-color: #94a3b8;
}

.sa-modal-actions {
  display: flex;
  justify-content: flex-end;
  gap: 8px;
  margin-top: 22px;
}

.sa-modal-actions button {
  border-radius: 9px;
  padding: 9px 13px;
  font-size: 11px;
  font-weight: 800;
  cursor: pointer;
}

.sa-modal-actions button:disabled {
  opacity: 0.55;
  cursor: default;
}

.sa-secondary {
  border: 1px solid #dbe2ea;
  background: #ffffff;
  color: #475569;
}

.sa-ack {
  border: 1px solid #ddd0f3;
  background: #f4efff;
  color: #6941a5;
}

.sa-resolve {
  border: 1px solid #b7e4ca;
  background: #ecfdf3;
  color: #147a46;
}

@media (max-width: 1250px) {
  .sa-stat-grid {
    grid-template-columns:
      repeat(3, minmax(0, 1fr));
  }
}

@media (max-width: 850px) {
  .sa-page {
    padding: 18px;
  }

  .sa-header,
  .sa-toolbar {
    flex-direction: column;
    align-items: stretch;
  }

  .sa-refresh {
    align-self: flex-start;
  }

  .sa-stat-grid {
    grid-template-columns:
      repeat(2, minmax(0, 1fr));
  }
}

@media (max-width: 550px) {
  .sa-stat-grid {
    grid-template-columns: 1fr;
  }

  .sa-detail-grid {
    grid-template-columns: 1fr;
  }

  .sa-detail-grid > div:nth-child(odd) {
    border-right: 0;
  }

  .sa-detail-grid > div:nth-last-child(-n + 2) {
    border-bottom: 1px solid #edf0f4;
  }

  .sa-detail-grid > div:last-child {
    border-bottom: 0;
  }
}
`;