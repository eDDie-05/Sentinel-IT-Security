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

function formatRelative(value) {
  if (!value) return "Never";

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

function formatDate(value) {
  if (!value) return "Unknown";

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return "Unknown";
  }

  return date.toLocaleString();
}

function getDeviceName(device) {
  return (
    device.name ||
    device.hostname ||
    device.device_id ||
    "Unknown Device"
  );
}

function getSecurityStatus(device) {
  return normalize(
    device.security_status ||
      device.securityStatus
  );
}

function getControlStatus(device, type) {
  const status =
    device[`${type}_status`];

  if (status) {
    return normalize(status);
  }

  if (device[type] === true) {
    return "ENABLED";
  }

  if (device[type] === false) {
    return "DISABLED";
  }

  return "UNKNOWN";
}

function getOnlineStatus(device) {
  return device.online === true
    ? "ONLINE"
    : "OFFLINE";
}

function securityClass(status) {
  if (status === "SECURE") {
    return "secure";
  }

  if (status === "AT RISK") {
    return "risk";
  }

  return "unknown";
}

function controlClass(status) {
  if (status === "ENABLED") {
    return "enabled";
  }

  if (status === "DISABLED") {
    return "disabled";
  }

  return "unknown";
}

export default function DeviceList({
  devices: incomingDevices,
  securityPolicy = {},
  onDeviceDeleted,
  onDeviceUpdated,
}) {
  const [devices, setDevices] =
    useState(
      Array.isArray(incomingDevices)
        ? incomingDevices
        : []
    );

  const [search, setSearch] =
    useState("");

  const [department, setDepartment] =
    useState("ALL");

  const [statusFilter, setStatusFilter] =
    useState("ALL");

  const [securityFilter, setSecurityFilter] =
    useState("ALL");

  const [selectedDevice, setSelectedDevice] =
    useState(null);

  const [loading, setLoading] =
    useState(true);

  const [refreshing, setRefreshing] =
    useState(false);

  const [error, setError] = useState("");

  const currentUser = useMemo(() => {
    try {
      const raw =
        localStorage.getItem(
          "currentUser"
        );

      return raw
        ? JSON.parse(raw)
        : {};
    } catch {
      return {};
    }
  }, []);

  const role =
    currentUser.role || "";

  const canManage =
    role === "Administrator" ||
    role === "IT Manager";

  async function loadDevices(
    initial = false
  ) {
    try {
      if (initial) {
        setLoading(true);
      } else {
        setRefreshing(true);
      }

      setError("");

      const data =
        await apiFetch("/devices");

      const rows =
        Array.isArray(data)
          ? data
          : Array.isArray(data.devices)
          ? data.devices
          : [];

      setDevices(rows);

      if (selectedDevice) {
        const updated =
          rows.find(
            (device) =>
              device.id ===
                selectedDevice.id ||
              device.device_id ===
                selectedDevice.device_id
          );

        if (updated) {
          setSelectedDevice(updated);
        }
      }
    } catch (err) {
      console.error(
        "Failed to load devices:",
        err
      );

      setError(
        err.message ||
          "Failed to load devices."
      );
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }

  useEffect(() => {
    if (Array.isArray(incomingDevices)) {
      setDevices(incomingDevices);
      setLoading(false);
    }
  }, [incomingDevices]);

  useEffect(() => {
    loadDevices(true);

    const interval =
      setInterval(() => {
        loadDevices(false);
      }, 15000);

    return () =>
      clearInterval(interval);
  }, []);

  const departments = useMemo(() => {
    const values =
      devices
        .map(
          (device) =>
            device.department
        )
        .filter(Boolean);

    return [
      "ALL",
      ...Array.from(
        new Set(values)
      ).sort(),
    ];
  }, [devices]);

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

      const security =
        getSecurityStatus(device);

      if (security === "SECURE") {
        secure++;
      } else if (
        security === "AT RISK"
      ) {
        atRisk++;
      } else {
        unknown++;
      }
    }

    return {
      total: devices.length,
      online,
      offline,
      secure,
      atRisk,
      unknown,
    };
  }, [devices]);

  const filteredDevices = useMemo(() => {
    const query =
      search.trim().toLowerCase();

    return devices.filter(
      (device) => {
        const name =
          getDeviceName(
            device
          ).toLowerCase();

        const employee =
          String(
            device.employee ||
              device.username ||
              ""
          ).toLowerCase();

        const dept =
          String(
            device.department ||
              ""
          ).toLowerCase();

        const os =
          String(
            device.operating_system ||
              device.os ||
              ""
          ).toLowerCase();

        const matchesSearch =
          !query ||
          name.includes(query) ||
          employee.includes(query) ||
          dept.includes(query) ||
          os.includes(query);

        const matchesDepartment =
          department === "ALL" ||
          device.department ===
            department;

        const matchesStatus =
          statusFilter === "ALL" ||
          getOnlineStatus(device) ===
            statusFilter;

        const matchesSecurity =
          securityFilter === "ALL" ||
          getSecurityStatus(device) ===
            securityFilter;

        return (
          matchesSearch &&
          matchesDepartment &&
          matchesStatus &&
          matchesSecurity
        );
      }
    );
  }, [
    devices,
    search,
    department,
    statusFilter,
    securityFilter,
  ]);

  async function deleteDevice(device) {
    if (!canManage) return;

    const confirmed =
      window.confirm(
        `Delete ${getDeviceName(
          device
        )} from Sentinel?`
      );

    if (!confirmed) return;

    try {
      await apiFetch(
        `/devices/${device.id}`,
        {
          method: "DELETE",
        }
      );

      setSelectedDevice(null);

      await loadDevices(false);

      if (onDeviceDeleted) {
        onDeviceDeleted(device);
      }
    } catch (err) {
      setError(
        err.message ||
          "Failed to delete device."
      );
    }
  }

  function openAddDevice() {
    window.dispatchEvent(
      new CustomEvent(
        "open-add-device"
      )
    );
  }

  if (loading) {
    return (
      <div className="dm-page">
        <style>{styles}</style>

        <div className="dm-loading">
          <div className="dm-spinner" />

          <div>
            <strong>
              Loading Devices
            </strong>

            <span>
              Connecting to Sentinel
              monitoring service...
            </span>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="dm-page">
      <style>{styles}</style>

      <div className="dm-header">
        <div>
          <div className="dm-eyebrow">
            SENTINEL DEVICE MANAGEMENT
          </div>

          <h1>
            Device Monitoring
          </h1>

          <p>
            Monitor company computers,
            connectivity and security
            controls from one place.
          </p>
        </div>

        <div className="dm-header-actions">
          <div className="dm-live">
            <span />
            Live monitoring
          </div>

          <button
            className="dm-refresh"
            onClick={() =>
              loadDevices(false)
            }
            disabled={refreshing}
          >
            <span
              className={
                refreshing
                  ? "dm-refresh-icon dm-spin"
                  : "dm-refresh-icon"
              }
            >
              ↻
            </span>

            {refreshing
              ? "Refreshing..."
              : "Refresh"}
          </button>

          {canManage && (
            <button
              className="dm-add"
              onClick={openAddDevice}
            >
              + Add Device
            </button>
          )}
        </div>
      </div>

      {error && (
        <div className="dm-error">
          <div>
            <strong>
              Device monitoring error
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

      <div className="dm-stat-grid">
        <Stat
          label="Total Devices"
          value={statistics.total}
          icon="▣"
          type="blue"
        />

        <Stat
          label="Online"
          value={statistics.online}
          icon="●"
          type="green"
        />

        <Stat
          label="Offline"
          value={statistics.offline}
          icon="○"
          type="gray"
        />

        <Stat
          label="Secure"
          value={statistics.secure}
          icon="✓"
          type="green"
        />

        <Stat
          label="At Risk"
          value={statistics.atRisk}
          icon="!"
          type="red"
        />

        <Stat
          label="Unknown"
          value={statistics.unknown}
          icon="?"
          type="orange"
        />
      </div>

      <div className="dm-toolbar">
        <div className="dm-search">
          <span>⌕</span>

          <input
            value={search}
            onChange={(event) =>
              setSearch(
                event.target.value
              )
            }
            placeholder="Search devices, employees, departments..."
          />
        </div>

        <select
          value={department}
          onChange={(event) =>
            setDepartment(
              event.target.value
            )
          }
        >
          {departments.map(
            (item) => (
              <option
                key={item}
                value={item}
              >
                {item === "ALL"
                  ? "All Departments"
                  : item}
              </option>
            )
          )}
        </select>

        <select
          value={statusFilter}
          onChange={(event) =>
            setStatusFilter(
              event.target.value
            )
          }
        >
          <option value="ALL">
            All Connections
          </option>

          <option value="ONLINE">
            Online
          </option>

          <option value="OFFLINE">
            Offline
          </option>
        </select>

        <select
          value={securityFilter}
          onChange={(event) =>
            setSecurityFilter(
              event.target.value
            )
          }
        >
          <option value="ALL">
            All Security
          </option>

          <option value="SECURE">
            Secure
          </option>

          <option value="AT RISK">
            At Risk
          </option>

          <option value="UNKNOWN">
            Unknown
          </option>
        </select>
      </div>

      <div className="dm-results">
        Showing{" "}
        <strong>
          {filteredDevices.length}
        </strong>{" "}
        of{" "}
        <strong>
          {devices.length}
        </strong>{" "}
        devices
      </div>

      {filteredDevices.length === 0 ? (
        <div className="dm-empty">
          <div className="dm-empty-icon">
            ▣
          </div>

          <h3>
            No devices found
          </h3>

          <p>
            Try changing your search or
            filters.
          </p>
        </div>
      ) : (
        <div className="dm-grid">
          {filteredDevices.map(
            (device) => {
              const online =
                getOnlineStatus(
                  device
                );

              const security =
                getSecurityStatus(
                  device
                );

              const antivirus =
                getControlStatus(
                  device,
                  "antivirus"
                );

              const firewall =
                getControlStatus(
                  device,
                  "firewall"
                );

              const backup =
                getControlStatus(
                  device,
                  "backup"
                );

              return (
                <div
                  className="dm-card"
                  key={
                    device.id ||
                    device.device_id ||
                    device.name
                  }
                >
                  <div className="dm-card-header">
                    <div className="dm-computer">
                      ▣
                    </div>

                    <div className="dm-device-title">
                      <strong>
                        {getDeviceName(
                          device
                        )}
                      </strong>

                      <span>
                        {device.employee ||
                          device.username ||
                          "Unassigned"}
                      </span>
                    </div>

                    <div
                      className={
                        online ===
                        "ONLINE"
                          ? "dm-dot online"
                          : "dm-dot offline"
                      }
                    />
                  </div>

                  <div className="dm-status-row">
                    <span
                      className={
                        online ===
                        "ONLINE"
                          ? "dm-connection online"
                          : "dm-connection offline"
                      }
                    >
                      <i />
                      {online}
                    </span>

                    <span
                      className={`dm-security ${securityClass(
                        security
                      )}`}
                    >
                      {security ||
                        "UNKNOWN"}
                    </span>
                  </div>

                  <div className="dm-info-grid">
                    <Info
                      label="Operating System"
                      value={
                        device.operating_system ||
                        device.os ||
                        "Unknown"
                      }
                    />

                    <Info
                      label="CPU"
                      value={
                        device.cpu ||
                        "Unknown"
                      }
                    />

                    <Info
                      label="RAM"
                      value={
                        device.ram_gb
                          ? `${device.ram_gb} GB`
                          : device.total_memory_gb
                          ? `${device.total_memory_gb} GB`
                          : "Unknown"
                      }
                    />

                    <Info
                      label="IP Address"
                      value={
                        device.ip_address ||
                        "Unknown"
                      }
                    />
                  </div>

                  <div className="dm-controls">
                    <Control
                      label="Antivirus"
                      status={antivirus}
                    />

                    <Control
                      label="Firewall"
                      status={firewall}
                    />

                    <Control
                      label="Backup"
                      status={backup}
                    />
                  </div>

                  <div className="dm-footer">
                    <div>
                      <span>
                        Last heartbeat
                      </span>

                      <strong>
                        {formatRelative(
                          device.last_seen
                        )}
                      </strong>
                    </div>

                    <button
                      onClick={() =>
                        setSelectedDevice(
                          device
                        )
                      }
                    >
                      View Details
                    </button>
                  </div>
                </div>
              );
            }
          )}
        </div>
      )}

      {selectedDevice && (
        <div
          className="dm-modal-backdrop"
          onMouseDown={(event) => {
            if (
              event.target ===
              event.currentTarget
            ) {
              setSelectedDevice(null);
            }
          }}
        >
          <div className="dm-modal">
            <div className="dm-modal-header">
              <div>
                <div className="dm-eyebrow">
                  DEVICE DETAILS
                </div>

                <h2>
                  {getDeviceName(
                    selectedDevice
                  )}
                </h2>
              </div>

              <button
                className="dm-close"
                onClick={() =>
                  setSelectedDevice(
                    null
                  )
                }
              >
                ×
              </button>
            </div>

            <div className="dm-modal-status">
              <span
                className={
                  getOnlineStatus(
                    selectedDevice
                  ) === "ONLINE"
                    ? "dm-connection online"
                    : "dm-connection offline"
                }
              >
                <i />
                {getOnlineStatus(
                  selectedDevice
                )}
              </span>

              <span
                className={`dm-security ${securityClass(
                  getSecurityStatus(
                    selectedDevice
                  )
                )}`}
              >
                {getSecurityStatus(
                  selectedDevice
                ) || "UNKNOWN"}
              </span>
            </div>

            <div className="dm-detail-section">
              <h3>
                Device Information
              </h3>

              <div className="dm-detail-grid">
                <Detail
                  label="Device Name"
                  value={getDeviceName(
                    selectedDevice
                  )}
                />

                <Detail
                  label="Device ID"
                  value={
                    selectedDevice.device_id ||
                    "Unknown"
                  }
                />

                <Detail
                  label="Employee"
                  value={
                    selectedDevice.employee ||
                    selectedDevice.username ||
                    "Unassigned"
                  }
                />

                <Detail
                  label="Department"
                  value={
                    selectedDevice.department ||
                    "Unassigned"
                  }
                />

                <Detail
                  label="Operating System"
                  value={
                    selectedDevice.operating_system ||
                    selectedDevice.os ||
                    "Unknown"
                  }
                />

                <Detail
                  label="Architecture"
                  value={
                    selectedDevice.architecture ||
                    "Unknown"
                  }
                />

                <Detail
                  label="CPU"
                  value={
                    selectedDevice.cpu ||
                    "Unknown"
                  }
                />

                <Detail
                  label="CPU Cores"
                  value={
                    selectedDevice.cpu_cores ||
                    selectedDevice.cpuCores ||
                    "Unknown"
                  }
                />

                <Detail
                  label="RAM"
                  value={
                    selectedDevice.ram_gb
                      ? `${selectedDevice.ram_gb} GB`
                      : selectedDevice.total_memory_gb
                      ? `${selectedDevice.total_memory_gb} GB`
                      : "Unknown"
                  }
                />

                <Detail
                  label="IP Address"
                  value={
                    selectedDevice.ip_address ||
                    "Unknown"
                  }
                />

                <Detail
                  label="Agent Version"
                  value={
                    selectedDevice.agent_version ||
                    "Unknown"
                  }
                />

                <Detail
                  label="Last Seen"
                  value={
                    formatDate(
                      selectedDevice.last_seen
                    )
                  }
                />
              </div>
            </div>

            <div className="dm-detail-section">
              <h3>
                Security Controls
              </h3>

              <div className="dm-large-controls">
                <LargeControl
                  label="Antivirus"
                  status={getControlStatus(
                    selectedDevice,
                    "antivirus"
                  )}
                />

                <LargeControl
                  label="Firewall"
                  status={getControlStatus(
                    selectedDevice,
                    "firewall"
                  )}
                />

                <LargeControl
                  label="Backup"
                  status={getControlStatus(
                    selectedDevice,
                    "backup"
                  )}
                />
              </div>
            </div>

            {selectedDevice.security_message && (
              <div className="dm-security-message">
                <strong>
                  Security information
                </strong>

                <p>
                  {
                    selectedDevice.security_message
                  }
                </p>
              </div>
            )}

            <div className="dm-modal-actions">
              <button
                className="dm-secondary"
                onClick={() =>
                  setSelectedDevice(
                    null
                  )
                }
              >
                Close
              </button>

              {canManage &&
                selectedDevice.id && (
                  <button
                    className="dm-delete"
                    onClick={() =>
                      deleteDevice(
                        selectedDevice
                      )
                    }
                  >
                    Delete Device
                  </button>
                )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function Stat({
  label,
  value,
  icon,
  type,
}) {
  return (
    <div className="dm-stat">
      <div
        className={`dm-stat-icon ${type}`}
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

function Info({
  label,
  value,
}) {
  return (
    <div className="dm-info">
      <span>{label}</span>
      <strong title={value}>
        {value}
      </strong>
    </div>
  );
}

function Detail({
  label,
  value,
}) {
  return (
    <div className="dm-detail">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function Control({
  label,
  status,
}) {
  return (
    <div className="dm-control">
      <span>{label}</span>

      <strong
        className={controlClass(
          status
        )}
      >
        {status === "ENABLED"
          ? "ON"
          : status === "DISABLED"
          ? "OFF"
          : "?"}
      </strong>
    </div>
  );
}

function LargeControl({
  label,
  status,
}) {
  return (
    <div className="dm-large-control">
      <div>
        <strong>{label}</strong>

        <span>
          Security protection
        </span>
      </div>

      <span
        className={`dm-large-status ${controlClass(
          status
        )}`}
      >
        {status}
      </span>
    </div>
  );
}

const styles = `
.dm-page {
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

.dm-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 20px;
  margin-bottom: 22px;
}

.dm-eyebrow {
  color: #64748b;
  font-size: 10px;
  font-weight: 900;
  letter-spacing: .14em;
  margin-bottom: 7px;
}

.dm-header h1 {
  margin: 0;
  font-size: 29px;
  line-height: 1.15;
  letter-spacing: -.035em;
}

.dm-header p {
  margin: 7px 0 0;
  color: #64748b;
  font-size: 13px;
}

.dm-header-actions {
  display: flex;
  align-items: center;
  gap: 9px;
}

.dm-live {
  display: flex;
  align-items: center;
  gap: 7px;
  color: #526174;
  font-size: 10px;
  font-weight: 800;
  margin-right: 4px;
}

.dm-live span {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: #16a34a;
  box-shadow: 0 0 0 4px #dcfce7;
}

.dm-refresh,
.dm-add {
  border-radius: 9px;
  padding: 9px 12px;
  font-size: 10px;
  font-weight: 800;
  cursor: pointer;
}

.dm-refresh {
  border: 1px solid #dbe2ea;
  background: #fff;
  color: #334155;
}

.dm-add {
  border: 1px solid #24344d;
  background: #24344d;
  color: #fff;
}

.dm-refresh:disabled {
  opacity: .6;
  cursor: default;
}

.dm-refresh-icon {
  margin-right: 5px;
  font-size: 16px;
}

.dm-spin {
  display: inline-block;
  animation: dm-spin .8s linear infinite;
}

@keyframes dm-spin {
  to {
    transform: rotate(360deg);
  }
}

.dm-error {
  display: flex;
  justify-content: space-between;
  gap: 20px;
  padding: 13px 15px;
  margin-bottom: 17px;
  border: 1px solid #fecaca;
  background: #fff5f5;
  border-radius: 10px;
  color: #991b1b;
}

.dm-error div {
  display: flex;
  flex-direction: column;
  gap: 3px;
}

.dm-error strong {
  font-size: 11px;
}

.dm-error span {
  font-size: 10px;
}

.dm-error button {
  border: 0;
  background: transparent;
  color: #991b1b;
  font-size: 18px;
  cursor: pointer;
}

.dm-stat-grid {
  display: grid;
  grid-template-columns: repeat(6, minmax(0, 1fr));
  gap: 12px;
  margin-bottom: 17px;
}

.dm-stat {
  min-height: 91px;
  display: flex;
  align-items: center;
  gap: 11px;
  padding: 14px;
  background: #fff;
  border: 1px solid #e5eaf0;
  border-radius: 12px;
  box-shadow: 0 2px 5px rgba(15,23,42,.025);
}

.dm-stat-icon {
  width: 36px;
  height: 36px;
  flex-shrink: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: 9px;
  font-size: 15px;
  font-weight: 900;
}

.dm-stat-icon.blue {
  background: #eef4ff;
  color: #315ea8;
}

.dm-stat-icon.green {
  background: #ecfdf3;
  color: #16834b;
}

.dm-stat-icon.gray {
  background: #f1f5f9;
  color: #64748b;
}

.dm-stat-icon.red {
  background: #fff0f0;
  color: #c62828;
}

.dm-stat-icon.orange {
  background: #fff4e8;
  color: #c76516;
}

.dm-stat > div:last-child {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.dm-stat span {
  color: #7b8798;
  font-size: 9px;
  font-weight: 800;
  white-space: nowrap;
}

.dm-stat strong {
  color: #172033;
  font-size: 24px;
  line-height: 1;
}

.dm-toolbar {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 8px;
}

.dm-search {
  flex: 1;
  min-width: 220px;
  height: 37px;
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 0 11px;
  border: 1px solid #dbe2ea;
  border-radius: 9px;
  background: #fff;
}

.dm-search span {
  color: #94a3b8;
  font-size: 18px;
}

.dm-search input {
  width: 100%;
  border: 0;
  outline: 0;
  background: transparent;
  color: #334155;
  font: inherit;
  font-size: 11px;
}

.dm-toolbar select {
  height: 37px;
  min-width: 145px;
  padding: 0 10px;
  border: 1px solid #dbe2ea;
  border-radius: 9px;
  background: #fff;
  color: #475569;
  font: inherit;
  font-size: 10px;
  font-weight: 700;
  outline: none;
}

.dm-results {
  margin-bottom: 12px;
  color: #94a3b8;
  font-size: 9px;
}

.dm-results strong {
  color: #475569;
}

.dm-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 13px;
}

.dm-card {
  background: #fff;
  border: 1px solid #e5eaf0;
  border-radius: 13px;
  overflow: hidden;
  box-shadow: 0 2px 6px rgba(15,23,42,.025);
}

.dm-card-header {
  display: flex;
  align-items: center;
  gap: 9px;
  padding: 15px 15px 12px;
}

.dm-computer {
  width: 37px;
  height: 37px;
  flex-shrink: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: 10px;
  background: #eef3f8;
  color: #46566e;
  font-size: 16px;
  font-weight: 900;
}

.dm-device-title {
  flex: 1;
  min-width: 0;
  display: flex;
  flex-direction: column;
  gap: 3px;
}

.dm-device-title strong {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  color: #263449;
  font-size: 12px;
}

.dm-device-title span {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  color: #98a2b3;
  font-size: 9px;
}

.dm-dot {
  width: 8px;
  height: 8px;
  flex-shrink: 0;
  border-radius: 50%;
}

.dm-dot.online {
  background: #16a34a;
}

.dm-dot.offline {
  background: #94a3b8;
}

.dm-status-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 9px 15px;
  border-top: 1px solid #edf0f4;
  border-bottom: 1px solid #edf0f4;
}

.dm-connection {
  font-size: 9px;
  font-weight: 900;
}

.dm-connection i {
  display: inline-block;
  width: 6px;
  height: 6px;
  margin-right: 5px;
  border-radius: 50%;
  background: currentColor;
}

.dm-connection.online {
  color: #16834b;
}

.dm-connection.offline {
  color: #64748b;
}

.dm-security {
  padding: 4px 7px;
  border-radius: 999px;
  font-size: 8px;
  font-weight: 900;
}

.dm-security.secure {
  background: #ecfdf3;
  color: #16834b;
}

.dm-security.risk {
  background: #fff0f0;
  color: #c62828;
}

.dm-security.unknown {
  background: #f1f5f9;
  color: #64748b;
}

.dm-info-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  padding: 9px 15px;
  gap: 10px;
}

.dm-info {
  min-width: 0;
  display: flex;
  flex-direction: column;
  gap: 3px;
}

.dm-info span {
  color: #98a2b3;
  font-size: 8px;
  font-weight: 700;
}

.dm-info strong {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  color: #475569;
  font-size: 9px;
}

.dm-controls {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 5px;
  padding: 0 15px 12px;
}

.dm-control {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 3px;
  padding: 7px 3px;
  border-radius: 7px;
  background: #f8fafc;
}

.dm-control span {
  color: #8995a7;
  font-size: 7px;
  font-weight: 800;
}

.dm-control strong {
  font-size: 9px;
  font-weight: 900;
}

.dm-control strong.enabled {
  color: #16834b;
}

.dm-control strong.disabled {
  color: #c62828;
}

.dm-control strong.unknown {
  color: #64748b;
}

.dm-footer {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 8px;
  padding: 10px 15px;
  border-top: 1px solid #edf0f4;
}

.dm-footer div {
  min-width: 0;
  display: flex;
  flex-direction: column;
  gap: 3px;
}

.dm-footer div span {
  color: #98a2b3;
  font-size: 8px;
}

.dm-footer div strong {
  color: #475569;
  font-size: 9px;
}

.dm-footer button {
  border: 1px solid #dbe2ea;
  background: #fff;
  color: #475569;
  border-radius: 7px;
  padding: 7px 9px;
  font-size: 9px;
  font-weight: 800;
  cursor: pointer;
  white-space: nowrap;
}

.dm-footer button:hover {
  background: #f8fafc;
}

.dm-empty {
  min-height: 260px;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-direction: column;
  text-align: center;
  background: #fff;
  border: 1px solid #e5eaf0;
  border-radius: 13px;
}

.dm-empty-icon {
  width: 45px;
  height: 45px;
  display: flex;
  align-items: center;
  justify-content: center;
  margin-bottom: 10px;
  border-radius: 50%;
  background: #f1f5f9;
  color: #64748b;
  font-size: 19px;
}

.dm-empty h3 {
  margin: 0 0 4px;
  font-size: 14px;
}

.dm-empty p {
  margin: 0;
  color: #8995a7;
  font-size: 10px;
}

.dm-loading {
  min-height: 400px;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 12px;
}

.dm-loading > div:last-child {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.dm-loading strong {
  font-size: 13px;
}

.dm-loading span {
  color: #94a3b8;
  font-size: 10px;
}

.dm-spinner {
  width: 27px;
  height: 27px;
  border: 3px solid #e2e8f0;
  border-top-color: #475569;
  border-radius: 50%;
  animation: dm-spin .8s linear infinite;
}

.dm-modal-backdrop {
  position: fixed;
  inset: 0;
  z-index: 1000;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 20px;
  background: rgba(15,23,42,.42);
}

.dm-modal {
  width: min(720px, 100%);
  max-height: calc(100vh - 40px);
  overflow-y: auto;
  padding: 23px;
  border-radius: 16px;
  background: #fff;
  box-shadow: 0 25px 70px rgba(15,23,42,.22);
}

.dm-modal-header {
  display: flex;
  justify-content: space-between;
  gap: 20px;
}

.dm-modal-header h2 {
  margin: 0;
  font-size: 21px;
}

.dm-close {
  width: 31px;
  height: 31px;
  border: 0;
  border-radius: 8px;
  background: #f1f5f9;
  color: #475569;
  font-size: 21px;
  cursor: pointer;
}

.dm-modal-status {
  display: flex;
  align-items: center;
  gap: 9px;
  margin: 17px 0;
}

.dm-detail-section {
  margin-top: 17px;
}

.dm-detail-section h3 {
  margin: 0 0 9px;
  font-size: 13px;
}

.dm-detail-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  border: 1px solid #e8edf3;
  border-radius: 10px;
  overflow: hidden;
}

.dm-detail {
  padding: 11px;
  border-bottom: 1px solid #edf0f4;
}

.dm-detail:nth-child(odd) {
  border-right: 1px solid #edf0f4;
}

.dm-detail span {
  display: block;
  margin-bottom: 4px;
  color: #8995a7;
  font-size: 8px;
  font-weight: 800;
  text-transform: uppercase;
}

.dm-detail strong {
  display: block;
  color: #344054;
  font-size: 10px;
  word-break: break-word;
}

.dm-large-controls {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 9px;
}

.dm-large-control {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 9px;
  padding: 12px;
  border: 1px solid #e8edf3;
  border-radius: 10px;
}

.dm-large-control div {
  display: flex;
  flex-direction: column;
  gap: 3px;
}

.dm-large-control strong {
  color: #344054;
  font-size: 10px;
}

.dm-large-control div span {
  color: #98a2b3;
  font-size: 8px;
}

.dm-large-status {
  padding: 4px 6px;
  border-radius: 6px;
  font-size: 8px;
  font-weight: 900;
}

.dm-large-status.enabled {
  background: #ecfdf3;
  color: #16834b;
}

.dm-large-status.disabled {
  background: #fff0f0;
  color: #c62828;
}

.dm-large-status.unknown {
  background: #f1f5f9;
  color: #64748b;
}

.dm-security-message {
  margin-top: 15px;
  padding: 12px;
  border-radius: 9px;
  background: #f8fafc;
}

.dm-security-message strong {
  display: block;
  margin-bottom: 4px;
  font-size: 10px;
}

.dm-security-message p {
  margin: 0;
  color: #64748b;
  font-size: 10px;
  line-height: 1.5;
}

.dm-modal-actions {
  display: flex;
  justify-content: flex-end;
  gap: 8px;
  margin-top: 20px;
}

.dm-modal-actions button {
  padding: 9px 12px;
  border-radius: 8px;
  font-size: 10px;
  font-weight: 800;
  cursor: pointer;
}

.dm-secondary {
  border: 1px solid #dbe2ea;
  background: #fff;
  color: #475569;
}

.dm-delete {
  border: 1px solid #fecaca;
  background: #fff0f0;
  color: #b42318;
}

@media (max-width: 1200px) {
  .dm-stat-grid {
    grid-template-columns: repeat(3, 1fr);
  }

  .dm-grid {
    grid-template-columns: repeat(2, 1fr);
  }
}

@media (max-width: 850px) {
  .dm-header {
    flex-direction: column;
  }

  .dm-header-actions {
    flex-wrap: wrap;
  }

  .dm-toolbar {
    flex-wrap: wrap;
  }

  .dm-search {
    flex-basis: 100%;
  }

  .dm-grid {
    grid-template-columns: 1fr;
  }
}

@media (max-width: 600px) {
  .dm-page {
    padding: 17px;
  }

  .dm-stat-grid {
    grid-template-columns: 1fr 1fr;
  }

  .dm-detail-grid,
  .dm-large-controls {
    grid-template-columns: 1fr;
  }

  .dm-detail:nth-child(odd) {
    border-right: 0;
  }
}
`;