import { useCallback, useEffect, useMemo, useState } from "react";

const API = "http://localhost:5000/api";

const defaultPolicy = {
  antivirus_required: true,
  firewall_required: true,
  backup_required: true
};

/* =========================================================
   API
========================================================= */

function token() {
  return localStorage.getItem("token");
}

async function api(path, options = {}) {
  const headers = {
    "Content-Type": "application/json",
    ...(options.headers || {})
  };

  const t = token();

  if (t) {
    headers.Authorization = `Bearer ${t}`;
  }

  const res = await fetch(`${API}${path}`, {
    ...options,
    headers
  });

  const text = await res.text();

  let data = {};

  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    data = {
      error: text || "Server returned an invalid response."
    };
  }

  if (!res.ok) {
    if (res.status === 401 || res.status === 403) {
      throw new Error(
        data.error || "Session expired"
      );
    }

    throw new Error(
      data.error || "Request failed"
    );
  }

  return data;
}

/* =========================================================
   HELPERS
========================================================= */

function decodeToken(t) {
  try {
    const payload = t.split(".")[1];

    const normalized =
      payload
        .replace(/-/g, "+")
        .replace(/_/g, "/");

    return JSON.parse(atob(normalized));
  } catch {
    return null;
  }
}

function bool(v) {
  return (
    v === true ||
    v === "true" ||
    v === 1 ||
    v === "1"
  );
}

function onlineState(device) {
  if (
    device.connection_status ===
    "ONLINE"
  ) {
    return true;
  }

  if (
    device.connection_status ===
    "OFFLINE"
  ) {
    return false;
  }

  if (
    typeof device.online ===
    "boolean"
  ) {
    return device.online;
  }

  if (
    device.online === "true" ||
    device.online === 1 ||
    device.online === "1"
  ) {
    return true;
  }

  return false;
}

function controlState(device, control) {
  const status =
    device[
      `${control}_status`
    ];

  if (status === "ENABLED") {
    return true;
  }

  if (status === "DISABLED") {
    return false;
  }

  if (status === "UNKNOWN") {
    return null;
  }

  if (
    device[control] === true ||
    device[control] === "true" ||
    device[control] === 1 ||
    device[control] === "1"
  ) {
    return true;
  }

  if (
    device[control] === false ||
    device[control] === "false" ||
    device[control] === 0 ||
    device[control] === "0"
  ) {
    return false;
  }

  return null;
}

function normalizeDevice(d) {
  return {
    ...d,

    id: d.id,

    name:
      d.name ||
      d.hostname ||
      d.device_id ||
      "Unnamed device",

    hostname:
      d.hostname ||
      d.device_id ||
      d.name ||
      "Unknown",

    device_id:
      d.device_id ||
      d.hostname ||
      d.name ||
      null,

    operating_system:
      d.operating_system ||
      d.operatingSystem ||
      d.platform ||
      "Unknown",

    employee:
      d.employee ||
      d.username ||
      "",

    username:
      d.username ||
      d.employee ||
      "",

    department:
      d.department ||
      "",

    ip_address:
      d.ip_address ||
      d.ipAddress ||
      "",

    cpu:
      d.cpu ||
      "Unknown",

    cpu_cores:
      d.cpu_cores ||
      d.cpuCores ||
      null,

    ram_gb:
      d.ram_gb ??
      d.totalMemoryGB ??
      null,

    free_memory_gb:
      d.free_memory_gb ??
      d.freeMemoryGB ??
      null,

    uptime_minutes:
      d.uptime_minutes ??
      d.uptimeMinutes ??
      null,

    online:
      onlineState(d),

    antivirus:
      controlState(
        d,
        "antivirus"
      ),

    firewall:
      controlState(
        d,
        "firewall"
      ),

    backup:
      controlState(
        d,
        "backup"
      )
  };
}

function secure(device, policy) {
  const antivirus =
    controlState(
      device,
      "antivirus"
    );

  const firewall =
    controlState(
      device,
      "firewall"
    );

  const backup =
    controlState(
      device,
      "backup"
    );

  const online =
    onlineState(device);

  return (
    (!policy.antivirus_required ||
      antivirus === true) &&
    (!policy.firewall_required ||
      firewall === true) &&
    (!policy.backup_required ||
      backup === true) &&
    online
  );
}

function problems(device, policy) {
  const issues = [];

  const antivirus =
    controlState(
      device,
      "antivirus"
    );

  const firewall =
    controlState(
      device,
      "firewall"
    );

  const backup =
    controlState(
      device,
      "backup"
    );

  const online =
    onlineState(device);

  if (
    policy.antivirus_required &&
    antivirus !== true
  ) {
    issues.push(
      antivirus === null
        ? "Antivirus unknown"
        : "Antivirus disabled"
    );
  }

  if (
    policy.firewall_required &&
    firewall !== true
  ) {
    issues.push(
      firewall === null
        ? "Firewall unknown"
        : "Firewall disabled"
    );
  }

  if (
    policy.backup_required &&
    backup !== true
  ) {
    issues.push(
      backup === null
        ? "Backup unknown"
        : "Backup disabled"
    );
  }

  if (!online) {
    issues.push("Offline");
  }

  return issues;
}

function initials(name = "User") {
  return name
    .split(/\s+/)
    .filter(Boolean)
    .map((x) => x[0])
    .slice(0, 2)
    .join("")
    .toUpperCase();
}

function fmtDate(value) {
  if (!value) {
    return "—";
  }

  const date =
    new Date(value);

  if (
    Number.isNaN(
      date.getTime()
    )
  ) {
    return "—";
  }

  return date.toLocaleString([], {
    dateStyle: "medium",
    timeStyle: "short"
  });
}

/* =========================================================
   LOGIN
========================================================= */

function Login({ onLogin }) {
  const [email, setEmail] =
    useState(
      "admin@company.com"
    );

  const [password, setPassword] =
    useState(
      "Admin123456"
    );

  const [loading, setLoading] =
    useState(false);

  const [error, setError] =
    useState("");

  async function submit(e) {
    e.preventDefault();

    setError("");
    setLoading(true);

    try {
      const data =
        await api("/login", {
          method: "POST",
          body: JSON.stringify({
            email,
            password
          })
        });

      localStorage.setItem(
        "token",
        data.token
      );

      const user =
        decodeToken(data.token);

      if (!user) {
        throw new Error(
          "Login succeeded but the session could not be read."
        );
      }

      onLogin(user);
    } catch (error) {
      setError(
        error.message
      );
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="login-shell">

      <div className="login-visual">

        <div className="brand-mark">
          e
        </div>

        <div className="brand-name">
          eDDie
        </div>

        <h1>
          Company IT
          <br />
          <span>
            Security Center
          </span>
        </h1>

        <p>
          Centralized visibility, policy
          enforcement and security
          operations for company
          endpoints.
        </p>

        <div className="security-points">

          <span>
            Endpoint monitoring
          </span>

          <span>
            Policy compliance
          </span>

          <span>
            Audit accountability
          </span>

        </div>

      </div>

      <form
        className="login-card"
        onSubmit={submit}
      >

        <div className="eyebrow">
          SECURE ADMIN PORTAL
        </div>

        <h2>
          Welcome back
        </h2>

        <p className="muted">
          Sign in to manage your
          organization's security.
        </p>

        {error && (
          <div className="error-box">
            {error}
          </div>
        )}

        <label>
          Email address

          <input
            type="email"
            value={email}
            onChange={(e) =>
              setEmail(
                e.target.value
              )
            }
            required
          />
        </label>

        <label>
          Password

          <input
            type="password"
            value={password}
            onChange={(e) =>
              setPassword(
                e.target.value
              )
            }
            required
          />
        </label>

        <button
          className="primary wide"
          disabled={loading}
        >
          {loading
            ? "Signing in..."
            : "Sign in securely"}
        </button>

        <div className="login-note">
          Protected session
          {" · "}
          Role-based access control
        </div>

      </form>

    </div>
  );
}

/* =========================================================
   SIDEBAR
========================================================= */

function Sidebar({
  page,
  setPage,
  user,
  onLogout
}) {
  const admin =
    user.role ===
    "Administrator";

  const manager =
    admin ||
    user.role ===
      "IT Manager";

  const nav = [
    ["dashboard", "", "Overview"],
    ["devices", "", "Devices"],
    ["alerts", "", "Security Alerts"]
  ];

  return (
    <aside className="sidebar">

      <div className="side-brand">

        <div className="brand-mark small">
          e
        </div>

        <div>
          <b>eDDie</b>
          <small>
            IT SECURITY
          </small>
        </div>

      </div>

      <div className="side-label">
        WORKSPACE
      </div>

      {nav.map(
        ([id, icon, label]) => (
          <button
            key={id}
            className={
              page === id
                ? "nav active"
                : "nav"
            }
            onClick={() =>
              setPage(id)
            }
          >

            <span>
              {icon}
            </span>

            {label}

            {id ===
              "alerts" && (
              <span className="nav-dot" />
            )}

          </button>
        )
      )}

      <div className="side-label">
        ADMINISTRATION
      </div>

      {admin && (
        <button
          className={
            page === "users"
              ? "nav active"
              : "nav"
          }
          onClick={() =>
            setPage("users")
          }
        >
          <span />
          Users
        </button>
      )}

      {manager && (
        <button
          className={
            page === "settings"
              ? "nav active"
              : "nav"
          }
          onClick={() =>
            setPage("settings")
          }
        >
          <span />
          Security Policy
        </button>
      )}

      {admin && (
        <button
          className={
            page === "activity"
              ? "nav active"
              : "nav"
          }
          onClick={() =>
            setPage("activity")
          }
        >
          <span />
          Activity Log
        </button>
      )}

      <div className="side-bottom">

        <div className="user-mini">

          <div className="avatar">
            {initials(
              user.name
            )}
          </div>

          <div>
            <b>
              {user.name}
            </b>

            <small>
              {user.role}
            </small>
          </div>

        </div>

        <button
          className="logout"
          onClick={onLogout}
        >
          Sign out
        </button>

      </div>

    </aside>
  );
}

/* =========================================================
   HEADER
========================================================= */

function Header({
  title,
  subtitle,
  user,
  onRefresh,
  loading
}) {
  return (
    <header className="topbar">

      <div>

        <div className="crumb">
          SECURITY CENTER /{" "}
          <span>
            {title.toUpperCase()}
          </span>
        </div>

        <h1>
          {title}
        </h1>

        {subtitle && (
          <p>
            {subtitle}
          </p>
        )}

      </div>

      <div className="top-actions">

        <button
          className="icon-btn"
          title="Refresh"
          onClick={onRefresh}
          disabled={loading}
        >
          {loading
            ? "Loading"
            : "Refresh"}
        </button>

        <div className="top-user">

          <div className="avatar">
            {initials(
              user.name
            )}
          </div>

          <span>
            {user.name}
          </span>

        </div>

      </div>

    </header>
  );
}

/* =========================================================
   STAT
========================================================= */

function Stat({
  icon,
  label,
  value,
  detail,
  tone = "neutral"
}) {
  return (
    <div className="stat-card">

      <div
        className={`stat-icon ${tone}`}
      >
        {icon}
      </div>

      <div className="stat-body">

        <span>
          {label}
        </span>

        <strong>
          {value}
        </strong>

        <small>
          {detail}
        </small>

      </div>

    </div>
  );
}

/* =========================================================
   DASHBOARD
========================================================= */

function Dashboard({
  devices,
  policy,
  setPage
}) {
  const deviceList =
    Array.isArray(devices)
      ? devices
      : [];

  const total =
    deviceList.length;

  const online =
    deviceList.filter(
      (d) =>
        onlineState(d)
    ).length;

  const safe =
    deviceList.filter(
      (d) =>
        secure(d, policy)
    ).length;

  const risk =
    total - safe;

  const rate =
    total
      ? Math.round(
          (safe / total) *
            100
        )
      : 0;

  const alerts =
    deviceList.reduce(
      (count, device) =>
        count +
        problems(
          device,
          policy
        ).length,
      0
    );

  const departments = [
    ...new Set(
      deviceList
        .map(
          (d) =>
            d.department
        )
        .filter(Boolean)
    )
  ];

  return (
    <div>

      <div className="hero-strip">

        <div>

          <span className="pill green">
            SYSTEM OPERATIONAL
          </span>

          <h2>
            Security posture at a glance
          </h2>

          <p>
            Monitor endpoints, enforce
            policies and respond to
            security issues.
          </p>

        </div>

        <button
          className="primary"
          onClick={() =>
            setPage("devices")
          }
        >
          Manage devices
        </button>

      </div>

      <div className="stats-grid">

        <Stat
          icon=""
          label="Total devices"
          value={total}
          detail="Registered endpoints"
          tone="blue"
        />

        <Stat
          icon=""
          label="Secure devices"
          value={safe}
          detail={`${rate}% of fleet compliant`}
          tone="green"
        />

        <Stat
          icon=""
          label="At risk"
          value={risk}
          detail={
            risk
              ? "Needs attention"
              : "No critical exposure"
          }
          tone="red"
        />

        <Stat
          icon=""
          label="Online now"
          value={online}
          detail={`${
            total
              ? Math.round(
                  (online /
                    total) *
                    100
                )
              : 0
          }% reachable`}
          tone="purple"
        />

      </div>

      <div className="content-grid">

        <section className="panel posture">

          <div className="panel-head">

            <div>

              <h3>
                Security posture
              </h3>

              <p>
                Current compliance
                against your active
                policy
              </p>

            </div>

            <b className="big-rate">
              {rate}%
            </b>

          </div>

          <div className="progress">

            <span
              style={{
                width:
                  `${rate}%`
              }}
            />

          </div>

          <div className="legend">

            <span>
              <i className="dot green-bg" />
              Compliant{" "}
              <b>{safe}</b>
            </span>

            <span>
              <i className="dot red-bg" />
              At risk{" "}
              <b>{risk}</b>
            </span>

            <span>
              <i className="dot gray-bg" />
              Total{" "}
              <b>{total}</b>
            </span>

          </div>

          <div className="policy-mini">

            <b>
              Active controls
            </b>

            <span>
              Antivirus{" "}
              {policy.antivirus_required
                ? "Required"
                : "Optional"}
            </span>

            <span>
              Firewall{" "}
              {policy.firewall_required
                ? "Required"
                : "Optional"}
            </span>

            <span>
              Backup{" "}
              {policy.backup_required
                ? "Required"
                : "Optional"}
            </span>

          </div>

        </section>

        <section className="panel">

          <div className="panel-head">

            <div>

              <h3>
                Attention required
              </h3>

              <p>
                Endpoints with security
                findings
              </p>

            </div>

            <button
              className="text-btn"
              onClick={() =>
                setPage("alerts")
              }
            >
              View all
            </button>

          </div>

          {deviceList
            .filter(
              (d) =>
                !secure(
                  d,
                  policy
                )
            )
            .slice(0, 4)
            .map(
              (device) => (
                <div
                  className="issue-row"
                  key={device.id}
                >

                  <div className="device-avatar">
                  </div>

                  <div>

                    <b>
                      {device.name}
                    </b>

                    <small>
                      {problems(
                        device,
                        policy
                      ).join(
                        " · "
                      )}
                    </small>

                  </div>

                  <span className="badge risk">
                    At risk
                  </span>

                </div>
              )
            )}

          {!risk && (
            <div className="empty small">
              All registered devices
              meet the active policy.
            </div>
          )}

        </section>

      </div>

      <div className="content-grid lower">

        <section className="panel">

          <div className="panel-head">

            <div>

              <h3>
                Fleet by department
              </h3>

              <p>
                Device distribution
              </p>

            </div>

          </div>

          {departments.length ? (
            departments.map(
              (department) => {
                const count =
                  deviceList.filter(
                    (d) =>
                      d.department ===
                      department
                  ).length;

                return (
                  <div
                    className="bar-row"
                    key={department}
                  >

                    <span>
                      {department}
                    </span>

                    <div className="bar">

                      <i
                        style={{
                          width:
                            `${total ? (count / total) * 100 : 0}%`
                        }}
                      />

                    </div>

                    <b>
                      {count}
                    </b>

                  </div>
                );
              }
            )
          ) : (
            <div className="empty">
              No departments yet.
            </div>
          )}

        </section>

        <section className="panel">

          <div className="panel-head">

            <div>

              <h3>
                Security events
              </h3>

              <p>
                Live summary
              </p>

            </div>

          </div>

          <div className="event-stat">

            <span />

            <div>

              <b>
                {alerts}
              </b>

              <small>
                Open security findings
              </small>

            </div>

          </div>

          <div className="event-stat">

            <span />

            <div>

              <b>
                {online}
              </b>

              <small>
                Devices currently online
              </small>

            </div>

          </div>

          <div className="event-stat">

            <span />

            <div>

              <b>
                {safe}
              </b>

              <small>
                Devices meeting policy
              </small>

            </div>

          </div>

        </section>

      </div>

    </div>
  );
}

/* =========================================================
   DEVICE MODAL
========================================================= */

const emptyDevice = {
  name: "",
  operatingSystem: "Windows 11",
  employee: "",
  department: "",
  ipAddress: "",
  antivirus: true,
  firewall: true,
  backup: true
};

function DeviceModal({
  device,
  onClose,
  onSaved
}) {
  const [form, setForm] =
    useState(
      device
        ? { ...device }
        : { ...emptyDevice }
    );

  const [saving, setSaving] =
    useState(false);

  const [error, setError] =
    useState("");

  function change(key, value) {
    setForm((current) => ({
      ...current,
      [key]: value
    }));
  }

  async function save(e) {
    e.preventDefault();

    setError("");
    setSaving(true);

    try {
      const payload = {
        ...form,

        /*
          Online status is intentionally NOT
          controlled by the administrator.

          Sentinel Agent heartbeat determines
          whether the endpoint is online.
        */
        online: device
          ? undefined
          : false
      };

      delete payload.online;

      const data =
        await api(
          device
            ? `/devices/${device.id}`
            : "/devices",
          {
            method:
              device
                ? "PUT"
                : "POST",
            body:
              JSON.stringify(
                payload
              )
          }
        );

      onSaved(
        normalizeDevice(
          data
        )
      );
    } catch (error) {
      setError(
        error.message
      );
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="modal-backdrop">

      <form
        className="modal large"
        onSubmit={save}
      >

        <div className="modal-head">

          <div>

            <span className="eyebrow">
              {device
                ? "EDIT ENDPOINT"
                : "REGISTER ENDPOINT"}
            </span>

            <h2>
              {device
                ? "Update device"
                : "Add a company device"}
            </h2>

          </div>

          <button
            type="button"
            className="close"
            onClick={onClose}
          >
            ×
          </button>

        </div>

        {error && (
          <div className="error-box">
            {error}
          </div>
        )}

        <div className="form-grid">

          <label>
            Device name

            <input
              value={
                form.name || ""
              }
              onChange={(e) =>
                change(
                  "name",
                  e.target.value
                )
              }
              required
              placeholder="e.g. Finance-Laptop-01"
            />
          </label>

          <label>
            Operating system

            <select
              value={
                form.operatingSystem ||
                form.operating_system ||
                "Windows 11"
              }
              onChange={(e) =>
                change(
                  "operatingSystem",
                  e.target.value
                )
              }
            >
              <option>
                Windows 11
              </option>

              <option>
                Windows 10
              </option>

              <option>
                macOS
              </option>

              <option>
                Ubuntu Linux
              </option>

              <option>
                Other
              </option>
            </select>
          </label>

          <label>
            Assigned employee

            <input
              value={
                form.employee ||
                ""
              }
              onChange={(e) =>
                change(
                  "employee",
                  e.target.value
                )
              }
              placeholder="Employee name"
            />
          </label>

          <label>
            Department

            <input
              value={
                form.department ||
                ""
              }
              onChange={(e) =>
                change(
                  "department",
                  e.target.value
                )
              }
              placeholder="e.g. Finance"
            />
          </label>

          <label>
            IP address

            <input
              value={
                form.ipAddress ||
                form.ip_address ||
                ""
              }
              onChange={(e) =>
                change(
                  "ipAddress",
                  e.target.value
                )
              }
              placeholder="192.168.1.20"
            />
          </label>

        </div>

        <div className="control-box">

          <b>
            Security controls
          </b>

          <p>
            These values represent the
            endpoint's current protection
            state. Sentinel Agent can
            update them automatically.
          </p>

          <div className="toggle-grid">

            {[
              [
                "antivirus",
                "Antivirus",
                "Malware protection"
              ],
              [
                "firewall",
                "Firewall",
                "Network protection"
              ],
              [
                "backup",
                "Backup",
                "Data recovery"
              ]
            ].map(
              ([key, label, description]) => (
                <button
                  type="button"
                  className={`toggle-card ${
                    bool(form[key])
                      ? "on"
                      : ""
                  }`}
                  key={key}
                  onClick={() =>
                    change(
                      key,
                      !bool(
                        form[key]
                      )
                    )
                  }
                >

                  <span className="toggle-check">
                    {bool(
                      form[key]
                    )
                      ? "Enabled"
                      : "Disabled"}
                  </span>

                  <span>

                    <b>
                      {label}
                    </b>

                    <small>
                      {description}
                    </small>

                  </span>

                  <strong>
                    {bool(
                      form[key]
                    )
                      ? "Enabled"
                      : "Disabled"}
                  </strong>

                </button>
              )
            )}

          </div>

        </div>

        {!device && (
          <div className="info-panel">

            <h3>
              Automatic connection monitoring
            </h3>

            <p>
              This device will initially
              appear as <b>Offline</b>.
              Once Sentinel Agent is
              installed and sends its first
              heartbeat, the system will
              automatically mark it Online.
            </p>

          </div>
        )}

        {device && (
          <div className="info-panel">

            <h3>
              Connection status
            </h3>

            <p>
              Online/Offline status is
              controlled automatically by
              Sentinel Agent heartbeats.
              The administrator cannot
              manually override it here.
            </p>

          </div>
        )}

        <div className="modal-actions">

          <button
            type="button"
            className="secondary"
            onClick={onClose}
          >
            Cancel
          </button>

          <button
            className="primary"
            disabled={saving}
          >
            {saving
              ? "Saving..."
              : device
              ? "Save changes"
              : "Register device"}
          </button>

        </div>

      </form>

    </div>
  );
}

/* =========================================================
   DEVICE DETAILS
========================================================= */

function DeviceDetails({
  device,
  policy,
  canManage,
  onClose,
  onEdit
}) {
  if (!device) {
    return null;
  }

  const isSecure =
    secure(
      device,
      policy
    );

  const antivirus =
    controlState(
      device,
      "antivirus"
    );

  const firewall =
    controlState(
      device,
      "firewall"
    );

  const backup =
    controlState(
      device,
      "backup"
    );

  const online =
    onlineState(device);

  function controlClass(value) {
    return value === true
      ? "on"
      : "";
  }

  function controlText(value) {
    if (value === true) {
      return "Enabled";
    }

    if (value === false) {
      return "Disabled";
    }

    return "Unknown";
  }

  return (
    <div className="modal-backdrop">

      <div className="modal large">

        <div className="modal-head">

          <div>

            <span className="eyebrow">
              ENDPOINT DETAILS
            </span>

            <h2>
              {device.name}
            </h2>

          </div>

          <button
            className="close"
            onClick={onClose}
          >
            ×
          </button>

        </div>

        <div className="device-detail-status">

          <span
            className={`badge ${
              isSecure
                ? "secure"
                : "risk"
            }`}
          >
            {isSecure
              ? "Secure"
              : "At risk"}
          </span>

          <span
            className={`connection ${
              online
                ? "online"
                : "offline"
            }`}
          >
            <i />

            {online
              ? "Online"
              : "Offline"}
          </span>

        </div>

        <div className="device-details-grid">

          <div className="detail-card">
            <span>
              Operating System
            </span>

            <strong>
              {device.operating_system ||
                "Unknown"}
            </strong>
          </div>

          <div className="detail-card">
            <span>
              Hostname
            </span>

            <strong>
              {device.hostname ||
                device.name ||
                "Unknown"}
            </strong>
          </div>

          <div className="detail-card">
            <span>
              Username
            </span>

            <strong>
              {device.username ||
                "Unknown"}
            </strong>
          </div>

          <div className="detail-card">
            <span>
              Department
            </span>

            <strong>
              {device.department ||
                "Unassigned"}
            </strong>
          </div>

          <div className="detail-card">
            <span>
              IP Address
            </span>

            <strong>
              {device.ip_address ||
                "Unknown"}
            </strong>
          </div>

          <div className="detail-card">
            <span>
              CPU
            </span>

            <strong>
              {device.cpu ||
                "Unknown"}
            </strong>
          </div>

          <div className="detail-card">
            <span>
              CPU Cores
            </span>

            <strong>
              {device.cpu_cores ||
                "Unknown"}
            </strong>
          </div>

          <div className="detail-card">
            <span>
              Total RAM
            </span>

            <strong>
              {device.ram_gb != null
                ? `${device.ram_gb} GB`
                : "Unknown"}
            </strong>
          </div>

          <div className="detail-card">
            <span>
              Free RAM
            </span>

            <strong>
              {device.free_memory_gb !=
              null
                ? `${device.free_memory_gb} GB`
                : "Unknown"}
            </strong>
          </div>

          <div className="detail-card">
            <span>
              Device ID
            </span>

            <strong>
              #{device.id}
            </strong>
          </div>

          <div className="detail-card">
            <span>
              Last Seen
            </span>

            <strong>
              {fmtDate(
                device.last_seen
              )}
            </strong>
          </div>

          <div className="detail-card">
            <span>
              Uptime
            </span>

            <strong>
              {device.uptime_minutes !=
              null
                ? `${device.uptime_minutes} min`
                : "Unknown"}
            </strong>
          </div>

        </div>

        <div className="control-box">

          <b>
            Security controls
          </b>

          <p>
            Current protection state
            reported for this endpoint.
          </p>

          <div className="toggle-grid">

            {[
              [
                "Antivirus",
                antivirus,
                "Malware protection"
              ],
              [
                "Firewall",
                firewall,
                "Network protection"
              ],
              [
                "Backup",
                backup,
                "Data recovery"
              ]
            ].map(
              ([label, value, description]) => (
                <div
                  className={`toggle-card ${controlClass(
                    value
                  )}`}
                  key={label}
                >

                  <span className="toggle-check">
                    {controlText(
                      value
                    )}
                  </span>

                  <span>

                    <b>
                      {label}
                    </b>

                    <small>
                      {description}
                    </small>

                  </span>

                  <strong>
                    {controlText(
                      value
                    )}
                  </strong>

                </div>
              )
            )}

          </div>

        </div>

        <div className="modal-actions">

          <button
            className="secondary"
            onClick={onClose}
          >
            Close
          </button>

          {canManage && (
            <button
              className="primary"
              onClick={onEdit}
            >
              Edit device
            </button>
          )}

        </div>

      </div>

    </div>
  );
}

/* =========================================================
   DEVICES
========================================================= */

function Devices({
  devices,
  setDevices,
  policy,
  user
}) {
  const deviceList =
    Array.isArray(devices)
      ? devices
      : [];

  const [query, setQuery] =
    useState("");

  const [filter, setFilter] =
    useState("all");

  const [department, setDepartment] =
    useState("all");

  const [modal, setModal] =
    useState(null);

  const [selected, setSelected] =
    useState(null);

  const [error, setError] =
    useState("");

  const canManage =
    user.role !==
    "IT Staff";

  const departments = [
    ...new Set(
      deviceList
        .map(
          (d) =>
            d.department
        )
        .filter(Boolean)
    )
  ];

  const rows = useMemo(
    () => {
      return deviceList.filter(
        (device) => {
          const q =
            query
              .toLowerCase()
              .trim();

          const matchesSearch =
            !q ||
            [
              device.name,
              device.employee,
              device.department,
              device.operating_system,
              device.ip_address,
              device.hostname,
              device.username
            ].some((value) =>
              String(
                value || ""
              )
                .toLowerCase()
                .includes(q)
            );

          const online =
            onlineState(
              device
            );

          let matchesFilter =
            true;

          if (
            filter ===
            "online"
          ) {
            matchesFilter =
              online;
          }

          if (
            filter ===
            "offline"
          ) {
            matchesFilter =
              !online;
          }

          if (
            filter ===
            "secure"
          ) {
            matchesFilter =
              secure(
                device,
                policy
              );
          }

          if (
            filter ===
            "risk"
          ) {
            matchesFilter =
              !secure(
                device,
                policy
              );
          }

          const matchesDepartment =
            department ===
              "all" ||
            device.department ===
              department;

          return (
            matchesSearch &&
            matchesFilter &&
            matchesDepartment
          );
        }
      );
    },
    [
      deviceList,
      query,
      filter,
      department,
      policy
    ]
  );

  async function removeDevice(
    device
  ) {
    if (
      !window.confirm(
        `Remove ${device.name} from the system?`
      )
    ) {
      return;
    }

    try {
      await api(
        `/devices/${device.id}`,
        {
          method: "DELETE"
        }
      );

      setDevices(
        (current) =>
          current.filter(
            (item) =>
              item.id !==
              device.id
          )
      );

      if (
        selected?.id ===
        device.id
      ) {
        setSelected(null);
      }
    } catch (error) {
      setError(
        error.message
      );
    }
  }

  function savedDevice(device) {
    setDevices(
      (current) => {
        const exists =
          current.some(
            (item) =>
              item.id ===
              device.id
          );

        if (exists) {
          return current.map(
            (item) =>
              item.id ===
              device.id
                ? device
                : item
          );
        }

        return [
          device,
          ...current
        ];
      }
    );

    setModal(null);
  }

  function countFilter(
    type
  ) {
    if (type === "all") {
      return deviceList.length;
    }

    if (type === "online") {
      return deviceList.filter(
        onlineState
      ).length;
    }

    if (type === "offline") {
      return deviceList.filter(
        (device) =>
          !onlineState(
            device
          )
      ).length;
    }

    if (type === "secure") {
      return deviceList.filter(
        (device) =>
          secure(
            device,
            policy
          )
      ).length;
    }

    return deviceList.filter(
      (device) =>
        !secure(
          device,
          policy
        )
    ).length;
  }

  return (
    <div>

      <div className="toolbar">

        <div className="search">

          <span />

          <input
            placeholder="Search devices, employees, departments..."
            value={query}
            onChange={(e) =>
              setQuery(
                e.target.value
              )
            }
          />

        </div>

        {canManage && (
          <button
            className="primary"
            onClick={() =>
              setModal("add")
            }
          >
            Add device
          </button>
        )}

      </div>

      {error && (
        <div className="error-box">
          {error}
        </div>
      )}

      <div className="filter-row">

        <div className="tabs">

          {[
            ["all", "All"],
            ["online", "Online"],
            ["offline", "Offline"],
            ["secure", "Secure"],
            ["risk", "At risk"]
          ].map(
            ([value, label]) => (
              <button
                key={value}
                className={
                  filter === value
                    ? "selected"
                    : ""
                }
                onClick={() =>
                  setFilter(
                    value
                  )
                }
              >

                {label}

                <span>
                  {countFilter(
                    value
                  )}
                </span>

              </button>
            )
          )}

        </div>

        <select
          className="compact-select"
          value={department}
          onChange={(e) =>
            setDepartment(
              e.target.value
            )
          }
        >

          <option value="all">
            All departments
          </option>

          {departments.map(
            (item) => (
              <option
                key={item}
                value={item}
              >
                {item}
              </option>
            )
          )}

        </select>

      </div>

      <section className="panel table-panel">

        <div className="panel-head">

          <div>

            <h3>
              Company endpoints
            </h3>

            <p>
              {rows.length} of{" "}
              {deviceList.length} devices
              shown
            </p>

          </div>

          <span className="live-indicator">
            Live data
          </span>

        </div>

        <div className="table-wrap">

          <table>

            <thead>

              <tr>
                <th>DEVICE</th>
                <th>ASSIGNED TO</th>
                <th>OS</th>
                <th>CONNECTION</th>
                <th>PROTECTION</th>
                <th>STATUS</th>
                <th>ACTIONS</th>
              </tr>

            </thead>

            <tbody>

              {rows.map(
                (device) => {
                  const antivirus =
                    controlState(
                      device,
                      "antivirus"
                    );

                  const firewall =
                    controlState(
                      device,
                      "firewall"
                    );

                  const backup =
                    controlState(
                      device,
                      "backup"
                    );

                  const online =
                    onlineState(
                      device
                    );

                  const status =
                    secure(
                      device,
                      policy
                    );

                  return (
                    <tr
                      key={
                        device.id
                      }
                    >

                      <td>

                        <div className="device-cell">

                          <div className="device-avatar">
                          </div>

                          <div>

                            <b>
                              {device.name}
                            </b>

                            <small>
                              {device.ip_address ||
                                "IP unknown"}
                            </small>

                          </div>

                        </div>

                      </td>

                      <td>

                        <b className="normal">
                          {device.employee ||
                            device.username ||
                            "Unassigned"}
                        </b>

                        <small>
                          {device.department ||
                            "Unassigned"}
                        </small>

                      </td>

                      <td>

                        <span className="os-chip">
                          {device.operating_system ||
                            "Unknown"}
                        </span>

                      </td>

                      <td>

                        <span
                          className={`connection ${
                            online
                              ? "online"
                              : "offline"
                          }`}
                        >
                          <i />

                          {online
                            ? "Online"
                            : "Offline"}
                        </span>

                      </td>

                      <td>

                        <div className="control-chips">

                          <span
                            className={
                              antivirus ===
                              true
                                ? "good"
                                : antivirus ===
                                  null
                                ? "unknown"
                                : "bad"
                            }
                          >
                            AV
                          </span>

                          <span
                            className={
                              firewall ===
                              true
                                ? "good"
                                : firewall ===
                                  null
                                ? "unknown"
                                : "bad"
                            }
                          >
                            FW
                          </span>

                          <span
                            className={
                              backup ===
                              true
                                ? "good"
                                : backup ===
                                  null
                                ? "unknown"
                                : "bad"
                            }
                          >
                            BK
                          </span>

                        </div>

                      </td>

                      <td>

                        <span
                          className={`badge ${
                            status
                              ? "secure"
                              : "risk"
                          }`}
                        >
                          {status
                            ? "Secure"
                            : "At risk"}
                        </span>

                        {!status && (
                          <small className="reason">
                            {problems(
                              device,
                              policy
                            ).join(
                              ", "
                            )}
                          </small>
                        )}

                      </td>

                      <td>

                        <div className="actions">

                          <button
                            title="View device"
                            onClick={() =>
                              setSelected(
                                device
                              )
                            }
                          >
                            View
                          </button>

                          <button
                            title="Edit"
                            onClick={() =>
                              setModal(
                                device
                              )
                            }
                            disabled={
                              !canManage
                            }
                          >
                            Edit
                          </button>

                          <button
                            title="Delete"
                            onClick={() =>
                              removeDevice(
                                device
                              )
                            }
                            disabled={
                              !canManage
                            }
                          >
                            Delete
                          </button>

                        </div>

                      </td>

                    </tr>
                  );
                }
              )}

            </tbody>

          </table>

          {!rows.length && (
            <div className="empty">
              No devices match your
              filters.
            </div>
          )}

        </div>

      </section>

      {selected && (
        <DeviceDetails
          device={selected}
          policy={policy}
          canManage={canManage}
          onClose={() =>
            setSelected(null)
          }
          onEdit={() => {
            setModal(
              selected
            );
            setSelected(null);
          }}
        />
      )}

      {modal && (
        <DeviceModal
          device={
            modal === "add"
              ? null
              : modal
          }
          onClose={() =>
            setModal(null)
          }
          onSaved={
            savedDevice
          }
        />
      )}

    </div>
  );
}

/* =========================================================
   ALERTS
========================================================= */

function Alerts({
  setPage,
  user
}) {
  const [alerts, setAlerts] =
    useState([]);

  const [loading, setLoading] =
    useState(false);

  const [error, setError] =
    useState("");

  const [filter, setFilter] =
    useState("OPEN");

  const canResolve =
    user.role ===
      "Administrator" ||
    user.role ===
      "IT Manager";

  const loadAlerts =
    useCallback(
      async () => {
        setLoading(true);

        try {
          const data =
            await api(
              "/security-alerts"
            );

          setAlerts(
            Array.isArray(data)
              ? data
              : data.alerts || []
          );

          setError("");
        } catch (error) {
          setError(
            error.message
          );
        } finally {
          setLoading(false);
        }
      },
      []
    );

  useEffect(() => {
    loadAlerts();

    const interval =
      setInterval(
        loadAlerts,
        15000
      );

    return () =>
      clearInterval(
        interval
      );
  }, [loadAlerts]);

  async function resolveAlert(
    id
  ) {
    try {
      setError("");

      await api(
        `/security-alerts/${id}/resolve`,
        {
          method: "PUT"
        }
      );

      await loadAlerts();
    } catch (error) {
      setError(
        error.message
      );
    }
  }

  const openCount =
    alerts.filter(
      (alert) =>
        alert.status ===
        "OPEN"
    ).length;

  const resolvedCount =
    alerts.filter(
      (alert) =>
        alert.status ===
        "RESOLVED"
    ).length;

  const criticalCount =
    alerts.filter(
      (alert) =>
        alert.status ===
          "OPEN" &&
        String(
          alert.severity
        ).toLowerCase() ===
          "critical"
    ).length;

  const filtered =
    alerts.filter(
      (alert) => {
        if (
          filter ===
          "ALL"
        ) {
          return true;
        }

        return (
          alert.status ===
          filter
        );
      }
    );

  return (
    <div>

      <div className="hero-strip compact">

        <div>

          <span className="pill red">
            {openCount} OPEN ALERTS
          </span>

          <h2>
            Security alerts
          </h2>

          <p>
            Automatically detected
            security conditions from
            company endpoints.
          </p>

        </div>

        <button
          className="secondary"
          onClick={() =>
            setPage("devices")
          }
        >
          Review devices
        </button>

      </div>

      {error && (
        <div className="error-box">
          {error}
        </div>
      )}

      <div className="stats-grid">

        <Stat
          icon=""
          label="Open alerts"
          value={openCount}
          detail="Require attention"
          tone="red"
        />

        <Stat
          icon=""
          label="Critical"
          value={criticalCount}
          detail="High-priority findings"
          tone="red"
        />

        <Stat
          icon=""
          label="Resolved"
          value={resolvedCount}
          detail="Previously resolved"
          tone="green"
        />

        <Stat
          icon=""
          label="Open findings"
          value={alerts.length}
          detail="Stored in database"
          tone="blue"
        />

      </div>

      <section className="panel table-panel">

        <div className="panel-head">

          <div>

            <h3>
              Security findings
            </h3>

            <p>
              Alerts are generated
              automatically by Sentinel.
            </p>

          </div>

          <button
            className="icon-btn"
            onClick={loadAlerts}
            disabled={loading}
            title="Refresh alerts"
          >
            {loading
              ? "Loading"
              : "Refresh"}
          </button>

        </div>

        <div className="filter-row">

          <div className="tabs">

            <button
              className={
                filter === "OPEN"
                  ? "selected"
                  : ""
              }
              onClick={() =>
                setFilter("OPEN")
              }
            >
              Open
              <span>
                {openCount}
              </span>
            </button>

            <button
              className={
                filter ===
                "RESOLVED"
                  ? "selected"
                  : ""
              }
              onClick={() =>
                setFilter(
                  "RESOLVED"
                )
              }
            >
              Resolved
              <span>
                {resolvedCount}
              </span>
            </button>

            <button
              className={
                filter === "ALL"
                  ? "selected"
                  : ""
              }
              onClick={() =>
                setFilter("ALL")
              }
            >
              All
              <span>
                {alerts.length}
              </span>
            </button>

          </div>

        </div>

        {filtered.length ? (

          <div className="alert-list">

            {filtered.map(
              (alert) => {
                const severity =
                  String(
                    alert.severity ||
                    "warning"
                  ).toLowerCase();

                const isCritical =
                  severity ===
                  "critical";

                return (
                  <div
                    className="alert-row"
                    key={
                      alert.id
                    }
                  >

                    <div
                      className={`alert-icon ${
                        isCritical
                          ? "critical"
                          : "warning"
                      }`}
                    >
                      {isCritical
                        ? "Critical"
                        : "Warning"}
                    </div>

                    <div className="alert-main">

                      <b>
                        {alert.alert_type ||
                          "Security alert"}
                      </b>

                      <span>
                        {alert.device_name ||
                          alert.hostname ||
                          "Unknown device"}

                        {alert.employee
                          ? ` · ${alert.employee}`
                          : ""}

                        {alert.department
                          ? ` · ${alert.department}`
                          : ""}
                      </span>

                      <small>
                        {alert.message ||
                          "Security condition detected."}
                      </small>

                      <small>
                        IP:{" "}
                        {alert.ip_address ||
                          "Unknown"}

                        {" · "}

                        Detected:{" "}
                        {fmtDate(
                          alert.created_at
                        )}

                        {alert.resolved_at &&
                          ` · Resolved: ${fmtDate(
                            alert.resolved_at
                          )}`}
                      </small>

                    </div>

                    <div className="alert-actions">

                      <span
                        className={`badge ${
                          alert.status ===
                          "RESOLVED"
                            ? "secure"
                            : isCritical
                            ? "risk"
                            : "warning"
                        }`}
                      >
                        {alert.status ===
                        "RESOLVED"
                          ? "Resolved"
                          : isCritical
                          ? "Critical"
                          : "Warning"}
                      </span>

                      {alert.status ===
                        "OPEN" &&
                        canResolve && (
                          <button
                            className="secondary"
                            onClick={() =>
                              resolveAlert(
                                alert.id
                              )
                            }
                          >
                            Resolve
                          </button>
                        )}

                    </div>

                  </div>
                );
              }
            )}

          </div>

        ) : (

          <div className="empty success-empty">

            <div>
              No alerts
            </div>

            <b>
              {filter ===
              "OPEN"
                ? "No open alerts"
                : filter ===
                  "RESOLVED"
                ? "No resolved alerts"
                : "No security alerts"}
            </b>

            <span>
              Sentinel has no matching
              security findings at the
              moment.
            </span>

          </div>

        )}

      </section>

      <section className="panel info-panel">

        <h3>
          Automatic detection
        </h3>

        <p>
          Sentinel receives endpoint
          heartbeats and stores security
          findings in PostgreSQL. Alerts
          remain open until the underlying
          condition is cleared.
        </p>

      </section>

    </div>
  );
}

/* =========================================================
   SECURITY SETTINGS
========================================================= */

function Settings({
  policy,
  setPolicy
}) {
  const [draft, setDraft] =
    useState(
      policy
    );

  const [saving, setSaving] =
    useState(false);

  const [message, setMessage] =
    useState("");

  const [error, setError] =
    useState("");

  useEffect(() => {
    setDraft(
      policy
    );
  }, [policy]);

  async function save() {
    setSaving(true);
    setMessage("");
    setError("");

    try {
      const data =
        await api(
          "/security-policy",
          {
            method: "PUT",
            body:
              JSON.stringify(
                draft
              )
          }
        );

      setPolicy({
        ...defaultPolicy,
        ...data
      });

      setMessage(
        "Security policy saved successfully."
      );
    } catch (error) {
      setError(
        error.message
      );
    } finally {
      setSaving(false);
    }
  }

  function setting(
    key,
    title,
    description,
    icon
  ) {
    return (
      <div className="setting-row">

        <div className="setting-icon">
          {icon}
        </div>

        <div className="setting-copy">

          <b>
            {title}
          </b>

          <span>
            {description}
          </span>

        </div>

        <button
          className={`switch ${
            draft[key]
              ? "on"
              : ""
          }`}
          onClick={() =>
            setDraft(
              (current) => ({
                ...current,
                [key]:
                  !current[key]
              })
            )
          }
        >

          <i />

          {draft[key]
            ? "Required"
            : "Optional"}

        </button>

      </div>
    );
  }

  return (
    <div>

      <div className="hero-strip compact">

        <div>

          <span className="pill blue">
            POLICY CONTROL
          </span>

          <h2>
            Endpoint security policy
          </h2>

          <p>
            Define which controls are
            mandatory for a device to
            be considered secure.
          </p>

        </div>

      </div>

      {error && (
        <div className="error-box">
          {error}
        </div>
      )}

      {message && (
        <div className="success-box">
          {message}
        </div>
      )}

      <section className="panel settings-panel">

        <div className="panel-head">

          <div>

            <h3>
              Required controls
            </h3>

            <p>
              Changes apply immediately
              to compliance calculations.
            </p>

          </div>

        </div>

        {setting(
          "antivirus_required",
          "Antivirus protection",
          "Every managed endpoint must have antivirus protection enabled.",
          ""
        )}

        {setting(
          "firewall_required",
          "Firewall protection",
          "Every managed endpoint must have its host firewall enabled.",
          ""
        )}

        {setting(
          "backup_required",
          "Data backup",
          "Every managed endpoint must have backup protection enabled.",
          ""
        )}

        <div className="save-strip">

          <div>

            <b>
              Policy status
            </b>

            <span>
              {
                Object.values(
                  draft
                ).filter(Boolean)
                  .length
              }{" "}
              of 3 controls
              required
            </span>

          </div>

          <button
            className="primary"
            onClick={save}
            disabled={saving}
          >
            {saving
              ? "Saving..."
              : "Save policy"}
          </button>

        </div>

      </section>

      <section className="panel info-panel">

        <h3>
          How compliance works
        </h3>

        <p>
          A device is marked{" "}
          <b>Secure</b> when every
          required control is enabled
          and the endpoint is online.
        </p>

      </section>

    </div>
  );
}

/* =========================================================
   USERS
========================================================= */

function Users({ user }) {
  const [users, setUsers] =
    useState([]);

  const [open, setOpen] =
    useState(false);

  const [saving, setSaving] =
    useState(false);

  const [error, setError] =
    useState("");

  const [form, setForm] =
    useState({
      name: "",
      email: "",
      password: "",
      role: "IT Staff"
    });

  const load =
    useCallback(
      async () => {
        try {
          const data =
            await api(
              "/users"
            );

          setUsers(
            Array.isArray(data)
              ? data
              : []
          );

          setError("");
        } catch (error) {
          setError(
            error.message
          );
        }
      },
      []
    );

  useEffect(() => {
    load();
  }, [load]);

  async function addUser(e) {
    e.preventDefault();

    setSaving(true);
    setError("");

    try {
      const created =
        await api(
          "/users",
          {
            method: "POST",
            body:
              JSON.stringify(
                form
              )
          }
        );

      setUsers(
        (current) => [
          created,
          ...current
        ]
      );

      setOpen(false);

      setForm({
        name: "",
        email: "",
        password: "",
        role: "IT Staff"
      });
    } catch (error) {
      setError(
        error.message
      );
    } finally {
      setSaving(false);
    }
  }

  async function deleteUser(
    target
  ) {
    if (
      target.id ===
      user.id
    ) {
      alert(
        "You cannot delete your own active account."
      );

      return;
    }

    if (
      !window.confirm(
        `Delete ${target.name}'s account?`
      )
    ) {
      return;
    }

    try {
      await api(
        `/users/${target.id}`,
        {
          method: "DELETE"
        }
      );

      setUsers(
        (current) =>
          current.filter(
            (item) =>
              item.id !==
              target.id
          )
      );
    } catch (error) {
      setError(
        error.message
      );
    }
  }

  return (
    <div>

      <div className="toolbar">

        <div>

          <h2 className="page-title">
            User access
          </h2>

          <p className="muted">
            Manage people who can
            access the security center.
          </p>

        </div>

        <button
          className="primary"
          onClick={() =>
            setOpen(true)
          }
        >
          Add user
        </button>

      </div>

      {error && (
        <div className="error-box">
          {error}
        </div>
      )}

      <section className="panel table-panel">

        <div className="panel-head">

          <div>

            <h3>
              Authorized users
            </h3>

            <p>
              {users.length} accounts
            </p>

          </div>

        </div>

        <div className="table-wrap">

          <table>

            <thead>

              <tr>
                <th>USER</th>
                <th>EMAIL</th>
                <th>ROLE</th>
                <th>ACTIONS</th>
              </tr>

            </thead>

            <tbody>

              {users.map(
                (target) => (
                  <tr
                    key={
                      target.id
                    }
                  >

                    <td>

                      <div className="device-cell">

                        <div className="avatar">
                          {initials(
                            target.name
                          )}
                        </div>

                        <div>

                          <b>
                            {target.name}
                          </b>

                          <small>
                            ID #
                            {target.id}
                          </small>

                        </div>

                      </div>

                    </td>

                    <td className="normal">
                      {target.email}
                    </td>

                    <td>

                      <span className="role-chip">
                        {target.role}
                      </span>

                    </td>

                    <td>

                      <button
                        className="danger-link"
                        disabled={
                          target.id ===
                          user.id
                        }
                        onClick={() =>
                          deleteUser(
                            target
                          )
                        }
                      >
                        Delete
                      </button>

                    </td>

                  </tr>
                )
              )}

            </tbody>

          </table>

          {!users.length && (
            <div className="empty">
              No users found.
            </div>
          )}

        </div>

      </section>

      {open && (
        <div className="modal-backdrop">

          <form
            className="modal"
            onSubmit={
              addUser
            }
          >

            <div className="modal-head">

              <div>

                <span className="eyebrow">
                  NEW ACCOUNT
                </span>

                <h2>
                  Create user
                </h2>

              </div>

              <button
                type="button"
                className="close"
                onClick={() =>
                  setOpen(false)
                }
              >
                ×
              </button>

            </div>

            <label>
              Full name

              <input
                required
                value={
                  form.name
                }
                onChange={(e) =>
                  setForm(
                    {
                      ...form,
                      name:
                        e.target.value
                    }
                  )
                }
              />
            </label>

            <label>
              Email

              <input
                required
                type="email"
                value={
                  form.email
                }
                onChange={(e) =>
                  setForm(
                    {
                      ...form,
                      email:
                        e.target.value
                    }
                  )
                }
              />
            </label>

            <label>
              Temporary password

              <input
                required
                minLength={8}
                type="password"
                value={
                  form.password
                }
                onChange={(e) =>
                  setForm(
                    {
                      ...form,
                      password:
                        e.target.value
                    }
                  )
                }
              />
            </label>

            <label>
              Role

              <select
                value={
                  form.role
                }
                onChange={(e) =>
                  setForm(
                    {
                      ...form,
                      role:
                        e.target.value
                    }
                  )
                }
              >
                <option>
                  Administrator
                </option>

                <option>
                  IT Manager
                </option>

                <option>
                  IT Staff
                </option>
              </select>
            </label>

            <div className="modal-actions">

              <button
                type="button"
                className="secondary"
                onClick={() =>
                  setOpen(false)
                }
              >
                Cancel
              </button>

              <button
                className="primary"
                disabled={saving}
              >
                {saving
                  ? "Creating..."
                  : "Create account"}
              </button>

            </div>

          </form>

        </div>
      )}

    </div>
  );
}

/* =========================================================
   ACTIVITY
========================================================= */

function Activity() {
  const [logs, setLogs] =
    useState([]);

  const [error, setError] =
    useState("");

  const load =
    useCallback(
      async () => {
        try {
          const data =
            await api(
              "/audit-logs"
            );

          setLogs(
            Array.isArray(data)
              ? data
              : []
          );

          setError("");
        } catch (error) {
          setError(
            error.message
          );
        }
      },
      []
    );

  useEffect(() => {
    load();
  }, [load]);

  return (
    <div>

      <div className="page-title-wrap">

        <h2 className="page-title">
          Activity log
        </h2>

        <p className="muted">
          A chronological record of
          important security
          administration actions.
        </p>

      </div>

      {error && (
        <div className="error-box">
          {error}
        </div>
      )}

      <section className="panel">

        <div className="panel-head">

          <div>

            <h3>
              Audit trail
            </h3>

            <p>
              Latest 200 recorded events
            </p>

          </div>

          <span className="live-indicator">
            Audited
          </span>

        </div>

        <div className="timeline">

          {logs.map(
            (log) => (
              <div
                className="timeline-row"
                key={
                  log.id
                }
              >

                <div className="timeline-dot" />

                <div>

                  <b>
                    {log.action}
                  </b>

                  <span>
                    {log.details ||
                      "—"}
                  </span>

                  <small>
                    {log.user_name ||
                      "System"}

                    {" · "}

                    {fmtDate(
                      log.created_at
                    )}
                  </small>

                </div>

              </div>
            )
          )}

          {!logs.length && (
            <div className="empty">
              No activity has been
              recorded yet.
            </div>
          )}

        </div>

      </section>

    </div>
  );
}

/* =========================================================
   MAIN APP
========================================================= */

export default function App() {
  const [user, setUser] =
    useState(null);

  const [page, setPage] =
    useState(
      "dashboard"
    );

  const [devices, setDevices] =
    useState([]);

  const [policy, setPolicy] =
    useState(
      defaultPolicy
    );

  const [loading, setLoading] =
    useState(false);

  const [error, setError] =
    useState("");

  /* =======================================================
     RESTORE SESSION
  ======================================================= */

  useEffect(() => {
    const currentToken =
      token();

    if (!currentToken) {
      return;
    }

    const payload =
      decodeToken(
        currentToken
      );

    if (
      payload &&
      (
        !payload.exp ||
        payload.exp * 1000 >
          Date.now()
      )
    ) {
      setUser(payload);
    } else {
      localStorage.removeItem(
        "token"
      );
    }
  }, []);

  /* =======================================================
     LOAD DATA
  ======================================================= */

  const load =
    useCallback(
      async () => {
        if (!user) {
          return;
        }

        setLoading(true);

        try {
          const [
            deviceData,
            policyData
          ] =
            await Promise.all([
              api(
                "/devices"
              ),
              api(
                "/security-policy"
              )
            ]);

          const normalized =
            Array.isArray(
              deviceData
            )
              ? deviceData.map(
                  normalizeDevice
                )
              : [];

          setDevices(
            normalized
          );

          setPolicy({
            ...defaultPolicy,
            ...(policyData ||
              {})
          });

          setError("");
        } catch (error) {
          if (
            error.message ===
            "Session expired" ||
            error.message ===
            "Invalid or expired session"
          ) {
            localStorage.removeItem(
              "token"
            );

            setUser(null);
            setDevices([]);
          } else {
            setError(
              error.message
            );
          }
        } finally {
          setLoading(false);
        }
      },
      [user]
    );

  /* =======================================================
     AUTOMATIC MONITORING
  ======================================================= */

  useEffect(() => {
    if (!user) {
      return;
    }

    load();

    const interval =
      setInterval(
        load,
        15000
      );

    return () =>
      clearInterval(
        interval
      );
  }, [user, load]);

  /* =======================================================
     LOGOUT
  ======================================================= */

  function logout() {
    localStorage.removeItem(
      "token"
    );

    setUser(null);
    setDevices([]);
    setPage(
      "dashboard"
    );
    setError("");
  }

  /* =======================================================
     LOGIN
  ======================================================= */

  if (!user) {
    return (
      <Login
        onLogin={(loggedInUser) => {
          setUser(
            loggedInUser
          );

          setPage(
            "dashboard"
          );

          setError("");
        }}
      />
    );
  }

  /* =======================================================
     PAGE TITLES
  ======================================================= */

  const titles = {
    dashboard: [
      "Dashboard",
      "Organization-wide endpoint security overview"
    ],

    devices: [
      "Devices",
      "Manage and monitor company endpoints"
    ],

    alerts: [
      "Security Alerts",
      "Identify and respond to security findings"
    ],

    users: [
      "Users",
      "Control access to the security center"
    ],

    settings: [
      "Security Policy",
      "Configure mandatory endpoint controls"
    ],

    activity: [
      "Activity Log",
      "Review security administration events"
    ]
  };

  const [
    title,
    subtitle
  ] =
    titles[page] ||
    titles.dashboard;

  /* =======================================================
     APPLICATION
  ======================================================= */

  return (
    <div className="app-shell">

      <Sidebar
        page={page}
        setPage={setPage}
        user={user}
        onLogout={logout}
      />

      <main className="main">

        <Header
          title={title}
          subtitle={subtitle}
          user={user}
          onRefresh={load}
          loading={loading}
        />

        {error && (
          <div className="error-box global-error">

            {error}

            <button
              onClick={() =>
                setError("")
              }
            >
              ×
            </button>

          </div>
        )}

        {page ===
          "dashboard" && (
          <Dashboard
            devices={devices}
            policy={policy}
            setPage={setPage}
          />
        )}

        {page ===
          "devices" && (
          <Devices
            devices={devices}
            setDevices={
              setDevices
            }
            policy={policy}
            user={user}
          />
        )}

        {page ===
          "alerts" && (
          <Alerts
            setPage={setPage}
            user={user}
          />
        )}

        {page ===
          "settings" && (
          <Settings
            policy={policy}
            setPolicy={
              setPolicy
            }
          />
        )}

        {page ===
          "users" && (
          <Users
            user={user}
          />
        )}

        {page ===
          "activity" && (
          <Activity />
        )}

      </main>

    </div>
  );
}