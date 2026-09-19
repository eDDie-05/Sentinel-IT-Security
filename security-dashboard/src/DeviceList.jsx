import { useEffect, useMemo, useState } from "react";
import {
  isDeviceSecure,
  getDeviceSecurityProblems,
} from "./securityUtils";

const API = "http://localhost:5000/api";

function DeviceList({
  devices = [],
  setDevices,
  userRole,
  securityPolicy = {},
  onDeviceDeleted,
  onDeviceUpdated,
}) {
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState("all");
  const [departmentFilter, setDepartmentFilter] = useState("all");
  const [editingDevice, setEditingDevice] = useState(null);
  const [message, setMessage] = useState("");
  const [loading, setLoading] = useState(false);
  const [lastRefresh, setLastRefresh] = useState(null);

  const canManage =
    userRole === "Administrator" ||
    userRole === "IT Manager";

  function getAgentOnline(device) {
    if (device.connection_status) {
      const status = String(device.connection_status).toLowerCase();

      if (status === "online") return true;
      if (status === "offline") return false;
    }

    if (device.online === true) return true;
    if (device.online === false) return false;

    if (device.agent_status) {
      const status = String(device.agent_status).toLowerCase();

      if (status === "online") return true;
      if (status === "offline") return false;
    }

    return false;
  }

  function getAgentStatus(device) {
    if (device.connection_status) {
      return String(device.connection_status).toUpperCase();
    }

    if (device.online === true) {
      return "ONLINE";
    }

    if (device.online === false) {
      return "OFFLINE";
    }

    if (device.agent_status) {
      return String(device.agent_status).toUpperCase();
    }

    return "OFFLINE";
  }

  function getSecurityValue(device, field) {
    const statusField = `${field}_status`;

    if (device[statusField]) {
      return String(device[statusField]).toUpperCase();
    }

    const value = device[field];

    if (value === true) return "ENABLED";
    if (value === false) return "DISABLED";

    return "UNKNOWN";
  }

  function getDisplayValue(value, fallback = "Unknown") {
    if (
      value === null ||
      value === undefined ||
      value === ""
    ) {
      return fallback;
    }

    return value;
  }

  function formatDate(value) {
    if (!value) return "Never";

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
      return value;
    }

    return date.toLocaleString();
  }

  function formatUptime(value) {
    if (
      value === null ||
      value === undefined ||
      value === ""
    ) {
      return "Unknown";
    }

    const totalMinutes = Number(value);

    if (!Number.isFinite(totalMinutes)) {
      return String(value);
    }

    const days = Math.floor(totalMinutes / 1440);
    const hours = Math.floor((totalMinutes % 1440) / 60);
    const minutes = Math.floor(totalMinutes % 60);

    return `${days}d ${hours}h ${minutes}m`;
  }

  function getSecurityState(device) {
    const agentSecurity =
      device.security_status ||
      device.securityStatus;

    if (agentSecurity) {
      const normalized = String(agentSecurity).toUpperCase();

      if (normalized === "SECURE") {
        return "SECURE";
      }

      if (
        normalized === "AT RISK" ||
        normalized === "RISK"
      ) {
        return "AT RISK";
      }

      if (normalized === "UNKNOWN") {
        return "UNKNOWN";
      }
    }

    return isDeviceSecure(
      device,
      securityPolicy
    )
      ? "SECURE"
      : "AT RISK";
  }

  function deviceIsSecure(device) {
    return getSecurityState(device) === "SECURE";
  }

  useEffect(() => {
    let cancelled = false;

    async function loadDevices(showError = true) {
      try {
        const token = localStorage.getItem("token");

        const response = await fetch(
          `${API}/devices`,
          {
            headers: {
              Authorization: `Bearer ${token}`,
            },
          }
        );

        const data = await response.json();

        if (!response.ok) {
          throw new Error(
            data.error ||
              "Failed to load devices"
          );
        }

        if (!cancelled) {
          setDevices(
            Array.isArray(data)
              ? data
              : []
          );

          setLastRefresh(new Date());

          if (showError) {
            setMessage("");
          }
        }
      } catch (error) {
        console.error(
          "Device refresh error:",
          error
        );

        if (!cancelled && showError) {
          setMessage(error.message);
        }
      }
    }

    loadDevices(true);

    const interval = setInterval(() => {
      loadDevices(false);
    }, 30000);

    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [setDevices]);

  const filteredDevices = useMemo(() => {
    const searchText = search.trim().toLowerCase();

    return devices.filter((device) => {
      const searchableText = [
        device.name,
        device.hostname,
        device.employee,
        device.department,
        device.operating_system,
        device.ip_address,
        device.username,
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();

      if (
        searchText &&
        !searchableText.includes(searchText)
      ) {
        return false;
      }

      if (
        departmentFilter !== "all" &&
        device.department !== departmentFilter
      ) {
        return false;
      }

      const online = getAgentOnline(device);
      const secure = deviceIsSecure(device);

      if (
        filter === "online" &&
        !online
      ) {
        return false;
      }

      if (
        filter === "offline" &&
        online
      ) {
        return false;
      }

      if (
        filter === "secure" &&
        !secure
      ) {
        return false;
      }

      if (
        filter === "risk" &&
        secure
      ) {
        return false;
      }

      return true;
    });
  }, [
    devices,
    search,
    filter,
    departmentFilter,
    securityPolicy,
  ]);

  const departments = useMemo(
    () =>
      [
        ...new Set(
          devices
            .map(
              (device) =>
                device.department
            )
            .filter(Boolean)
        ),
      ].sort(),
    [devices]
  );

  const total = devices.length;

  const secure = devices.filter(
    (device) =>
      deviceIsSecure(device)
  ).length;

  const atRisk = devices.filter(
    (device) =>
      !deviceIsSecure(device)
  ).length;

  const online = devices.filter(
    (device) =>
      getAgentOnline(device)
  ).length;

  const offline = total - online;

  async function deleteDevice(deviceId) {
    if (!canManage) return;

    const confirmed = window.confirm(
      "Are you sure you want to delete this device?"
    );

    if (!confirmed) return;

    try {
      setLoading(true);

      const token =
        localStorage.getItem("token");

      const response = await fetch(
        `${API}/devices/${deviceId}`,
        {
          method: "DELETE",
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.error ||
            "Failed to delete device"
        );
      }

      setDevices((previous) =>
        previous.filter(
          (device) =>
            device.id !== deviceId
        )
      );

      if (onDeviceDeleted) {
        onDeviceDeleted(deviceId);
      }

      setMessage(
        "Device deleted successfully."
      );
    } catch (error) {
      console.error(
        "Delete device error:",
        error
      );

      setMessage(error.message);
    } finally {
      setLoading(false);
    }
  }

  async function updateDevice(event) {
    event.preventDefault();

    if (
      !canManage ||
      !editingDevice
    ) {
      return;
    }

    try {
      setLoading(true);

      const token =
        localStorage.getItem("token");

      const response = await fetch(
        `${API}/devices/${editingDevice.id}`,
        {
          method: "PUT",
          headers: {
            "Content-Type":
              "application/json",
            Authorization: `Bearer ${token}`,
          },
          body: JSON.stringify({
            name:
              editingDevice.name,
            operatingSystem:
              editingDevice.operating_system,
            employee:
              editingDevice.employee,
            department:
              editingDevice.department,
            ipAddress:
              editingDevice.ip_address,
          }),
        }
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.error ||
            "Failed to update device"
        );
      }

      setDevices((previous) =>
        previous.map(
          (device) =>
            device.id === data.id
              ? data
              : device
        )
      );

      if (onDeviceUpdated) {
        onDeviceUpdated(data);
      }

      setEditingDevice(null);

      setMessage(
        "Device updated successfully."
      );
    } catch (error) {
      console.error(
        "Update device error:",
        error
      );

      setMessage(error.message);
    } finally {
      setLoading(false);
    }
  }

  async function toggleSecurity(
    device,
    field
  ) {
    if (!canManage) return;

    const updatedValue = !device[field];

    try {
      setLoading(true);

      const token =
        localStorage.getItem("token");

      const response = await fetch(
        `${API}/devices/${device.id}`,
        {
          method: "PUT",
          headers: {
            "Content-Type":
              "application/json",
            Authorization: `Bearer ${token}`,
          },
          body: JSON.stringify({
            [field]:
              updatedValue,
          }),
        }
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.error ||
            "Failed to update security"
        );
      }

      setDevices((previous) =>
        previous.map(
          (item) =>
            item.id === data.id
              ? data
              : item
        )
      );

      if (onDeviceUpdated) {
        onDeviceUpdated(data);
      }

      setMessage(
        `${field} updated successfully.`
      );
    } catch (error) {
      console.error(
        "Security update error:",
        error
      );

      setMessage(error.message);
    } finally {
      setLoading(false);
    }
  }

  function goToAddDevice() {
    window.dispatchEvent(
      new CustomEvent(
        "open-add-device"
      )
    );
  }

  function statusStyle(isOnline) {
    return {
      display: "inline-flex",
      alignItems: "center",
      gap: "7px",
      padding: "6px 11px",
      borderRadius: "20px",
      fontSize: "12px",
      fontWeight: "700",
      background: isOnline
        ? "#e8f5e9"
        : "#eeeeee",
      color: isOnline
        ? "#2e7d32"
        : "#555",
    };
  }

  function securityStyle(status) {
    const secure =
      status === "SECURE";

    return {
      display: "inline-flex",
      alignItems: "center",
      padding: "6px 11px",
      borderRadius: "20px",
      fontSize: "12px",
      fontWeight: "700",
      background: secure
        ? "#e8f5e9"
        : "#fde8e8",
      color: secure
        ? "#2e7d32"
        : "#c62828",
    };
  }

  return (
    <div
      style={{
        padding: "25px",
        background: "#f6f8fb",
        minHeight:
          "calc(100vh - 70px)",
      }}
    >
      <div
        style={{
          display: "flex",
          justifyContent:
            "space-between",
          alignItems: "center",
          marginBottom: "20px",
          gap: "15px",
          flexWrap: "wrap",
        }}
      >
        <div>
          <h1
            style={{
              margin: "0 0 5px 0",
            }}
          >
            Devices
          </h1>

          <p
            style={{
              margin: 0,
              color: "#666",
            }}
          >
            Monitor company
            computers and their
            security status.
          </p>
        </div>

        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: "12px",
          }}
        >
          <div
            style={{
              fontSize: "12px",
              color: "#666",
            }}
          >
            Live monitoring
            <br />
            <strong
              style={{
                color: "#2e7d32",
              }}
            >
              ● Active
            </strong>
          </div>

          {canManage && (
            <button
              onClick={goToAddDevice}
              style={{
                padding:
                  "11px 18px",
                border: "none",
                borderRadius: "7px",
                background: "#1a73e8",
                color: "white",
                cursor: "pointer",
                fontWeight: "bold",
              }}
            >
              + Add Device
            </button>
          )}
        </div>
      </div>

      <div
        style={{
          marginBottom: "15px",
          padding: "10px 14px",
          background: "#eef7ff",
          border:
            "1px solid #d6e9ff",
          borderRadius: "8px",
          fontSize: "13px",
          color: "#555",
        }}
      >
        Device status automatically
        refreshes every 30 seconds.

        {lastRefresh && (
          <>
            {" "}
            Last checked:{" "}
            <strong>
              {lastRefresh.toLocaleTimeString()}
            </strong>
          </>
        )}
      </div>

      {message && (
        <div
          style={{
            marginBottom: "15px",
            padding: "12px",
            background: "#e8f0fe",
            borderRadius: "7px",
            display: "flex",
            justifyContent:
              "space-between",
            alignItems: "center",
          }}
        >
          <span>{message}</span>

          <button
            onClick={() =>
              setMessage("")
            }
            style={{
              border: "none",
              background:
                "transparent",
              cursor: "pointer",
              fontSize: "16px",
            }}
          >
            ×
          </button>
        </div>
      )}

      <div
        style={{
          display: "grid",
          gridTemplateColumns:
            "repeat(auto-fit, minmax(150px, 1fr))",
          gap: "15px",
          marginBottom: "20px",
        }}
      >
        {[
          ["Total Devices", total, "#222"],
          ["Secure", secure, "#2e7d32"],
          ["At Risk", atRisk, "#d32f2f"],
          ["Online", online, "#1a73e8"],
          ["Offline", offline, "#555"],
        ].map(
          ([label, value, color]) => (
            <div
              key={label}
              style={{
                background: "white",
                padding: "18px",
                border:
                  "1px solid #ddd",
                borderRadius: "10px",
              }}
            >
              <small
                style={{
                  color: "#666",
                }}
              >
                {label}
              </small>

              <h2
                style={{
                  margin:
                    "8px 0 0",
                  color,
                }}
              >
                {value}
              </h2>
            </div>
          )
        )}
      </div>

      <div
        style={{
          background: "white",
          padding: "15px",
          border:
            "1px solid #ddd",
          borderRadius: "10px",
          marginBottom: "20px",
          display: "flex",
          gap: "10px",
          flexWrap: "wrap",
        }}
      >
        <input
          type="text"
          placeholder="Search name, hostname, employee, IP..."
          value={search}
          onChange={(event) =>
            setSearch(
              event.target.value
            )
          }
          style={{
            padding: "10px",
            flex: 1,
            minWidth: "240px",
            border:
              "1px solid #ccc",
            borderRadius: "7px",
          }}
        />

        <select
          value={filter}
          onChange={(event) =>
            setFilter(
              event.target.value
            )
          }
          style={{
            padding: "10px",
            border:
              "1px solid #ccc",
            borderRadius: "7px",
          }}
        >
          <option value="all">
            All Devices
          </option>
          <option value="online">
            Online
          </option>
          <option value="offline">
            Offline
          </option>
          <option value="secure">
            Secure
          </option>
          <option value="risk">
            At Risk
          </option>
        </select>

        <select
          value={departmentFilter}
          onChange={(event) =>
            setDepartmentFilter(
              event.target.value
            )
          }
          style={{
            padding: "10px",
            border:
              "1px solid #ccc",
            borderRadius: "7px",
          }}
        >
          <option value="all">
            All Departments
          </option>

          {departments.map(
            (department) => (
              <option
                key={department}
                value={department}
              >
                {department}
              </option>
            )
          )}
        </select>
      </div>

      <div
        style={{
          display: "grid",
          gridTemplateColumns:
            "repeat(auto-fit, minmax(430px, 1fr))",
          gap: "20px",
        }}
      >
        {filteredDevices.map(
          (device) => {
            const online =
              getAgentOnline(
                device
              );

            const agentStatus =
              getAgentStatus(
                device
              );

            const securityStatus =
              getSecurityState(
                device
              );

            const secure =
              securityStatus ===
              "SECURE";

            const problems =
              getDeviceSecurityProblems(
                device,
                securityPolicy
              );

            return (
              <div
                key={device.id}
                style={{
                  background: "white",
                  border: secure
                    ? "1px solid #ddd"
                    : "2px solid #d32f2f",
                  borderRadius: "12px",
                  padding: "20px",
                  boxShadow:
                    "0 2px 8px rgba(0,0,0,0.05)",
                }}
              >
                <div
                  style={{
                    display: "flex",
                    justifyContent:
                      "space-between",
                    alignItems:
                      "flex-start",
                    gap: "15px",
                  }}
                >
                  <div>
                    <h2
                      style={{
                        margin:
                          "0 0 6px",
                      }}
                    >
                      {getDisplayValue(
                        device.name,
                        "Unnamed Device"
                      )}
                    </h2>

                    <div
                      style={{
                        color: "#777",
                        fontSize:
                          "14px",
                      }}
                    >
                      Hostname:{" "}
                      <strong>
                        {getDisplayValue(
                          device.hostname
                        )}
                      </strong>
                    </div>

                    <div
                      style={{
                        color: "#777",
                        fontSize:
                          "14px",
                      }}
                    >
                      OS:{" "}
                      <strong>
                        {getDisplayValue(
                          device.operating_system
                        )}
                      </strong>
                    </div>
                  </div>

                  <div
                    style={{
                      display: "flex",
                      flexDirection:
                        "column",
                      alignItems:
                        "flex-end",
                      gap: "7px",
                    }}
                  >
                    <span
                      style={statusStyle(
                        online
                      )}
                    >
                      <span>●</span>
                      {agentStatus}
                    </span>

                    <span
                      style={securityStyle(
                        securityStatus
                      )}
                    >
                      {securityStatus}
                    </span>
                  </div>
                </div>

                <div
                  style={{
                    marginTop: "18px",
                    padding: "15px",
                    background: "#f8f9fa",
                    borderRadius: "9px",
                    display: "grid",
                    gridTemplateColumns:
                      "repeat(2, minmax(0, 1fr))",
                    gap: "10px 15px",
                    fontSize: "14px",
                  }}
                >
                  <div>
                    <strong>
                      Employee
                    </strong>
                    <br />
                    {getDisplayValue(
                      device.employee
                    )}
                  </div>

                  <div>
                    <strong>
                      Department
                    </strong>
                    <br />
                    {getDisplayValue(
                      device.department
                    )}
                  </div>

                  <div>
                    <strong>
                      Username
                    </strong>
                    <br />
                    {getDisplayValue(
                      device.username
                    )}
                  </div>

                  <div>
                    <strong>
                      IP Address
                    </strong>
                    <br />
                    {getDisplayValue(
                      device.ip_address
                    )}
                  </div>

                  <div>
                    <strong>
                      CPU
                    </strong>
                    <br />
                    {getDisplayValue(
                      device.cpu
                    )}
                  </div>

                  <div>
                    <strong>
                      CPU Cores
                    </strong>
                    <br />
                    {getDisplayValue(
                      device.cpu_cores
                    )}
                  </div>

                  <div>
                    <strong>
                      RAM
                    </strong>
                    <br />
                    {getDisplayValue(
                      device.ram_gb
                    )}
                    {device.ram_gb !==
                      null &&
                      device.ram_gb !==
                        undefined &&
                      " GB"}
                  </div>

                  <div>
                    <strong>
                      Free RAM
                    </strong>
                    <br />
                    {getDisplayValue(
                      device.free_memory_gb
                    )}
                    {device.free_memory_gb !==
                      null &&
                      device.free_memory_gb !==
                        undefined &&
                      " GB"}
                  </div>

                  <div>
                    <strong>
                      Uptime
                    </strong>
                    <br />
                    {formatUptime(
                      device.uptime_minutes
                    )}
                  </div>

                  <div>
                    <strong>
                      Architecture
                    </strong>
                    <br />
                    {getDisplayValue(
                      device.architecture
                    )}
                  </div>

                  <div
                    style={{
                      gridColumn:
                        "1 / -1",
                    }}
                  >
                    <strong>
                      Last Seen
                    </strong>
                    <br />
                    {formatDate(
                      device.last_seen ||
                        device.updated_at
                    )}
                  </div>
                </div>

                <div
                  style={{
                    marginTop: "18px",
                    paddingTop: "15px",
                    borderTop:
                      "1px solid #eee",
                  }}
                >
                  <div
                    style={{
                      display: "flex",
                      justifyContent:
                        "space-between",
                      alignItems:
                        "center",
                      marginBottom:
                        "10px",
                    }}
                  >
                    <h3
                      style={{
                        margin: 0,
                      }}
                    >
                      Security
                    </h3>

                    <span
                      style={{
                        fontSize: "12px",
                        color: "#777",
                      }}
                    >
                      Agent data
                    </span>
                  </div>

                  <div
                    style={{
                      display: "grid",
                      gridTemplateColumns:
                        "repeat(3, 1fr)",
                      gap: "8px",
                    }}
                  >
                    {[
                      [
                        "Antivirus",
                        "antivirus",
                      ],
                      [
                        "Firewall",
                        "firewall",
                      ],
                      [
                        "Backup",
                        "backup",
                      ],
                    ].map(
                      ([label, field]) => {
                        const value =
                          getSecurityValue(
                            device,
                            field
                          );

                        const enabled =
                          value ===
                          "ENABLED";

                        return (
                          <button
                            key={field}
                            disabled={
                              !canManage ||
                              loading
                            }
                            onClick={() =>
                              toggleSecurity(
                                device,
                                field
                              )
                            }
                            style={{
                              padding:
                                "10px 6px",
                              border: "none",
                              borderRadius:
                                "7px",
                              cursor:
                                canManage
                                  ? "pointer"
                                  : "default",
                              background:
                                enabled
                                  ? "#e8f5e9"
                                  : value ===
                                    "DISABLED"
                                  ? "#fde8e8"
                                  : "#f1f3f4",
                              color:
                                enabled
                                  ? "#2e7d32"
                                  : value ===
                                    "DISABLED"
                                  ? "#c62828"
                                  : "#666",
                              fontWeight:
                                "600",
                            }}
                          >
                            {label}
                            <br />
                            <span
                              style={{
                                fontSize:
                                  "11px",
                              }}
                            >
                              {value}
                            </span>
                          </button>
                        );
                      }
                    )}
                  </div>

                  {!secure &&
                    problems.length > 0 && (
                      <div
                        style={{
                          marginTop: "12px",
                          padding: "12px",
                          background:
                            "#fde8e8",
                          borderRadius:
                            "7px",
                          color:
                            "#c62828",
                        }}
                      >
                        <strong>
                          Security Problems
                        </strong>

                        <ul
                          style={{
                            margin:
                              "8px 0 0 20px",
                          }}
                        >
                          {problems.map(
                            (
                              problem,
                              index
                            ) => (
                              <li
                                key={
                                  problem.type ||
                                  index
                                }
                              >
                                {
                                  problem.message
                                }
                              </li>
                            )
                          )}
                        </ul>
                      </div>
                    )}
                </div>

                <div
                  style={{
                    marginTop: "15px",
                    padding: "12px",
                    background:
                      "#eef4ff",
                    borderRadius: "8px",
                    fontSize: "13px",
                  }}
                >
                  <strong>
                    Sentinel Agent
                  </strong>

                  <div
                    style={{
                      marginTop: "5px",
                      color: "#555",
                    }}
                  >
                    Status is automatically
                    reported by the
                    installed agent.
                  </div>

                  <div
                    style={{
                      marginTop: "6px",
                      fontSize: "12px",
                      color: online
                        ? "#2e7d32"
                        : "#c62828",
                      fontWeight: "600",
                    }}
                  >
                    ●{" "}
                    {online
                      ? "Agent is communicating"
                      : "Agent is not communicating"}
                  </div>
                </div>

                {canManage && (
                  <div
                    style={{
                      display: "flex",
                      gap: "10px",
                      marginTop: "15px",
                    }}
                  >
                    <button
                      disabled={loading}
                      onClick={() =>
                        setEditingDevice({
                          ...device,
                        })
                      }
                      style={{
                        padding:
                          "9px 15px",
                        border: "none",
                        borderRadius:
                          "6px",
                        background:
                          "#1a73e8",
                        color: "white",
                        cursor:
                          "pointer",
                      }}
                    >
                      Edit
                    </button>

                    <button
                      disabled={loading}
                      onClick={() =>
                        deleteDevice(
                          device.id
                        )
                      }
                      style={{
                        padding:
                          "9px 15px",
                        border: "none",
                        borderRadius:
                          "6px",
                        background:
                          "#d32f2f",
                        color: "white",
                        cursor:
                          "pointer",
                      }}
                    >
                      Delete
                    </button>
                  </div>
                )}
              </div>
            );
          }
        )}
      </div>

      {filteredDevices.length === 0 && (
        <div
          style={{
            marginTop: "20px",
            background: "white",
            padding: "40px",
            textAlign: "center",
            borderRadius: "10px",
            border:
              "1px solid #ddd",
          }}
        >
          <h3>
            No devices found
          </h3>

          <p
            style={{
              color: "#777",
            }}
          >
            Try changing your
            search or filters.
          </p>
        </div>
      )}

      {editingDevice && (
        <div
          style={{
            position: "fixed",
            inset: 0,
            background:
              "rgba(0,0,0,0.45)",
            display: "flex",
            alignItems: "center",
            justifyContent:
              "center",
            zIndex: 1000,
            padding: "20px",
          }}
        >
          <form
            onSubmit={updateDevice}
            style={{
              width: "500px",
              maxWidth: "100%",
              maxHeight: "90vh",
              overflowY: "auto",
              background: "white",
              padding: "25px",
              borderRadius: "12px",
              boxSizing:
                "border-box",
            }}
          >
            <h2
              style={{
                marginTop: 0,
              }}
            >
              Edit Device
            </h2>

            <label>
              Device Name
            </label>

            <input
              value={
                editingDevice.name ||
                ""
              }
              onChange={(event) =>
                setEditingDevice({
                  ...editingDevice,
                  name:
                    event.target.value,
                })
              }
              placeholder="Device name"
              style={{
                width: "100%",
                padding: "10px",
                margin:
                  "6px 0 12px",
                boxSizing:
                  "border-box",
                border:
                  "1px solid #ccc",
                borderRadius: "6px",
              }}
            />

            <label>
              Operating System
            </label>

            <input
              value={
                editingDevice.operating_system ||
                ""
              }
              onChange={(event) =>
                setEditingDevice({
                  ...editingDevice,
                  operating_system:
                    event.target.value,
                })
              }
              placeholder="Operating system"
              style={{
                width: "100%",
                padding: "10px",
                margin:
                  "6px 0 12px",
                boxSizing:
                  "border-box",
                border:
                  "1px solid #ccc",
                borderRadius: "6px",
              }}
            />

            <label>
              Employee
            </label>

            <input
              value={
                editingDevice.employee ||
                ""
              }
              onChange={(event) =>
                setEditingDevice({
                  ...editingDevice,
                  employee:
                    event.target.value,
                })
              }
              placeholder="Employee"
              style={{
                width: "100%",
                padding: "10px",
                margin:
                  "6px 0 12px",
                boxSizing:
                  "border-box",
                border:
                  "1px solid #ccc",
                borderRadius: "6px",
              }}
            />

            <label>
              Department
            </label>

            <input
              value={
                editingDevice.department ||
                ""
              }
              onChange={(event) =>
                setEditingDevice({
                  ...editingDevice,
                  department:
                    event.target.value,
                })
              }
              placeholder="Department"
              style={{
                width: "100%",
                padding: "10px",
                margin:
                  "6px 0 12px",
                boxSizing:
                  "border-box",
                border:
                  "1px solid #ccc",
                borderRadius: "6px",
              }}
            />

            <label>
              IP Address
            </label>

            <input
              value={
                editingDevice.ip_address ||
                ""
              }
              onChange={(event) =>
                setEditingDevice({
                  ...editingDevice,
                  ip_address:
                    event.target.value,
                })
              }
              placeholder="IP Address"
              style={{
                width: "100%",
                padding: "10px",
                margin:
                  "6px 0 18px",
                boxSizing:
                  "border-box",
                border:
                  "1px solid #ccc",
                borderRadius: "6px",
              }}
            />

            <div
              style={{
                padding: "12px",
                background:
                  "#f5f5f5",
                borderRadius: "7px",
                marginBottom:
                  "18px",
                fontSize: "13px",
                color: "#666",
              }}
            >
              ONLINE/OFFLINE status,
              CPU, RAM, uptime and
              other agent information
              are automatically
              reported by the Sentinel
              Agent and are not edited
              manually here.
            </div>

            <div
              style={{
                display: "flex",
                gap: "10px",
              }}
            >
              <button
                type="submit"
                disabled={loading}
                style={{
                  padding:
                    "10px 18px",
                  border: "none",
                  borderRadius: "7px",
                  background:
                    "#1a73e8",
                  color: "white",
                  cursor:
                    "pointer",
                }}
              >
                {loading
                  ? "Saving..."
                  : "Save Changes"}
              </button>

              <button
                type="button"
                onClick={() =>
                  setEditingDevice(null)
                }
                style={{
                  padding:
                    "10px 18px",
                  border:
                    "1px solid #ccc",
                  borderRadius: "7px",
                  background: "white",
                  cursor:
                    "pointer",
                }}
              >
                Cancel
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
}

export default DeviceList;