import { useEffect, useMemo, useState } from "react";

const API = "http://localhost:5000/api";

function getToken() {
    return localStorage.getItem("token");
}

async function apiRequest(path, options = {}) {
    const token = getToken();

    const response = await fetch(`${API}${path}`, {
        ...options,
        headers: {
            "Content-Type": "application/json",
            ...(token
                ? { Authorization: `Bearer ${token}` }
                : {}),
            ...(options.headers || {})
        }
    });

    const data = await response.json();

    if (!response.ok) {
        throw new Error(
            data.error ||
            data.message ||
            "Request failed"
        );
    }

    return data;
}

function formatDate(value) {
    if (!value) {
        return "—";
    }

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
        return "—";
    }

    return date.toLocaleString();
}

function getSeverityStyle(severity) {
    const value = String(
        severity || ""
    ).toUpperCase();

    if (value === "CRITICAL") {
        return {
            background: "#fde2e2",
            color: "#b71c1c"
        };
    }

    if (value === "HIGH") {
        return {
            background: "#fde8e8",
            color: "#c62828"
        };
    }

    if (value === "MEDIUM") {
        return {
            background: "#fff3cd",
            color: "#856404"
        };
    }

    return {
        background: "#e8f1ff",
        color: "#1565c0"
    };
}

function getStatusStyle(status) {
    const value = String(
        status || ""
    ).toUpperCase();

    if (value === "RESOLVED") {
        return {
            background: "#e8f5e9",
            color: "#2e7d32"
        };
    }

    return {
        background: "#fff3cd",
        color: "#856404"
    };
}

function SecurityAlerts() {
    const [alerts, setAlerts] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState("");
    const [filter, setFilter] = useState("ALL");
    const [resolvingId, setResolvingId] = useState(null);

    async function loadAlerts() {
        try {
            setError("");

            const data = await apiRequest(
                "/security-alerts"
            );

            if (Array.isArray(data)) {
                setAlerts(data);
            } else if (Array.isArray(data.alerts)) {
                setAlerts(data.alerts);
            } else {
                setAlerts([]);
            }
        } catch (err) {
            console.error(
                "Failed to load security alerts:",
                err
            );

            setError(err.message);
        } finally {
            setLoading(false);
        }
    }

    useEffect(() => {
        loadAlerts();

        const interval = setInterval(() => {
            loadAlerts();
        }, 30000);

        return () => {
            clearInterval(interval);
        };
    }, []);

    async function resolveAlert(id) {
        try {
            setResolvingId(id);
            setError("");

            await apiRequest(
                `/security-alerts/${id}/resolve`,
                {
                    method: "PUT"
                }
            );

            await loadAlerts();
        } catch (err) {
            console.error(
                "Failed to resolve alert:",
                err
            );

            setError(err.message);
        } finally {
            setResolvingId(null);
        }
    }

    const activeAlerts = useMemo(() => {
        return alerts.filter(
            alert =>
                String(
                    alert.status || "OPEN"
                ).toUpperCase() !== "RESOLVED"
        );
    }, [alerts]);

    const resolvedAlerts = useMemo(() => {
        return alerts.filter(
            alert =>
                String(
                    alert.status || ""
                ).toUpperCase() === "RESOLVED"
        );
    }, [alerts]);

    const criticalAlerts = useMemo(() => {
        return activeAlerts.filter(
            alert =>
                String(
                    alert.severity || ""
                ).toUpperCase() === "CRITICAL"
        );
    }, [activeAlerts]);

    const highAlerts = useMemo(() => {
        return activeAlerts.filter(
            alert =>
                String(
                    alert.severity || ""
                ).toUpperCase() === "HIGH"
        );
    }, [activeAlerts]);

    const filteredAlerts = useMemo(() => {
        if (filter === "ALL") {
            return alerts;
        }

        if (filter === "OPEN") {
            return activeAlerts;
        }

        if (filter === "RESOLVED") {
            return resolvedAlerts;
        }

        return activeAlerts.filter(
            alert =>
                String(
                    alert.severity || ""
                ).toUpperCase() === filter
        );
    }, [
        alerts,
        filter,
        activeAlerts,
        resolvedAlerts
    ]);

    const cardStyle = {
        background: "#ffffff",
        border: "1px solid #e2e8f0",
        borderRadius: "12px",
        padding: "20px",
        boxSizing: "border-box"
    };

    const statGridStyle = {
        display: "grid",
        gridTemplateColumns:
            "repeat(4, minmax(0, 1fr))",
        gap: "16px",
        marginBottom: "20px"
    };

    return (
        <div
            style={{
                padding: "25px",
                background: "#f6f8fb",
                minHeight:
                    "calc(100vh - 70px)",
                boxSizing: "border-box"
            }}
        >
            <div
                style={{
                    display: "flex",
                    justifyContent:
                        "space-between",
                    alignItems: "center",
                    gap: "20px",
                    marginBottom: "25px",
                    flexWrap: "wrap"
                }}
            >
                <div>
                    <h1
                        style={{
                            margin:
                                "0 0 8px 0",
                            fontSize: "30px"
                        }}
                    >
                        Security Alert Center
                    </h1>

                    <p
                        style={{
                            margin: 0,
                            color: "#64748b"
                        }}
                    >
                        Monitor and manage security
                        events detected by Sentinel.
                    </p>
                </div>

                <button
                    onClick={loadAlerts}
                    style={{
                        border: "1px solid #cbd5e1",
                        background: "#ffffff",
                        padding:
                            "10px 16px",
                        borderRadius: "8px",
                        cursor: "pointer",
                        fontWeight: "600"
                    }}
                >
                    ↻ Refresh
                </button>
            </div>

            {error && (
                <div
                    style={{
                        background: "#fde8e8",
                        border:
                            "1px solid #f5c2c2",
                        color: "#b71c1c",
                        padding: "14px 16px",
                        borderRadius: "8px",
                        marginBottom: "20px"
                    }}
                >
                    <strong>
                        Alert Center error:
                    </strong>{" "}
                    {error}
                </div>
            )}

            <div style={statGridStyle}>
                <div style={cardStyle}>
                    <div
                        style={{
                            color: "#64748b",
                            fontSize: "14px"
                        }}
                    >
                        Active Alerts
                    </div>

                    <div
                        style={{
                            fontSize: "30px",
                            fontWeight: "700",
                            marginTop: "8px",
                            color:
                                activeAlerts.length >
                                0
                                    ? "#dc2626"
                                    : "#16a34a"
                        }}
                    >
                        {activeAlerts.length}
                    </div>
                </div>

                <div style={cardStyle}>
                    <div
                        style={{
                            color: "#64748b",
                            fontSize: "14px"
                        }}
                    >
                        Critical
                    </div>

                    <div
                        style={{
                            fontSize: "30px",
                            fontWeight: "700",
                            marginTop: "8px",
                            color: "#b71c1c"
                        }}
                    >
                        {criticalAlerts.length}
                    </div>
                </div>

                <div style={cardStyle}>
                    <div
                        style={{
                            color: "#64748b",
                            fontSize: "14px"
                        }}
                    >
                        High
                    </div>

                    <div
                        style={{
                            fontSize: "30px",
                            fontWeight: "700",
                            marginTop: "8px",
                            color: "#c62828"
                        }}
                    >
                        {highAlerts.length}
                    </div>
                </div>

                <div style={cardStyle}>
                    <div
                        style={{
                            color: "#64748b",
                            fontSize: "14px"
                        }}
                    >
                        Resolved
                    </div>

                    <div
                        style={{
                            fontSize: "30px",
                            fontWeight: "700",
                            marginTop: "8px",
                            color: "#2e7d32"
                        }}
                    >
                        {resolvedAlerts.length}
                    </div>
                </div>
            </div>

            <div
                style={{
                    ...cardStyle,
                    padding: "12px 16px",
                    marginBottom: "20px",
                    display: "flex",
                    gap: "8px",
                    flexWrap: "wrap"
                }}
            >
                {[
                    ["ALL", "All Alerts"],
                    ["OPEN", "Open"],
                    ["CRITICAL", "Critical"],
                    ["HIGH", "High"],
                    ["MEDIUM", "Medium"],
                    ["RESOLVED", "Resolved"]
                ].map(([value, label]) => (
                    <button
                        key={value}
                        onClick={() =>
                            setFilter(value)
                        }
                        style={{
                            border:
                                filter === value
                                    ? "1px solid #2563eb"
                                    : "1px solid #cbd5e1",
                            background:
                                filter === value
                                    ? "#eff6ff"
                                    : "#ffffff",
                            color:
                                filter === value
                                    ? "#1d4ed8"
                                    : "#475569",
                            padding:
                                "9px 14px",
                            borderRadius: "8px",
                            cursor: "pointer",
                            fontWeight:
                                filter === value
                                    ? "700"
                                    : "500"
                        }}
                    >
                        {label}
                    </button>
                ))}
            </div>

            <div
                style={{
                    ...cardStyle,
                    padding: 0,
                    overflow: "hidden"
                }}
            >
                <div
                    style={{
                        padding: "18px 20px",
                        borderBottom:
                            "1px solid #e2e8f0",
                        fontWeight: "700",
                        fontSize: "17px"
                    }}
                >
                    Security Events
                </div>

                {loading ? (
                    <div
                        style={{
                            padding: "50px",
                            textAlign: "center",
                            color: "#64748b"
                        }}
                    >
                        Loading security alerts...
                    </div>
                ) : filteredAlerts.length === 0 ? (
                    <div
                        style={{
                            padding: "60px",
                            textAlign: "center"
                        }}
                    >
                        <div
                            style={{
                                fontSize: "42px",
                                marginBottom: "10px"
                            }}
                        >
                            ✓
                        </div>

                        <h2
                            style={{
                                margin:
                                    "0 0 8px 0",
                                color: "#2e7d32"
                            }}
                        >
                            No Alerts
                        </h2>

                        <p
                            style={{
                                margin: 0,
                                color: "#64748b"
                            }}
                        >
                            There are no alerts in
                            the selected category.
                        </p>
                    </div>
                ) : (
                    <div
                        style={{
                            overflowX: "auto"
                        }}
                    >
                        <table
                            style={{
                                width: "100%",
                                minWidth: "950px",
                                borderCollapse:
                                    "collapse"
                            }}
                        >
                            <thead>
                                <tr
                                    style={{
                                        background:
                                            "#f8fafc",
                                        textAlign:
                                            "left"
                                    }}
                                >
                                    <th
                                        style={{
                                            padding:
                                                "14px 16px"
                                        }}
                                    >
                                        Device
                                    </th>

                                    <th
                                        style={{
                                            padding:
                                                "14px 16px"
                                        }}
                                    >
                                        Alert Type
                                    </th>

                                    <th
                                        style={{
                                            padding:
                                                "14px 16px"
                                        }}
                                    >
                                        Severity
                                    </th>

                                    <th
                                        style={{
                                            padding:
                                                "14px 16px"
                                        }}
                                    >
                                        Message
                                    </th>

                                    <th
                                        style={{
                                            padding:
                                                "14px 16px"
                                        }}
                                    >
                                        Status
                                    </th>

                                    <th
                                        style={{
                                            padding:
                                                "14px 16px"
                                        }}
                                    >
                                        Created
                                    </th>

                                    <th
                                        style={{
                                            padding:
                                                "14px 16px"
                                        }}
                                    >
                                        Action
                                    </th>
                                </tr>
                            </thead>

                            <tbody>
                                {filteredAlerts.map(
                                    alert => {
                                        const severityStyle =
                                            getSeverityStyle(
                                                alert.severity
                                            );

                                        const statusStyle =
                                            getStatusStyle(
                                                alert.status
                                            );

                                        const isResolved =
                                            String(
                                                alert.status ||
                                                    ""
                                            ).toUpperCase() ===
                                            "RESOLVED";

                                        return (
                                            <tr
                                                key={
                                                    alert.id
                                                }
                                                style={{
                                                    borderTop:
                                                        "1px solid #e2e8f0"
                                                }}
                                            >
                                                <td
                                                    style={{
                                                        padding:
                                                            "16px"
                                                    }}
                                                >
                                                    <strong>
                                                        {
                                                            alert.device_name ||
                                                            alert.device_hostname ||
                                                            alert.hostname ||
                                                            alert.device ||
                                                            "Unknown Device"
                                                        }
                                                    </strong>

                                                    {alert.employee && (
                                                        <div
                                                            style={{
                                                                color:
                                                                    "#64748b",
                                                                fontSize:
                                                                    "12px",
                                                                marginTop:
                                                                    "4px"
                                                            }}
                                                        >
                                                            {
                                                                alert.employee
                                                            }
                                                        </div>
                                                    )}
                                                </td>

                                                <td
                                                    style={{
                                                        padding:
                                                            "16px"
                                                    }}
                                                >
                                                    {alert.alert_type ||
                                                        alert.type ||
                                                        "Security Alert"}
                                                </td>

                                                <td
                                                    style={{
                                                        padding:
                                                            "16px"
                                                    }}
                                                >
                                                    <span
                                                        style={{
                                                            display:
                                                                "inline-block",
                                                            padding:
                                                                "5px 10px",
                                                            borderRadius:
                                                                "20px",
                                                            background:
                                                                severityStyle.background,
                                                            color:
                                                                severityStyle.color,
                                                            fontSize:
                                                                "12px",
                                                            fontWeight:
                                                                "700"
                                                        }}
                                                    >
                                                        {String(
                                                            alert.severity ||
                                                                "UNKNOWN"
                                                        ).toUpperCase()}
                                                    </span>
                                                </td>

                                                <td
                                                    style={{
                                                        padding:
                                                            "16px",
                                                        maxWidth:
                                                            "350px"
                                                    }}
                                                >
                                                    {
                                                        alert.message
                                                    }
                                                </td>

                                                <td
                                                    style={{
                                                        padding:
                                                            "16px"
                                                    }}
                                                >
                                                    <span
                                                        style={{
                                                            display:
                                                                "inline-block",
                                                            padding:
                                                                "5px 10px",
                                                            borderRadius:
                                                                "20px",
                                                            background:
                                                                statusStyle.background,
                                                            color:
                                                                statusStyle.color,
                                                            fontSize:
                                                                "12px",
                                                            fontWeight:
                                                                "700"
                                                        }}
                                                    >
                                                        {String(
                                                            alert.status ||
                                                                "OPEN"
                                                        ).toUpperCase()}
                                                    </span>
                                                </td>

                                                <td
                                                    style={{
                                                        padding:
                                                            "16px",
                                                        whiteSpace:
                                                            "nowrap",
                                                        color:
                                                            "#64748b"
                                                    }}
                                                >
                                                    {formatDate(
                                                        alert.created_at
                                                    )}
                                                </td>

                                                <td
                                                    style={{
                                                        padding:
                                                            "16px"
                                                    }}
                                                >
                                                    {!isResolved && (
                                                        <button
                                                            onClick={() =>
                                                                resolveAlert(
                                                                    alert.id
                                                                )
                                                            }
                                                            disabled={
                                                                resolvingId ===
                                                                alert.id
                                                            }
                                                            style={{
                                                                border:
                                                                    "none",
                                                                background:
                                                                    "#16a34a",
                                                                color:
                                                                    "#ffffff",
                                                                padding:
                                                                    "8px 12px",
                                                                borderRadius:
                                                                    "7px",
                                                                cursor:
                                                                    resolvingId ===
                                                                    alert.id
                                                                        ? "not-allowed"
                                                                        : "pointer",
                                                                opacity:
                                                                    resolvingId ===
                                                                    alert.id
                                                                        ? 0.6
                                                                        : 1,
                                                                fontWeight:
                                                                    "600"
                                                            }}
                                                        >
                                                            {resolvingId ===
                                                            alert.id
                                                                ? "Resolving..."
                                                                : "Resolve"}
                                                        </button>
                                                    )}
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
        </div>
    );
}

export default SecurityAlerts;