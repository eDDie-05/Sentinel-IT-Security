import { useEffect, useMemo, useState } from "react";

const API = "http://localhost:5000/api";

function getToken() {
    return localStorage.getItem("token");
}

async function loadAuditLogs() {
    const token = getToken();

    const response = await fetch(
        `${API}/audit-logs`,
        {
            headers: {
                Authorization:
                    `Bearer ${token}`
            }
        }
    );

    const data =
        await response.json();

    if (!response.ok) {
        throw new Error(
            data.error ||
            "Failed to load audit logs"
        );
    }

    return Array.isArray(data)
        ? data
        : data.logs || [];
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

function getActionStyle(action) {
    const value =
        String(action || "").toUpperCase();

    if (
        value.includes("DELETE") ||
        value.includes("REMOVE")
    ) {
        return {
            background: "#fde8e8",
            color: "#c62828"
        };
    }

    if (
        value.includes("CREATE") ||
        value.includes("ADD")
    ) {
        return {
            background: "#e8f5e9",
            color: "#2e7d32"
        };
    }

    if (
        value.includes("UPDATE") ||
        value.includes("EDIT") ||
        value.includes("CHANGE")
    ) {
        return {
            background: "#e8f0fe",
            color: "#1a73e8"
        };
    }

    if (
        value.includes("LOGIN")
    ) {
        return {
            background: "#ede9fe",
            color: "#6d28d9"
        };
    }

    if (
        value.includes("OFFLINE") ||
        value.includes("ALERT")
    ) {
        return {
            background: "#fff3cd",
            color: "#856404"
        };
    }

    return {
        background: "#f1f5f9",
        color: "#475569"
    };
}

function AuditLogs() {
    const [logs, setLogs] = useState([]);
    const [loading, setLoading] =
        useState(true);
    const [error, setError] =
        useState("");
    const [search, setSearch] =
        useState("");
    const [actionFilter, setActionFilter] =
        useState("ALL");

    async function refreshLogs() {
        try {
            setError("");

            const data =
                await loadAuditLogs();

            setLogs(data);
        } catch (err) {
            console.error(
                "Audit log error:",
                err
            );

            setError(err.message);
        } finally {
            setLoading(false);
        }
    }

    useEffect(() => {
        refreshLogs();

        const interval =
            setInterval(() => {
                refreshLogs();
            }, 30000);

        return () => {
            clearInterval(interval);
        };
    }, []);

    const actionTypes = useMemo(() => {
        const types = logs
            .map(log => log.action)
            .filter(Boolean);

        return [
            "ALL",
            ...new Set(types)
        ];
    }, [logs]);

    const filteredLogs = useMemo(() => {
        const searchValue =
            search.trim().toLowerCase();

        return logs.filter(log => {
            const action =
                String(
                    log.action || ""
                ).toUpperCase();

            const matchesAction =
                actionFilter === "ALL" ||
                action === actionFilter;

            const searchableText = [
                log.user_name,
                log.username,
                log.email,
                log.action,
                log.details
            ]
                .filter(Boolean)
                .join(" ")
                .toLowerCase();

            const matchesSearch =
                !searchValue ||
                searchableText.includes(
                    searchValue
                );

            return (
                matchesAction &&
                matchesSearch
            );
        });
    }, [
        logs,
        search,
        actionFilter
    ]);

    const todayCount = useMemo(() => {
        const today =
            new Date()
                .toISOString()
                .slice(0, 10);

        return logs.filter(log => {
            if (!log.created_at) {
                return false;
            }

            return new Date(log.created_at)
                .toISOString()
                .slice(0, 10) === today;
        }).length;
    }, [logs]);

    const securityEvents = useMemo(() => {
        return logs.filter(log => {
            const action =
                String(
                    log.action || ""
                ).toUpperCase();

            return (
                action.includes("ALERT") ||
                action.includes("OFFLINE") ||
                action.includes("SECURITY") ||
                action.includes("POLICY")
            );
        }).length;
    }, [logs]);

    const cardStyle = {
        background: "#ffffff",
        border:
            "1px solid #e2e8f0",
        borderRadius: "12px",
        padding: "20px"
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
                        Audit Logs
                    </h1>

                    <p
                        style={{
                            margin: 0,
                            color: "#64748b"
                        }}
                    >
                        Track important activity
                        across the security system.
                    </p>
                </div>

                <button
                    onClick={refreshLogs}
                    style={{
                        padding:
                            "10px 16px",
                        border: "none",
                        borderRadius: "8px",
                        background:
                            "#2563eb",
                        color: "#ffffff",
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
                        marginBottom: "20px",
                        padding: "14px 16px",
                        background: "#fde8e8",
                        color: "#b71c1c",
                        border:
                            "1px solid #f5c2c2",
                        borderRadius: "8px"
                    }}
                >
                    <strong>
                        Error:
                    </strong>{" "}
                    {error}
                </div>
            )}

            <div
                style={{
                    display: "grid",
                    gridTemplateColumns:
                        "repeat(3, minmax(0, 1fr))",
                    gap: "16px",
                    marginBottom: "20px"
                }}
            >
                <div style={cardStyle}>
                    <div
                        style={{
                            color: "#64748b",
                            fontSize: "14px"
                        }}
                    >
                        Total Events
                    </div>

                    <div
                        style={{
                            fontSize: "30px",
                            fontWeight: "700",
                            marginTop: "8px"
                        }}
                    >
                        {logs.length}
                    </div>
                </div>

                <div style={cardStyle}>
                    <div
                        style={{
                            color: "#64748b",
                            fontSize: "14px"
                        }}
                    >
                        Today's Events
                    </div>

                    <div
                        style={{
                            fontSize: "30px",
                            fontWeight: "700",
                            marginTop: "8px",
                            color: "#2563eb"
                        }}
                    >
                        {todayCount}
                    </div>
                </div>

                <div style={cardStyle}>
                    <div
                        style={{
                            color: "#64748b",
                            fontSize: "14px"
                        }}
                    >
                        Security Events
                    </div>

                    <div
                        style={{
                            fontSize: "30px",
                            fontWeight: "700",
                            marginTop: "8px",
                            color: "#dc2626"
                        }}
                    >
                        {securityEvents}
                    </div>
                </div>
            </div>

            <div
                style={{
                    ...cardStyle,
                    marginBottom: "20px",
                    display: "flex",
                    gap: "12px",
                    flexWrap: "wrap"
                }}
            >
                <input
                    type="text"
                    placeholder="Search user, action or details..."
                    value={search}
                    onChange={e =>
                        setSearch(
                            e.target.value
                        )
                    }
                    style={{
                        flex: "1 1 280px",
                        padding:
                            "11px 13px",
                        border:
                            "1px solid #cbd5e1",
                        borderRadius: "8px",
                        outline: "none",
                        boxSizing:
                            "border-box"
                    }}
                />

                <select
                    value={actionFilter}
                    onChange={e =>
                        setActionFilter(
                            e.target.value
                        )
                    }
                    style={{
                        minWidth: "180px",
                        padding:
                            "11px 13px",
                        border:
                            "1px solid #cbd5e1",
                        borderRadius: "8px",
                        background:
                            "#ffffff"
                    }}
                >
                    {actionTypes.map(action => (
                        <option
                            key={action}
                            value={action}
                        >
                            {action === "ALL"
                                ? "All Actions"
                                : action}
                        </option>
                    ))}
                </select>
            </div>

            {loading ? (
                <div
                    style={{
                        ...cardStyle,
                        textAlign: "center",
                        padding: "50px"
                    }}
                >
                    Loading audit logs...
                </div>
            ) : filteredLogs.length === 0 ? (
                <div
                    style={{
                        ...cardStyle,
                        textAlign: "center",
                        padding: "60px"
                    }}
                >
                    <h2>
                        No Activity Found
                    </h2>

                    <p
                        style={{
                            color: "#64748b"
                        }}
                    >
                        No audit events match
                        the current filter.
                    </p>
                </div>
            ) : (
                <div
                    style={{
                        background:
                            "#ffffff",
                        border:
                            "1px solid #e2e8f0",
                        borderRadius:
                            "12px",
                        overflow:
                            "hidden"
                    }}
                >
                    <div
                        style={{
                            overflowX:
                                "auto"
                        }}
                    >
                        <table
                            style={{
                                width: "100%",
                                minWidth:
                                    "850px",
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
                                        Date & Time
                                    </th>

                                    <th
                                        style={{
                                            padding:
                                                "14px 16px"
                                        }}
                                    >
                                        User
                                    </th>

                                    <th
                                        style={{
                                            padding:
                                                "14px 16px"
                                        }}
                                    >
                                        Action
                                    </th>

                                    <th
                                        style={{
                                            padding:
                                                "14px 16px"
                                        }}
                                    >
                                        Details
                                    </th>
                                </tr>
                            </thead>

                            <tbody>
                                {filteredLogs.map(
                                    log => (
                                        <tr
                                            key={
                                                log.id
                                            }
                                            style={{
                                                borderTop:
                                                    "1px solid #e2e8f0"
                                            }}
                                        >
                                            <td
                                                style={{
                                                    padding:
                                                        "16px",
                                                    whiteSpace:
                                                        "nowrap",
                                                    color:
                                                        "#475569"
                                                }}
                                            >
                                                {formatDate(
                                                    log.created_at
                                                )}
                                            </td>

                                            <td
                                                style={{
                                                    padding:
                                                        "16px"
                                                }}
                                            >
                                                <strong>
                                                    {log.user_name ||
                                                        log.username ||
                                                        log.email ||
                                                        "System"}
                                                </strong>
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
                                                        fontSize:
                                                            "12px",
                                                        fontWeight:
                                                            "700",
                                                        ...getActionStyle(
                                                            log.action
                                                        )
                                                    }}
                                                >
                                                    {log.action ||
                                                        "UNKNOWN"}
                                                </span>
                                            </td>

                                            <td
                                                style={{
                                                    padding:
                                                        "16px",
                                                    color:
                                                        "#475569"
                                                }}
                                            >
                                                {log.details ||
                                                    "—"}
                                            </td>
                                        </tr>
                                    )
                                )}
                            </tbody>
                        </table>
                    </div>
                </div>
            )}
        </div>
    );
}

export default AuditLogs;