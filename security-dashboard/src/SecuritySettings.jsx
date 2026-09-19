import { useEffect, useState } from "react";

const API = "http://localhost:5000/api";

function SecuritySettings({
    securityPolicy = {},
    setSecurityPolicy,
    userRole
}) {
    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState(false);
    const [message, setMessage] = useState("");
    const [error, setError] = useState("");

    const isAdmin =
        userRole === "Administrator" ||
        userRole === "Admin";

    const antivirusRequired =
        securityPolicy.antivirus_required ??
        securityPolicy.antivirusRequired ??
        true;

    const firewallRequired =
        securityPolicy.firewall_required ??
        securityPolicy.firewallRequired ??
        true;

    const backupRequired =
        securityPolicy.backup_required ??
        securityPolicy.backupRequired ??
        true;

    useEffect(() => {
        async function loadPolicy() {
            try {
                setLoading(true);
                setError("");

                const token =
                    localStorage.getItem("token");

                const response = await fetch(
                    `${API}/security-policy`,
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
                        "Failed to load security policy"
                    );
                }

                setSecurityPolicy({
                    ...data,
                    antivirus_required:
                        data.antivirus_required ??
                        data.antivirusRequired ??
                        true,
                    firewall_required:
                        data.firewall_required ??
                        data.firewallRequired ??
                        true,
                    backup_required:
                        data.backup_required ??
                        data.backupRequired ??
                        true
                });

            } catch (err) {
                console.error(
                    "Policy loading error:",
                    err
                );

                setError(err.message);
            } finally {
                setLoading(false);
            }
        }

        loadPolicy();
    }, [setSecurityPolicy]);

    async function updatePolicy(setting) {
        if (!isAdmin) {
            setError(
                "Only an Administrator can change security policies."
            );
            return;
        }

        const currentValue =
            setting === "antivirus_required"
                ? antivirusRequired
                : setting === "firewall_required"
                    ? firewallRequired
                    : backupRequired;

        const newPolicy = {
            antivirus_required:
                antivirusRequired,
            firewall_required:
                firewallRequired,
            backup_required:
                backupRequired
        };

        newPolicy[setting] = !currentValue;

        setSaving(true);
        setMessage("");
        setError("");

        try {
            const token =
                localStorage.getItem("token");

            const response = await fetch(
                `${API}/security-policy`,
                {
                    method: "PUT",
                    headers: {
                        "Content-Type":
                            "application/json",
                        Authorization:
                            `Bearer ${token}`
                    },
                    body: JSON.stringify(
                        newPolicy
                    )
                }
            );

            const data =
                await response.json();

            if (!response.ok) {
                throw new Error(
                    data.error ||
                    "Failed to update security policy"
                );
            }

            setSecurityPolicy({
                ...data,
                antivirus_required:
                    data.antivirus_required ??
                    newPolicy.antivirus_required,
                firewall_required:
                    data.firewall_required ??
                    newPolicy.firewall_required,
                backup_required:
                    data.backup_required ??
                    newPolicy.backup_required
            });

            setMessage(
                "Security policy updated successfully."
            );

        } catch (err) {
            console.error(
                "Policy update error:",
                err
            );

            setError(err.message);

        } finally {
            setSaving(false);
        }
    }

    if (loading) {
        return (
            <div
                style={{
                    padding: "30px"
                }}
            >
                <h2>
                    Security Policy
                </h2>

                <p>
                    Loading security policy...
                </p>
            </div>
        );
    }

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
                    marginBottom: "25px"
                }}
            >
                <h1
                    style={{
                        margin:
                            "0 0 8px 0",
                        fontSize: "30px"
                    }}
                >
                    Security Policy
                </h1>

                <p
                    style={{
                        margin: 0,
                        color: "#64748b"
                    }}
                >
                    Configure the security requirements
                    that company devices must follow.
                </p>
            </div>

            {message && (
                <div
                    style={{
                        background: "#e8f5e9",
                        color: "#2e7d32",
                        border:
                            "1px solid #a5d6a7",
                        padding: "14px 16px",
                        borderRadius: "8px",
                        marginBottom: "20px"
                    }}
                >
                    ✓ {message}
                </div>
            )}

            {error && (
                <div
                    style={{
                        background: "#fde8e8",
                        color: "#b71c1c",
                        border:
                            "1px solid #f5c2c2",
                        padding: "14px 16px",
                        borderRadius: "8px",
                        marginBottom: "20px"
                    }}
                >
                    ✕ {error}
                </div>
            )}

            {!isAdmin && (
                <div
                    style={{
                        background: "#fff8e1",
                        color: "#8a6d1d",
                        border:
                            "1px solid #ffe082",
                        padding: "14px 16px",
                        borderRadius: "8px",
                        marginBottom: "20px"
                    }}
                >
                    You can view the security policy,
                    but only an Administrator can change it.
                </div>
            )}

            <div
                style={{
                    background: "#ffffff",
                    border:
                        "1px solid #e2e8f0",
                    borderRadius: "12px",
                    overflow: "hidden"
                }}
            >
                <div
                    style={{
                        padding: "20px",
                        borderBottom:
                            "1px solid #e2e8f0"
                    }}
                >
                    <h2
                        style={{
                            margin:
                                "0 0 6px 0"
                        }}
                    >
                        Protection Requirements
                    </h2>

                    <p
                        style={{
                            margin: 0,
                            color: "#64748b"
                        }}
                    >
                        When enabled, the protection
                        must be active on company
                        computers.
                    </p>
                </div>

                <div
                    style={{
                        padding: "0 20px"
                    }}
                >
                    <SettingRow
                        title="Antivirus Protection"
                        description="Company devices must have approved antivirus protection."
                        enabled={
                            antivirusRequired
                        }
                        disabled={
                            saving || !isAdmin
                        }
                        onClick={() =>
                            updatePolicy(
                                "antivirus_required"
                            )
                        }
                    />

                    <SettingRow
                        title="Firewall Protection"
                        description="Company devices must have their firewall enabled."
                        enabled={
                            firewallRequired
                        }
                        disabled={
                            saving || !isAdmin
                        }
                        onClick={() =>
                            updatePolicy(
                                "firewall_required"
                            )
                        }
                    />

                    <SettingRow
                        title="Backup Protection"
                        description="Company devices must have a configured backup system."
                        enabled={
                            backupRequired
                        }
                        disabled={
                            saving || !isAdmin
                        }
                        onClick={() =>
                            updatePolicy(
                                "backup_required"
                            )
                        }
                    />
                </div>
            </div>

            <div
                style={{
                    marginTop: "20px",
                    padding: "18px 20px",
                    background: "#ffffff",
                    border:
                        "1px solid #e2e8f0",
                    borderRadius: "12px"
                }}
            >
                <h3
                    style={{
                        margin:
                            "0 0 8px 0"
                    }}
                >
                    Current Policy
                </h3>

                <p
                    style={{
                        margin: "6px 0",
                        color: "#475569"
                    }}
                >
                    Antivirus:{" "}
                    <strong>
                        {antivirusRequired
                            ? "Required"
                            : "Not Required"}
                    </strong>
                </p>

                <p
                    style={{
                        margin: "6px 0",
                        color: "#475569"
                    }}
                >
                    Firewall:{" "}
                    <strong>
                        {firewallRequired
                            ? "Required"
                            : "Not Required"}
                    </strong>
                </p>

                <p
                    style={{
                        margin: "6px 0",
                        color: "#475569"
                    }}
                >
                    Backup:{" "}
                    <strong>
                        {backupRequired
                            ? "Required"
                            : "Not Required"}
                    </strong>
                </p>

                {saving && (
                    <p
                        style={{
                            margin:
                                "12px 0 0 0",
                            color: "#2563eb"
                        }}
                    >
                        Saving policy...
                    </p>
                )}
            </div>
        </div>
    );
}

function SettingRow({
    title,
    description,
    enabled,
    disabled,
    onClick
}) {
    return (
        <div
            style={{
                display: "flex",
                justifyContent:
                    "space-between",
                alignItems: "center",
                gap: "20px",
                padding: "22px 0",
                borderBottom:
                    "1px solid #e2e8f0"
            }}
        >
            <div>
                <h3
                    style={{
                        margin:
                            "0 0 6px 0"
                    }}
                >
                    {title}
                </h3>

                <p
                    style={{
                        margin: 0,
                        color: "#64748b"
                    }}
                >
                    {description}
                </p>
            </div>

            <button
                type="button"
                disabled={disabled}
                onClick={onClick}
                style={{
                    minWidth: "110px",
                    padding:
                        "10px 16px",
                    border: "none",
                    borderRadius: "8px",
                    cursor: disabled
                        ? "not-allowed"
                        : "pointer",
                    background: enabled
                        ? "#16a34a"
                        : "#64748b",
                    color: "#ffffff",
                    fontWeight: "700",
                    opacity: disabled
                        ? 0.6
                        : 1
                }}
            >
                {enabled
                    ? "Required"
                    : "Not Required"}
            </button>
        </div>
    );
}

export default SecuritySettings;