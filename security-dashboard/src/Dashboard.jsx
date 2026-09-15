import { isDeviceSecure } from "./securityUtils";

function Dashboard({
    devices = [],
    securityPolicy = {}
}) {

    const totalDevices =
        devices.length;


    const secureDevices =
        devices.filter(
            device =>
                isDeviceSecure(
                    device,
                    securityPolicy
                )
        );


    const atRiskDevices =
        devices.filter(
            device =>
                !isDeviceSecure(
                    device,
                    securityPolicy
                )
        );


    const onlineDevices =
        devices.filter(
            device =>
                device.online === true
        );


    const offlineDevices =
        devices.filter(
            device =>
                device.online !== true
        );


    const protectionRate =
        totalDevices === 0
            ? 0
            : Math.round(
                (secureDevices.length /
                    totalDevices) *
                100
            );


    const cardStyle = {
        background: "#ffffff",
        border: "1px solid #ddd",
        borderRadius: "10px",
        padding: "20px",
        boxSizing: "border-box"
    };


    return (

        <div
            style={{
                padding: "25px",
                background: "#f6f8fb",
                minHeight:
                    "calc(100vh - 70px)"
            }}
        >

            <h1>
                Dashboard
            </h1>

            <p
                style={{
                    color: "#666"
                }}
            >
                Monitor company devices and
                security status.
            </p>


            {/* SUMMARY */}

            <div
                style={{
                    display: "grid",
                    gridTemplateColumns:
                        "repeat(4, 1fr)",
                    gap: "18px",
                    marginTop: "25px"
                }}
            >

                <div style={cardStyle}>
                    <p>Total Devices</p>

                    <h2>
                        {totalDevices}
                    </h2>
                </div>


                <div style={cardStyle}>
                    <p>Secure Devices</p>

                    <h2
                        style={{
                            color: "#2e7d32"
                        }}
                    >
                        {secureDevices.length}
                    </h2>
                </div>


                <div style={cardStyle}>
                    <p>At Risk Devices</p>

                    <h2
                        style={{
                            color:
                                atRiskDevices.length >
                                0
                                    ? "#d32f2f"
                                    : "#2e7d32"
                        }}
                    >
                        {atRiskDevices.length}
                    </h2>
                </div>


                <div style={cardStyle}>
                    <p>Online Devices</p>

                    <h2
                        style={{
                            color: "#1a73e8"
                        }}
                    >
                        {onlineDevices.length}
                    </h2>
                </div>

            </div>


            {/* PROTECTION RATE */}

            <div
                style={{
                    ...cardStyle,
                    marginTop: "20px"
                }}
            >

                <h2>
                    Protection Rate
                </h2>

                <div
                    style={{
                        display: "flex",
                        justifyContent:
                            "space-between"
                    }}
                >

                    <span>
                        Devices meeting all
                        required policies
                    </span>

                    <strong>
                        {protectionRate}%
                    </strong>

                </div>


                <div
                    style={{
                        marginTop: "10px",
                        width: "100%",
                        height: "12px",
                        background: "#e5e7eb",
                        borderRadius: "10px"
                    }}
                >

                    <div
                        style={{
                            width:
                                `${protectionRate}%`,
                            height: "100%",
                            background:
                                protectionRate >= 80
                                    ? "#2e7d32"
                                    : "#d32f2f",
                            borderRadius:
                                "10px"
                        }}
                    />

                </div>

            </div>


            {/* DEVICE STATUS */}

            <div
                style={{
                    ...cardStyle,
                    marginTop: "20px"
                }}
            >

                <h2>
                    Device Security Status
                </h2>


                {devices.length === 0 ? (

                    <p>
                        No devices found.
                    </p>

                ) : (

                    <table
                        style={{
                            width: "100%",
                            borderCollapse:
                                "collapse"
                        }}
                    >

                        <thead>

                            <tr
                                style={{
                                    textAlign:
                                        "left",
                                    background:
                                        "#f5f5f5"
                                }}
                            >

                                <th
                                    style={{
                                        padding: "12px"
                                    }}
                                >
                                    Device
                                </th>

                                <th
                                    style={{
                                        padding: "12px"
                                    }}
                                >
                                    Antivirus
                                </th>

                                <th
                                    style={{
                                        padding: "12px"
                                    }}
                                >
                                    Firewall
                                </th>

                                <th
                                    style={{
                                        padding: "12px"
                                    }}
                                >
                                    Backup
                                </th>

                                <th
                                    style={{
                                        padding: "12px"
                                    }}
                                >
                                    Status
                                </th>

                            </tr>

                        </thead>


                        <tbody>

                            {devices.map(
                                device => {

                                    const secure =
                                        isDeviceSecure(
                                            device,
                                            securityPolicy
                                        );


                                    return (

                                        <tr
                                            key={
                                                device.id
                                            }
                                            style={{
                                                borderTop:
                                                    "1px solid #eee"
                                            }}
                                        >

                                            <td
                                                style={{
                                                    padding:
                                                        "12px"
                                                }}
                                            >
                                                <strong>
                                                    {
                                                        device.name
                                                    }
                                                </strong>
                                            </td>


                                            <td
                                                style={{
                                                    padding:
                                                        "12px"
                                                }}
                                            >
                                                {device.antivirus
                                                    ? "✓ Enabled"
                                                    : "✗ Disabled"}
                                            </td>


                                            <td
                                                style={{
                                                    padding:
                                                        "12px"
                                                }}
                                            >
                                                {device.firewall
                                                    ? "✓ Enabled"
                                                    : "✗ Disabled"}
                                            </td>


                                            <td
                                                style={{
                                                    padding:
                                                        "12px"
                                                }}
                                            >
                                                {device.backup
                                                    ? "✓ Enabled"
                                                    : "✗ Disabled"}
                                            </td>


                                            <td
                                                style={{
                                                    padding:
                                                        "12px"
                                                }}
                                            >

                                                <span
                                                    style={{
                                                        padding:
                                                            "6px 12px",
                                                        borderRadius:
                                                            "20px",
                                                        fontWeight:
                                                            "bold",
                                                        fontSize:
                                                            "12px",
                                                        background:
                                                            secure
                                                                ? "#e8f5e9"
                                                                : "#fde8e8",
                                                        color:
                                                            secure
                                                                ? "#2e7d32"
                                                                : "#c62828"
                                                    }}
                                                >
                                                    {secure
                                                        ? "Secure"
                                                        : "At Risk"}
                                                </span>

                                            </td>

                                        </tr>

                                    );
                                }
                            )}

                        </tbody>

                    </table>

                )}

            </div>


            {/* POLICY */}

            <div
                style={{
                    ...cardStyle,
                    marginTop: "20px"
                }}
            >

                <h2>
                    Current Security Policy
                </h2>

                <p>
                    Antivirus:{" "}
                    {securityPolicy.antivirus_required
                        ? "Required"
                        : "Not Required"}
                </p>

                <p>
                    Firewall:{" "}
                    {securityPolicy.firewall_required
                        ? "Required"
                        : "Not Required"}
                </p>

                <p>
                    Backup:{" "}
                    {securityPolicy.backup_required
                        ? "Required"
                        : "Not Required"}
                </p>

            </div>

        </div>
    );
}


export default Dashboard;