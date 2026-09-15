import { useMemo } from "react";

function SecurityAlerts({
    devices = [],
    securityPolicy = {}
}) {

    // =====================================================
    // SECURITY POLICY
    // =====================================================

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


    // =====================================================
    // FIND SECURITY PROBLEMS
    // =====================================================

    const alerts = useMemo(() => {

        const results = [];


        devices.forEach(device => {

            // ---------------------------------------------
            // ANTIVIRUS
            // ---------------------------------------------

            if (
                antivirusRequired &&
                device.antivirus !== true
            ) {

                results.push({
                    id:
                        `${device.id}-antivirus`,
                    device:
                        device.name,
                    employee:
                        device.employee,
                    department:
                        device.department,
                    type:
                        "Antivirus",
                    message:
                        "Antivirus protection is disabled.",
                    severity:
                        "High"
                });

            }


            // ---------------------------------------------
            // FIREWALL
            // ---------------------------------------------

            if (
                firewallRequired &&
                device.firewall !== true
            ) {

                results.push({
                    id:
                        `${device.id}-firewall`,
                    device:
                        device.name,
                    employee:
                        device.employee,
                    department:
                        device.department,
                    type:
                        "Firewall",
                    message:
                        "Firewall protection is disabled.",
                    severity:
                        "High"
                });

            }


            // ---------------------------------------------
            // BACKUP
            // ---------------------------------------------

            if (
                backupRequired &&
                device.backup !== true
            ) {

                results.push({
                    id:
                        `${device.id}-backup`,
                    device:
                        device.name,
                    employee:
                        device.employee,
                    department:
                        device.department,
                    type:
                        "Backup",
                    message:
                        "Backup protection is disabled.",
                    severity:
                        "High"
                });

            }


            // ---------------------------------------------
            // OFFLINE
            // ---------------------------------------------

            if (
                device.online === false
            ) {

                results.push({
                    id:
                        `${device.id}-offline`,
                    device:
                        device.name,
                    employee:
                        device.employee,
                    department:
                        device.department,
                    type:
                        "Device Offline",
                    message:
                        "Device is currently offline.",
                    severity:
                        "Medium"
                });

            }

        });


        return results;

    }, [
        devices,
        antivirusRequired,
        firewallRequired,
        backupRequired
    ]);


    // =====================================================
    // DEVICE RISK COUNT
    // =====================================================

    const atRiskDevices =
        useMemo(() => {

            return devices.filter(
                device => {

                    const antivirusOK =
                        !antivirusRequired ||
                        device.antivirus === true;

                    const firewallOK =
                        !firewallRequired ||
                        device.firewall === true;

                    const backupOK =
                        !backupRequired ||
                        device.backup === true;

                    return !(
                        antivirusOK &&
                        firewallOK &&
                        backupOK
                    );
                }
            );

        }, [
            devices,
            antivirusRequired,
            firewallRequired,
            backupRequired
        ]);


    // =====================================================
    // STYLES
    // =====================================================

    const cardStyle = {
        background: "#ffffff",
        border: "1px solid #ddd",
        borderRadius: "10px",
        padding: "20px",
        marginBottom: "20px"
    };


    // =====================================================
    // RENDER
    // =====================================================

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

            {/* =================================================
                HEADER
            ================================================= */}

            <div
                style={{
                    marginBottom: "25px"
                }}
            >

                <h1
                    style={{
                        margin:
                            "0 0 8px 0"
                    }}
                >
                    Security Alerts
                </h1>

                <p
                    style={{
                        margin: 0,
                        color: "#666"
                    }}
                >
                    Devices that do not meet
                    the current security policy.
                </p>

            </div>


            {/* =================================================
                SUMMARY
            ================================================= */}

            <div
                style={{
                    display: "grid",
                    gridTemplateColumns:
                        "1fr 1fr",
                    gap: "20px",
                    marginBottom: "20px"
                }}
            >

                <div style={cardStyle}>

                    <p
                        style={{
                            margin: 0,
                            color: "#777"
                        }}
                    >
                        At Risk Devices
                    </p>

                    <h2
                        style={{
                            margin:
                                "8px 0 0 0",
                            fontSize: "32px",
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

                    <p
                        style={{
                            margin: 0,
                            color: "#777"
                        }}
                    >
                        Security Alerts
                    </p>

                    <h2
                        style={{
                            margin:
                                "8px 0 0 0",
                            fontSize: "32px",
                            color:
                                alerts.length > 0
                                    ? "#d32f2f"
                                    : "#2e7d32"
                        }}
                    >
                        {alerts.length}
                    </h2>

                </div>

            </div>


            {/* =================================================
                NO ALERTS
            ================================================= */}

            {alerts.length === 0 ? (

                <div
                    style={{
                        ...cardStyle,
                        textAlign: "center",
                        padding: "50px"
                    }}
                >

                    <h2
                        style={{
                            color: "#2e7d32"
                        }}
                    >
                        ✓ No Security Alerts
                    </h2>

                    <p
                        style={{
                            color: "#777"
                        }}
                    >
                        All devices currently meet
                        the security policy.
                    </p>

                </div>

            ) : (

                /* =================================================
                   ALERT TABLE
                ================================================= */

                <div
                    style={{
                        ...cardStyle,
                        padding: 0,
                        overflow: "hidden"
                    }}
                >

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
                                    background:
                                        "#f5f5f5",
                                    textAlign:
                                        "left"
                                }}
                            >

                                <th
                                    style={{
                                        padding:
                                            "14px"
                                    }}
                                >
                                    Device
                                </th>

                                <th
                                    style={{
                                        padding:
                                            "14px"
                                    }}
                                >
                                    Employee
                                </th>

                                <th
                                    style={{
                                        padding:
                                            "14px"
                                    }}
                                >
                                    Department
                                </th>

                                <th
                                    style={{
                                        padding:
                                            "14px"
                                    }}
                                >
                                    Problem
                                </th>

                                <th
                                    style={{
                                        padding:
                                            "14px"
                                    }}
                                >
                                    Severity
                                </th>

                                <th
                                    style={{
                                        padding:
                                            "14px"
                                    }}
                                >
                                    Details
                                </th>

                            </tr>

                        </thead>


                        <tbody>

                            {alerts.map(
                                alert => (

                                    <tr
                                        key={
                                            alert.id
                                        }
                                        style={{
                                            borderTop:
                                                "1px solid #eee"
                                        }}
                                    >

                                        <td
                                            style={{
                                                padding:
                                                    "14px"
                                            }}
                                        >
                                            <strong>
                                                {
                                                    alert.device
                                                }
                                            </strong>
                                        </td>


                                        <td
                                            style={{
                                                padding:
                                                    "14px"
                                            }}
                                        >
                                            {
                                                alert.employee
                                            }
                                        </td>


                                        <td
                                            style={{
                                                padding:
                                                    "14px"
                                            }}
                                        >
                                            {
                                                alert.department
                                            }
                                        </td>


                                        <td
                                            style={{
                                                padding:
                                                    "14px"
                                            }}
                                        >
                                            {alert.type}
                                        </td>


                                        <td
                                            style={{
                                                padding:
                                                    "14px"
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
                                                        alert.severity ===
                                                        "High"
                                                            ? "#fde8e8"
                                                            : "#fff3cd",
                                                    color:
                                                        alert.severity ===
                                                        "High"
                                                            ? "#c62828"
                                                            : "#856404",
                                                    fontSize:
                                                        "12px",
                                                    fontWeight:
                                                        "bold"
                                                }}
                                            >
                                                {
                                                    alert.severity
                                                }
                                            </span>

                                        </td>


                                        <td
                                            style={{
                                                padding:
                                                    "14px"
                                            }}
                                        >
                                            {
                                                alert.message
                                            }
                                        </td>

                                    </tr>

                                )
                            )}

                        </tbody>

                    </table>

                </div>

            )}

        </div>
    );
}


export default SecurityAlerts;