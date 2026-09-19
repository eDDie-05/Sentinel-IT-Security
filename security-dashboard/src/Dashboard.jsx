function Dashboard({
    devices = [],
    securityPolicy = {}
}) {

    // =========================================
    // BASIC DATA
    // =========================================

    const deviceList =
        Array.isArray(devices)
            ? devices
            : [];

    const totalDevices =
        deviceList.length;


    // =========================================
    // ONLINE / OFFLINE HELPER
    // =========================================

    function isDeviceOnline(device) {

        return (
            device.online === true ||
            device.online === "true" ||
            device.online === 1 ||
            device.online === "1" ||
            String(
                device.connection_status || ""
            ).toUpperCase() === "ONLINE"
        );
    }


    // =========================================
    // SECURITY STATUS HELPERS
    // =========================================

    function getControlStatus(
        device,
        control
    ) {

        const statusField =
            device[`${control}_status`];

        if (
            typeof statusField === "string" &&
            statusField.trim().length > 0
        ) {
            return statusField.toUpperCase();
        }


        const value =
            device[control];


        if (
            value === true ||
            value === "true" ||
            value === 1 ||
            value === "1"
        ) {
            return "ENABLED";
        }


        if (
            value === false ||
            value === "false" ||
            value === 0 ||
            value === "0"
        ) {
            return "DISABLED";
        }


        return "UNKNOWN";
    }


    function getSecurityStatus(device) {

        /*
         * An offline computer should not be
         * considered secure because the system
         * cannot currently verify its condition.
         */
        if (!isDeviceOnline(device)) {
            return "AT RISK";
        }


        /*
         * Use the security status calculated
         * by the backend when available.
         */
        const backendStatus =
            String(
                device.security_status || ""
            ).toUpperCase();


        if (
            backendStatus === "SECURE" ||
            backendStatus === "AT RISK" ||
            backendStatus === "UNKNOWN"
        ) {
            return backendStatus;
        }


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


        const antivirusRequired =
            securityPolicy.antivirus_required !== false;


        const firewallRequired =
            securityPolicy.firewall_required !== false;


        const backupRequired =
            securityPolicy.backup_required !== false;


        if (
            (antivirusRequired &&
                antivirus === "DISABLED") ||

            (firewallRequired &&
                firewall === "DISABLED") ||

            (backupRequired &&
                backup === "DISABLED")
        ) {
            return "AT RISK";
        }


        if (
            (antivirusRequired &&
                antivirus === "UNKNOWN") ||

            (firewallRequired &&
                firewall === "UNKNOWN") ||

            (backupRequired &&
                backup === "UNKNOWN")
        ) {
            return "UNKNOWN";
        }


        return "SECURE";
    }


    // =========================================
    // DEVICE GROUPS
    // =========================================

    const secureDevices =
        deviceList.filter(
            device =>
                getSecurityStatus(device) === "SECURE"
        );


    const atRiskDevices =
        deviceList.filter(
            device =>
                getSecurityStatus(device) === "AT RISK"
        );


    const unknownDevices =
        deviceList.filter(
            device =>
                getSecurityStatus(device) === "UNKNOWN"
        );


    const onlineDevices =
        deviceList.filter(
            device =>
                isDeviceOnline(device)
        );


    const offlineDevices =
        deviceList.filter(
            device =>
                !isDeviceOnline(device)
        );


    // =========================================
    // PROTECTION RATE
    // =========================================

    const protectionRate =
        totalDevices === 0
            ? 0
            : Math.round(
                (
                    secureDevices.length /
                    totalDevices
                ) * 100
            );


    // =========================================
    // CONTROL STATISTICS
    // =========================================

    const antivirusEnabled =
        deviceList.filter(
            device =>
                getControlStatus(
                    device,
                    "antivirus"
                ) === "ENABLED"
        ).length;


    const antivirusDisabled =
        deviceList.filter(
            device =>
                getControlStatus(
                    device,
                    "antivirus"
                ) === "DISABLED"
        ).length;


    const antivirusUnknown =
        deviceList.filter(
            device =>
                getControlStatus(
                    device,
                    "antivirus"
                ) === "UNKNOWN"
        ).length;


    const firewallEnabled =
        deviceList.filter(
            device =>
                getControlStatus(
                    device,
                    "firewall"
                ) === "ENABLED"
        ).length;


    const firewallDisabled =
        deviceList.filter(
            device =>
                getControlStatus(
                    device,
                    "firewall"
                ) === "DISABLED"
        ).length;


    const firewallUnknown =
        deviceList.filter(
            device =>
                getControlStatus(
                    device,
                    "firewall"
                ) === "UNKNOWN"
        ).length;


    const backupEnabled =
        deviceList.filter(
            device =>
                getControlStatus(
                    device,
                    "backup"
                ) === "ENABLED"
        ).length;


    const backupDisabled =
        deviceList.filter(
            device =>
                getControlStatus(
                    device,
                    "backup"
                ) === "DISABLED"
        ).length;


    const backupUnknown =
        deviceList.filter(
            device =>
                getControlStatus(
                    device,
                    "backup"
                ) === "UNKNOWN"
        ).length;


    // =========================================
    // CARD STYLE
    // =========================================

    const cardStyle = {

        background: "#ffffff",

        border:
            "1px solid #e1e5eb",

        borderRadius: "12px",

        padding: "20px",

        boxSizing: "border-box",

        boxShadow:
            "0 2px 8px rgba(0,0,0,0.04)"
    };


    // =========================================
    // FORMAT LAST SEEN
    // =========================================

    function formatLastSeen(value) {

        if (!value) {
            return "Never";
        }


        const date =
            new Date(value);


        if (
            Number.isNaN(
                date.getTime()
            )
        ) {
            return "Unknown";
        }


        return date.toLocaleString();
    }


    // =========================================
    // SECURITY VALUE
    // =========================================

    function securityValue(value) {

        const status =
            String(
                value || "UNKNOWN"
            ).toUpperCase();


        if (status === "ENABLED") {

            return {

                text: "✓ Enabled",

                color: "#2e7d32",

                background: "#e8f5e9"
            };
        }


        if (status === "DISABLED") {

            return {

                text: "✗ Disabled",

                color: "#c62828",

                background: "#fde8e8"
            };
        }


        return {

            text: "? Unknown",

            color: "#b26a00",

            background: "#fff4d6"
        };
    }


    // =========================================
    // CONNECTION STATUS
    // =========================================

    function statusBadge(device) {

        const online =
            isDeviceOnline(device);


        if (online) {

            return {

                text: "ONLINE",

                color: "#087f23",

                background: "#e8f5e9"
            };
        }


        return {

            text: "OFFLINE",

            color: "#c62828",

            background: "#fde8e8"
        };
    }


    // =========================================
    // SECURITY BADGE
    // =========================================

    function securityBadge(status) {

        if (status === "SECURE") {

            return {

                text: "SECURE",

                color: "#2e7d32",

                background: "#e8f5e9"
            };
        }


        if (status === "AT RISK") {

            return {

                text: "AT RISK",

                color: "#c62828",

                background: "#fde8e8"
            };
        }


        return {

            text: "UNKNOWN",

            color: "#b26a00",

            background: "#fff4d6"
        };
    }


    // =========================================
    // MAIN UI
    // =========================================

    return (

        <div
            style={{

                padding: "25px",

                background: "#f6f8fb",

                minHeight:
                    "calc(100vh - 70px)"
            }}
        >

            {/* =========================================
                HEADER
            ========================================= */}

            <div
                style={{

                    display: "flex",

                    justifyContent:
                        "space-between",

                    alignItems: "center",

                    flexWrap: "wrap",

                    gap: "15px"
                }}
            >

                <div>

                    <div
                        style={{
                            fontSize: "12px",
                            fontWeight: "700",
                            color: "#667085",
                            letterSpacing: "0.5px",
                            marginBottom: "5px"
                        }}
                    >
                        SECURITY OPERATIONS CENTER
                    </div>

                    <h1
                        style={{

                            margin: 0,

                            fontSize: "30px",

                            color: "#101828"
                        }}
                    >
                        Security Dashboard
                    </h1>


                    <p
                        style={{

                            color: "#667085",

                            marginTop: "8px",

                            fontSize: "14px"
                        }}
                    >
                        Monitor company devices,
                        security controls and
                        system health.
                    </p>

                </div>


                <div
                    style={{

                        padding:
                            "8px 14px",

                        borderRadius:
                            "20px",

                        background:
                            "#e8f5e9",

                        color:
                            "#2e7d32",

                        fontWeight:
                            "600",

                        fontSize:
                            "13px"
                    }}
                >
                    ● Sentinel Monitoring Active
                </div>

            </div>


            {/* =========================================
                SUMMARY CARDS
            ========================================= */}

            <div
                style={{

                    display: "grid",

                    gridTemplateColumns:
                        "repeat(auto-fit, minmax(200px, 1fr))",

                    gap: "18px",

                    marginTop: "25px"
                }}
            >

                {/* TOTAL DEVICES */}

                <div style={cardStyle}>

                    <p
                        style={{

                            color: "#667085",

                            margin: 0,

                            fontWeight: "600"
                        }}
                    >
                        Total Devices
                    </p>


                    <h2
                        style={{

                            fontSize: "32px",

                            margin:
                                "10px 0 0 0",

                            color: "#101828"
                        }}
                    >
                        {totalDevices}
                    </h2>


                    <small
                        style={{
                            color: "#667085"
                        }}
                    >
                        Registered company
                        computers
                    </small>

                </div>


                {/* ONLINE DEVICES */}

                <div style={cardStyle}>

                    <p
                        style={{

                            color: "#667085",

                            margin: 0,

                            fontWeight: "600"
                        }}
                    >
                        Online Devices
                    </p>


                    <h2
                        style={{

                            color: "#1a73e8",

                            fontSize: "32px",

                            margin:
                                "10px 0 0 0"
                        }}
                    >
                        {onlineDevices.length}
                    </h2>


                    <small
                        style={{
                            color: "#667085"
                        }}
                    >
                        {offlineDevices.length}
                        {" "}
                        offline
                    </small>

                </div>


                {/* SECURE DEVICES */}

                <div style={cardStyle}>

                    <p
                        style={{

                            color: "#667085",

                            margin: 0,

                            fontWeight: "600"
                        }}
                    >
                        Secure Devices
                    </p>


                    <h2
                        style={{

                            color: "#2e7d32",

                            fontSize: "32px",

                            margin:
                                "10px 0 0 0"
                        }}
                    >
                        {secureDevices.length}
                    </h2>


                    <small
                        style={{
                            color: "#667085"
                        }}
                    >
                        All required controls
                        confirmed
                    </small>

                </div>


                {/* AT RISK DEVICES */}

                <div style={cardStyle}>

                    <p
                        style={{

                            color: "#667085",

                            margin: 0,

                            fontWeight: "600"
                        }}
                    >
                        At Risk Devices
                    </p>


                    <h2
                        style={{

                            color:
                                atRiskDevices.length > 0
                                    ? "#d32f2f"
                                    : "#2e7d32",

                            fontSize: "32px",

                            margin:
                                "10px 0 0 0"
                        }}
                    >
                        {atRiskDevices.length}
                    </h2>


                    <small
                        style={{
                            color: "#667085"
                        }}
                    >
                        Security action required
                    </small>

                </div>


                {/* UNKNOWN */}

                <div style={cardStyle}>

                    <p
                        style={{

                            color: "#667085",

                            margin: 0,

                            fontWeight: "600"
                        }}
                    >
                        Unknown Status
                    </p>


                    <h2
                        style={{

                            color: "#b26a00",

                            fontSize: "32px",

                            margin:
                                "10px 0 0 0"
                        }}
                    >
                        {unknownDevices.length}
                    </h2>


                    <small
                        style={{
                            color: "#667085"
                        }}
                    >
                        Security information
                        unavailable
                    </small>

                </div>

            </div>


            {/* =========================================
                PROTECTION RATE
            ========================================= */}

            <div
                style={{

                    ...cardStyle,

                    marginTop: "20px"
                }}
            >

                <div
                    style={{

                        display: "flex",

                        justifyContent:
                            "space-between",

                        alignItems:
                            "center",

                        gap: "15px"
                    }}
                >

                    <div>

                        <h2
                            style={{

                                margin:
                                    "0 0 6px 0"
                            }}
                        >
                            Protection Rate
                        </h2>


                        <span
                            style={{

                                color: "#667085",

                                fontSize: "14px"
                            }}
                        >
                            Devices meeting
                            required security
                            policies
                        </span>

                    </div>


                    <strong
                        style={{

                            fontSize: "26px",

                            color:
                                protectionRate >= 80
                                    ? "#2e7d32"
                                    : protectionRate >= 50
                                        ? "#b26a00"
                                        : "#c62828"
                        }}
                    >
                        {protectionRate}%
                    </strong>

                </div>


                <div
                    style={{

                        marginTop: "15px",

                        width: "100%",

                        height: "12px",

                        background:
                            "#e5e7eb",

                        borderRadius:
                            "10px",

                        overflow:
                            "hidden"
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
                                    : protectionRate >= 50
                                        ? "#b26a00"
                                        : "#d32f2f",

                            borderRadius:
                                "10px",

                            transition:
                                "width 0.4s ease"
                        }}
                    />

                </div>

            </div>


            {/* =========================================
                SECURITY CONTROL OVERVIEW
            ========================================= */}

            <div
                style={{

                    display: "grid",

                    gridTemplateColumns:
                        "repeat(auto-fit, minmax(220px, 1fr))",

                    gap: "18px",

                    marginTop: "20px"
                }}
            >

                {/* ANTIVIRUS */}

                <div style={cardStyle}>

                    <h3
                        style={{
                            marginTop: 0
                        }}
                    >
                        🛡️ Antivirus
                    </h3>


                    <p
                        style={{
                            color: "#667085",
                            fontSize: "13px"
                        }}
                    >
                        Endpoint protection
                    </p>


                    <div
                        style={{
                            marginTop: "15px",
                            color: "#2e7d32",
                            fontWeight: "600"
                        }}
                    >
                        {antivirusEnabled}
                        {" "}
                        Enabled
                    </div>


                    <div
                        style={{
                            marginTop: "7px",
                            color: "#c62828",
                            fontSize: "13px"
                        }}
                    >
                        {antivirusDisabled}
                        {" "}
                        Disabled
                    </div>


                    <div
                        style={{
                            marginTop: "7px",
                            color: "#b26a00",
                            fontSize: "13px"
                        }}
                    >
                        {antivirusUnknown}
                        {" "}
                        Unknown
                    </div>

                </div>


                {/* FIREWALL */}

                <div style={cardStyle}>

                    <h3
                        style={{
                            marginTop: 0
                        }}
                    >
                        🔥 Firewall
                    </h3>


                    <p
                        style={{
                            color: "#667085",
                            fontSize: "13px"
                        }}
                    >
                        Network protection
                    </p>


                    <div
                        style={{
                            marginTop: "15px",
                            color: "#2e7d32",
                            fontWeight: "600"
                        }}
                    >
                        {firewallEnabled}
                        {" "}
                        Enabled
                    </div>


                    <div
                        style={{
                            marginTop: "7px",
                            color: "#c62828",
                            fontSize: "13px"
                        }}
                    >
                        {firewallDisabled}
                        {" "}
                        Disabled
                    </div>


                    <div
                        style={{
                            marginTop: "7px",
                            color: "#b26a00",
                            fontSize: "13px"
                        }}
                    >
                        {firewallUnknown}
                        {" "}
                        Unknown
                    </div>

                </div>


                {/* BACKUP */}

                <div style={cardStyle}>

                    <h3
                        style={{
                            marginTop: 0
                        }}
                    >
                        💾 Backup
                    </h3>


                    <p
                        style={{
                            color: "#667085",
                            fontSize: "13px"
                        }}
                    >
                        Data protection
                    </p>


                    <div
                        style={{
                            marginTop: "15px",
                            color: "#2e7d32",
                            fontWeight: "600"
                        }}
                    >
                        {backupEnabled}
                        {" "}
                        Enabled
                    </div>


                    <div
                        style={{
                            marginTop: "7px",
                            color: "#c62828",
                            fontSize: "13px"
                        }}
                    >
                        {backupDisabled}
                        {" "}
                        Disabled
                    </div>


                    <div
                        style={{
                            marginTop: "7px",
                            color: "#b26a00",
                            fontSize: "13px"
                        }}
                    >
                        {backupUnknown}
                        {" "}
                        Unknown
                    </div>

                </div>

            </div>


            {/* =========================================
                LIVE DEVICE MONITORING
            ========================================= */}

            <div
                style={{

                    ...cardStyle,

                    marginTop: "20px",

                    overflowX: "auto"
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
                            "15px",

                        gap: "10px"
                    }}
                >

                    <div>

                        <h2
                            style={{
                                margin: 0
                            }}
                        >
                            Live Device Monitoring
                        </h2>


                        <p
                            style={{

                                margin:
                                    "6px 0 0 0",

                                color:
                                    "#667085",

                                fontSize:
                                    "14px"
                            }}
                        >
                            Information reported
                            automatically by the
                            Sentinel Agent.
                        </p>

                    </div>


                    <div
                        style={{

                            padding:
                                "6px 12px",

                            background:
                                "#f1f5f9",

                            borderRadius:
                                "20px",

                            fontSize:
                                "12px",

                            fontWeight:
                                "600",

                            color:
                                "#475467"
                        }}
                    >
                        {deviceList.length}
                        {" "}
                        devices
                    </div>

                </div>


                {deviceList.length === 0 ? (

                    <div
                        style={{

                            padding: "40px",

                            textAlign:
                                "center",

                            color:
                                "#667085"
                        }}
                    >

                        <div
                            style={{

                                fontSize:
                                    "42px",

                                marginBottom:
                                    "10px"
                            }}
                        >
                            🖥️
                        </div>

                        <strong
                            style={{

                                display:
                                    "block",

                                fontSize:
                                    "18px",

                                color:
                                    "#344054"
                            }}
                        >
                            No devices found
                        </strong>

                        <p>
                            Waiting for a Sentinel
                            Agent heartbeat.
                        </p>

                    </div>

                ) : (

                    <table
                        style={{

                            width: "100%",

                            minWidth:
                                "1200px",

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
                                        "#f8fafc"
                                }}
                            >

                                <th style={{
                                    padding: "13px"
                                }}>
                                    Device
                                </th>

                                <th style={{
                                    padding: "13px"
                                }}>
                                    OS
                                </th>

                                <th style={{
                                    padding: "13px"
                                }}>
                                    CPU
                                </th>

                                <th style={{
                                    padding: "13px"
                                }}>
                                    RAM
                                </th>

                                <th style={{
                                    padding: "13px"
                                }}>
                                    Antivirus
                                </th>

                                <th style={{
                                    padding: "13px"
                                }}>
                                    Firewall
                                </th>

                                <th style={{
                                    padding: "13px"
                                }}>
                                    Backup
                                </th>

                                <th style={{
                                    padding: "13px"
                                }}>
                                    Connection
                                </th>

                                <th style={{
                                    padding: "13px"
                                }}>
                                    Last Seen
                                </th>

                                <th style={{
                                    padding: "13px"
                                }}>
                                    Security
                                </th>

                            </tr>

                        </thead>


                        <tbody>

                            {deviceList.map(
                                (device, index) => {

                                    const antivirusStatus =
                                        getControlStatus(
                                            device,
                                            "antivirus"
                                        );


                                    const firewallStatus =
                                        getControlStatus(
                                            device,
                                            "firewall"
                                        );


                                    const backupStatus =
                                        getControlStatus(
                                            device,
                                            "backup"
                                        );


                                    const securityStatus =
                                        getSecurityStatus(
                                            device
                                        );


                                    const antivirus =
                                        securityValue(
                                            antivirusStatus
                                        );


                                    const firewall =
                                        securityValue(
                                            firewallStatus
                                        );


                                    const backup =
                                        securityValue(
                                            backupStatus
                                        );


                                    const connection =
                                        statusBadge(
                                            device
                                        );


                                    const security =
                                        securityBadge(
                                            securityStatus
                                        );


                                    return (

                                        <tr
                                            key={
                                                device.id ||
                                                device.device_id ||
                                                index
                                            }
                                            style={{
                                                borderTop:
                                                    "1px solid #eee"
                                            }}
                                        >

                                            {/* DEVICE */}

                                            <td
                                                style={{
                                                    padding:
                                                        "13px"
                                                }}
                                            >

                                                <strong>
                                                    {
                                                        device.name ||
                                                        device.device_name ||
                                                        device.hostname ||
                                                        device.device_id ||
                                                        "Unknown Device"
                                                    }
                                                </strong>


                                                <div
                                                    style={{

                                                        marginTop:
                                                            "4px",

                                                        fontSize:
                                                            "12px",

                                                        color:
                                                            "#667085"
                                                    }}
                                                >
                                                    ID:{" "}

                                                    {
                                                        device.device_id ||
                                                        "Manual device"
                                                    }
                                                </div>


                                                {device.username && (

                                                    <div
                                                        style={{

                                                            marginTop:
                                                                "3px",

                                                            fontSize:
                                                                "12px",

                                                            color:
                                                                "#667085"
                                                        }}
                                                    >
                                                        User:{" "}
                                                        {
                                                            device.username
                                                        }
                                                    </div>

                                                )}

                                            </td>


                                            {/* OS */}

                                            <td
                                                style={{
                                                    padding:
                                                        "13px"
                                                }}
                                            >
                                                {
                                                    device.operating_system ||
                                                    device.operatingSystem ||
                                                    device.os ||
                                                    "Unknown"
                                                }
                                            </td>


                                            {/* CPU */}

                                            <td
                                                style={{

                                                    padding:
                                                        "13px",

                                                    maxWidth:
                                                        "220px"
                                                }}
                                            >
                                                <span
                                                    style={{
                                                        fontSize:
                                                            "12px"
                                                    }}
                                                >
                                                    {
                                                        device.cpu ||
                                                        device.cpu_usage ||
                                                        device.cpu_percent !== undefined
                                                            ? (
                                                                device.cpu ||
                                                                device.cpu_usage ||
                                                                `${device.cpu_percent}%`
                                                            )
                                                            : "Unknown"
                                                    }
                                                </span>
                                            </td>


                                            {/* RAM */}

                                            <td
                                                style={{
                                                    padding:
                                                        "13px"
                                                }}
                                            >

                                                {
                                                    device.ram_gb !== null &&
                                                    device.ram_gb !== undefined
                                                        ? `${device.ram_gb} GB`

                                                        : device.total_memory_gb !== null &&
                                                            device.total_memory_gb !== undefined

                                                            ? `${device.total_memory_gb} GB`

                                                            : device.ram ||
                                                                device.memory ||
                                                                "Unknown"
                                                }

                                            </td>


                                            {/* ANTIVIRUS */}

                                            <td
                                                style={{
                                                    padding:
                                                        "13px"
                                                }}
                                            >

                                                <span
                                                    style={{

                                                        padding:
                                                            "5px 9px",

                                                        borderRadius:
                                                            "15px",

                                                        background:
                                                            antivirus.background,

                                                        color:
                                                            antivirus.color,

                                                        fontSize:
                                                            "12px",

                                                        fontWeight:
                                                            "600",

                                                        whiteSpace:
                                                            "nowrap"
                                                    }}
                                                >
                                                    {
                                                        antivirus.text
                                                    }
                                                </span>


                                                {device.antivirus_product && (

                                                    <div
                                                        style={{

                                                            marginTop:
                                                                "5px",

                                                            fontSize:
                                                                "11px",

                                                            color:
                                                                "#667085"
                                                        }}
                                                    >
                                                        {
                                                            device.antivirus_product
                                                        }
                                                    </div>

                                                )}

                                            </td>


                                            {/* FIREWALL */}

                                            <td
                                                style={{
                                                    padding:
                                                        "13px"
                                                }}
                                            >

                                                <span
                                                    style={{

                                                        padding:
                                                            "5px 9px",

                                                        borderRadius:
                                                            "15px",

                                                        background:
                                                            firewall.background,

                                                        color:
                                                            firewall.color,

                                                        fontSize:
                                                            "12px",

                                                        fontWeight:
                                                            "600",

                                                        whiteSpace:
                                                            "nowrap"
                                                    }}
                                                >
                                                    {
                                                        firewall.text
                                                    }
                                                </span>

                                            </td>


                                            {/* BACKUP */}

                                            <td
                                                style={{
                                                    padding:
                                                        "13px"
                                                }}
                                            >

                                                <span
                                                    style={{

                                                        padding:
                                                            "5px 9px",

                                                        borderRadius:
                                                            "15px",

                                                        background:
                                                            backup.background,

                                                        color:
                                                            backup.color,

                                                        fontSize:
                                                            "12px",

                                                        fontWeight:
                                                            "600",

                                                        whiteSpace:
                                                            "nowrap"
                                                    }}
                                                >
                                                    {
                                                        backup.text
                                                    }
                                                </span>

                                            </td>


                                            {/* CONNECTION */}

                                            <td
                                                style={{
                                                    padding:
                                                        "13px"
                                                }}
                                            >

                                                <span
                                                    style={{

                                                        display:
                                                            "inline-block",

                                                        padding:
                                                            "6px 10px",

                                                        borderRadius:
                                                            "15px",

                                                        background:
                                                            connection.background,

                                                        color:
                                                            connection.color,

                                                        fontSize:
                                                            "12px",

                                                        fontWeight:
                                                            "700"
                                                    }}
                                                >
                                                    ●{" "}
                                                    {
                                                        connection.text
                                                    }
                                                </span>

                                            </td>


                                            {/* LAST SEEN */}

                                            <td
                                                style={{

                                                    padding:
                                                        "13px",

                                                    whiteSpace:
                                                        "nowrap",

                                                    fontSize:
                                                        "12px",

                                                    color:
                                                        "#667085"
                                                }}
                                            >

                                                {
                                                    formatLastSeen(
                                                        device.last_seen ||
                                                        device.lastSeen ||
                                                        device.updated_at
                                                    )
                                                }

                                            </td>


                                            {/* SECURITY */}

                                            <td
                                                style={{
                                                    padding:
                                                        "13px"
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
                                                            security.background,

                                                        color:
                                                            security.color,

                                                        whiteSpace:
                                                            "nowrap"
                                                    }}
                                                >
                                                    {
                                                        security.text
                                                    }
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


            {/* =========================================
                OFFLINE DEVICES
            ========================================= */}

            {offlineDevices.length > 0 && (

                <div
                    style={{

                        ...cardStyle,

                        marginTop: "20px",

                        borderLeft:
                            "4px solid #d32f2f"
                    }}
                >

                    <h2
                        style={{
                            marginTop: 0
                        }}
                    >
                        Offline Devices
                    </h2>


                    <p
                        style={{

                            color:
                                "#667085",

                            fontSize:
                                "14px"
                        }}
                    >
                        These devices have not
                        recently sent a heartbeat
                        to the Sentinel server.
                    </p>


                    {offlineDevices.map(
                        (device, index) => (

                            <div
                                key={
                                    device.id ||
                                    device.device_id ||
                                    index
                                }
                                style={{

                                    padding:
                                        "12px 0",

                                    borderBottom:
                                        "1px solid #eee",

                                    display:
                                        "flex",

                                    justifyContent:
                                        "space-between",

                                    alignItems:
                                        "center",

                                    gap:
                                        "15px"
                                }}
                            >

                                <div>

                                    <strong>
                                        {
                                            device.name ||
                                            device.device_name ||
                                            device.hostname ||
                                            device.device_id ||
                                            "Unknown Device"
                                        }
                                    </strong>


                                    <div
                                        style={{

                                            fontSize:
                                                "12px",

                                            color:
                                                "#667085",

                                            marginTop:
                                                "4px"
                                        }}
                                    >
                                        Last seen:{" "}

                                        {
                                            formatLastSeen(
                                                device.last_seen ||
                                                device.lastSeen ||
                                                device.updated_at
                                            )
                                        }
                                    </div>

                                </div>


                                <span
                                    style={{

                                        padding:
                                            "6px 10px",

                                        borderRadius:
                                            "15px",

                                        background:
                                            "#fde8e8",

                                        color:
                                            "#c62828",

                                        fontWeight:
                                            "600",

                                        fontSize:
                                            "12px"
                                    }}
                                >
                                    OFFLINE
                                </span>

                            </div>

                        )
                    )}

                </div>

            )}


            {/* =========================================
                SECURITY POLICY
            ========================================= */}

            <div
                style={{

                    ...cardStyle,

                    marginTop: "20px"
                }}
            >

                <h2
                    style={{
                        marginTop: 0
                    }}
                >
                    Current Security Policy
                </h2>


                <p
                    style={{

                        color:
                            "#667085",

                        fontSize:
                            "14px"
                    }}
                >
                    These controls determine
                    which security requirements
                    Sentinel checks on company
                    devices.
                </p>


                <div
                    style={{

                        display: "grid",

                        gridTemplateColumns:
                            "repeat(auto-fit, minmax(180px, 1fr))",

                        gap: "12px"
                    }}
                >

                    {/* ANTIVIRUS */}

                    <div
                        style={{

                            padding: "15px",

                            background:
                                "#f8fafc",

                            borderRadius:
                                "8px",

                            border:
                                "1px solid #e5e7eb"
                        }}
                    >

                        <strong>
                            Antivirus
                        </strong>


                        <div
                            style={{
                                marginTop:
                                    "7px",

                                color:
                                    securityPolicy.antivirus_required === false
                                        ? "#667085"
                                        : "#2e7d32",

                                fontWeight:
                                    "600"
                            }}
                        >
                            {
                                securityPolicy.antivirus_required === false
                                    ? "Not Required"
                                    : "Required"
                            }
                        </div>

                    </div>


                    {/* FIREWALL */}

                    <div
                        style={{

                            padding: "15px",

                            background:
                                "#f8fafc",

                            borderRadius:
                                "8px",

                            border:
                                "1px solid #e5e7eb"
                        }}
                    >

                        <strong>
                            Firewall
                        </strong>


                        <div
                            style={{

                                marginTop:
                                    "7px",

                                color:
                                    securityPolicy.firewall_required === false
                                        ? "#667085"
                                        : "#2e7d32",

                                fontWeight:
                                    "600"
                            }}
                        >
                            {
                                securityPolicy.firewall_required === false
                                    ? "Not Required"
                                    : "Required"
                            }
                        </div>

                    </div>


                    {/* BACKUP */}

                    <div
                        style={{

                            padding: "15px",

                            background:
                                "#f8fafc",

                            borderRadius:
                                "8px",

                            border:
                                "1px solid #e5e7eb"
                        }}
                    >

                        <strong>
                            Backup
                        </strong>


                        <div
                            style={{

                                marginTop:
                                    "7px",

                                color:
                                    securityPolicy.backup_required === false
                                        ? "#667085"
                                        : "#2e7d32",

                                fontWeight:
                                    "600"
                            }}
                        >
                            {
                                securityPolicy.backup_required === false
                                    ? "Not Required"
                                    : "Required"
                            }
                        </div>

                    </div>

                </div>

            </div>


            {/* =========================================
                HOW SENTINEL WORKS
            ========================================= */}

            <div
                style={{

                    ...cardStyle,

                    marginTop: "20px",

                    marginBottom: "25px"
                }}
            >

                <h2
                    style={{
                        marginTop: 0
                    }}
                >
                    Sentinel Monitoring
                </h2>


                <p
                    style={{

                        color:
                            "#667085",

                        fontSize:
                            "14px"
                    }}
                >
                    The Sentinel Agent automatically
                    reports device and security
                    information to the server.
                </p>


                <div
                    style={{

                        display:
                            "grid",

                        gridTemplateColumns:
                            "repeat(auto-fit, minmax(200px, 1fr))",

                        gap:
                            "15px",

                        marginTop:
                            "15px"
                    }}
                >


                    {/* AGENT */}

                    <div
                        style={{

                            padding:
                                "18px",

                            background:
                                "#f8fafc",

                            borderRadius:
                                "10px"
                        }}
                    >

                        <strong>
                            01. Agent
                        </strong>

                        <p
                            style={{

                                color:
                                    "#667085",

                                fontSize:
                                    "13px"
                            }}
                        >
                            Collects device,
                            firewall, backup
                            and antivirus
                            information.
                        </p>

                    </div>


                    {/* SERVER */}

                    <div
                        style={{

                            padding:
                                "18px",

                            background:
                                "#f8fafc",

                            borderRadius:
                                "10px"
                        }}
                    >

                        <strong>
                            02. Server
                        </strong>

                        <p
                            style={{

                                color:
                                    "#667085",

                                fontSize:
                                    "13px"
                            }}
                        >
                            Receives the device
                            heartbeat every
                            30 seconds.
                        </p>

                    </div>


                    {/* DATABASE */}

                    <div
                        style={{

                            padding:
                                "18px",

                            background:
                                "#f8fafc",

                            borderRadius:
                                "10px"
                        }}
                    >

                        <strong>
                            03. Database
                        </strong>

                        <p
                            style={{

                                color:
                                    "#667085",

                                fontSize:
                                    "13px"
                            }}
                        >
                            PostgreSQL stores
                            device and security
                            information.
                        </p>

                    </div>


                    {/* DASHBOARD */}

                    <div
                        style={{

                            padding:
                                "18px",

                            background:
                                "#f8fafc",

                            borderRadius:
                                "10px"
                        }}
                    >

                        <strong>
                            04. Dashboard
                        </strong>

                        <p
                            style={{

                                color:
                                    "#667085",

                                fontSize:
                                    "13px"
                            }}
                        >
                            Administrator
                            monitors the
                            company environment.
                        </p>

                    </div>

                </div>

            </div>

        </div>

    );
}


export default Dashboard;