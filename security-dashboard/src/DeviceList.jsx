import { useEffect, useState } from "react";
import {
    isDeviceSecure,
    getDeviceSecurityProblems
} from "./securityUtils";


function DeviceList({
    devices = [],
    setDevices,
    userRole,
    securityPolicy = {},
    onDeviceDeleted,
    onDeviceUpdated
}) {

    const [search, setSearch] =
        useState("");

    const [filter, setFilter] =
        useState("all");

    const [departmentFilter, setDepartmentFilter] =
        useState("all");

    const [editingDevice, setEditingDevice] =
        useState(null);

    const [message, setMessage] =
        useState("");


    const canManage =
        userRole === "Administrator" ||
        userRole === "IT Manager";


    // =====================================================
    // LOAD DEVICES AGAIN
    // =====================================================

    useEffect(() => {

        async function refreshDevices() {

            try {

                const token =
                    localStorage.getItem(
                        "token"
                    );

                const response =
                    await fetch(
                        "http://localhost:5000/api/devices",
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
                        "Failed to load devices"
                    );
                }


                setDevices(data);

            } catch (error) {

                console.error(
                    "Device refresh error:",
                    error
                );
            }
        }


        refreshDevices();

    }, [setDevices]);


    // =====================================================
    // DEVICE SECURITY
    // =====================================================

    function deviceIsSecure(device) {

        return isDeviceSecure(
            device,
            securityPolicy
        );
    }


    // =====================================================
    // FILTER DEVICES
    // =====================================================

    const filteredDevices =
        devices.filter(device => {

            const searchText =
                search.toLowerCase();


            const matchesSearch =
                device.name
                    ?.toLowerCase()
                    .includes(searchText) ||

                device.employee
                    ?.toLowerCase()
                    .includes(searchText) ||

                device.department
                    ?.toLowerCase()
                    .includes(searchText) ||

                device.operating_system
                    ?.toLowerCase()
                    .includes(searchText);


            if (!matchesSearch) {
                return false;
            }


            if (
                departmentFilter !== "all" &&
                device.department !==
                departmentFilter
            ) {

                return false;
            }


            if (filter === "online") {

                return device.online === true;
            }


            if (filter === "offline") {

                return device.online !== true;
            }


            if (filter === "secure") {

                return deviceIsSecure(device);
            }


            if (filter === "risk") {

                return !deviceIsSecure(
                    device
                );
            }


            return true;

        });


    // =====================================================
    // DEPARTMENTS
    // =====================================================

    const departments = [
        ...new Set(
            devices
                .map(
                    device =>
                        device.department
                )
                .filter(Boolean)
        )
    ];


    // =====================================================
    // COUNTS
    // =====================================================

    const total =
        devices.length;


    const secure =
        devices.filter(
            device =>
                deviceIsSecure(device)
        ).length;


    const atRisk =
        devices.filter(
            device =>
                !deviceIsSecure(device)
        ).length;


    const online =
        devices.filter(
            device =>
                device.online === true
        ).length;


    const offline =
        devices.filter(
            device =>
                device.online !== true
        ).length;


    // =====================================================
    // DELETE
    // =====================================================

    async function deleteDevice(
        deviceId
    ) {

        if (!canManage) {
            return;
        }


        const confirmed =
            window.confirm(
                "Are you sure you want to delete this device?"
            );


        if (!confirmed) {
            return;
        }


        try {

            const token =
                localStorage.getItem(
                    "token"
                );


            const response =
                await fetch(
                    `http://localhost:5000/api/devices/${deviceId}`,
                    {
                        method: "DELETE",
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
                    "Failed to delete device"
                );
            }


            setDevices(
                previous =>
                    previous.filter(
                        device =>
                            device.id !==
                            deviceId
                    )
            );


            if (onDeviceDeleted) {

                onDeviceDeleted(
                    deviceId
                );
            }


            setMessage(
                "Device deleted successfully."
            );


        } catch (error) {

            console.error(
                "Delete device error:",
                error
            );

            setMessage(
                error.message
            );
        }
    }


    // =====================================================
    // UPDATE
    // =====================================================

    async function updateDevice(
        event
    ) {

        event.preventDefault();


        if (!canManage) {
            return;
        }


        try {

            const token =
                localStorage.getItem(
                    "token"
                );


            const response =
                await fetch(
                    `http://localhost:5000/api/devices/${editingDevice.id}`,
                    {
                        method: "PUT",

                        headers: {
                            "Content-Type":
                                "application/json",

                            Authorization:
                                `Bearer ${token}`
                        },

                        body:
                            JSON.stringify({
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

                                antivirus:
                                    editingDevice.antivirus,

                                firewall:
                                    editingDevice.firewall,

                                backup:
                                    editingDevice.backup,

                                online:
                                    editingDevice.online
                            })
                    }
                );


            const data =
                await response.json();


            if (!response.ok) {

                throw new Error(
                    data.error ||
                    "Failed to update device"
                );
            }


            setDevices(
                previous =>
                    previous.map(
                        device =>
                            device.id ===
                            data.id
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

            setMessage(
                error.message
            );
        }
    }


    // =====================================================
    // TOGGLE SECURITY
    // =====================================================

    async function toggleSecurity(
        device,
        field
    ) {

        if (!canManage) {
            return;
        }


        const updatedValue =
            !device[field];


        try {

            const token =
                localStorage.getItem(
                    "token"
                );


            const response =
                await fetch(
                    `http://localhost:5000/api/devices/${device.id}`,
                    {
                        method: "PUT",

                        headers: {
                            "Content-Type":
                                "application/json",

                            Authorization:
                                `Bearer ${token}`
                        },

                        body:
                            JSON.stringify({
                                [field]:
                                    updatedValue
                            })
                    }
                );


            const data =
                await response.json();


            if (!response.ok) {

                throw new Error(
                    data.error ||
                    "Failed to update security"
                );
            }


            setDevices(
                previous =>
                    previous.map(
                        item =>
                            item.id ===
                            data.id
                                ? data
                                : item
                    )
            );


            if (onDeviceUpdated) {

                onDeviceUpdated(data);
            }


        } catch (error) {

            console.error(
                "Security update error:",
                error
            );

            setMessage(
                error.message
            );
        }
    }


    // =====================================================
    // TOGGLE ONLINE
    // =====================================================

    async function toggleOnline(
        device
    ) {

        if (!canManage) {
            return;
        }


        try {

            const token =
                localStorage.getItem(
                    "token"
                );


            const response =
                await fetch(
                    `http://localhost:5000/api/devices/${device.id}`,
                    {
                        method: "PUT",

                        headers: {
                            "Content-Type":
                                "application/json",

                            Authorization:
                                `Bearer ${token}`
                        },

                        body:
                            JSON.stringify({
                                online:
                                    !device.online
                            })
                    }
                );


            const data =
                await response.json();


            if (!response.ok) {

                throw new Error(
                    data.error ||
                    "Failed to update device status"
                );
            }


            setDevices(
                previous =>
                    previous.map(
                        item =>
                            item.id ===
                            data.id
                                ? data
                                : item
                    )
            );


            if (onDeviceUpdated) {

                onDeviceUpdated(data);
            }


        } catch (error) {

            console.error(
                "Online status error:",
                error
            );

            setMessage(
                error.message
            );
        }
    }


    // =====================================================
    // ADD DEVICE
    // =====================================================

    function goToAddDevice() {

        window.dispatchEvent(
            new CustomEvent(
                "open-add-device"
            )
        );
    }


    // =====================================================
    // RENDER
    // =====================================================

    return (

        <div
            style={{
                padding: "25px",
                background: "#f6f8fb",
                minHeight:
                    "calc(100vh - 70px)"
            }}
        >

            {/* HEADER */}

            <div
                style={{
                    display: "flex",
                    justifyContent:
                        "space-between",
                    alignItems: "center",
                    marginBottom: "20px"
                }}
            >

                <div>

                    <h1
                        style={{
                            margin:
                                "0 0 5px 0"
                        }}
                    >
                        Devices
                    </h1>

                    <p
                        style={{
                            margin: 0,
                            color: "#666"
                        }}
                    >
                        Manage company devices
                        and security status.
                    </p>

                </div>


                {canManage && (

                    <button
                        onClick={
                            goToAddDevice
                        }
                        style={{
                            padding:
                                "11px 18px",
                            border: "none",
                            borderRadius:
                                "7px",
                            background:
                                "#1a73e8",
                            color: "white",
                            cursor:
                                "pointer",
                            fontWeight:
                                "bold"
                        }}
                    >
                        + Add Device
                    </button>

                )}

            </div>


            {/* MESSAGE */}

            {message && (

                <div
                    style={{
                        marginBottom:
                            "15px",
                        padding: "12px",
                        background:
                            "#e8f0fe",
                        borderRadius:
                            "7px"
                    }}
                >
                    {message}
                </div>

            )}


            {/* SUMMARY */}

            <div
                style={{
                    display: "grid",
                    gridTemplateColumns:
                        "repeat(5, 1fr)",
                    gap: "15px",
                    marginBottom:
                        "20px"
                }}
            >

                <div
                    style={{
                        background:
                            "white",
                        padding: "18px",
                        borderRadius:
                            "10px",
                        border:
                            "1px solid #ddd"
                    }}
                >
                    <small>
                        Total
                    </small>

                    <h2>
                        {total}
                    </h2>
                </div>


                <div
                    style={{
                        background:
                            "white",
                        padding: "18px",
                        borderRadius:
                            "10px",
                        border:
                            "1px solid #ddd"
                    }}
                >
                    <small>
                        Secure
                    </small>

                    <h2
                        style={{
                            color:
                                "#2e7d32"
                        }}
                    >
                        {secure}
                    </h2>
                </div>


                <div
                    style={{
                        background:
                            "white",
                        padding: "18px",
                        borderRadius:
                            "10px",
                        border:
                            "1px solid #ddd"
                    }}
                >
                    <small>
                        At Risk
                    </small>

                    <h2
                        style={{
                            color:
                                atRisk > 0
                                    ? "#d32f2f"
                                    : "#2e7d32"
                        }}
                    >
                        {atRisk}
                    </h2>
                </div>


                <div
                    style={{
                        background:
                            "white",
                        padding: "18px",
                        borderRadius:
                            "10px",
                        border:
                            "1px solid #ddd"
                    }}
                >
                    <small>
                        Online
                    </small>

                    <h2
                        style={{
                            color:
                                "#1a73e8"
                        }}
                    >
                        {online}
                    </h2>
                </div>


                <div
                    style={{
                        background:
                            "white",
                        padding: "18px",
                        borderRadius:
                            "10px",
                        border:
                            "1px solid #ddd"
                    }}
                >
                    <small>
                        Offline
                    </small>

                    <h2>
                        {offline}
                    </h2>
                </div>

            </div>


            {/* SEARCH / FILTER */}

            <div
                style={{
                    background:
                        "white",
                    padding: "15px",
                    borderRadius:
                        "10px",
                    border:
                        "1px solid #ddd",
                    marginBottom:
                        "20px",
                    display: "flex",
                    gap: "10px",
                    flexWrap:
                        "wrap"
                }}
            >

                <input
                    type="text"
                    placeholder=
                        "Search devices..."
                    value={search}
                    onChange={
                        event =>
                            setSearch(
                                event.target.value
                            )
                    }
                    style={{
                        padding:
                            "10px",
                        flex: 1,
                        minWidth:
                            "200px",
                        border:
                            "1px solid #ccc",
                        borderRadius:
                            "7px"
                    }}
                />


                <select
                    value={filter}
                    onChange={
                        event =>
                            setFilter(
                                event.target.value
                            )
                    }
                    style={{
                        padding:
                            "10px",
                        border:
                            "1px solid #ccc",
                        borderRadius:
                            "7px"
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
                    value={
                        departmentFilter
                    }
                    onChange={
                        event =>
                            setDepartmentFilter(
                                event.target.value
                            )
                    }
                    style={{
                        padding:
                            "10px",
                        border:
                            "1px solid #ccc",
                        borderRadius:
                            "7px"
                    }}
                >

                    <option value="all">
                        All Departments
                    </option>

                    {departments.map(
                        department => (

                            <option
                                key={
                                    department
                                }
                                value={
                                    department
                                }
                            >
                                {department}
                            </option>

                        )
                    )}

                </select>

            </div>


            {/* DEVICES */}

            <div
                style={{
                    display: "grid",
                    gridTemplateColumns:
                        "repeat(2, 1fr)",
                    gap: "20px"
                }}
            >

                {filteredDevices.map(
                    device => {

                        const secure =
                            deviceIsSecure(
                                device
                            );


                        const problems =
                            getDeviceSecurityProblems(
                                device,
                                securityPolicy
                            );


                        return (

                            <div
                                key={
                                    device.id
                                }
                                style={{
                                    background:
                                        "white",
                                    border:
                                        secure
                                            ? "1px solid #ddd"
                                            : "2px solid #d32f2f",
                                    borderRadius:
                                        "12px",
                                    padding:
                                        "20px"
                                }}
                            >

                                {/* DEVICE HEADER */}

                                <div
                                    style={{
                                        display:
                                            "flex",
                                        justifyContent:
                                            "space-between",
                                        alignItems:
                                            "center"
                                    }}
                                >

                                    <div>

                                        <h2
                                            style={{
                                                margin:
                                                    "0 0 5px 0"
                                            }}
                                        >
                                            {
                                                device.name
                                            }
                                        </h2>

                                        <span
                                            style={{
                                                color:
                                                    "#777"
                                            }}
                                        >
                                            {
                                                device.operating_system
                                            }
                                        </span>

                                    </div>


                                    <span
                                        style={{
                                            padding:
                                                "7px 12px",
                                            borderRadius:
                                                "20px",
                                            fontSize:
                                                "12px",
                                            fontWeight:
                                                "bold",
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
                                            ? "SECURE"
                                            : "AT RISK"}
                                    </span>

                                </div>


                                {/* DEVICE DETAILS */}

                                <div
                                    style={{
                                        marginTop:
                                            "18px",
                                        lineHeight:
                                            "1.8"
                                    }}
                                >

                                    <div>
                                        <strong>
                                            Employee:
                                        </strong>{" "}
                                        {
                                            device.employee
                                        }
                                    </div>

                                    <div>
                                        <strong>
                                            Department:
                                        </strong>{" "}
                                        {
                                            device.department
                                        }
                                    </div>

                                    <div>
                                        <strong>
                                            IP Address:
                                        </strong>{" "}
                                        {
                                            device.ip_address
                                        }
                                    </div>

                                </div>


                                {/* SECURITY STATUS */}

                                <div
                                    style={{
                                        marginTop:
                                            "18px",
                                        paddingTop:
                                            "15px",
                                        borderTop:
                                            "1px solid #eee"
                                    }}
                                >

                                    <h3>
                                        Security
                                    </h3>


                                    <div
                                        style={{
                                            display:
                                                "grid",
                                            gridTemplateColumns:
                                                "repeat(3, 1fr)",
                                            gap:
                                                "8px"
                                        }}
                                    >

                                        <button
                                            disabled={
                                                !canManage
                                            }
                                            onClick={() =>
                                                toggleSecurity(
                                                    device,
                                                    "antivirus"
                                                )
                                            }
                                            style={{
                                                padding:
                                                    "9px",
                                                border:
                                                    "none",
                                                borderRadius:
                                                    "6px",
                                                cursor:
                                                    canManage
                                                        ? "pointer"
                                                        : "default",
                                                background:
                                                    device.antivirus
                                                        ? "#e8f5e9"
                                                        : "#fde8e8",
                                                color:
                                                    device.antivirus
                                                        ? "#2e7d32"
                                                        : "#c62828"
                                            }}
                                        >
                                            Antivirus
                                            <br />
                                            {device.antivirus
                                                ? "ON"
                                                : "OFF"}
                                        </button>


                                        <button
                                            disabled={
                                                !canManage
                                            }
                                            onClick={() =>
                                                toggleSecurity(
                                                    device,
                                                    "firewall"
                                                )
                                            }
                                            style={{
                                                padding:
                                                    "9px",
                                                border:
                                                    "none",
                                                borderRadius:
                                                    "6px",
                                                cursor:
                                                    canManage
                                                        ? "pointer"
                                                        : "default",
                                                background:
                                                    device.firewall
                                                        ? "#e8f5e9"
                                                        : "#fde8e8",
                                                color:
                                                    device.firewall
                                                        ? "#2e7d32"
                                                        : "#c62828"
                                            }}
                                        >
                                            Firewall
                                            <br />
                                            {device.firewall
                                                ? "ON"
                                                : "OFF"}
                                        </button>


                                        <button
                                            disabled={
                                                !canManage
                                            }
                                            onClick={() =>
                                                toggleSecurity(
                                                    device,
                                                    "backup"
                                                )
                                            }
                                            style={{
                                                padding:
                                                    "9px",
                                                border:
                                                    "none",
                                                borderRadius:
                                                    "6px",
                                                cursor:
                                                    canManage
                                                        ? "pointer"
                                                        : "default",
                                                background:
                                                    device.backup
                                                        ? "#e8f5e9"
                                                        : "#fde8e8",
                                                color:
                                                    device.backup
                                                        ? "#2e7d32"
                                                        : "#c62828"
                                            }}
                                        >
                                            Backup
                                            <br />
                                            {device.backup
                                                ? "ON"
                                                : "OFF"}
                                        </button>

                                    </div>


                                    {/* PROBLEMS */}

                                    {!secure && (

                                        <div
                                            style={{
                                                marginTop:
                                                    "12px",
                                                padding:
                                                    "12px",
                                                background:
                                                    "#fde8e8",
                                                borderRadius:
                                                    "7px",
                                                color:
                                                    "#c62828"
                                            }}
                                        >

                                            <strong>
                                                Security Problems:
                                            </strong>

                                            <ul
                                                style={{
                                                    margin:
                                                        "8px 0 0 20px"
                                                }}
                                            >

                                                {problems.map(
                                                    problem => (

                                                        <li
                                                            key={
                                                                problem.type
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


                                {/* ONLINE */}

                                <div
                                    style={{
                                        marginTop:
                                            "15px"
                                    }}
                                >

                                    <button
                                        disabled={
                                            !canManage
                                        }
                                        onClick={() =>
                                            toggleOnline(
                                                device
                                            )
                                        }
                                        style={{
                                            padding:
                                                "8px 12px",
                                            border:
                                                "1px solid #ccc",
                                            borderRadius:
                                                "6px",
                                            background:
                                                "white",
                                            cursor:
                                                canManage
                                                    ? "pointer"
                                                    : "default"
                                        }}
                                    >
                                        {device.online
                                            ? "Set Offline"
                                            : "Set Online"}
                                    </button>

                                </div>


                                {/* ACTIONS */}

                                {canManage && (

                                    <div
                                        style={{
                                            display:
                                                "flex",
                                            gap:
                                                "10px",
                                            marginTop:
                                                "15px"
                                        }}
                                    >

                                        <button
                                            onClick={() =>
                                                setEditingDevice(
                                                    {
                                                        ...device
                                                    }
                                                )
                                            }
                                            style={{
                                                padding:
                                                    "9px 15px",
                                                border:
                                                    "none",
                                                borderRadius:
                                                    "6px",
                                                background:
                                                    "#1a73e8",
                                                color:
                                                    "white",
                                                cursor:
                                                    "pointer"
                                            }}
                                        >
                                            Edit
                                        </button>


                                        <button
                                            onClick={() =>
                                                deleteDevice(
                                                    device.id
                                                )
                                            }
                                            style={{
                                                padding:
                                                    "9px 15px",
                                                border:
                                                    "none",
                                                borderRadius:
                                                    "6px",
                                                background:
                                                    "#d32f2f",
                                                color:
                                                    "white",
                                                cursor:
                                                    "pointer"
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
                        marginTop:
                            "20px",
                        background:
                            "white",
                        padding:
                            "40px",
                        textAlign:
                            "center",
                        borderRadius:
                            "10px"
                    }}
                >
                    No devices match your filter.
                </div>

            )}


            {/* =================================================
                EDIT MODAL
            ================================================= */}

            {editingDevice && (

                <div
                    style={{
                        position:
                            "fixed",
                        inset: 0,
                        background:
                            "rgba(0,0,0,0.45)",
                        display:
                            "flex",
                        alignItems:
                            "center",
                        justifyContent:
                            "center",
                        zIndex: 1000
                    }}
                >

                    <form
                        onSubmit={
                            updateDevice
                        }
                        style={{
                            width:
                                "500px",
                            maxWidth:
                                "90%",
                            background:
                                "white",
                            padding:
                                "25px",
                            borderRadius:
                                "12px"
                        }}
                    >

                        <h2>
                            Edit Device
                        </h2>


                        <input
                            value={
                                editingDevice.name ||
                                ""
                            }
                            onChange={
                                event =>
                                    setEditingDevice({
                                        ...editingDevice,
                                        name:
                                            event.target.value
                                    })
                            }
                            placeholder="Device name"
                            style={{
                                width:
                                    "100%",
                                padding:
                                    "10px",
                                marginBottom:
                                    "10px",
                                boxSizing:
                                    "border-box"
                            }}
                        />


                        <input
                            value={
                                editingDevice.operating_system ||
                                ""
                            }
                            onChange={
                                event =>
                                    setEditingDevice({
                                        ...editingDevice,
                                        operating_system:
                                            event.target.value
                                    })
                            }
                            placeholder="Operating system"
                            style={{
                                width:
                                    "100%",
                                padding:
                                    "10px",
                                marginBottom:
                                    "10px",
                                boxSizing:
                                    "border-box"
                            }}
                        />


                        <input
                            value={
                                editingDevice.employee ||
                                ""
                            }
                            onChange={
                                event =>
                                    setEditingDevice({
                                        ...editingDevice,
                                        employee:
                                            event.target.value
                                    })
                            }
                            placeholder="Employee"
                            style={{
                                width:
                                    "100%",
                                padding:
                                    "10px",
                                marginBottom:
                                    "10px",
                                boxSizing:
                                    "border-box"
                            }}
                        />


                        <input
                            value={
                                editingDevice.department ||
                                ""
                            }
                            onChange={
                                event =>
                                    setEditingDevice({
                                        ...editingDevice,
                                        department:
                                            event.target.value
                                    })
                            }
                            placeholder="Department"
                            style={{
                                width:
                                    "100%",
                                padding:
                                    "10px",
                                marginBottom:
                                    "10px",
                                boxSizing:
                                    "border-box"
                            }}
                        />


                        <input
                            value={
                                editingDevice.ip_address ||
                                ""
                            }
                            onChange={
                                event =>
                                    setEditingDevice({
                                        ...editingDevice,
                                        ip_address:
                                            event.target.value
                                    })
                            }
                            placeholder="IP Address"
                            style={{
                                width:
                                    "100%",
                                padding:
                                    "10px",
                                marginBottom:
                                    "15px",
                                boxSizing:
                                    "border-box"
                            }}
                        />


                        <div
                            style={{
                                display:
                                    "flex",
                                gap:
                                    "10px"
                            }}
                        >

                            <button
                                type="submit"
                                style={{
                                    padding:
                                        "10px 18px",
                                    border:
                                        "none",
                                    borderRadius:
                                        "7px",
                                    background:
                                        "#1a73e8",
                                    color:
                                        "white",
                                    cursor:
                                        "pointer"
                                }}
                            >
                                Save Changes
                            </button>


                            <button
                                type="button"
                                onClick={() =>
                                    setEditingDevice(
                                        null
                                    )
                                }
                                style={{
                                    padding:
                                        "10px 18px",
                                    border:
                                        "1px solid #ccc",
                                    borderRadius:
                                        "7px",
                                    background:
                                        "white",
                                    cursor:
                                        "pointer"
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