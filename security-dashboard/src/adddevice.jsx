import { useState } from "react";

function AddDevice({
    setDevices,
    userRole
}) {
    const [deviceName, setDeviceName] = useState("");
    const [operatingSystem, setOperatingSystem] = useState("");
    const [employee, setEmployee] = useState("");
    const [department, setDepartment] = useState("");
    const [ipAddress, setIpAddress] = useState("");
    const [loading, setLoading] = useState(false);

    // =====================================================
    // CHECK USER PERMISSION
    // =====================================================

    const canAddDevice =
        userRole === "Administrator" ||
        userRole === "IT Manager";

    // =====================================================
    // ADD DEVICE
    // =====================================================

    async function handleSubmit(event) {
        event.preventDefault();

        if (!canAddDevice) {
            alert(
                "You do not have permission to add devices."
            );
            return;
        }

        const token =
            localStorage.getItem("token");

        if (!token) {
            alert(
                "Your session has expired. Please login again."
            );
            return;
        }

        // Remove unnecessary spaces
        const cleanDeviceName =
            deviceName.trim();

        const cleanOperatingSystem =
            operatingSystem.trim();

        const cleanEmployee =
            employee.trim();

        const cleanDepartment =
            department.trim();

        const cleanIpAddress =
            ipAddress.trim();

        // =====================================================
        // BASIC VALIDATION
        // =====================================================

        if (
            !cleanDeviceName ||
            !cleanOperatingSystem ||
            !cleanEmployee ||
            !cleanDepartment ||
            !cleanIpAddress
        ) {
            alert(
                "Please fill in all fields."
            );
            return;
        }

        const newDevice = {
            name: cleanDeviceName,

            operatingSystem:
                cleanOperatingSystem,

            employee:
                cleanEmployee,

            department:
                cleanDepartment,

            ipAddress:
                cleanIpAddress,

            antivirus: true,

            firewall: true,

            backup: false,

            online: true
        };

        try {
            setLoading(true);

            const response =
                await fetch(
                    "http://localhost:5000/api/devices",
                    {
                        method: "POST",

                        headers: {
                            "Content-Type":
                                "application/json",

                            Authorization:
                                `Bearer ${token}`
                        },

                        body: JSON.stringify(
                            newDevice
                        )
                    }
                );

            const data =
                await response.json();

            if (!response.ok) {
                throw new Error(
                    data.error ||
                    "Failed to add device."
                );
            }

            // =====================================================
            // ADD DEVICE TO CURRENT LIST
            // =====================================================

            setDevices(
                previousDevices => [
                    ...previousDevices,
                    data
                ]
            );

            // =====================================================
            // CLEAR FORM
            // =====================================================

            setDeviceName("");
            setOperatingSystem("");
            setEmployee("");
            setDepartment("");
            setIpAddress("");

            alert(
                "Device added successfully!"
            );

        } catch (error) {
            console.error(
                "Add device error:",
                error
            );

            alert(
                error.message ||
                "Could not connect to server."
            );

        } finally {
            setLoading(false);
        }
    }

    // =====================================================
    // NO PERMISSION
    // =====================================================

    if (!canAddDevice) {
        return (
            <div
                style={{
                    padding: "30px",
                    textAlign: "center"
                }}
            >
                <h2>
                    Add Device
                </h2>

                <p>
                    🔒 You do not have permission
                    to add devices.
                </p>

                <p>
                    Only Administrators and
                    IT Managers can add devices.
                </p>
            </div>
        );
    }

    // =====================================================
    // PAGE
    // =====================================================

    return (
        <div
            style={{
                maxWidth: "600px",
                margin: "0 auto",
                padding: "20px"
            }}
        >

            <h2>
                Add Device
            </h2>

            <p>
                Register a company computer or
                device in the security system.
            </p>

            <form
                onSubmit={handleSubmit}
                style={{
                    display: "flex",
                    flexDirection: "column",
                    gap: "8px"
                }}
            >

                {/* DEVICE NAME */}

                <label>
                    <strong>
                        Device Name
                    </strong>
                </label>

                <input
                    type="text"
                    placeholder="Example: Office-PC-01"
                    value={deviceName}
                    onChange={event =>
                        setDeviceName(
                            event.target.value
                        )
                    }
                    disabled={loading}
                    required
                    style={{
                        padding: "10px"
                    }}
                />

                {/* OPERATING SYSTEM */}

                <label>
                    <strong>
                        Operating System
                    </strong>
                </label>

                <input
                    type="text"
                    placeholder="Example: Windows 11 / macOS"
                    value={operatingSystem}
                    onChange={event =>
                        setOperatingSystem(
                            event.target.value
                        )
                    }
                    disabled={loading}
                    required
                    style={{
                        padding: "10px"
                    }}
                />

                {/* EMPLOYEE */}

                <label>
                    <strong>
                        Employee
                    </strong>
                </label>

                <input
                    type="text"
                    placeholder="Example: John"
                    value={employee}
                    onChange={event =>
                        setEmployee(
                            event.target.value
                        )
                    }
                    disabled={loading}
                    required
                    style={{
                        padding: "10px"
                    }}
                />

                {/* DEPARTMENT */}

                <label>
                    <strong>
                        Department
                    </strong>
                </label>

                <select
                    value={department}
                    onChange={event =>
                        setDepartment(
                            event.target.value
                        )
                    }
                    disabled={loading}
                    required
                    style={{
                        padding: "10px"
                    }}
                >

                    <option value="">
                        Select Department
                    </option>

                    <option value="Management">
                        Management
                    </option>

                    <option value="IT">
                        IT
                    </option>

                    <option value="Finance">
                        Finance
                    </option>

                    <option value="HR">
                        HR
                    </option>

                    <option value="Reception">
                        Reception
                    </option>

                </select>

                {/* IP ADDRESS */}

                <label>
                    <strong>
                        IP Address
                    </strong>
                </label>

                <input
                    type="text"
                    placeholder="Example: 192.168.1.10"
                    value={ipAddress}
                    onChange={event =>
                        setIpAddress(
                            event.target.value
                        )
                    }
                    disabled={loading}
                    required
                    style={{
                        padding: "10px"
                    }}
                />

                {/* SECURITY DEFAULTS */}

                <div
                    style={{
                        marginTop: "10px",
                        padding: "15px",
                        border: "1px solid #ddd",
                        borderRadius: "8px"
                    }}
                >

                    <strong>
                        Initial Security Status
                    </strong>

                    <p>
                        🟢 Antivirus: Enabled
                    </p>

                    <p>
                        🟢 Firewall: Enabled
                    </p>

                    <p>
                        🔴 Backup: Not configured
                    </p>

                    <p>
                        🟢 Device: Online
                    </p>

                </div>

                {/* SUBMIT */}

                <button
                    type="submit"
                    disabled={loading}
                    style={{
                        padding: "12px",
                        marginTop: "10px",
                        cursor: loading
                            ? "not-allowed"
                            : "pointer"
                    }}
                >
                    {loading
                        ? "Adding Device..."
                        : "Add Device"}
                </button>

            </form>

        </div>
    );
}

export default AddDevice;