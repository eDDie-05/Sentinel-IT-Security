import { useEffect, useState } from "react";

import Login from "./Login";
import Sidebar from "./Sidebar";
import Dashboard from "./Dashboard";
import DeviceList from "./DeviceList";
import AddDevice from "./AddDevice";
import SecurityAlerts from "./SecurityAlerts";
import SecuritySettings from "./SecuritySettings";
import Users from "./Users";
import AuditLogs from "./AuditLogs";

import "./App.css";


function App() {

    // =====================================================
    // CURRENT USER
    // =====================================================

    const [currentUser, setCurrentUser] =
        useState(null);


    // =====================================================
    // CURRENT PAGE
    // =====================================================

    const [page, setPage] =
        useState("dashboard");


    // =====================================================
    // DEVICES
    // =====================================================

    const [devices, setDevices] =
        useState([]);


    // =====================================================
    // SECURITY POLICY
    // =====================================================

    const [securityPolicy, setSecurityPolicy] =
        useState({
            antivirusRequired: true,
            firewallRequired: true,
            backupRequired: true
        });


    // =====================================================
    // RESTORE LOGIN AFTER REFRESH
    // =====================================================

    useEffect(() => {

        const token =
            localStorage.getItem("token");

        if (!token) {
            return;
        }

        try {

            const payload =
                JSON.parse(
                    atob(
                        token.split(".")[1]
                    )
                );


            if (
                payload.exp &&
                payload.exp * 1000 < Date.now()
            ) {

                localStorage.removeItem(
                    "token"
                );

                return;
            }


            setCurrentUser({
                id: payload.id,
                name: payload.name,
                email: payload.email,
                role: payload.role
            });

        } catch (error) {

            console.error(
                "Invalid token:",
                error
            );

            localStorage.removeItem(
                "token"
            );
        }

    }, []);


    // =====================================================
    // LOAD DEVICES
    // =====================================================

    useEffect(() => {

        if (!currentUser) {
            return;
        }


        async function loadDevices() {

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


                if (
                    response.status === 401 ||
                    response.status === 403
                ) {

                    handleLogout();

                    return;
                }


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
                    "Device loading error:",
                    error
                );
            }
        }


        loadDevices();

    }, [currentUser]);


    // =====================================================
    // LOAD SECURITY POLICY
    // =====================================================

    useEffect(() => {

        if (!currentUser) {
            return;
        }


        async function loadSecurityPolicy() {

            try {

                const token =
                    localStorage.getItem(
                        "token"
                    );


                const response =
                    await fetch(
                        "http://localhost:5000/api/security-policy",
                        {
                            headers: {
                                Authorization:
                                    `Bearer ${token}`
                            }
                        }
                    );


                if (
                    response.status === 401 ||
                    response.status === 403
                ) {

                    handleLogout();

                    return;
                }


                const data =
                    await response.json();


                if (!response.ok) {

                    throw new Error(
                        data.error ||
                        "Failed to load security policy"
                    );
                }


                setSecurityPolicy(data);

            } catch (error) {

                console.error(
                    "Security policy loading error:",
                    error
                );
            }
        }


        loadSecurityPolicy();

    }, [currentUser]);


    // =====================================================
    // LOGIN
    // =====================================================

    function handleLogin(user) {

        localStorage.setItem(
            "token",
            user.token
        );


        setCurrentUser({
            id: user.id,
            name: user.name,
            email: user.email,
            role: user.role
        });


        setPage("dashboard");
    }


    // =====================================================
    // LOGOUT
    // =====================================================

    function handleLogout() {

        localStorage.removeItem(
            "token"
        );


        setCurrentUser(null);


        setDevices([]);


        setPage("dashboard");
    }


    // =====================================================
    // IF NOT LOGGED IN
    // =====================================================

    if (!currentUser) {

        return (
            <Login
                onLogin={handleLogin}
            />
        );
    }


    // =====================================================
    // DEVICE ADDED
    // =====================================================

    function handleDeviceAdded(
        newDevice
    ) {

        setDevices(
            previousDevices => [
                ...previousDevices,
                newDevice
            ]
        );


        setPage("devices");
    }


    // =====================================================
    // DELETE DEVICE
    // =====================================================

    function handleDeviceDeleted(
        deviceId
    ) {

        setDevices(
            previousDevices =>
                previousDevices.filter(
                    device =>
                        device.id !== deviceId
                )
        );
    }


    // =====================================================
    // UPDATE DEVICE
    // =====================================================

    function handleDeviceUpdated(
        updatedDevice
    ) {

        setDevices(
            previousDevices =>
                previousDevices.map(
                    device =>
                        device.id ===
                        updatedDevice.id
                            ? updatedDevice
                            : device
                )
        );
    }


    // =====================================================
    // PAGE CONTENT
    // =====================================================

    function renderPage() {

        switch (page) {


            // =================================================
            // DASHBOARD
            // =================================================

            case "dashboard":

                return (
                    <Dashboard
                        devices={devices}
                        securityPolicy={
                            securityPolicy
                        }
                    />
                );


            // =================================================
            // DEVICES
            // =================================================

            case "devices":

                return (
                    <DeviceList
                        devices={devices}
                        setDevices={setDevices}
                        userRole={
                            currentUser.role
                        }
                        securityPolicy={
                            securityPolicy
                        }
                        onDeviceDeleted={
                            handleDeviceDeleted
                        }
                        onDeviceUpdated={
                            handleDeviceUpdated
                        }
                    />
                );


            // =================================================
            // ADD DEVICE
            // =================================================

            case "add-device":

                return (
                    <AddDevice
                        setDevices={
                            setDevices
                        }
                        userRole={
                            currentUser.role
                        }
                        onDeviceAdded={
                            handleDeviceAdded
                        }
                    />
                );


            // =================================================
            // SECURITY ALERTS
            // =================================================

            case "alerts":

                return (
                    <SecurityAlerts
                        devices={devices}
                        securityPolicy={
                            securityPolicy
                        }
                    />
                );


            // =================================================
            // SETTINGS
            // =================================================

            case "settings":

                return (
                    <SecuritySettings
                        securityPolicy={
                            securityPolicy
                        }
                        setSecurityPolicy={
                            setSecurityPolicy
                        }
                        userRole={
                            currentUser.role
                        }
                    />
                );


            // =================================================
            // USERS
            // =================================================

            case "users":

                return (
                    <Users />
                );


            // =================================================
            // AUDIT LOGS
            // =================================================

            case "audit-logs":

                return (
                    <AuditLogs />
                );


            // =================================================
            // DEFAULT
            // =================================================

            default:

                return (
                    <Dashboard
                        devices={devices}
                        securityPolicy={
                            securityPolicy
                        }
                    />
                );
        }
    }


    // =====================================================
    // MAIN APP
    // =====================================================

    return (

        <div className="app">

            <Sidebar
                page={page}
                setPage={setPage}
                userRole={
                    currentUser.role
                }
            />


            <div className="main-content">


                {/* TOP BAR */}

                <div className="top-bar">

                    <div>
                        <strong>
                            Company IT Security
                        </strong>
                    </div>


                    <div className="user-info">

                        <span>
                            👤 {currentUser.name}
                        </span>


                        <span>
                            {currentUser.role}
                        </span>


                        <button
                            onClick={
                                handleLogout
                            }
                        >
                            Logout
                        </button>

                    </div>

                </div>


                {/* PAGE CONTENT */}

                <main>
                    {renderPage()}
                </main>

            </div>

        </div>
    );
}


export default App;