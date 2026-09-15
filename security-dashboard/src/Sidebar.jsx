function Sidebar({
    page,
    setPage,
    userRole
}) {

    const isAdministrator =
        userRole === "Administrator";

    const isManager =
        userRole === "IT Manager";


    function menuButton(
        pageName,
        label
    ) {

        return (
            <button
                onClick={() =>
                    setPage(pageName)
                }
                style={{
                    width: "100%",
                    padding: "12px 15px",
                    marginBottom: "6px",
                    border: "none",
                    borderRadius: "8px",
                    textAlign: "left",
                    cursor: "pointer",
                    background:
                        page === pageName
                            ? "#e8f0fe"
                            : "transparent",
                    color:
                        page === pageName
                            ? "#1a73e8"
                            : "#333",
                    fontWeight:
                        page === pageName
                            ? "bold"
                            : "normal"
                }}
            >
                {label}
            </button>
        );
    }


    return (

        <aside
            style={{
                width: "230px",
                minHeight: "100vh",
                background: "#ffffff",
                borderRight:
                    "1px solid #ddd",
                padding: "20px",
                boxSizing: "border-box"
            }}
        >

            <h2
                style={{
                    marginTop: 0,
                    marginBottom: "5px"
                }}
            >
                Security
            </h2>


            <p
                style={{
                    color: "#777",
                    fontSize: "13px",
                    marginTop: 0,
                    marginBottom: "25px"
                }}
            >
                Device Management
            </p>


            {/* DASHBOARD */}

            {menuButton(
                "dashboard",
                "Dashboard"
            )}


            {/* DEVICES */}

            {menuButton(
                "devices",
                "Devices"
            )}


            {/* SECURITY ALERTS */}

            {menuButton(
                "alerts",
                "Security Alerts"
            )}


            {/* USERS */}

            {isAdministrator &&
                menuButton(
                    "users",
                    "Users"
                )}


            {/* SETTINGS */}

            {(isAdministrator ||
                isManager) &&
                menuButton(
                    "settings",
                    "Settings"
                )}


            {/* AUDIT LOG */}

            {isAdministrator &&
                menuButton(
                    "audit-logs",
                    "Activity / Audit Log"
                )}


            <div
                style={{
                    marginTop: "30px",
                    paddingTop: "20px",
                    borderTop:
                        "1px solid #eee"
                }}
            >

                <p
                    style={{
                        fontSize: "13px",
                        color: "#777",
                        marginBottom: "8px"
                    }}
                >
                    Access level
                </p>


                <strong>
                    {userRole}
                </strong>

            </div>

        </aside>
    );
}


export default Sidebar;