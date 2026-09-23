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
                type="button"
                onClick={() => setPage(pageName)}
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
                            : "normal",
                    fontSize: "14px",
                    transition:
                        "background 0.2s ease, color 0.2s ease"
                }}
                onMouseEnter={(event) => {
                    if (page !== pageName) {
                        event.currentTarget.style.background =
                            "#f5f7fa";
                    }
                }}
                onMouseLeave={(event) => {
                    if (page !== pageName) {
                        event.currentTarget.style.background =
                            "transparent";
                    }
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
                borderRight: "1px solid #ddd",
                padding: "20px",
                boxSizing: "border-box",
                flexShrink: 0
            }}
        >

            {/* BRAND */}

            <h2
                style={{
                    marginTop: 0,
                    marginBottom: "5px",
                    fontSize: "22px",
                    fontWeight: "700",
                    color: "#111827"
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


            {/* MAIN NAVIGATION */}

            {menuButton(
                "dashboard",
                "Dashboard"
            )}


            {menuButton(
                "devices",
                "Devices"
            )}


            {menuButton(
                "alerts",
                "Security Alerts"
            )}


            {/* ADMINISTRATION */}

            {isAdministrator &&
                menuButton(
                    "users",
                    "Users"
                )
            }


            {(isAdministrator || isManager) &&
                menuButton(
                    "settings",
                    "Security Policy"
                )
            }


            {/* AUDIT TRAILS */}

            {isAdministrator &&
                menuButton(
                    "activity",
                    "Audit Trails"
                )
            }


            {/* ACCESS LEVEL */}

            <div
                style={{
                    marginTop: "30px",
                    paddingTop: "20px",
                    borderTop: "1px solid #eee"
                }}
            >

                <p
                    style={{
                        fontSize: "13px",
                        color: "#777",
                        marginTop: 0,
                        marginBottom: "8px"
                    }}
                >
                    Access level
                </p>


                <strong
                    style={{
                        fontSize: "14px",
                        color: "#222"
                    }}
                >
                    {userRole || "Unknown"}
                </strong>

            </div>

        </aside>
    );
}


export default Sidebar;