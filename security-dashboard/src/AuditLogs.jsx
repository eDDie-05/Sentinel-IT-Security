import { useEffect, useState } from "react";


function AuditLogs() {

    const [logs, setLogs] =
        useState([]);

    const [loading, setLoading] =
        useState(true);

    const [error, setError] =
        useState("");


    useEffect(() => {

        loadLogs();

    }, []);


    async function loadLogs() {

        try {

            setLoading(true);
            setError("");


            const token =
                localStorage.getItem(
                    "token"
                );


            const response =
                await fetch(
                    "http://localhost:5000/api/audit-logs",
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


            setLogs(data);

        } catch (error) {

            console.error(
                "Audit log error:",
                error
            );

            setError(
                error.message
            );

        } finally {

            setLoading(false);
        }
    }


    function formatDate(date) {

        return new Date(
            date
        ).toLocaleString();
    }


    function getActionStyle(action) {

        if (
            action.includes("DELETE")
        ) {

            return {
                background: "#fde8e8",
                color: "#c62828"
            };
        }


        if (
            action.includes("CREATE") ||
            action.includes("ADD")
        ) {

            return {
                background: "#e8f5e9",
                color: "#2e7d32"
            };
        }


        if (
            action.includes("UPDATE") ||
            action.includes("LOGIN")
        ) {

            return {
                background: "#e8f0fe",
                color: "#1a73e8"
            };
        }


        return {
            background: "#f5f5f5",
            color: "#555"
        };
    }


    return (

        <div
            style={{
                padding: "25px"
            }}
        >

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

                    <h2
                        style={{
                            margin:
                                "0 0 5px 0"
                        }}
                    >
                        Activity / Audit Log
                    </h2>

                    <p
                        style={{
                            color: "#666",
                            margin: 0
                        }}
                    >
                        Track important activities
                        performed in the system.
                    </p>

                </div>


                <button
                    onClick={loadLogs}
                    style={{
                        padding:
                            "10px 16px",
                        border: "none",
                        borderRadius: "7px",
                        background:
                            "#1a73e8",
                        color: "white",
                        cursor: "pointer"
                    }}
                >
                    Refresh
                </button>

            </div>


            {loading && (

                <div
                    style={{
                        padding: "40px",
                        textAlign: "center"
                    }}
                >
                    Loading activity...
                </div>

            )}


            {!loading && error && (

                <div
                    style={{
                        padding: "20px",
                        background: "#fde8e8",
                        color: "#c62828",
                        borderRadius: "10px",
                        border:
                            "1px solid #f5b5b5"
                    }}
                >

                    <strong>
                        Error:
                    </strong>{" "}

                    {error}

                </div>

            )}


            {!loading &&
                !error &&
                logs.length === 0 && (

                    <div
                        style={{
                            padding: "50px",
                            textAlign:
                                "center",
                            background:
                                "#fff",
                            border:
                                "1px solid #ddd",
                            borderRadius:
                                "10px"
                        }}
                    >

                        <h3>
                            No activity yet
                        </h3>

                        <p
                            style={{
                                color: "#777"
                            }}
                        >
                            System activities
                            will appear here.
                        </p>

                    </div>

                )}


            {!loading &&
                !error &&
                logs.length > 0 && (

                    <div
                        style={{
                            background:
                                "#fff",
                            border:
                                "1px solid #ddd",
                            borderRadius:
                                "10px",
                            overflow:
                                "hidden"
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
                                                "14px",
                                            borderBottom:
                                                "1px solid #ddd"
                                        }}
                                    >
                                        Date
                                    </th>


                                    <th
                                        style={{
                                            padding:
                                                "14px",
                                            borderBottom:
                                                "1px solid #ddd"
                                        }}
                                    >
                                        User
                                    </th>


                                    <th
                                        style={{
                                            padding:
                                                "14px",
                                            borderBottom:
                                                "1px solid #ddd"
                                        }}
                                    >
                                        Action
                                    </th>


                                    <th
                                        style={{
                                            padding:
                                                "14px",
                                            borderBottom:
                                                "1px solid #ddd"
                                        }}
                                    >
                                        Details
                                    </th>

                                </tr>

                            </thead>


                            <tbody>

                                {logs.map(
                                    log => (

                                        <tr
                                            key={
                                                log.id
                                            }
                                        >

                                            <td
                                                style={{
                                                    padding:
                                                        "14px",
                                                    borderBottom:
                                                        "1px solid #eee"
                                                }}
                                            >
                                                {formatDate(
                                                    log.created_at
                                                )}
                                            </td>


                                            <td
                                                style={{
                                                    padding:
                                                        "14px",
                                                    borderBottom:
                                                        "1px solid #eee"
                                                }}
                                            >
                                                {log.user_name ||
                                                    "System"}
                                            </td>


                                            <td
                                                style={{
                                                    padding:
                                                        "14px",
                                                    borderBottom:
                                                        "1px solid #eee"
                                                }}
                                            >

                                                <span
                                                    style={{
                                                        display:
                                                            "inline-block",
                                                        padding:
                                                            "5px 9px",
                                                        borderRadius:
                                                            "5px",
                                                        fontSize:
                                                            "12px",
                                                        fontWeight:
                                                            "bold",
                                                        ...getActionStyle(
                                                            log.action
                                                        )
                                                    }}
                                                >
                                                    {log.action}
                                                </span>

                                            </td>


                                            <td
                                                style={{
                                                    padding:
                                                        "14px",
                                                    borderBottom:
                                                        "1px solid #eee"
                                                }}
                                            >
                                                {log.details ||
                                                    "-"}
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


export default AuditLogs;