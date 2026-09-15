import { useEffect, useState } from "react";

function SecuritySettings({
    securityPolicy,
    setSecurityPolicy,
    userRole
}) {

    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState(false);
    const [message, setMessage] = useState("");
    const [error, setError] = useState("");


    // =====================================================
    // LOAD SECURITY POLICY FROM DATABASE
    // =====================================================

    useEffect(() => {

        async function loadPolicy() {

            try {

                const token =
                    localStorage.getItem("token");


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


                const data =
                    await response.json();


                if (!response.ok) {

                    throw new Error(
                        data.error ||
                        "Failed to load security policy"
                    );

                }


                setSecurityPolicy(data);


            } catch (err) {

                console.error(err);

                setError(
                    err.message
                );

            } finally {

                setLoading(false);

            }

        }


        loadPolicy();

    }, [setSecurityPolicy]);


    // =====================================================
    // TOGGLE SECURITY SETTING
    // =====================================================

    async function toggleSetting(setting) {

        const newPolicy = {
            ...securityPolicy,
            [setting]:
                !securityPolicy[setting]
        };


        setSecurityPolicy(newPolicy);

        setSaving(true);

        setMessage("");

        setError("");


        try {

            const token =
                localStorage.getItem("token");


            const response =
                await fetch(
                    "http://localhost:5000/api/security-policy",
                    {
                        method: "PUT",

                        headers: {
                            "Content-Type":
                                "application/json",

                            Authorization:
                                `Bearer ${token}`
                        },

                        body:
                            JSON.stringify(
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


            setSecurityPolicy(data);

            setMessage(
                "Security policy saved successfully."
            );


        } catch (err) {

            console.error(err);

            setError(
                err.message
            );

            // Reload the database value if update failed
            try {

                const token =
                    localStorage.getItem("token");


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


                const data =
                    await response.json();


                if (response.ok) {

                    setSecurityPolicy(data);

                }

            } catch (reloadError) {

                console.error(
                    reloadError
                );

            }

        } finally {

            setSaving(false);

        }

    }


    // =====================================================
    // LOADING
    // =====================================================

    if (loading) {

        return (
            <div>
                <h2>Security Settings</h2>

                <p>
                    Loading security policy...
                </p>
            </div>
        );

    }


    // =====================================================
    // PAGE
    // =====================================================

    return (
        <div>

            <h2>Security Settings</h2>


            {message && (
                <div className="success-message">
                    ✅ {message}
                </div>
            )}


            {error && (
                <div className="error-message">
                    ❌ {error}
                </div>
            )}


            <div className="settings-card">


                {/* ANTIVIRUS */}

                <div className="setting">

                    <div>

                        <h3>
                            Antivirus Required
                        </h3>

                        <p>
                            Devices must have
                            antivirus protection.
                        </p>

                    </div>


                    <button
                        disabled={
                            saving ||
                            userRole === "IT Staff"
                        }
                        onClick={() =>
                            toggleSetting(
                                "antivirusRequired"
                            )
                        }
                    >

                        {securityPolicy.antivirusRequired
                            ? "Enabled"
                            : "Disabled"}

                    </button>

                </div>


                {/* FIREWALL */}

                <div className="setting">

                    <div>

                        <h3>
                            Firewall Required
                        </h3>

                        <p>
                            Devices must have
                            the firewall enabled.
                        </p>

                    </div>


                    <button
                        disabled={
                            saving ||
                            userRole === "IT Staff"
                        }
                        onClick={() =>
                            toggleSetting(
                                "firewallRequired"
                            )
                        }
                    >

                        {securityPolicy.firewallRequired
                            ? "Enabled"
                            : "Disabled"}

                    </button>

                </div>


                {/* BACKUP */}

                <div className="setting">

                    <div>

                        <h3>
                            Backup Required
                        </h3>

                        <p>
                            Devices must have
                            a working backup.
                        </p>

                    </div>


                    <button
                        disabled={
                            saving ||
                            userRole === "IT Staff"
                        }
                        onClick={() =>
                            toggleSetting(
                                "backupRequired"
                            )
                        }
                    >

                        {securityPolicy.backupRequired
                            ? "Enabled"
                            : "Disabled"}

                    </button>

                </div>


            </div>


            <p>
                {saving
                    ? "Saving..."
                    : "Changes are saved to the database automatically."}
            </p>

        </div>
    );

}


export default SecuritySettings;