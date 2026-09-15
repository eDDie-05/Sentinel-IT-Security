import { useState } from "react";

function Login({ onLogin }) {

    const [email, setEmail] =
        useState("");

    const [password, setPassword] =
        useState("");

    const [error, setError] =
        useState("");

    const [loading, setLoading] =
        useState(false);


    async function handleLogin(event) {

        event.preventDefault();

        setError("");

        setLoading(true);


        try {

            const response =
                await fetch(
                    "http://localhost:5000/api/login",
                    {
                        method: "POST",

                        headers: {
                            "Content-Type":
                                "application/json"
                        },

                        body: JSON.stringify({
                            email,
                            password
                        })
                    }
                );


            const data =
                await response.json();


            if (!response.ok) {

                setError(
                    data.error ||
                    "Login failed"
                );

                setLoading(false);

                return;

            }


            // Send the logged-in user
            // back to App.jsx

            onLogin(data);


        } catch (error) {

            console.error(
                "Login error:",
                error
            );


            setError(
                "Cannot connect to the server."
            );

        } finally {

            setLoading(false);

        }

    }


    return (

        <div className="login-page">

            <div className="login-card">

                <h1>
                    Company IT Security
                </h1>

                <h2>
                    Login
                </h2>


                <form
                    onSubmit={handleLogin}
                >

                    <div>

                        <label>
                            Email
                        </label>

                        <input
                            type="email"
                            value={email}
                            onChange={(event) =>
                                setEmail(
                                    event.target.value
                                )
                            }
                            placeholder="Enter your email"
                            required
                        />

                    </div>


                    <div>

                        <label>
                            Password
                        </label>

                        <input
                            type="password"
                            value={password}
                            onChange={(event) =>
                                setPassword(
                                    event.target.value
                                )
                            }
                            placeholder="Enter your password"
                            required
                        />

                    </div>


                    {error && (

                        <div className="login-error">

                            {error}

                        </div>

                    )}


                    <button
                        type="submit"
                        disabled={loading}
                    >

                        {loading
                            ? "Logging in..."
                            : "Login"}

                    </button>

                </form>

            </div>

        </div>

    );

}


export default Login;