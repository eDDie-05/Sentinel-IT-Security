import { useEffect, useState } from "react";

function Users() {

    const [users, setUsers] =
        useState([]);

    const [loading, setLoading] =
        useState(true);

    const [error, setError] =
        useState("");

    const [showForm, setShowForm] =
        useState(false);

    const [name, setName] =
        useState("");

    const [email, setEmail] =
        useState("");

    const [password, setPassword] =
        useState("");

    const [role, setRole] =
        useState("IT Staff");

    const [message, setMessage] =
        useState("");


    // =====================================================
    // LOAD USERS
    // =====================================================

    async function loadUsers() {

        try {

            setLoading(true);

            setError("");

            const token =
                localStorage.getItem("token");


            const response =
                await fetch(
                    "http://localhost:5000/api/users",
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
                    "Failed to load users"
                );

            }


            setUsers(data);


        } catch (err) {

            console.error(err);

            setError(
                err.message
            );

        } finally {

            setLoading(false);

        }

    }


    // =====================================================
    // LOAD USERS WHEN PAGE OPENS
    // =====================================================

    useEffect(() => {

        loadUsers();

    }, []);


    // =====================================================
    // ADD USER
    // =====================================================

    async function handleAddUser(event) {

        event.preventDefault();

        setError("");

        setMessage("");


        try {

            const token =
                localStorage.getItem("token");


            const response =
                await fetch(
                    "http://localhost:5000/api/users",
                    {
                        method: "POST",

                        headers: {
                            "Content-Type":
                                "application/json",

                            Authorization:
                                `Bearer ${token}`
                        },

                        body: JSON.stringify({
                            name,
                            email,
                            password,
                            role
                        })
                    }
                );


            const data =
                await response.json();


            if (!response.ok) {

                throw new Error(
                    data.error ||
                    "Failed to create user"
                );

            }


            setUsers(
                previousUsers => [
                    ...previousUsers,
                    data
                ]
            );


            setName("");

            setEmail("");

            setPassword("");

            setRole("IT Staff");

            setShowForm(false);

            setMessage(
                "User created successfully."
            );


        } catch (err) {

            console.error(err);

            setError(
                err.message
            );

        }

    }


    // =====================================================
    // DELETE USER
    // =====================================================

    async function handleDeleteUser(userId) {

        const confirmed =
            window.confirm(
                "Are you sure you want to delete this user?"
            );


        if (!confirmed) {

            return;

        }


        try {

            setError("");

            setMessage("");


            const token =
                localStorage.getItem("token");


            const response =
                await fetch(
                    `http://localhost:5000/api/users/${userId}`,
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
                    "Failed to delete user"
                );

            }


            setUsers(
                previousUsers =>
                    previousUsers.filter(
                        user =>
                            user.id !== userId
                    )
            );


            setMessage(
                "User deleted successfully."
            );


        } catch (err) {

            console.error(err);

            setError(
                err.message
            );

        }

    }


    // =====================================================
    // LOADING
    // =====================================================

    if (loading) {

        return (

            <div>

                <h2>
                    Users
                </h2>

                <p>
                    Loading users...
                </p>

            </div>

        );

    }


    // =====================================================
    // PAGE
    // =====================================================

    return (

        <div>

            <h2>
                Users
            </h2>


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


            <button
                onClick={() =>
                    setShowForm(
                        !showForm
                    )
                }
            >
                {showForm
                    ? "Cancel"
                    : "+ Add User"}
            </button>


            {/* =====================================================
                ADD USER FORM
            ===================================================== */}

            {showForm && (

                <div className="settings-card">

                    <h3>
                        Add New User
                    </h3>


                    <form
                        onSubmit={
                            handleAddUser
                        }
                    >

                        <div>

                            <label>
                                Name
                            </label>

                            <input
                                type="text"
                                value={name}
                                onChange={(event) =>
                                    setName(
                                        event.target.value
                                    )
                                }
                                placeholder="Enter name"
                                required
                            />

                        </div>


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
                                placeholder="Enter email"
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
                                placeholder="Minimum 6 characters"
                                minLength="6"
                                required
                            />

                        </div>


                        <div>

                            <label>
                                Role
                            </label>

                            <select
                                value={role}
                                onChange={(event) =>
                                    setRole(
                                        event.target.value
                                    )
                                }
                            >

                                <option value="Administrator">
                                    Administrator
                                </option>

                                <option value="IT Manager">
                                    IT Manager
                                </option>

                                <option value="IT Staff">
                                    IT Staff
                                </option>

                            </select>

                        </div>


                        <button
                            type="submit"
                        >
                            Create User
                        </button>

                    </form>

                </div>

            )}


            {/* =====================================================
                USERS TABLE
            ===================================================== */}

            <div className="table-container">

                <table>

                    <thead>

                        <tr>

                            <th>
                                ID
                            </th>

                            <th>
                                Name
                            </th>

                            <th>
                                Email
                            </th>

                            <th>
                                Role
                            </th>

                            <th>
                                Action
                            </th>

                        </tr>

                    </thead>


                    <tbody>

                        {users.map(user => (

                            <tr
                                key={user.id}
                            >

                                <td>
                                    {user.id}
                                </td>

                                <td>
                                    {user.name}
                                </td>

                                <td>
                                    {user.email}
                                </td>

                                <td>
                                    {user.role}
                                </td>

                                <td>

                                    <button
                                        onClick={() =>
                                            handleDeleteUser(
                                                user.id
                                            )
                                        }
                                    >
                                        Delete
                                    </button>

                                </td>

                            </tr>

                        ))}

                    </tbody>

                </table>

            </div>

        </div>

    );

}


export default Users;