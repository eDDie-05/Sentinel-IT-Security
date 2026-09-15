const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const pool = require("./db");

const app = express();

app.use(cors());
app.use(express.json());

const JWT_SECRET =
    "company-security-system-secret-change-this-later";


// =====================================================
// AUTHENTICATION
// =====================================================

function authenticateToken(req, res, next) {

    const authHeader =
        req.headers["authorization"];

    const token =
        authHeader &&
        authHeader.split(" ")[1];

    if (!token) {
        return res.status(401).json({
            error: "Authentication required"
        });
    }

    jwt.verify(
        token,
        JWT_SECRET,
        (error, user) => {

            if (error) {
                return res.status(403).json({
                    error: "Invalid or expired token"
                });
            }

            req.user = user;

            next();
        }
    );
}


function requireRole(allowedRoles) {

    return (req, res, next) => {

        if (!req.user) {
            return res.status(401).json({
                error: "Authentication required"
            });
        }

        if (!allowedRoles.includes(req.user.role)) {
            return res.status(403).json({
                error: "You do not have permission"
            });
        }

        next();
    };
}


// =====================================================
// AUDIT LOG HELPER
// =====================================================

async function createAuditLog(
    user,
    action,
    details
) {

    try {

        await pool.query(
            `
            INSERT INTO audit_logs
            (
                user_id,
                user_name,
                action,
                details
            )
            VALUES ($1, $2, $3, $4)
            `,
            [
                user?.id || null,
                user?.name || "System",
                action,
                details || null
            ]
        );

    } catch (error) {

        console.error(
            "Audit log error:",
            error
        );

    }
}


// =====================================================
// HOME
// =====================================================

app.get("/", (req, res) => {

    res.json({
        message:
            "Company Security System API is running"
    });

});


// =====================================================
// LOGIN
// =====================================================

app.post("/api/login", async (req, res) => {

    try {

        const {
            email,
            password
        } = req.body;

        const result =
            await pool.query(
                `
                SELECT *
                FROM users
                WHERE email = $1
                `,
                [email]
            );

        if (result.rows.length === 0) {

            return res.status(401).json({
                error: "Invalid email or password"
            });

        }

        const user =
            result.rows[0];

        const passwordMatch =
            await bcrypt.compare(
                password,
                user.password_hash
            );

        if (!passwordMatch) {

            return res.status(401).json({
                error: "Invalid email or password"
            });

        }

        const token =
            jwt.sign(
                {
                    id: user.id,
                    name: user.name,
                    email: user.email,
                    role: user.role
                },
                JWT_SECRET,
                {
                    expiresIn: "2h"
                }
            );


        await createAuditLog(
            user,
            "USER LOGIN",
            `Successful login for ${user.email}`
        );


        res.json({

            message: "Login successful",

            token,

            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                role: user.role
            }

        });

    } catch (error) {

        console.error(error);

        res.status(500).json({
            error: "Database error"
        });

    }

});


// =====================================================
// DEVICES - GET
// =====================================================

app.get(
    "/api/devices",
    authenticateToken,
    async (req, res) => {

        try {

            const result =
                await pool.query(
                    `
                    SELECT *
                    FROM devices
                    ORDER BY id DESC
                    `
                );

            res.json(result.rows);

        } catch (error) {

            console.error(error);

            res.status(500).json({
                error: "Database error"
            });

        }

    }
);


// =====================================================
// DEVICES - ADD
// =====================================================

app.post(
    "/api/devices",
    authenticateToken,
    requireRole([
        "Administrator",
        "IT Manager"
    ]),
    async (req, res) => {

        try {

            const {
                name,
                operatingSystem,
                employee,
                department,
                ipAddress,
                antivirus,
                firewall,
                backup,
                online
            } = req.body;


            const result =
                await pool.query(
                    `
                    INSERT INTO devices
                    (
                        name,
                        operating_system,
                        employee,
                        department,
                        ip_address,
                        antivirus,
                        firewall,
                        backup,
                        online
                    )
                    VALUES
                    (
                        $1,
                        $2,
                        $3,
                        $4,
                        $5,
                        $6,
                        $7,
                        $8,
                        $9
                    )
                    RETURNING *
                    `,
                    [
                        name,
                        operatingSystem,
                        employee,
                        department,
                        ipAddress,
                        antivirus ?? true,
                        firewall ?? true,
                        backup ?? false,
                        online ?? true
                    ]
                );


            const device =
                result.rows[0];


            await createAuditLog(
                req.user,
                "DEVICE ADDED",
                `${device.name} (${device.operating_system})`
            );


            res.status(201).json(device);

        } catch (error) {

            console.error(error);

            res.status(500).json({
                error: "Database error"
            });

        }

    }
);


// =====================================================
// DEVICES - UPDATE
// =====================================================

app.put(
    "/api/devices/:id",
    authenticateToken,
    requireRole([
        "Administrator",
        "IT Manager"
    ]),
    async (req, res) => {

        try {

            const {
                name,
                operatingSystem,
                employee,
                department,
                ipAddress,
                antivirus,
                firewall,
                backup,
                online
            } = req.body;


            // Get current device first
            const currentResult =
                await pool.query(
                    `
                    SELECT *
                    FROM devices
                    WHERE id = $1
                    `,
                    [req.params.id]
                );


            if (
                currentResult.rows.length === 0
            ) {

                return res.status(404).json({
                    error: "Device not found"
                });

            }


            const current =
                currentResult.rows[0];


            const result =
                await pool.query(
                    `
                    UPDATE devices
                    SET
                        name = $1,
                        operating_system = $2,
                        employee = $3,
                        department = $4,
                        ip_address = $5,
                        antivirus = $6,
                        firewall = $7,
                        backup = $8,
                        online = $9
                    WHERE id = $10
                    RETURNING *
                    `,
                    [
                        name ??
                            current.name,

                        operatingSystem ??
                            current.operating_system,

                        employee ??
                            current.employee,

                        department ??
                            current.department,

                        ipAddress ??
                            current.ip_address,

                        antivirus ??
                            current.antivirus,

                        firewall ??
                            current.firewall,

                        backup ??
                            current.backup,

                        online ??
                            current.online,

                        req.params.id
                    ]
                );


            const device =
                result.rows[0];


            await createAuditLog(
                req.user,
                "DEVICE UPDATED",
                `${device.name} (${device.operating_system})`
            );


            res.json(device);

        } catch (error) {

            console.error(error);

            res.status(500).json({
                error: "Database error"
            });

        }

    }
);


// =====================================================
// DEVICES - DELETE
// =====================================================

app.delete(
    "/api/devices/:id",
    authenticateToken,
    requireRole([
        "Administrator",
        "IT Manager"
    ]),
    async (req, res) => {

        try {

            const result =
                await pool.query(
                    `
                    DELETE FROM devices
                    WHERE id = $1
                    RETURNING *
                    `,
                    [req.params.id]
                );


            if (
                result.rows.length === 0
            ) {

                return res.status(404).json({
                    error: "Device not found"
                });

            }


            const device =
                result.rows[0];


            await createAuditLog(
                req.user,
                "DEVICE DELETED",
                `${device.name} (${device.operating_system})`
            );


            res.json({
                message:
                    "Device deleted successfully"
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                error: "Database error"
            });

        }

    }
);


// =====================================================
// USERS - GET
// =====================================================

app.get(
    "/api/users",
    authenticateToken,
    requireRole([
        "Administrator"
    ]),
    async (req, res) => {

        try {

            const result =
                await pool.query(
                    `
                    SELECT
                        id,
                        name,
                        email,
                        role
                    FROM users
                    ORDER BY id DESC
                    `
                );

            res.json(result.rows);

        } catch (error) {

            console.error(error);

            res.status(500).json({
                error: "Database error"
            });

        }

    }
);


// =====================================================
// USERS - CREATE
// =====================================================

app.post(
    "/api/users",
    authenticateToken,
    requireRole([
        "Administrator"
    ]),
    async (req, res) => {

        try {

            const {
                name,
                email,
                password,
                role
            } = req.body;


            const passwordHash =
                await bcrypt.hash(
                    password,
                    10
                );


            const result =
                await pool.query(
                    `
                    INSERT INTO users
                    (
                        name,
                        email,
                        role,
                        password_hash
                    )
                    VALUES
                    (
                        $1,
                        $2,
                        $3,
                        $4
                    )
                    RETURNING
                        id,
                        name,
                        email,
                        role
                    `,
                    [
                        name,
                        email,
                        role,
                        passwordHash
                    ]
                );


            const newUser =
                result.rows[0];


            await createAuditLog(
                req.user,
                "USER CREATED",
                `${newUser.name} (${newUser.email})`
            );


            res.status(201).json(
                newUser
            );

        } catch (error) {

            console.error(error);

            if (
                error.code === "23505"
            ) {

                return res.status(400).json({
                    error:
                        "Email already exists"
                });

            }

            res.status(500).json({
                error: "Database error"
            });

        }

    }
);


// =====================================================
// USERS - DELETE
// =====================================================

app.delete(
    "/api/users/:id",
    authenticateToken,
    requireRole([
        "Administrator"
    ]),
    async (req, res) => {

        try {

            const result =
                await pool.query(
                    `
                    DELETE FROM users
                    WHERE id = $1
                    RETURNING
                        id,
                        name,
                        email,
                        role
                    `,
                    [req.params.id]
                );


            if (
                result.rows.length === 0
            ) {

                return res.status(404).json({
                    error: "User not found"
                });

            }


            const deletedUser =
                result.rows[0];


            await createAuditLog(
                req.user,
                "USER DELETED",
                `${deletedUser.name} (${deletedUser.email})`
            );


            res.json({
                message:
                    "User deleted successfully"
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                error: "Database error"
            });

        }

    }
);


// =====================================================
// SECURITY POLICY - GET
// =====================================================

app.get(
    "/api/security-policy",
    authenticateToken,
    async (req, res) => {

        try {

            const result =
                await pool.query(
                    `
                    SELECT *
                    FROM security_policy
                    ORDER BY id DESC
                    LIMIT 1
                    `
                );


            if (
                result.rows.length === 0
            ) {

                return res.json({
                    antivirus_required: true,
                    firewall_required: true,
                    backup_required: true
                });

            }


            res.json(
                result.rows[0]
            );

        } catch (error) {

            console.error(error);

            res.status(500).json({
                error: "Database error"
            });

        }

    }
);


// =====================================================
// SECURITY POLICY - UPDATE
// =====================================================

app.put(
    "/api/security-policy",
    authenticateToken,
    requireRole([
        "Administrator",
        "IT Manager"
    ]),
    async (req, res) => {

        try {

            const {
                antivirus_required,
                firewall_required,
                backup_required
            } = req.body;


            const result =
                await pool.query(
                    `
                    UPDATE security_policy
                    SET
                        antivirus_required = $1,
                        firewall_required = $2,
                        backup_required = $3
                    WHERE id = (
                        SELECT id
                        FROM security_policy
                        ORDER BY id DESC
                        LIMIT 1
                    )
                    RETURNING *
                    `,
                    [
                        antivirus_required,
                        firewall_required,
                        backup_required
                    ]
                );


            if (
                result.rows.length === 0
            ) {

                const insertResult =
                    await pool.query(
                        `
                        INSERT INTO security_policy
                        (
                            antivirus_required,
                            firewall_required,
                            backup_required
                        )
                        VALUES ($1, $2, $3)
                        RETURNING *
                        `,
                        [
                            antivirus_required,
                            firewall_required,
                            backup_required
                        ]
                    );


                const policy =
                    insertResult.rows[0];


                await createAuditLog(
                    req.user,
                    "SECURITY POLICY UPDATED",
                    `Antivirus: ${
                        policy.antivirus_required
                            ? "Required"
                            : "Not required"
                    }, Firewall: ${
                        policy.firewall_required
                            ? "Required"
                            : "Not required"
                    }, Backup: ${
                        policy.backup_required
                            ? "Required"
                            : "Not required"
                    }`
                );


                return res.json(policy);
            }


            const policy =
                result.rows[0];


            await createAuditLog(
                req.user,
                "SECURITY POLICY UPDATED",
                `Antivirus: ${
                    policy.antivirus_required
                        ? "Required"
                        : "Not required"
                }, Firewall: ${
                    policy.firewall_required
                        ? "Required"
                        : "Not required"
                }, Backup: ${
                    policy.backup_required
                        ? "Required"
                        : "Not required"
                }`
            );


            res.json(policy);

        } catch (error) {

            console.error(error);

            res.status(500).json({
                error: "Database error"
            });

        }

    }
);


// =====================================================
// AUDIT LOGS - GET
// ADMINISTRATOR ONLY
// =====================================================

app.get(
    "/api/audit-logs",
    authenticateToken,
    requireRole([
        "Administrator"
    ]),
    async (req, res) => {

        try {

            const result =
                await pool.query(
                    `
                    SELECT
                        id,
                        user_id,
                        user_name,
                        action,
                        details,
                        created_at
                    FROM audit_logs
                    ORDER BY
                        created_at DESC,
                        id DESC
                    LIMIT 200
                    `
                );


            res.json(
                result.rows
            );

        } catch (error) {

            console.error(error);

            res.status(500).json({
                error: "Database error"
            });

        }

    }
);


// =====================================================
// START SERVER
// =====================================================

app.listen(
    5000,
    () => {

        console.log(
            "Server running on http://localhost:5000"
        );

    }
);