const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

const app = express();

const PORT = 5000;
const JWT_SECRET =
  process.env.JWT_SECRET || "sentinel-development-secret";

const pool = new Pool({
  user: process.env.PGUSER || "georgemollel",
  host: process.env.PGHOST || "localhost",
  database:
    process.env.PGDATABASE || "security_dashboard",
  password: process.env.PGPASSWORD || "",
  port: Number(process.env.PGPORT || 5432)
});

app.use(cors());
app.use(express.json());

/* =========================================================
   DATABASE
========================================================= */

async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name VARCHAR(150) NOT NULL,
      email VARCHAR(255) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role VARCHAR(50) NOT NULL DEFAULT 'IT Staff',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS devices (
      id SERIAL PRIMARY KEY,
      device_id VARCHAR(255),
      name VARCHAR(255),
      hostname VARCHAR(255),
      operating_system VARCHAR(255),
      employee VARCHAR(255),
      username VARCHAR(255),
      department VARCHAR(255),
      ip_address VARCHAR(100),
      cpu VARCHAR(255),
      cpu_cores INTEGER,
      ram_gb NUMERIC,
      free_memory_gb NUMERIC,
      uptime_minutes NUMERIC,

      antivirus BOOLEAN,
      firewall BOOLEAN,
      backup BOOLEAN,

      antivirus_status VARCHAR(30),
      firewall_status VARCHAR(30),
      backup_status VARCHAR(30),

      security_status VARCHAR(30),
      connection_status VARCHAR(30) DEFAULT 'OFFLINE',

      online BOOLEAN DEFAULT FALSE,

      last_seen TIMESTAMP,

      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS
    devices_device_id_unique
    ON devices(device_id)
    WHERE device_id IS NOT NULL
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS security_policy (
      id INTEGER PRIMARY KEY,
      antivirus_required BOOLEAN NOT NULL DEFAULT TRUE,
      firewall_required BOOLEAN NOT NULL DEFAULT TRUE,
      backup_required BOOLEAN NOT NULL DEFAULT TRUE,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS audit_logs (
      id SERIAL PRIMARY KEY,
      user_id INTEGER,
      action VARCHAR(255) NOT NULL,
      details TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  /* =======================================================
     SECURITY ALERTS
  ======================================================= */

  await pool.query(`
    CREATE TABLE IF NOT EXISTS security_alerts (
      id SERIAL PRIMARY KEY,

      device_id INTEGER
        REFERENCES devices(id)
        ON DELETE CASCADE,

      alert_type VARCHAR(100) NOT NULL,

      severity VARCHAR(20)
        NOT NULL DEFAULT 'warning',

      message TEXT NOT NULL,

      status VARCHAR(20)
        NOT NULL DEFAULT 'OPEN',

      created_at TIMESTAMP
        DEFAULT CURRENT_TIMESTAMP,

      resolved_at TIMESTAMP
    )
  `);

  await pool.query(`
    INSERT INTO security_policy
      (
        id,
        antivirus_required,
        firewall_required,
        backup_required
      )
    VALUES
      (1, TRUE, TRUE, TRUE)
    ON CONFLICT (id) DO NOTHING
  `);

  /* =======================================================
     DEFAULT ADMIN
  ======================================================= */

  const adminEmail = "admin@company.com";

  const existingAdmin =
    await pool.query(
      `SELECT id FROM users WHERE email = $1`,
      [adminEmail]
    );

  if (!existingAdmin.rows.length) {
    const passwordHash =
      await bcrypt.hash(
        "Admin123456",
        10
      );

    await pool.query(
      `
      INSERT INTO users
        (name, email, password_hash, role)
      VALUES
        ($1, $2, $3, $4)
      `,
      [
        "System Administrator",
        adminEmail,
        passwordHash,
        "Administrator"
      ]
    );

    console.log(
      "Default administrator account created."
    );
  }
}

/* =========================================================
   AUTHENTICATION
========================================================= */

function auth(req, res, next) {
  const header =
    req.headers.authorization || "";

  if (!header.startsWith("Bearer ")) {
    return res.status(401).json({
      error: "Authentication required"
    });
  }

  const token =
    header.substring(7);

  try {
    const decoded =
      jwt.verify(
        token,
        JWT_SECRET
      );

    req.user = decoded;

    next();
  } catch {
    return res.status(401).json({
      error: "Invalid or expired session"
    });
  }
}

function requireAdmin(req, res, next) {
  if (
    req.user.role !==
    "Administrator"
  ) {
    return res.status(403).json({
      error:
        "Administrator access required"
    });
  }

  next();
}

function requireManager(req, res, next) {
  if (
    req.user.role !==
      "Administrator" &&
    req.user.role !==
      "IT Manager"
  ) {
    return res.status(403).json({
      error:
        "IT Manager or Administrator access required"
    });
  }

  next();
}

/* =========================================================
   HELPERS
========================================================= */

function statusToBoolean(status) {
  if (status === "ENABLED") {
    return true;
  }

  if (status === "DISABLED") {
    return false;
  }

  return null;
}

function calculateSecurityStatus(
  antivirus,
  firewall,
  backup
) {
  if (
    antivirus === false ||
    firewall === false ||
    backup === false
  ) {
    return "AT RISK";
  }

  if (
    antivirus === null ||
    firewall === null ||
    backup === null
  ) {
    return "UNKNOWN";
  }

  return "SECURE";
}

async function writeAudit(
  userId,
  action,
  details
) {
  try {
    await pool.query(
      `
      INSERT INTO audit_logs
        (user_id, action, details)
      VALUES
        ($1, $2, $3)
      `,
      [
        userId || null,
        action,
        details || null
      ]
    );
  } catch (error) {
    console.error(
      "Audit log error:",
      error.message
    );
  }
}

/* =========================================================
   ALERT HELPERS
========================================================= */

async function createAlertIfMissing(
  deviceId,
  alertType,
  severity,
  message
) {
  const existing =
    await pool.query(
      `
      SELECT id
      FROM security_alerts
      WHERE device_id = $1
        AND alert_type = $2
        AND status = 'OPEN'
      LIMIT 1
      `,
      [
        deviceId,
        alertType
      ]
    );

  if (existing.rows.length) {
    return existing.rows[0];
  }

  const result =
    await pool.query(
      `
      INSERT INTO security_alerts
        (
          device_id,
          alert_type,
          severity,
          message,
          status
        )
      VALUES
        ($1, $2, $3, $4, 'OPEN')
      RETURNING *
      `,
      [
        deviceId,
        alertType,
        severity,
        message
      ]
    );

  return result.rows[0];
}

async function resolveAlert(
  deviceId,
  alertType
) {
  await pool.query(
    `
    UPDATE security_alerts
    SET
      status = 'RESOLVED',
      resolved_at = CURRENT_TIMESTAMP
    WHERE device_id = $1
      AND alert_type = $2
      AND status = 'OPEN'
    `,
    [
      deviceId,
      alertType
    ]
  );
}

/* =========================================================
   AUTOMATIC SECURITY EVALUATION
========================================================= */

async function evaluateDeviceSecurity(
  device
) {
  if (!device || !device.id) {
    return;
  }

  const antivirus =
    statusToBoolean(
      device.antivirus_status
    );

  const firewall =
    statusToBoolean(
      device.firewall_status
    );

  const backup =
    statusToBoolean(
      device.backup_status
    );

  const online =
    device.connection_status ===
      "ONLINE" ||
    device.online === true;

  /* DEVICE OFFLINE */

  if (!online) {
    await createAlertIfMissing(
      device.id,
      "DEVICE_OFFLINE",
      "warning",
      `${device.name || device.hostname || "Device"} is offline.`
    );
  } else {
    await resolveAlert(
      device.id,
      "DEVICE_OFFLINE"
    );
  }

  /* ANTIVIRUS */

  if (antivirus === false) {
    await createAlertIfMissing(
      device.id,
      "ANTIVIRUS_DISABLED",
      "critical",
      "Antivirus protection is disabled."
    );
  } else {
    await resolveAlert(
      device.id,
      "ANTIVIRUS_DISABLED"
    );
  }

  /* ANTIVIRUS UNKNOWN */

  if (antivirus === null) {
    await createAlertIfMissing(
      device.id,
      "ANTIVIRUS_UNKNOWN",
      "warning",
      "Antivirus protection status is unknown."
    );
  } else {
    await resolveAlert(
      device.id,
      "ANTIVIRUS_UNKNOWN"
    );
  }

  /* FIREWALL */

  if (firewall === false) {
    await createAlertIfMissing(
      device.id,
      "FIREWALL_DISABLED",
      "critical",
      "Firewall protection is disabled."
    );
  } else {
    await resolveAlert(
      device.id,
      "FIREWALL_DISABLED"
    );
  }

  /* FIREWALL UNKNOWN */

  if (firewall === null) {
    await createAlertIfMissing(
      device.id,
      "FIREWALL_UNKNOWN",
      "warning",
      "Firewall protection status is unknown."
    );
  } else {
    await resolveAlert(
      device.id,
      "FIREWALL_UNKNOWN"
    );
  }

  /* BACKUP */

  if (backup === false) {
    await createAlertIfMissing(
      device.id,
      "BACKUP_DISABLED",
      "critical",
      "Backup protection is disabled."
    );
  } else {
    await resolveAlert(
      device.id,
      "BACKUP_DISABLED"
    );
  }

  /* BACKUP UNKNOWN */

  if (backup === null) {
    await createAlertIfMissing(
      device.id,
      "BACKUP_UNKNOWN",
      "warning",
      "Backup protection status is unknown."
    );
  } else {
    await resolveAlert(
      device.id,
      "BACKUP_UNKNOWN"
    );
  }
}

/* =========================================================
   HEALTH
========================================================= */

app.get(
  "/",
  (req, res) => {
    res.json({
      message:
        "Sentinel Security API is running"
    });
  }
);

app.get(
  "/api/health",
  (req, res) => {
    res.json({
      status: "ok",
      service: "Sentinel Security API"
    });
  }
);

/* =========================================================
   LOGIN
========================================================= */

app.post(
  "/api/login",
  async (req, res) => {
    try {
      const {
        email,
        password
      } = req.body;

      if (!email || !password) {
        return res.status(400).json({
          error:
            "Email and password are required"
        });
      }

      const result =
        await pool.query(
          `
          SELECT *
          FROM users
          WHERE LOWER(email) = LOWER($1)
          LIMIT 1
          `,
          [email.trim()]
        );

      if (!result.rows.length) {
        return res.status(401).json({
          error:
            "Invalid login details"
        });
      }

      const user =
        result.rows[0];

      const valid =
        await bcrypt.compare(
          password,
          user.password_hash
        );

      if (!valid) {
        return res.status(401).json({
          error:
            "Invalid login details"
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
            expiresIn: "8h"
          }
        );

      await writeAudit(
        user.id,
        "LOGIN",
        `${user.name} signed in.`
      );

      res.json({
        token
      });
    } catch (error) {
      console.error(
        "Login error:",
        error
      );

      res.status(500).json({
        error:
          "Login failed"
      });
    }
  }
);

/* =========================================================
   DEVICES - GET
========================================================= */

app.get(
  "/api/devices",
  auth,
  async (req, res) => {
    try {
      const result =
        await pool.query(`
          SELECT *
          FROM devices
          ORDER BY id DESC
        `);

      res.json(
        result.rows
      );
    } catch (error) {
      console.error(
        "Failed to load devices:",
        error
      );

      res.status(500).json({
        error:
          "Failed to load devices"
      });
    }
  }
);

/* =========================================================
   DEVICES - POST
========================================================= */

app.post(
  "/api/devices",
  auth,
  requireManager,
  async (req, res) => {
    try {
      const {
        name,
        device_id,
        hostname,
        operatingSystem,
        operating_system,
        employee,
        username,
        department,
        ipAddress,
        ip_address,
        antivirus,
        firewall,
        backup,
        online
      } = req.body;

      if (!name) {
        return res.status(400).json({
          error:
            "Device name is required"
        });
      }

      const antivirusStatus =
        typeof antivirus === "boolean"
          ? antivirus
            ? "ENABLED"
            : "DISABLED"
          : "UNKNOWN";

      const firewallStatus =
        typeof firewall === "boolean"
          ? firewall
            ? "ENABLED"
            : "DISABLED"
          : "UNKNOWN";

      const backupStatus =
        typeof backup === "boolean"
          ? backup
            ? "ENABLED"
            : "DISABLED"
          : "UNKNOWN";

      const securityStatus =
        calculateSecurityStatus(
          statusToBoolean(
            antivirusStatus
          ),
          statusToBoolean(
            firewallStatus
          ),
          statusToBoolean(
            backupStatus
          )
        );

      const connectionStatus =
        online === true
          ? "ONLINE"
          : "OFFLINE";

      const result =
        await pool.query(
          `
          INSERT INTO devices
          (
            device_id,
            name,
            hostname,
            operating_system,
            employee,
            username,
            department,
            ip_address,
            antivirus,
            firewall,
            backup,
            antivirus_status,
            firewall_status,
            backup_status,
            security_status,
            connection_status,
            online,
            last_seen
          )
          VALUES
          (
            $1,$2,$3,$4,$5,$6,$7,$8,
            $9,$10,$11,$12,$13,$14,$15,$16,$17,
            CASE
              WHEN $17 = TRUE
              THEN CURRENT_TIMESTAMP
              ELSE NULL
            END
          )
          RETURNING *
          `,
          [
            device_id || null,
            name,
            hostname || null,
            operating_system ||
              operatingSystem ||
              null,
            employee || null,
            username || null,
            department || null,
            ip_address ||
              ipAddress ||
              null,
            typeof antivirus ===
              "boolean"
              ? antivirus
              : null,
            typeof firewall ===
              "boolean"
              ? firewall
              : null,
            typeof backup ===
              "boolean"
              ? backup
              : null,
            antivirusStatus,
            firewallStatus,
            backupStatus,
            securityStatus,
            connectionStatus,
            online === true
          ]
        );

      const device =
        result.rows[0];

      await evaluateDeviceSecurity(
        device
      );

      await writeAudit(
        req.user.id,
        "DEVICE_CREATED",
        `Device ${device.name} was registered.`
      );

      res.status(201).json(
        device
      );
    } catch (error) {
      console.error(
        "Failed to add device:",
        error
      );

      res.status(500).json({
        error:
          "Failed to add device"
      });
    }
  }
);

/* =========================================================
   DEVICES - PUT
========================================================= */

app.put(
  "/api/devices/:id",
  auth,
  requireManager,
  async (req, res) => {
    try {
      const {
        name,
        device_id,
        hostname,
        operatingSystem,
        operating_system,
        employee,
        username,
        department,
        ipAddress,
        ip_address,
        antivirus,
        firewall,
        backup,
        online
      } = req.body;

      const existing =
        await pool.query(
          `
          SELECT *
          FROM devices
          WHERE id = $1
          `,
          [req.params.id]
        );

      if (!existing.rows.length) {
        return res.status(404).json({
          error:
            "Device not found"
        });
      }

      const old =
        existing.rows[0];

      const newAntivirus =
        typeof antivirus ===
        "boolean"
          ? antivirus
          : old.antivirus;

      const newFirewall =
        typeof firewall ===
        "boolean"
          ? firewall
          : old.firewall;

      const newBackup =
        typeof backup ===
        "boolean"
          ? backup
          : old.backup;

      const antivirusStatus =
        typeof antivirus ===
        "boolean"
          ? antivirus
            ? "ENABLED"
            : "DISABLED"
          : old.antivirus_status ||
            "UNKNOWN";

      const firewallStatus =
        typeof firewall ===
        "boolean"
          ? firewall
            ? "ENABLED"
            : "DISABLED"
          : old.firewall_status ||
            "UNKNOWN";

      const backupStatus =
        typeof backup ===
        "boolean"
          ? backup
            ? "ENABLED"
            : "DISABLED"
          : old.backup_status ||
            "UNKNOWN";

      const securityStatus =
        calculateSecurityStatus(
          statusToBoolean(
            antivirusStatus
          ),
          statusToBoolean(
            firewallStatus
          ),
          statusToBoolean(
            backupStatus
          )
        );

      const newOnline =
        typeof online ===
        "boolean"
          ? online
          : old.online;

      const connectionStatus =
        newOnline
          ? "ONLINE"
          : "OFFLINE";

      const result =
        await pool.query(
          `
          UPDATE devices
          SET
            device_id =
              COALESCE($1, device_id),

            name =
              COALESCE($2, name),

            hostname =
              COALESCE($3, hostname),

            operating_system =
              COALESCE($4, operating_system),

            employee =
              COALESCE($5, employee),

            username =
              COALESCE($6, username),

            department =
              COALESCE($7, department),

            ip_address =
              COALESCE($8, ip_address),

            antivirus = $9,
            firewall = $10,
            backup = $11,

            antivirus_status = $12,
            firewall_status = $13,
            backup_status = $14,

            security_status = $15,

            connection_status = $16,

            online = $17,

            last_seen =
              CASE
                WHEN $17 = TRUE
                THEN CURRENT_TIMESTAMP
                ELSE last_seen
              END,

            updated_at =
              CURRENT_TIMESTAMP

          WHERE id = $18

          RETURNING *
          `,
          [
            device_id ||
              null,
            name ||
              null,
            hostname ||
              null,
            operating_system ||
              operatingSystem ||
              null,
            employee ||
              null,
            username ||
              null,
            department ||
              null,
            ip_address ||
              ipAddress ||
              null,
            newAntivirus,
            newFirewall,
            newBackup,
            antivirusStatus,
            firewallStatus,
            backupStatus,
            securityStatus,
            connectionStatus,
            newOnline,
            req.params.id
          ]
        );

      const device =
        result.rows[0];

      await evaluateDeviceSecurity(
        device
      );

      await writeAudit(
        req.user.id,
        "DEVICE_UPDATED",
        `Device ${device.name} was updated.`
      );

      res.json(
        device
      );
    } catch (error) {
      console.error(
        "Failed to update device:",
        error
      );

      res.status(500).json({
        error:
          "Failed to update device"
      });
    }
  }
);

/* =========================================================
   DEVICES - DELETE
========================================================= */

app.delete(
  "/api/devices/:id",
  auth,
  requireManager,
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

      if (!result.rows.length) {
        return res.status(404).json({
          error:
            "Device not found"
        });
      }

      await writeAudit(
        req.user.id,
        "DEVICE_DELETED",
        `Device ${result.rows[0].name} was deleted.`
      );

      res.json({
        message:
          "Device deleted successfully"
      });
    } catch (error) {
      console.error(
        "Failed to delete device:",
        error
      );

      res.status(500).json({
        error:
          "Failed to delete device"
      });
    }
  }
);

/* =========================================================
   AGENT HEARTBEAT
========================================================= */

app.post(
  "/api/agent/heartbeat",
  async (req, res) => {
    try {
      const {
        hostname,
        platform,
        operatingSystem,
        architecture,
        cpu,
        cpuCores,
        totalMemoryGB,
        freeMemoryGB,
        uptimeMinutes,
        username,
        online,
        security
      } = req.body;

      if (!hostname) {
        return res.status(400).json({
          error:
            "Hostname is required"
        });
      }

      const deviceId =
        hostname;

      const antivirusStatus =
        security?.antivirus?.status ||
        "UNKNOWN";

      const firewallStatus =
        security?.firewall?.status ||
        "UNKNOWN";

      const backupStatus =
        security?.backup?.status ||
        "UNKNOWN";

      const antivirus =
        statusToBoolean(
          antivirusStatus
        );

      const firewall =
        statusToBoolean(
          firewallStatus
        );

      const backup =
        statusToBoolean(
          backupStatus
        );

      const securityStatus =
        calculateSecurityStatus(
          antivirus,
          firewall,
          backup
        );

      const result =
        await pool.query(
          `
          INSERT INTO devices
          (
            device_id,
            name,
            hostname,
            operating_system,
            username,
            ip_address,
            cpu,
            cpu_cores,
            ram_gb,
            free_memory_gb,
            uptime_minutes,

            antivirus,
            firewall,
            backup,

            antivirus_status,
            firewall_status,
            backup_status,

            security_status,
            connection_status,
            online,
            last_seen
          )
          VALUES
          (
            $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,
            $12,$13,$14,$15,$16,$17,$18,
            'ONLINE',
            TRUE,
            CURRENT_TIMESTAMP
          )

          ON CONFLICT (device_id)
          WHERE device_id IS NOT NULL

          DO UPDATE SET

            name =
              EXCLUDED.name,

            hostname =
              EXCLUDED.hostname,

            operating_system =
              EXCLUDED.operating_system,

            username =
              EXCLUDED.username,

            ip_address =
              EXCLUDED.ip_address,

            cpu =
              EXCLUDED.cpu,

            cpu_cores =
              EXCLUDED.cpu_cores,

            ram_gb =
              EXCLUDED.ram_gb,

            free_memory_gb =
              EXCLUDED.free_memory_gb,

            uptime_minutes =
              EXCLUDED.uptime_minutes,

            antivirus =
              EXCLUDED.antivirus,

            firewall =
              EXCLUDED.firewall,

            backup =
              EXCLUDED.backup,

            antivirus_status =
              EXCLUDED.antivirus_status,

            firewall_status =
              EXCLUDED.firewall_status,

            backup_status =
              EXCLUDED.backup_status,

            security_status =
              EXCLUDED.security_status,

            connection_status =
              'ONLINE',

            online =
              TRUE,

            last_seen =
              CURRENT_TIMESTAMP,

            updated_at =
              CURRENT_TIMESTAMP

          RETURNING *
          `,
          [
            deviceId,
            hostname,
            hostname,
            operatingSystem ||
              platform ||
              "Unknown",
            username ||
              "Unknown",
            null,
            cpu ||
              "Unknown",
            Number(cpuCores) ||
              null,
            Number(totalMemoryGB) ||
              null,
            Number(freeMemoryGB) ||
              null,
            Number(uptimeMinutes) ||
              null,

            antivirus,
            firewall,
            backup,

            antivirusStatus,
            firewallStatus,
            backupStatus,

            securityStatus
          ]
        );

      const device =
        result.rows[0];

      await evaluateDeviceSecurity(
        device
      );

      /* =====================================================
         FIXED AGENT RESPONSE
      ===================================================== */

      res.json({
        message:
          "Heartbeat received",

        device: {
          hostname:
            device.hostname,

          online:
            device.online === true,

          security_status:
            device.security_status,

          antivirus_status:
            device.antivirus_status,

          firewall_status:
            device.firewall_status,

          backup_status:
            device.backup_status
        },

        status:
          device.online === true
            ? "ONLINE"
            : "OFFLINE",

        security:
          device.security_status,

        antivirus:
          device.antivirus_status,

        firewall:
          device.firewall_status,

        backup:
          device.backup_status
      });

    } catch (error) {
      console.error(
        "Heartbeat error:",
        error
      );

      res.status(500).json({
        error:
          "Failed to process heartbeat"
      });
    }
  }
);

/* =========================================================
   AUTOMATIC OFFLINE DETECTION
========================================================= */

async function markOfflineDevices() {
  try {
    const result =
      await pool.query(`
        UPDATE devices
        SET
          online = FALSE,
          connection_status = 'OFFLINE',
          updated_at = CURRENT_TIMESTAMP

        WHERE
          last_seen IS NOT NULL

          AND last_seen <
            CURRENT_TIMESTAMP -
            INTERVAL '90 seconds'

          AND (
            online = TRUE
            OR connection_status =
              'ONLINE'
          )

        RETURNING *
      `);

    for (
      const device
      of result.rows
    ) {
      await evaluateDeviceSecurity(
        device
      );

      await writeAudit(
        null,
        "DEVICE_OFFLINE",
        `${device.name || device.hostname || "Device"} went offline automatically.`
      );
    }

    if (result.rows.length) {
      console.log(
        `${result.rows.length} device(s) marked offline.`
      );
    }

  } catch (error) {
    console.error(
      "Offline detection error:",
      error.message
    );
  }
}

/* =========================================================
   SECURITY POLICY
========================================================= */

app.get(
  "/api/security-policy",
  auth,
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
          SELECT *
          FROM security_policy
          WHERE id = 1
          `
        );

      if (!result.rows.length) {
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
      console.error(
        "Policy error:",
        error
      );

      res.status(500).json({
        error:
          "Failed to load security policy"
      });
    }
  }
);

app.put(
  "/api/security-policy",
  auth,
  requireManager,
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
          INSERT INTO security_policy
          (
            id,
            antivirus_required,
            firewall_required,
            backup_required,
            updated_at
          )
          VALUES
          (
            1,$1,$2,$3,CURRENT_TIMESTAMP
          )

          ON CONFLICT (id)

          DO UPDATE SET

            antivirus_required =
              EXCLUDED.antivirus_required,

            firewall_required =
              EXCLUDED.firewall_required,

            backup_required =
              EXCLUDED.backup_required,

            updated_at =
              CURRENT_TIMESTAMP

          RETURNING *
          `,
          [
            antivirus_required !== false,
            firewall_required !== false,
            backup_required !== false
          ]
        );

      await writeAudit(
        req.user.id,
        "POLICY_UPDATED",
        "Endpoint security policy was updated."
      );

      res.json(
        result.rows[0]
      );

    } catch (error) {
      console.error(
        "Policy update error:",
        error
      );

      res.status(500).json({
        error:
          "Failed to update security policy"
      });
    }
  }
);

/* =========================================================
   SECURITY ALERTS - GET
========================================================= */

app.get(
  "/api/security-alerts",
  auth,
  async (req, res) => {
    try {
      const result =
        await pool.query(`
          SELECT
            sa.*,

            d.name AS device_name,
            d.hostname,
            d.ip_address,
            d.department,
            d.employee

          FROM security_alerts sa

          LEFT JOIN devices d
            ON d.id = sa.device_id

          ORDER BY
            CASE
              WHEN sa.status = 'OPEN'
              THEN 0
              ELSE 1
            END,

            sa.created_at DESC

          LIMIT 200
        `);

      res.json(
        result.rows
      );

    } catch (error) {
      console.error(
        "Failed to load security alerts:",
        error
      );

      res.status(500).json({
        error:
          "Failed to load security alerts"
      });
    }
  }
);

/* =========================================================
   SECURITY ALERTS - RESOLVE
========================================================= */

app.put(
  "/api/security-alerts/:id/resolve",
  auth,
  requireManager,
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
          UPDATE security_alerts

          SET
            status = 'RESOLVED',
            resolved_at =
              CURRENT_TIMESTAMP

          WHERE
            id = $1
            AND status = 'OPEN'

          RETURNING *
          `,
          [req.params.id]
        );

      if (!result.rows.length) {
        return res.status(404).json({
          error:
            "Open alert not found"
        });
      }

      await writeAudit(
        req.user.id,
        "ALERT_RESOLVED",
        `Security alert #${req.params.id} was manually resolved.`
      );

      res.json(
        result.rows[0]
      );

    } catch (error) {
      console.error(
        "Failed to resolve alert:",
        error
      );

      res.status(500).json({
        error:
          "Failed to resolve alert"
      });
    }
  }
);

/* =========================================================
   USERS - GET
========================================================= */

app.get(
  "/api/users",
  auth,
  requireAdmin,
  async (req, res) => {
    try {
      const result =
        await pool.query(`
          SELECT
            id,
            name,
            email,
            role,
            created_at

          FROM users

          ORDER BY id DESC
        `);

      res.json(
        result.rows
      );

    } catch (error) {
      console.error(
        "Failed to load users:",
        error
      );

      res.status(500).json({
        error:
          "Failed to load users"
      });
    }
  }
);

/* =========================================================
   USERS - POST
========================================================= */

app.post(
  "/api/users",
  auth,
  requireAdmin,
  async (req, res) => {
    try {
      const {
        name,
        email,
        password,
        role
      } = req.body;

      if (
        !name ||
        !email ||
        !password
      ) {
        return res.status(400).json({
          error:
            "Name, email and password are required"
        });
      }

      if (password.length < 8) {
        return res.status(400).json({
          error:
            "Password must be at least 8 characters"
        });
      }

      const allowedRoles = [
        "Administrator",
        "IT Manager",
        "IT Staff"
      ];

      const finalRole =
        allowedRoles.includes(role)
          ? role
          : "IT Staff";

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
            password_hash,
            role
          )

          VALUES
          ($1,$2,$3,$4)

          RETURNING
            id,
            name,
            email,
            role,
            created_at
          `,
          [
            name.trim(),
            email.trim(),
            passwordHash,
            finalRole
          ]
        );

      await writeAudit(
        req.user.id,
        "USER_CREATED",
        `User ${name} was created.`
      );

      res.status(201).json(
        result.rows[0]
      );

    } catch (error) {
      console.error(
        "Failed to create user:",
        error
      );

      if (
        error.code ===
        "23505"
      ) {
        return res.status(409).json({
          error:
            "A user with that email already exists."
        });
      }

      res.status(500).json({
        error:
          "Failed to create user"
      });
    }
  }
);

/* =========================================================
   USERS - DELETE
========================================================= */

app.delete(
  "/api/users/:id",
  auth,
  requireAdmin,
  async (req, res) => {
    try {
      if (
        Number(req.params.id) ===
        Number(req.user.id)
      ) {
        return res.status(400).json({
          error:
            "You cannot delete your own active account."
        });
      }

      const result =
        await pool.query(
          `
          DELETE FROM users
          WHERE id = $1
          RETURNING id, name, email
          `,
          [req.params.id]
        );

      if (!result.rows.length) {
        return res.status(404).json({
          error:
            "User not found"
        });
      }

      await writeAudit(
        req.user.id,
        "USER_DELETED",
        `User ${result.rows[0].name} was deleted.`
      );

      res.json({
        message:
          "User deleted successfully"
      });

    } catch (error) {
      console.error(
        "Failed to delete user:",
        error
      );

      res.status(500).json({
        error:
          "Failed to delete user"
      });
    }
  }
);

/* =========================================================
   AUDIT LOGS
========================================================= */

app.get(
  "/api/audit-logs",
  auth,
  requireAdmin,
  async (req, res) => {
    try {
      const result =
        await pool.query(`
          SELECT
            al.id,
            al.user_id,
            al.action,
            al.details,
            al.created_at,
            u.name AS user_name,
            u.email AS user_email

          FROM audit_logs al

          LEFT JOIN users u
            ON u.id = al.user_id

          ORDER BY
            al.created_at DESC

          LIMIT 200
        `);

      res.json(
        result.rows
      );

    } catch (error) {
      console.error(
        "Failed to load audit logs:",
        error
      );

      res.status(500).json({
        error:
          "Failed to load audit logs"
      });
    }
  }
);

/* =========================================================
   START SERVER
========================================================= */

async function startServer() {
  try {
    await initializeDatabase();

    app.listen(
      PORT,
      () => {
        console.log(
          `Sentinel server running on http://localhost:${PORT}`
        );

        console.log(
          "Automatic offline detection: ENABLED"
        );

        console.log(
          "Automatic security alerts: ENABLED"
        );
      }
    );

    setInterval(
      markOfflineDevices,
      30000
    );

    setTimeout(
      markOfflineDevices,
      3000
    );

  } catch (error) {
    console.error(
      "Failed to start Sentinel:",
      error
    );

    process.exit(1);
  }
}

startServer();