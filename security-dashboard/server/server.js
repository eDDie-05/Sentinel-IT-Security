const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const path = require("path");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

const app = express();

const PORT = Number(process.env.PORT || 5000);

const JWT_SECRET =
  process.env.JWT_SECRET ||
  "sentinel-development-secret-change-this";

const DATABASE_URL =
  process.env.DATABASE_URL || null;

const pool = new Pool(
  DATABASE_URL
    ? {
        connectionString: DATABASE_URL,
      }
    : {
        user: process.env.PGUSER || "georgemollel",
        host: process.env.PGHOST || "localhost",
        database:
          process.env.PGDATABASE || "security_dashboard",
        password: process.env.PGPASSWORD || "",
        port: Number(process.env.PGPORT || 5432),
      }
);

/* =========================================================
   EXPRESS
========================================================= */

app.use(
  cors({
    origin: true,
    credentials: true,
  })
);

app.use(
  express.json({
    limit: "1mb",
  })
);

pool.on("error", (error) => {
  console.error("PostgreSQL pool error:", error);
});

/* =========================================================
   CONSTANTS
========================================================= */

const ACTIVE_ALERT_STATUSES = [
  "OPEN",
  "ACKNOWLEDGED",
];

const ALERT_SEVERITY = {
  DEVICE_OFFLINE: "critical",
  SECURITY_RISK: "critical",

  ANTIVIRUS_DISABLED: "critical",
  ANTIVIRUS_UNKNOWN: "warning",

  FIREWALL_DISABLED: "critical",
  FIREWALL_UNKNOWN: "warning",

  BACKUP_DISABLED: "critical",
  BACKUP_UNKNOWN: "warning",
};

/* =========================================================
   BASIC HELPERS
========================================================= */

function normalizeStatus(value) {
  if (value === true) {
    return "ENABLED";
  }

  if (value === false) {
    return "DISABLED";
  }

  if (
    value === null ||
    value === undefined ||
    value === ""
  ) {
    return "UNKNOWN";
  }

  const stringValue = String(value)
    .trim()
    .toUpperCase();

  if (
    stringValue === "TRUE" ||
    stringValue === "YES" ||
    stringValue === "ON" ||
    stringValue === "ENABLED"
  ) {
    return "ENABLED";
  }

  if (
    stringValue === "FALSE" ||
    stringValue === "NO" ||
    stringValue === "OFF" ||
    stringValue === "DISABLED"
  ) {
    return "DISABLED";
  }

  if (
    stringValue === "AT RISK" ||
    stringValue === "AT_RISK"
  ) {
    return "AT RISK";
  }

  if (stringValue === "SECURE") {
    return "SECURE";
  }

  if (stringValue === "UNKNOWN") {
    return "UNKNOWN";
  }

  return "UNKNOWN";
}

function statusToBoolean(value) {
  const status = normalizeStatus(value);

  if (status === "ENABLED") {
    return true;
  }

  if (status === "DISABLED") {
    return false;
  }

  return null;
}

function cleanNumber(value) {
  if (
    value === null ||
    value === undefined ||
    value === ""
  ) {
    return null;
  }

  const number = Number(value);

  return Number.isFinite(number)
    ? number
    : null;
}

function cleanString(value, fallback = null) {
  if (
    value === null ||
    value === undefined
  ) {
    return fallback;
  }

  const stringValue = String(value).trim();

  return stringValue === ""
    ? fallback
    : stringValue;
}

function safeDate(value) {
  if (!value) {
    return null;
  }

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return null;
  }

  return date;
}

function sanitizeLogText(
  value,
  fallback = ""
) {
  return String(value ?? fallback)
    .replace(/[\r\n\t]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 2000);
}

function normalizeAlertStatus(value) {
  const status = String(value || "OPEN")
    .trim()
    .toUpperCase();

  if (status === "ACKNOWLEDGED") {
    return "ACKNOWLEDGED";
  }

  if (status === "RESOLVED") {
    return "RESOLVED";
  }

  return "OPEN";
}

function parseBoolean(value, fallback = false) {
  if (value === undefined || value === null) {
    return fallback;
  }

  if (typeof value === "boolean") {
    return value;
  }

  const normalized = String(value)
    .trim()
    .toLowerCase();

  if (
    normalized === "true" ||
    normalized === "yes" ||
    normalized === "1" ||
    normalized === "on"
  ) {
    return true;
  }

  if (
    normalized === "false" ||
    normalized === "no" ||
    normalized === "0" ||
    normalized === "off"
  ) {
    return false;
  }

  return fallback;
}

/* =========================================================
   DATABASE INITIALIZATION
========================================================= */

async function ensureDatabase() {
  /* =======================================================
     USERS
  ======================================================= */

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name VARCHAR(150) NOT NULL,
      email VARCHAR(255) UNIQUE NOT NULL,
      role VARCHAR(50) NOT NULL DEFAULT 'IT Staff',
      password_hash TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);

  /* =======================================================
     DEVICES
  ======================================================= */

  await pool.query(`
    CREATE TABLE IF NOT EXISTS devices (
      id SERIAL PRIMARY KEY,

      device_id VARCHAR(255),

      name VARCHAR(255) NOT NULL,

      hostname VARCHAR(255),

      operating_system VARCHAR(255),

      employee VARCHAR(255),

      username VARCHAR(255),

      department VARCHAR(255),

      ip_address VARCHAR(100),

      architecture VARCHAR(100),

      cpu VARCHAR(255),

      cpu_cores INTEGER,

      ram_gb NUMERIC,

      free_memory_gb NUMERIC,

      total_memory_gb NUMERIC,

      uptime_minutes NUMERIC,

      antivirus BOOLEAN,

      firewall BOOLEAN,

      backup BOOLEAN,

      antivirus_status VARCHAR(30),

      firewall_status VARCHAR(30),

      backup_status VARCHAR(30),

      antivirus_product VARCHAR(255),

      security_message TEXT,

      security_status VARCHAR(30),

      connection_status VARCHAR(30),

      online BOOLEAN DEFAULT FALSE,

      agent_version VARCHAR(100),

      security_checked_at TIMESTAMP,

      agent_last_error TEXT,

      last_seen TIMESTAMP,

      created_at TIMESTAMP DEFAULT NOW(),

      updated_at TIMESTAMP DEFAULT NOW()
    );
  `);

  /* =======================================================
     SECURITY POLICY
  ======================================================= */

  await pool.query(`
    CREATE TABLE IF NOT EXISTS security_policy (
      id INTEGER PRIMARY KEY DEFAULT 1,

      antivirus_required BOOLEAN NOT NULL DEFAULT TRUE,

      firewall_required BOOLEAN NOT NULL DEFAULT TRUE,

      backup_required BOOLEAN NOT NULL DEFAULT TRUE,

      updated_at TIMESTAMP DEFAULT NOW()
    );
  `);

  /* =======================================================
     AUDIT LOGS
  ======================================================= */

  await pool.query(`
    CREATE TABLE IF NOT EXISTS audit_logs (
      id SERIAL PRIMARY KEY,

      user_id INTEGER
        REFERENCES users(id)
        ON DELETE SET NULL,

      action VARCHAR(255) NOT NULL,

      entity_type VARCHAR(100),

      entity_id INTEGER,

      details TEXT,

      created_at TIMESTAMP DEFAULT NOW()
    );
  `);

  await pool.query(`
    ALTER TABLE audit_logs
    ADD COLUMN IF NOT EXISTS entity_type VARCHAR(100);
  `);

  await pool.query(`
    ALTER TABLE audit_logs
    ADD COLUMN IF NOT EXISTS entity_id INTEGER;
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

      severity VARCHAR(30) DEFAULT 'warning',

      message TEXT NOT NULL,

      status VARCHAR(30) DEFAULT 'OPEN',

      occurrence_count INTEGER NOT NULL DEFAULT 1,

      first_detected_at TIMESTAMP DEFAULT NOW(),

      last_detected_at TIMESTAMP DEFAULT NOW(),

      acknowledged_at TIMESTAMP,

      acknowledged_by INTEGER
        REFERENCES users(id)
        ON DELETE SET NULL,

      resolved_at TIMESTAMP,

      resolved_by INTEGER
        REFERENCES users(id)
        ON DELETE SET NULL,

      resolution_reason TEXT,

      created_at TIMESTAMP DEFAULT NOW()
    );
  `);

  /* =======================================================
     ALERT MIGRATIONS
  ======================================================= */

  const alertMigrations = [
    `
      ALTER TABLE security_alerts
      ADD COLUMN IF NOT EXISTS device_id INTEGER;
    `,
    `
      ALTER TABLE security_alerts
      ADD COLUMN IF NOT EXISTS alert_type VARCHAR(100);
    `,
    `
      ALTER TABLE security_alerts
      ADD COLUMN IF NOT EXISTS severity VARCHAR(30)
      DEFAULT 'warning';
    `,
    `
      ALTER TABLE security_alerts
      ADD COLUMN IF NOT EXISTS message TEXT;
    `,
    `
      ALTER TABLE security_alerts
      ADD COLUMN IF NOT EXISTS status VARCHAR(30)
      DEFAULT 'OPEN';
    `,
    `
      ALTER TABLE security_alerts
      ADD COLUMN IF NOT EXISTS occurrence_count INTEGER
      NOT NULL DEFAULT 1;
    `,
    `
      ALTER TABLE security_alerts
      ADD COLUMN IF NOT EXISTS first_detected_at TIMESTAMP
      DEFAULT NOW();
    `,
    `
      ALTER TABLE security_alerts
      ADD COLUMN IF NOT EXISTS last_detected_at TIMESTAMP
      DEFAULT NOW();
    `,
    `
      ALTER TABLE security_alerts
      ADD COLUMN IF NOT EXISTS acknowledged_at TIMESTAMP;
    `,
    `
      ALTER TABLE security_alerts
      ADD COLUMN IF NOT EXISTS acknowledged_by INTEGER;
    `,
    `
      ALTER TABLE security_alerts
      ADD COLUMN IF NOT EXISTS resolved_at TIMESTAMP;
    `,
    `
      ALTER TABLE security_alerts
      ADD COLUMN IF NOT EXISTS resolved_by INTEGER;
    `,
    `
      ALTER TABLE security_alerts
      ADD COLUMN IF NOT EXISTS resolution_reason TEXT;
    `,
  ];

  for (const migration of alertMigrations) {
    await pool.query(migration);
  }

  /* =======================================================
     DEVICE MIGRATIONS
  ======================================================= */

  const deviceMigrations = [
    `
      ALTER TABLE devices
      ADD COLUMN IF NOT EXISTS device_id VARCHAR(255);
    `,
    `
      ALTER TABLE devices
      ADD COLUMN IF NOT EXISTS hostname VARCHAR(255);
    `,
    `
      ALTER TABLE devices
      ADD COLUMN IF NOT EXISTS username VARCHAR(255);
    `,
    `
      ALTER TABLE devices
      ADD COLUMN IF NOT EXISTS architecture VARCHAR(100);
    `,
    `
      ALTER TABLE devices
      ADD COLUMN IF NOT EXISTS cpu_cores INTEGER;
    `,
    `
      ALTER TABLE devices
      ADD COLUMN IF NOT EXISTS total_memory_gb NUMERIC;
    `,
    `
      ALTER TABLE devices
      ADD COLUMN IF NOT EXISTS free_memory_gb NUMERIC;
    `,
    `
      ALTER TABLE devices
      ADD COLUMN IF NOT EXISTS agent_version VARCHAR(100);
    `,
    `
      ALTER TABLE devices
      ADD COLUMN IF NOT EXISTS security_checked_at TIMESTAMP;
    `,
    `
      ALTER TABLE devices
      ADD COLUMN IF NOT EXISTS antivirus_product VARCHAR(255);
    `,
    `
      ALTER TABLE devices
      ADD COLUMN IF NOT EXISTS security_message TEXT;
    `,
    `
      ALTER TABLE devices
      ADD COLUMN IF NOT EXISTS agent_last_error TEXT;
    `,
    `
      ALTER TABLE devices
      ADD COLUMN IF NOT EXISTS antivirus_status VARCHAR(30);
    `,
    `
      ALTER TABLE devices
      ADD COLUMN IF NOT EXISTS firewall_status VARCHAR(30);
    `,
    `
      ALTER TABLE devices
      ADD COLUMN IF NOT EXISTS backup_status VARCHAR(30);
    `,
    `
      ALTER TABLE devices
      ADD COLUMN IF NOT EXISTS security_status VARCHAR(30);
    `,
    `
      ALTER TABLE devices
      ADD COLUMN IF NOT EXISTS connection_status VARCHAR(30);
    `,
  ];

  for (const migration of deviceMigrations) {
    await pool.query(migration);
  }

  /* =======================================================
     REPAIR ALERT TIMESTAMPS
  ======================================================= */

  await pool.query(`
    UPDATE security_alerts
    SET
      first_detected_at =
        COALESCE(
          first_detected_at,
          created_at,
          NOW()
        ),

      last_detected_at =
        COALESCE(
          last_detected_at,
          created_at,
          NOW()
        ),

      occurrence_count =
        COALESCE(
          occurrence_count,
          1
        )
    WHERE
      first_detected_at IS NULL
      OR last_detected_at IS NULL
      OR occurrence_count IS NULL;
  `);

  /* =======================================================
     INDEXES
  ======================================================= */

  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS
    devices_device_id_unique_idx
    ON devices(device_id)
    WHERE device_id IS NOT NULL;
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS
    security_alerts_device_idx
    ON security_alerts(device_id);
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS
    security_alerts_status_idx
    ON security_alerts(status);
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS
    security_alerts_type_status_idx
    ON security_alerts(
      alert_type,
      status
    );
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS
    security_alerts_active_device_idx
    ON security_alerts(
      device_id,
      alert_type,
      status
    );
  `);

  /* =======================================================
     DEFAULT POLICY
  ======================================================= */

  await pool.query(`
    INSERT INTO security_policy (
      id,
      antivirus_required,
      firewall_required,
      backup_required
    )
    VALUES (
      1,
      TRUE,
      TRUE,
      TRUE
    )
    ON CONFLICT (id)
    DO NOTHING;
  `);

  /* =======================================================
     DEFAULT ADMIN
  ======================================================= */

  const adminEmail = "admin@company.com";

  const adminResult =
    await pool.query(
      `
        SELECT id
        FROM users
        WHERE LOWER(email) = LOWER($1)
        LIMIT 1;
      `,
      [adminEmail]
    );

  if (adminResult.rows.length === 0) {
    const adminPassword =
      process.env.ADMIN_PASSWORD ||
      "Admin123456";

    const passwordHash =
      await bcrypt.hash(
        adminPassword,
        12
      );

    await pool.query(
      `
        INSERT INTO users (
          name,
          email,
          role,
          password_hash
        )
        VALUES (
          $1,
          $2,
          $3,
          $4
        );
      `,
      [
        "System Administrator",
        adminEmail,
        "Administrator",
        passwordHash,
      ]
    );

    console.log(
      "Default administrator created:",
      adminEmail
    );
  }
}

/* =========================================================
   AUTHENTICATION
========================================================= */

function auth(req, res, next) {
  try {
    const header =
      req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
      return res.status(401).json({
        error:
          "Authentication required",
      });
    }

    const token =
      header.slice(7).trim();

    if (!token) {
      return res.status(401).json({
        error:
          "Authentication required",
      });
    }

    const decoded =
      jwt.verify(
        token,
        JWT_SECRET
      );

    req.user = decoded;

    next();
  } catch {
    return res.status(401).json({
      error:
        "Invalid or expired token",
    });
  }
}

function requireAdmin(
  req,
  res,
  next
) {
  if (
    req.user?.role !==
    "Administrator"
  ) {
    return res.status(403).json({
      error:
        "Administrator access required",
    });
  }

  next();
}

function requireManager(
  req,
  res,
  next
) {
  const allowedRoles = [
    "Administrator",
    "IT Manager",
  ];

  if (
    !allowedRoles.includes(
      req.user?.role
    )
  ) {
    return res.status(403).json({
      error:
        "Administrator or IT Manager access required",
    });
  }

  next();
}

/* =========================================================
   AUDIT LOG
========================================================= */

async function writeAudit({
  userId = null,
  action,
  entityType = null,
  entityId = null,
  details = null,
}) {
  try {
    await pool.query(
      `
        INSERT INTO audit_logs (
          user_id,
          action,
          entity_type,
          entity_id,
          details
        )
        VALUES (
          $1,
          $2,
          $3,
          $4,
          $5
        );
      `,
      [
        userId,
        sanitizeLogText(action),
        sanitizeLogText(entityType),
        entityId,
        sanitizeLogText(details),
      ]
    );
  } catch (error) {
    console.error(
      "Audit log write failed:",
      error.message
    );
  }
}

/* =========================================================
   SECURITY POLICY
========================================================= */

async function getSecurityPolicy() {
  const result =
    await pool.query(`
      SELECT
        id,
        antivirus_required,
        firewall_required,
        backup_required,
        updated_at
      FROM security_policy
      WHERE id = 1
      LIMIT 1;
    `);

  if (result.rows.length === 0) {
    return {
      id: 1,
      antivirus_required: true,
      firewall_required: true,
      backup_required: true,
    };
  }

  return result.rows[0];
}

/* =========================================================
   DEVICE SECURITY STATUS
========================================================= */

function calculateDeviceSecurityStatus(
  device,
  policy
) {
  if (!device) {
    return "UNKNOWN";
  }

  const online =
    device.online === true ||
    String(
      device.connection_status || ""
    ).toUpperCase() === "ONLINE";

  if (!online) {
    return "AT RISK";
  }

  const controls = [
    {
      required:
        policy.antivirus_required === true,
      status:
        normalizeStatus(
          device.antivirus_status ??
            device.antivirus
        ),
    },

    {
      required:
        policy.firewall_required === true,
      status:
        normalizeStatus(
          device.firewall_status ??
            device.firewall
        ),
    },

    {
      required:
        policy.backup_required === true,
      status:
        normalizeStatus(
          device.backup_status ??
            device.backup
        ),
    },
  ];

  const requiredControls =
    controls.filter(
      (control) =>
        control.required
    );

  if (
    requiredControls.length === 0
  ) {
    return "SECURE";
  }

  if (
    requiredControls.some(
      (control) =>
        control.status ===
        "DISABLED"
    )
  ) {
    return "AT RISK";
  }

  if (
    requiredControls.some(
      (control) =>
        control.status ===
        "UNKNOWN"
    )
  ) {
    return "UNKNOWN";
  }

  return "SECURE";
}

/* =========================================================
   ALERT HELPERS
========================================================= */

async function createAlertIfMissing({
  deviceId,
  alertType,
  severity,
  message,
}) {
  try {
    const safeMessage =
      sanitizeLogText(
        message,
        "Security condition detected."
      );

    const existingResult =
      await pool.query(
        `
          SELECT *
          FROM security_alerts
          WHERE
            device_id = $1
            AND alert_type = $2
            AND UPPER(status) IN (
              'OPEN',
              'ACKNOWLEDGED'
            )
          ORDER BY
            COALESCE(
              last_detected_at,
              created_at
            ) DESC
          LIMIT 1;
        `,
        [
          deviceId,
          alertType,
        ]
      );

    /* =====================================================
       ACTIVE ALERT ALREADY EXISTS
    ===================================================== */

    if (
      existingResult.rows.length > 0
    ) {
      const existing =
        existingResult.rows[0];

      const lastDetected =
        existing.last_detected_at
          ? new Date(
              existing.last_detected_at
            )
          : null;

      const now =
        new Date();

      let occurrenceCount =
        Number(
          existing.occurrence_count || 1
        );

      if (
        lastDetected &&
        Number.isFinite(
          lastDetected.getTime()
        ) &&
        now.getTime() -
          lastDetected.getTime() >=
          5 * 60 * 1000
      ) {
        occurrenceCount++;
      }

      const updated =
        await pool.query(
          `
            UPDATE security_alerts
            SET
              severity = $1,

              message = $2,

              last_detected_at = NOW(),

              occurrence_count = $3
            WHERE id = $4
            RETURNING *;
          `,
          [
            severity,
            safeMessage,
            occurrenceCount,
            existing.id,
          ]
        );

      console.log(
        `Existing alert refreshed: ${alertType} for device ${deviceId}`
      );

      return {
        created: false,
        alert:
          updated.rows[0],
      };
    }

    /* =====================================================
       CREATE NEW ALERT
    ===================================================== */

    const created =
      await pool.query(
        `
          INSERT INTO security_alerts (
            device_id,
            alert_type,
            severity,
            message,
            status,
            occurrence_count,
            first_detected_at,
            last_detected_at,
            created_at
          )
          VALUES (
            $1,
            $2,
            $3,
            $4,
            'OPEN',
            1,
            NOW(),
            NOW(),
            NOW()
          )
          RETURNING *;
        `,
        [
          deviceId,
          alertType,
          severity,
          safeMessage,
        ]
      );

    const alert =
      created.rows[0];

    console.log(
      "======================================="
    );

    console.log(
      "SECURITY ALERT CREATED"
    );

    console.log(
      `Device ID: ${deviceId}`
    );

    console.log(
      `Alert Type: ${alertType}`
    );

    console.log(
      `Severity: ${severity}`
    );

    console.log(
      `Message: ${safeMessage}`
    );

    console.log(
      "======================================="
    );

    await writeAudit({
      action:
        "SECURITY_ALERT_CREATED",

      entityType:
        "security_alert",

      entityId:
        alert.id,

      details:
        `${alertType}: ${safeMessage}`,
    });

    return {
      created: true,
      alert,
    };
  } catch (error) {
    console.error(
      `[SECURITY ALERT ERROR] ${alertType}:`,
      error.message
    );

    return null;
  }
}

/* =========================================================
   RESOLVE SECURITY ALERT
========================================================= */

async function resolveAlert(
  deviceId,
  alertType,
  reason = "Automatic recovery detected"
) {
  try {
    const result =
      await pool.query(
        `
          UPDATE security_alerts
          SET
            status = 'RESOLVED',

            resolved_at = NOW(),

            resolved_by = NULL,

            resolution_reason = $3
          WHERE
            device_id = $1

            AND alert_type = $2

            AND UPPER(status) IN (
              'OPEN',
              'ACKNOWLEDGED'
            )

          RETURNING *;
        `,
        [
          deviceId,
          alertType,
          sanitizeLogText(
            reason
          ),
        ]
      );

    for (
      const alert of result.rows
    ) {
      console.log(
        `SECURITY ALERT RESOLVED: ${alertType} for device ${deviceId}`
      );

      await writeAudit({
        action:
          "SECURITY_ALERT_AUTO_RESOLVED",

        entityType:
          "security_alert",

        entityId:
          alert.id,

        details:
          `${alertType}: ${reason}`,
      });
    }

    return result.rows;
  } catch (error) {
    console.error(
      `[SECURITY ALERT RESOLVE ERROR] ${alertType}:`,
      error.message
    );

    return [];
  }
}

/* =========================================================
   ACKNOWLEDGE ALERT
========================================================= */

async function acknowledgeAlert(
  alertId,
  userId
) {
  const result =
    await pool.query(
      `
        UPDATE security_alerts
        SET
          status = 'ACKNOWLEDGED',

          acknowledged_at = NOW(),

          acknowledged_by = $2
        WHERE
          id = $1

          AND status = 'OPEN'

        RETURNING *;
      `,
      [
        alertId,
        userId,
      ]
    );

  return (
    result.rows[0] ||
    null
  );
}

/* =========================================================
   AUTOMATIC SECURITY EVALUATION
========================================================= */

async function evaluateDeviceSecurity(
  deviceId
) {
  const deviceResult =
    await pool.query(
      `
        SELECT *
        FROM devices
        WHERE id = $1
        LIMIT 1;
      `,
      [deviceId]
    );

  if (
    deviceResult.rows.length ===
    0
  ) {
    return null;
  }

  const device =
    deviceResult.rows[0];

  const policy =
    await getSecurityPolicy();

  const antivirusStatus =
    normalizeStatus(
      device.antivirus_status ??
        device.antivirus
    );

  const firewallStatus =
    normalizeStatus(
      device.firewall_status ??
        device.firewall
    );

  const backupStatus =
    normalizeStatus(
      device.backup_status ??
        device.backup
    );

  const online =
    device.online === true ||
    String(
      device.connection_status || ""
    ).toUpperCase() === "ONLINE";

  const securityStatus =
    calculateDeviceSecurityStatus(
      {
        ...device,

        online,

        antivirus_status:
          antivirusStatus,

        firewall_status:
          firewallStatus,

        backup_status:
          backupStatus,
      },

      policy
    );

  /* =======================================================
     SAVE SECURITY STATUS
  ======================================================= */

  await pool.query(
    `
      UPDATE devices
      SET
        antivirus_status = $1,

        firewall_status = $2,

        backup_status = $3,

        antivirus = $4,

        firewall = $5,

        backup = $6,

        security_status = $7,

        connection_status = $8,

        online = $9,

        updated_at = NOW()

      WHERE id = $10;
    `,
    [
      antivirusStatus,
      firewallStatus,
      backupStatus,

      statusToBoolean(
        antivirusStatus
      ),

      statusToBoolean(
        firewallStatus
      ),

      statusToBoolean(
        backupStatus
      ),

      securityStatus,

      online
        ? "ONLINE"
        : "OFFLINE",

      online,

      deviceId,
    ]
  );

  /* =======================================================
     OFFLINE ALERT
  ======================================================= */

  if (!online) {
    await createAlertIfMissing({
      deviceId,

      alertType:
        "DEVICE_OFFLINE",

      severity:
        ALERT_SEVERITY
          .DEVICE_OFFLINE,

      message:
        `Device ${
          device.name ||
          device.hostname ||
          device.device_id ||
          "Unknown"
        } is offline. Last heartbeat: ${
          device.last_seen
            ? new Date(
                device.last_seen
              ).toLocaleString()
            : "never"
        }.`,
    });
  } else {
    await resolveAlert(
      deviceId,
      "DEVICE_OFFLINE",
      "Device heartbeat recovered"
    );
  }

  /* =======================================================
     ANTIVIRUS ALERTS
  ======================================================= */

  if (
    policy.antivirus_required
  ) {
    if (
      antivirusStatus ===
      "DISABLED"
    ) {
      await createAlertIfMissing({
        deviceId,

        alertType:
          "ANTIVIRUS_DISABLED",

        severity:
          ALERT_SEVERITY
            .ANTIVIRUS_DISABLED,

        message:
          "Required antivirus protection is disabled.",
      });

      await resolveAlert(
        deviceId,
        "ANTIVIRUS_UNKNOWN",
        "Antivirus status is now known"
      );
    } else if (
      antivirusStatus ===
      "UNKNOWN"
    ) {
      await createAlertIfMissing({
        deviceId,

        alertType:
          "ANTIVIRUS_UNKNOWN",

        severity:
          ALERT_SEVERITY
            .ANTIVIRUS_UNKNOWN,

        message:
          "The Sentinel agent could not determine the antivirus status.",
      });

      await resolveAlert(
        deviceId,
        "ANTIVIRUS_DISABLED",
        "Antivirus disabled condition cleared"
      );
    } else {
      await resolveAlert(
        deviceId,
        "ANTIVIRUS_DISABLED",
        "Antivirus protection recovered"
      );

      await resolveAlert(
        deviceId,
        "ANTIVIRUS_UNKNOWN",
        "Antivirus status is now known"
      );
    }
  } else {
    await resolveAlert(
      deviceId,
      "ANTIVIRUS_DISABLED",
      "Antivirus requirement disabled by security policy"
    );

    await resolveAlert(
      deviceId,
      "ANTIVIRUS_UNKNOWN",
      "Antivirus requirement disabled by security policy"
    );
  }

  /* =======================================================
     FIREWALL ALERTS
  ======================================================= */

  if (
    policy.firewall_required
  ) {
    if (
      firewallStatus ===
      "DISABLED"
    ) {
      await createAlertIfMissing({
        deviceId,

        alertType:
          "FIREWALL_DISABLED",

        severity:
          ALERT_SEVERITY
            .FIREWALL_DISABLED,

        message:
          "Required firewall protection is disabled.",
      });

      await resolveAlert(
        deviceId,
        "FIREWALL_UNKNOWN",
        "Firewall status is now known"
      );
    } else if (
      firewallStatus ===
      "UNKNOWN"
    ) {
      await createAlertIfMissing({
        deviceId,

        alertType:
          "FIREWALL_UNKNOWN",

        severity:
          ALERT_SEVERITY
            .FIREWALL_UNKNOWN,

        message:
          "The Sentinel agent could not determine the firewall status.",
      });

      await resolveAlert(
        deviceId,
        "FIREWALL_DISABLED",
        "Firewall disabled condition cleared"
      );
    } else {
      await resolveAlert(
        deviceId,
        "FIREWALL_DISABLED",
        "Firewall protection recovered"
      );

      await resolveAlert(
        deviceId,
        "FIREWALL_UNKNOWN",
        "Firewall status is now known"
      );
    }
  } else {
    await resolveAlert(
      deviceId,
      "FIREWALL_DISABLED",
      "Firewall requirement disabled by security policy"
    );

    await resolveAlert(
      deviceId,
      "FIREWALL_UNKNOWN",
      "Firewall requirement disabled by security policy"
    );
  }

  /* =======================================================
     BACKUP ALERTS
  ======================================================= */

  if (
    policy.backup_required
  ) {
    if (
      backupStatus ===
      "DISABLED"
    ) {
      await createAlertIfMissing({
        deviceId,

        alertType:
          "BACKUP_DISABLED",

        severity:
          ALERT_SEVERITY
            .BACKUP_DISABLED,

        message:
          "Required backup protection is disabled.",
      });

      await resolveAlert(
        deviceId,
        "BACKUP_UNKNOWN",
        "Backup status is now known"
      );
    } else if (
      backupStatus ===
      "UNKNOWN"
    ) {
      await createAlertIfMissing({
        deviceId,

        alertType:
          "BACKUP_UNKNOWN",

        severity:
          ALERT_SEVERITY
            .BACKUP_UNKNOWN,

        message:
          "The Sentinel agent could not determine the backup status.",
      });

      await resolveAlert(
        deviceId,
        "BACKUP_DISABLED",
        "Backup disabled condition cleared"
      );
    } else {
      await resolveAlert(
        deviceId,
        "BACKUP_DISABLED",
        "Backup protection recovered"
      );

      await resolveAlert(
        deviceId,
        "BACKUP_UNKNOWN",
        "Backup status is now known"
      );
    }
  } else {
    await resolveAlert(
      deviceId,
      "BACKUP_DISABLED",
      "Backup requirement disabled by security policy"
    );

    await resolveAlert(
      deviceId,
      "BACKUP_UNKNOWN",
      "Backup requirement disabled by security policy"
    );
  }

  /* =======================================================
     OVERALL SECURITY RISK
  ======================================================= */

  if (
    securityStatus ===
    "AT RISK"
  ) {
    const problems = [];

    if (
      policy.antivirus_required &&
      antivirusStatus ===
        "DISABLED"
    ) {
      problems.push(
        "Antivirus disabled"
      );
    }

    if (
      policy.firewall_required &&
      firewallStatus ===
        "DISABLED"
    ) {
      problems.push(
        "Firewall disabled"
      );
    }

    if (
      policy.backup_required &&
      backupStatus ===
        "DISABLED"
    ) {
      problems.push(
        "Backup disabled"
      );
    }

    if (!online) {
      problems.push(
        "Device offline"
      );
    }

    await createAlertIfMissing({
      deviceId,

      alertType:
        "SECURITY_RISK",

      severity:
        ALERT_SEVERITY
          .SECURITY_RISK,

      message:
        problems.length > 0
          ? `Device security is AT RISK: ${problems.join(
              ", "
            )}.`
          : "Device security is AT RISK.",
    });
  } else {
    await resolveAlert(
      deviceId,
      "SECURITY_RISK",
      "Device security condition recovered"
    );
  }

  /* =======================================================
     UNKNOWN STATUS LOG
  ======================================================= */

  if (
    securityStatus ===
    "UNKNOWN"
  ) {
    const unknownControls = [];

    if (
      policy.antivirus_required &&
      antivirusStatus ===
        "UNKNOWN"
    ) {
      unknownControls.push(
        "Antivirus"
      );
    }

    if (
      policy.firewall_required &&
      firewallStatus ===
        "UNKNOWN"
    ) {
      unknownControls.push(
        "Firewall"
      );
    }

    if (
      policy.backup_required &&
      backupStatus ===
        "UNKNOWN"
    ) {
      unknownControls.push(
        "Backup"
      );
    }

    console.log(
      `Security status UNKNOWN for device ${deviceId}: ${
        unknownControls.join(", ") ||
        "No control details"
      }`
    );
  }

  /* =======================================================
     RETURN FINAL DEVICE
  ======================================================= */

  const finalResult =
    await pool.query(
      `
        SELECT *
        FROM devices
        WHERE id = $1
        LIMIT 1;
      `,
      [deviceId]
    );

  return (
    finalResult.rows[0] ||
    null
  );
}

/* =========================================================
   REFRESH ALL DEVICE SECURITY
========================================================= */

async function refreshDeviceSecurityStatuses() {
  const result =
    await pool.query(`
      SELECT id
      FROM devices
      ORDER BY id ASC;
    `);

  for (
    const device of result.rows
  ) {
    try {
      await evaluateDeviceSecurity(
        device.id
      );
    } catch (error) {
      console.error(
        `Security evaluation failed for device ${device.id}:`,
        error.message
      );
    }
  }
}

/* =========================================================
   ROOT
========================================================= */

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "..", "dist", "index.html"));
});

/* =========================================================
   HEALTH
========================================================= */

app.get(
  "/api/health",
  async (req, res) => {
    try {
      await pool.query(
        "SELECT 1"
      );

      res.json({
        status: "ok",

        database:
          "connected",

        service:
          "Sentinel API",

        timestamp:
          new Date().toISOString(),
      });
    } catch (error) {
      console.error(
        "Health check error:",
        error
      );

      res.status(500).json({
        status: "error",

        database:
          "disconnected",

        message:
          "Database connection failed",
      });
    }
  }
);

/* =========================================================
   LOGIN
========================================================= */

app.post(
  "/api/login",
  async (req, res) => {
    try {
      const email =
        cleanString(
          req.body?.email
        );

      const password =
        cleanString(
          req.body?.password
        );

      if (
        !email ||
        !password
      ) {
        return res.status(400).json({
          error:
            "Email and password are required",
        });
      }

      const result =
        await pool.query(
          `
            SELECT
              id,
              name,
              email,
              role,
              password_hash
            FROM users
            WHERE LOWER(email) = LOWER($1)
            LIMIT 1;
          `,
          [email]
        );

      if (
        result.rows.length ===
        0
      ) {
        await writeAudit({
          action:
            "LOGIN_FAILED",

          entityType:
            "user",

          details:
            `Login failed for ${email}`,
        });

        return res.status(401).json({
          error:
            "Invalid email or password",
        });
      }

      const user =
        result.rows[0];

      const passwordMatches =
        await bcrypt.compare(
          password,
          user.password_hash
        );

      if (!passwordMatches) {
        await writeAudit({
          action:
            "LOGIN_FAILED",

          entityType:
            "user",

          entityId:
            user.id,

          details:
            "Invalid password",
        });

        return res.status(401).json({
          error:
            "Invalid email or password",
        });
      }

      const token =
        jwt.sign(
          {
            id:
              user.id,

            name:
              user.name,

            email:
              user.email,

            role:
              user.role,
          },

          JWT_SECRET,

          {
            expiresIn:
              "8h",
          }
        );

      await writeAudit({
        userId:
          user.id,

        action:
          "LOGIN_SUCCESS",

        entityType:
          "user",

        entityId:
          user.id,

        details:
          "User authenticated successfully",
      });

      res.json({
        token,

        user: {
          id:
            user.id,

          name:
            user.name,

          email:
            user.email,

          role:
            user.role,
        },
      });
    } catch (error) {
      console.error(
        "Login error:",
        error
      );

      res.status(500).json({
        error:
          "Login failed",
      });
    }
  }
);

/* =========================================================
   CURRENT USER
========================================================= */

app.get(
  "/api/me",
  auth,
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
            SELECT
              id,
              name,
              email,
              role,
              created_at
            FROM users
            WHERE id = $1
            LIMIT 1;
          `,
          [req.user.id]
        );

      if (
        result.rows.length ===
        0
      ) {
        return res.status(404).json({
          error:
            "User not found",
        });
      }

      res.json(
        result.rows[0]
      );
    } catch (error) {
      console.error(
        "Current user error:",
        error
      );

      res.status(500).json({
        error:
          "Failed to load current user",
      });
    }
  }
);

/* =========================================================
   GET DEVICES
========================================================= */

app.get(
  "/api/devices",
  auth,
  async (req, res) => {
    try {
      await refreshDeviceSecurityStatuses();

      const result =
        await pool.query(`
          SELECT
            d.*,

            COUNT(
              CASE
                WHEN sa.status IN (
                  'OPEN',
                  'ACKNOWLEDGED'
                )
                THEN 1
              END
            ) AS active_alert_count

          FROM devices d

          LEFT JOIN security_alerts sa
            ON sa.device_id = d.id

          GROUP BY d.id

          ORDER BY d.id DESC;
        `);

      res.json(
        result.rows
      );
    } catch (error) {
      console.error(
        "Get devices error:",
        error
      );

      res.status(500).json({
        error:
          "Failed to load devices",
      });
    }
  }
);

/* =========================================================
   GET SINGLE DEVICE
========================================================= */

app.get(
  "/api/devices/:id",
  auth,
  async (req, res) => {
    try {
      const deviceId =
        Number(
          req.params.id
        );

      if (
        !Number.isInteger(
          deviceId
        )
      ) {
        return res.status(400).json({
          error:
            "Invalid device ID",
        });
      }

      const deviceResult =
        await pool.query(
          `
            SELECT *
            FROM devices
            WHERE id = $1
            LIMIT 1;
          `,
          [deviceId]
        );

      if (
        deviceResult.rows.length ===
        0
      ) {
        return res.status(404).json({
          error:
            "Device not found",
        });
      }

      const alertsResult =
        await pool.query(
          `
            SELECT
              sa.*,

              au.name
                AS acknowledged_by_name,

              au.email
                AS acknowledged_by_email,

              ru.name
                AS resolved_by_name,

              ru.email
                AS resolved_by_email

            FROM security_alerts sa

            LEFT JOIN users au
              ON au.id =
                sa.acknowledged_by

            LEFT JOIN users ru
              ON ru.id =
                sa.resolved_by

            WHERE sa.device_id =
              $1

            ORDER BY
              sa.created_at DESC;
          `,
          [deviceId]
        );

      res.json({
        device:
          deviceResult.rows[0],

        alerts:
          alertsResult.rows,
      });
    } catch (error) {
      console.error(
        "Get device error:",
        error
      );

      res.status(500).json({
        error:
          "Failed to load device",
      });
    }
  }
);

/* =========================================================
   ADD DEVICE
========================================================= */

app.post(
  "/api/devices",
  auth,
  requireManager,
  async (req, res) => {
    try {
      const body =
        req.body || {};

      const name =
        cleanString(
          body.name
        ) ||
        cleanString(
          body.hostname
        ) ||
        "Unnamed Device";

      const deviceId =
        cleanString(
          body.deviceId ??
            body.device_id
        ) || null;

      const hostname =
        cleanString(
          body.hostname
        ) || null;

      const operatingSystem =
        cleanString(
          body.operatingSystem
        ) ||
        cleanString(
          body.operating_system
        ) ||
        null;

      const employee =
        cleanString(
          body.employee
        ) ||
        "Unknown";

      const username =
        cleanString(
          body.username
        );

      const department =
        cleanString(
          body.department
        ) ||
        "Unassigned";

      const ipAddress =
        cleanString(
          body.ipAddress
        ) ||
        cleanString(
          body.ip_address
        ) ||
        "Unknown";

      const architecture =
        cleanString(
          body.architecture
        );

      const cpu =
        cleanString(
          body.cpu
        );

      const cpuCores =
        cleanNumber(
          body.cpuCores ??
            body.cpu_cores
        );

      const ramGB =
        cleanNumber(
          body.ramGb ??
            body.ram_gb
        );

      const freeMemoryGB =
        cleanNumber(
          body.freeMemoryGb ??
            body.free_memory_gb
        );

      const totalMemoryGB =
        cleanNumber(
          body.totalMemoryGb ??
            body.total_memory_gb
        );

      const uptimeMinutes =
        cleanNumber(
          body.uptimeMinutes ??
            body.uptime_minutes
        );

      const antivirusStatus =
        normalizeStatus(
          body.antivirusStatus ??
            body.antivirus
        );

      const firewallStatus =
        normalizeStatus(
          body.firewallStatus ??
            body.firewall
        );

      const backupStatus =
        normalizeStatus(
          body.backupStatus ??
            body.backup
        );

      const antivirusProduct =
        cleanString(
          body.antivirusProduct
        );

      const securityMessage =
        cleanString(
          body.securityMessage
        );

      const agentVersion =
        cleanString(
          body.agentVersion
        );

      const securityCheckedAt =
        safeDate(
          body.securityCheckedAt
        );

      const online =
        parseBoolean(
          body.online,
          false
        );

      const policy =
        await getSecurityPolicy();

      const securityStatus =
        calculateDeviceSecurityStatus(
          {
            online,

            antivirus_status:
              antivirusStatus,

            firewall_status:
              firewallStatus,

            backup_status:
              backupStatus,
          },

          policy
        );

      const result =
        await pool.query(
          `
            INSERT INTO devices (
              device_id,
              name,
              hostname,
              operating_system,
              employee,
              username,
              department,
              ip_address,
              architecture,
              cpu,
              cpu_cores,
              ram_gb,
              free_memory_gb,
              total_memory_gb,
              uptime_minutes,
              antivirus,
              firewall,
              backup,
              antivirus_status,
              firewall_status,
              backup_status,
              antivirus_product,
              security_message,
              security_status,
              connection_status,
              online,
              agent_version,
              security_checked_at,
              last_seen,
              created_at,
              updated_at
            )
            VALUES (
              $1,
              $2,
              $3,
              $4,
              $5,
              $6,
              $7,
              $8,
              $9,
              $10,
              $11,
              $12,
              $13,
              $14,
              $15,
              $16,
              $17,
              $18,
              $19,
              $20,
              $21,
              $22,
              $23,
              $24,
              $25,
              $26,
              $27,
              $28,
              $29,
              NOW(),
              NOW()
            )
            RETURNING *;
          `,
          [
            deviceId,
            name,
            hostname,
            operatingSystem,
            employee,
            username,
            department,
            ipAddress,
            architecture,
            cpu,
            cpuCores,
            ramGB,
            freeMemoryGB,
            totalMemoryGB,
            uptimeMinutes,

            statusToBoolean(
              antivirusStatus
            ),

            statusToBoolean(
              firewallStatus
            ),

            statusToBoolean(
              backupStatus
            ),

            antivirusStatus,
            firewallStatus,
            backupStatus,

            antivirusProduct,
            securityMessage,

            securityStatus,

            online
              ? "ONLINE"
              : "OFFLINE",

            online,

            agentVersion,
            securityCheckedAt,

            online
              ? new Date()
              : null,
          ]
        );

      const device =
        result.rows[0];

      await writeAudit({
        userId:
          req.user.id,

        action:
          "DEVICE_CREATED",

        entityType:
          "device",

        entityId:
          device.id,

        details:
          `Created device ${name}`,
      });

      await evaluateDeviceSecurity(
        device.id
      );

      const finalDevice =
        await pool.query(
          `
            SELECT *
            FROM devices
            WHERE id = $1;
          `,
          [device.id]
        );

      res.status(201).json(
        finalDevice.rows[0]
      );
    } catch (error) {
      console.error(
        "Add device error:",
        error
      );

      if (
        error.code === "23505"
      ) {
        return res.status(409).json({
          error:
            "A device with this device ID already exists",
        });
      }

      res.status(500).json({
        error:
          "Failed to create device",

        message:
          error.message,
      });
    }
  }
);

/* =========================================================
   UPDATE DEVICE
========================================================= */

app.put(
  "/api/devices/:id",
  auth,
  requireManager,
  async (req, res) => {
    try {
      const deviceId =
        Number(
          req.params.id
        );

      if (
        !Number.isInteger(
          deviceId
        )
      ) {
        return res.status(400).json({
          error:
            "Invalid device ID",
        });
      }

      const existingResult =
        await pool.query(
          `
            SELECT *
            FROM devices
            WHERE id = $1
            LIMIT 1;
          `,
          [deviceId]
        );

      if (
        existingResult.rows.length ===
        0
      ) {
        return res.status(404).json({
          error:
            "Device not found",
        });
      }

      const existing =
        existingResult.rows[0];

      const body =
        req.body || {};

      const name =
        cleanString(
          body.name
        ) ||
        existing.name;

      const employee =
        body.employee !==
        undefined
          ? cleanString(
              body.employee
            )
          : existing.employee;

      const department =
        body.department !==
        undefined
          ? cleanString(
              body.department
            )
          : existing.department;

      const ipAddress =
        body.ipAddress !==
          undefined ||
        body.ip_address !==
          undefined
          ? cleanString(
              body.ipAddress ??
                body.ip_address
            )
          : existing.ip_address;

      const antivirusStatus =
        body.antivirusStatus !==
            undefined ||
        body.antivirus !==
            undefined
          ? normalizeStatus(
              body.antivirusStatus ??
                body.antivirus
            )
          : normalizeStatus(
              existing.antivirus_status ??
                existing.antivirus
            );

      const firewallStatus =
        body.firewallStatus !==
            undefined ||
        body.firewall !==
            undefined
          ? normalizeStatus(
              body.firewallStatus ??
                body.firewall
            )
          : normalizeStatus(
              existing.firewall_status ??
                existing.firewall
            );

      const backupStatus =
        body.backupStatus !==
            undefined ||
        body.backup !==
            undefined
          ? normalizeStatus(
              body.backupStatus ??
                body.backup
            )
          : normalizeStatus(
              existing.backup_status ??
                existing.backup
            );

      const online =
        body.online !==
        undefined
          ? parseBoolean(
              body.online,
              false
            )
          : existing.online ===
            true;

      const policy =
        await getSecurityPolicy();

      const securityStatus =
        calculateDeviceSecurityStatus(
          {
            ...existing,

            online,

            antivirus_status:
              antivirusStatus,

            firewall_status:
              firewallStatus,

            backup_status:
              backupStatus,
          },

          policy
        );

      const securityMessage =
        body.securityMessage !==
        undefined
          ? cleanString(
              body.securityMessage
            )
          : existing.security_message;

      const antivirusProduct =
        body.antivirusProduct !==
        undefined
          ? cleanString(
              body.antivirusProduct
            )
          : existing.antivirus_product;

      await pool.query(
        `
          UPDATE devices
          SET
            name = $1,

            employee = $2,

            department = $3,

            ip_address = $4,

            antivirus = $5,

            firewall = $6,

            backup = $7,

            antivirus_status = $8,

            firewall_status = $9,

            backup_status = $10,

            antivirus_product = $11,

            security_message = $12,

            online = $13,

            connection_status = $14,

            security_status = $15,

            updated_at = NOW()

          WHERE id = $16;
        `,
        [
          name,
          employee,
          department,
          ipAddress,

          statusToBoolean(
            antivirusStatus
          ),

          statusToBoolean(
            firewallStatus
          ),

          statusToBoolean(
            backupStatus
          ),

          antivirusStatus,
          firewallStatus,
          backupStatus,

          antivirusProduct,
          securityMessage,

          online,

          online
            ? "ONLINE"
            : "OFFLINE",

          securityStatus,

          deviceId,
        ]
      );

      await writeAudit({
        userId:
          req.user.id,

        action:
          "DEVICE_UPDATED",

        entityType:
          "device",

        entityId:
          deviceId,

        details:
          `Updated device ${name}`,
      });

      await evaluateDeviceSecurity(
        deviceId
      );

      const finalDevice =
        await pool.query(
          `
            SELECT *
            FROM devices
            WHERE id = $1;
          `,
          [deviceId]
        );

      res.json(
        finalDevice.rows[0]
      );
    } catch (error) {
      console.error(
        "Update device error:",
        error
      );

      res.status(500).json({
        error:
          "Failed to update device",

        message:
          error.message,
      });
    }
  }
);

/* =========================================================
   DELETE DEVICE
========================================================= */

app.delete(
  "/api/devices/:id",
  auth,
  requireManager,
  async (req, res) => {
    try {
      const deviceId =
        Number(
          req.params.id
        );

      if (
        !Number.isInteger(
          deviceId
        )
      ) {
        return res.status(400).json({
          error:
            "Invalid device ID",
        });
      }

      const existing =
        await pool.query(
          `
            SELECT
              id,
              name
            FROM devices
            WHERE id = $1
            LIMIT 1;
          `,
          [deviceId]
        );

      if (
        existing.rows.length ===
        0
      ) {
        return res.status(404).json({
          error:
            "Device not found",
        });
      }

      await pool.query(
        `
          DELETE FROM devices
          WHERE id = $1;
        `,
        [deviceId]
      );

      await writeAudit({
        userId:
          req.user.id,

        action:
          "DEVICE_DELETED",

        entityType:
          "device",

        entityId:
          deviceId,

        details:
          `Deleted device ${existing.rows[0].name}`,
      });

      res.json({
        message:
          "Device deleted successfully",
      });
    } catch (error) {
      console.error(
        "Delete device error:",
        error
      );

      res.status(500).json({
        error:
          "Failed to delete device",
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
      const body =
        req.body || {};

      const deviceId =
        cleanString(
          body.deviceId ??
            body.device_id
        ) ||
        cleanString(
          body.hostname
        );

      if (!deviceId) {
        return res.status(400).json({
          error:
            "deviceId or hostname is required",
        });
      }

      const hostname =
        cleanString(
          body.hostname
        ) ||
        deviceId;

      const name =
        cleanString(
          body.name
        ) ||
        hostname;

      const operatingSystem =
        cleanString(
          body.operatingSystem
        ) ||
        cleanString(
          body.operating_system
        ) ||
        "Unknown";

      const username =
        cleanString(
          body.username
        );

      const architecture =
        cleanString(
          body.architecture
        );

      const cpu =
        cleanString(
          body.cpu
        );

      const cpuCores =
        cleanNumber(
          body.cpuCores ??
            body.cpu_cores
        );

      const ramGB =
        cleanNumber(
          body.ramGb ??
            body.ram_gb
        );

      const freeMemoryGB =
        cleanNumber(
          body.freeMemoryGb ??
            body.free_memory_gb
        );

      const totalMemoryGB =
        cleanNumber(
          body.totalMemoryGb ??
            body.total_memory_gb
        );

      const uptimeMinutes =
        cleanNumber(
          body.uptimeMinutes ??
            body.uptime_minutes
        );

      const ipAddress =
        cleanString(
          body.ipAddress ??
            body.ip_address
        ) ||
        "Unknown";

      const agentVersion =
        cleanString(
          body.agentVersion
        );

      /* ===================================================
         SECURITY DATA
      =================================================== */

      const security =
        body.security &&
        typeof body.security ===
          "object"
          ? body.security
          : {};

      const antivirusObject =
        security.antivirus &&
        typeof security.antivirus ===
          "object"
          ? security.antivirus
          : {};

      const firewallObject =
        security.firewall &&
        typeof security.firewall ===
          "object"
          ? security.firewall
          : {};

      const backupObject =
        security.backup &&
        typeof security.backup ===
          "object"
          ? security.backup
          : {};

      /* ===================================================
         ANTIVIRUS STATUS
      =================================================== */

      const antivirusStatus =
        normalizeStatus(
          security.antivirusStatus ??
            antivirusObject.status ??
            body.antivirusStatus ??
            (
              typeof body.antivirus ===
              "object"
                ? body.antivirus.status
                : body.antivirus
            ) ??
            antivirusObject.enabled
        );

      /* ===================================================
         FIREWALL STATUS
      =================================================== */

      const firewallStatus =
        normalizeStatus(
          security.firewallStatus ??
            firewallObject.status ??
            body.firewallStatus ??
            (
              typeof body.firewall ===
              "object"
                ? body.firewall.status
                : body.firewall
            ) ??
            firewallObject.enabled
        );

      /* ===================================================
         BACKUP STATUS
      =================================================== */

      const backupStatus =
        normalizeStatus(
          security.backupStatus ??
            backupObject.status ??
            body.backupStatus ??
            (
              typeof body.backup ===
              "object"
                ? body.backup.status
                : body.backup
            ) ??
            backupObject.enabled
        );

      const antivirusProduct =
        cleanString(
          security.antivirusProduct ??
            antivirusObject.product ??
            body.antivirusProduct
        );

      const securityMessage =
        cleanString(
          security.message ??
            body.securityMessage
        );

      const securityCheckedAt =
        safeDate(
          security.checkedAt ??
            body.securityCheckedAt
        ) ||
        new Date();

      const agentOverallStatus =
        normalizeStatus(
          security.overallStatus ??
            security.securityStatus ??
            body.securityStatus
        );

      console.log("");
      console.log(
        "======================================="
      );
      console.log(
        "AGENT HEARTBEAT RECEIVED"
      );
      console.log(
        "======================================="
      );
      console.log(
        `Device: ${name}`
      );
      console.log(
        `Device ID: ${deviceId}`
      );
      console.log(
        `Antivirus: ${antivirusStatus}`
      );
      console.log(
        `Firewall: ${firewallStatus}`
      );
      console.log(
        `Backup: ${backupStatus}`
      );
      console.log(
        `Agent Security: ${agentOverallStatus}`
      );

      /* ===================================================
         FIND DEVICE
      =================================================== */

      const existingResult =
        await pool.query(
          `
            SELECT *
            FROM devices
            WHERE device_id = $1
            LIMIT 1;
          `,
          [deviceId]
        );

      let databaseDevice;

      /* ===================================================
         REGISTER NEW DEVICE
      =================================================== */

      if (
        existingResult.rows.length ===
        0
      ) {
        const policy =
          await getSecurityPolicy();

        const calculatedStatus =
          calculateDeviceSecurityStatus(
            {
              online: true,

              antivirus_status:
                antivirusStatus,

              firewall_status:
                firewallStatus,

              backup_status:
                backupStatus,
            },

            policy
          );

        const insertResult =
          await pool.query(
            `
              INSERT INTO devices (
                device_id,
                name,
                hostname,
                operating_system,
                employee,
                username,
                department,
                ip_address,
                architecture,
                cpu,
                cpu_cores,
                ram_gb,
                free_memory_gb,
                total_memory_gb,
                uptime_minutes,
                antivirus,
                firewall,
                backup,
                antivirus_status,
                firewall_status,
                backup_status,
                antivirus_product,
                security_message,
                security_status,
                connection_status,
                online,
                agent_version,
                security_checked_at,
                last_seen,
                created_at,
                updated_at
              )
              VALUES (
                $1,
                $2,
                $3,
                $4,
                $5,
                $6,
                $7,
                $8,
                $9,
                $10,
                $11,
                $12,
                $13,
                $14,
                $15,
                $16,
                $17,
                $18,
                $19,
                $20,
                $21,
                $22,
                $23,
                $24,
                $25,
                $26,
                $27,
                $28,
                $29,
                NOW(),
                NOW()
              )
              RETURNING *;
            `,
            [
              deviceId,
              name,
              hostname,
              operatingSystem,

              username ||
                "Unknown",

              username,

              "Unassigned",

              ipAddress,

              architecture,
              cpu,
              cpuCores,

              ramGB,
              freeMemoryGB,
              totalMemoryGB,

              uptimeMinutes,

              statusToBoolean(
                antivirusStatus
              ),

              statusToBoolean(
                firewallStatus
              ),

              statusToBoolean(
                backupStatus
              ),

              antivirusStatus,
              firewallStatus,
              backupStatus,

              antivirusProduct,
              securityMessage,

              calculatedStatus,

              "ONLINE",

              true,

              agentVersion,

              securityCheckedAt,

              new Date(),
            ]
          );

        databaseDevice =
          insertResult.rows[0];

        console.log(
          `New device registered: ${name}`
        );

        await writeAudit({
          action:
            "DEVICE_REGISTERED",

          entityType:
            "device",

          entityId:
            databaseDevice.id,

          details:
            `Agent registered device ${name}`,
        });
      } else {
        /* =================================================
           UPDATE EXISTING DEVICE
        ================================================= */

        const existing =
          existingResult.rows[0];

        const policy =
          await getSecurityPolicy();

        const calculatedStatus =
          calculateDeviceSecurityStatus(
            {
              ...existing,

              online: true,

              antivirus_status:
                antivirusStatus,

              firewall_status:
                firewallStatus,

              backup_status:
                backupStatus,
            },

            policy
          );

        const updateResult =
          await pool.query(
            `
              UPDATE devices
              SET
                name = $1,

                hostname = $2,

                operating_system = $3,

                username = $4,

                ip_address = $5,

                architecture = $6,

                cpu = $7,

                cpu_cores = $8,

                ram_gb = $9,

                free_memory_gb = $10,

                total_memory_gb = $11,

                uptime_minutes = $12,

                antivirus = $13,

                firewall = $14,

                backup = $15,

                antivirus_status = $16,

                firewall_status = $17,

                backup_status = $18,

                antivirus_product = $19,

                security_message = $20,

                security_status = $21,

                connection_status = 'ONLINE',

                online = TRUE,

                agent_version = $22,

                security_checked_at = $23,

                agent_last_error = NULL,

                last_seen = NOW(),

                updated_at = NOW()

              WHERE id = $24

              RETURNING *;
            `,
            [
              name,
              hostname,
              operatingSystem,
              username,
              ipAddress,

              architecture,

              cpu,
              cpuCores,

              ramGB,
              freeMemoryGB,
              totalMemoryGB,

              uptimeMinutes,

              statusToBoolean(
                antivirusStatus
              ),

              statusToBoolean(
                firewallStatus
              ),

              statusToBoolean(
                backupStatus
              ),

              antivirusStatus,
              firewallStatus,
              backupStatus,

              antivirusProduct,
              securityMessage,

              calculatedStatus,

              agentVersion,
              securityCheckedAt,

              existing.id,
            ]
          );

        databaseDevice =
          updateResult.rows[0];
      }

      /* ===================================================
         EVALUATE SECURITY
      =================================================== */

      const evaluated =
        await evaluateDeviceSecurity(
          databaseDevice.id
        );

      console.log(
        `FINAL SECURITY STATUS: ${evaluated.security_status}`
      );

      console.log(
        `FINAL ANTIVIRUS: ${evaluated.antivirus_status}`
      );

      console.log(
        `FINAL FIREWALL: ${evaluated.firewall_status}`
      );

      console.log(
        `FINAL BACKUP: ${evaluated.backup_status}`
      );

      console.log(
        "======================================="
      );

      console.log("");

      res.json({
        success: true,

        message:
          "Heartbeat received",

        status:
          "ONLINE",

        device:
          evaluated,

        security: {
          status:
            evaluated.security_status,

          antivirus:
            evaluated.antivirus_status,

          firewall:
            evaluated.firewall_status,

          backup:
            evaluated.backup_status,
        },
      });
    } catch (error) {
      console.error(
        "Agent heartbeat error:",
        error
      );

      res.status(500).json({
        error:
          "Heartbeat processing failed",

        message:
          error.message,
      });
    }
  }
);

/* =========================================================
   APPLICATION INVENTORY
========================================================= */

app.post(
  "/api/agent/applications",
  async (req, res) => {
    try {
      const body = req.body || {};

      const deviceId =
        cleanString(
          body.deviceId ??
            body.device_id
        );

      const applications =
        Array.isArray(body.applications)
          ? body.applications
          : [];

      if (!deviceId) {
        return res.status(400).json({
          error: "deviceId is required",
        });
      }

      if (applications.length === 0) {
        return res.json({
          success: true,
          message: "No applications received",
          deviceId,
          count: 0,
        });
      }

      const deviceResult =
        await pool.query(
          `
            SELECT id
            FROM devices
            WHERE device_id = $1
            LIMIT 1;
          `,
          [deviceId]
        );

      if (deviceResult.rows.length === 0) {
        return res.status(404).json({
          error: "Device not found",
          deviceId,
        });
      }

      let saved = 0;

      for (const application of applications) {
        const name =
          cleanString(
            application.name ??
              application.application_name
          );

        if (!name) {
          continue;
        }

        const version =
          cleanString(
            application.version
          ) || null;

        const path =
          cleanString(
            application.path
          ) || null;

        const detectedAt =
          safeDate(
            application.detectedAt ??
              application.detected_at
          ) || new Date();

        await pool.query(
          `
            INSERT INTO device_applications (
              device_id,
              application_name,
              version,
              path,
              detected_at
            )
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (
              device_id,
              application_name,
              path
            )
            DO UPDATE SET
              version = EXCLUDED.version,
              detected_at = EXCLUDED.detected_at;
          `,
          [
            deviceId,
            name,
            version,
            path,
            detectedAt,
          ]
        );

        saved++;
      }

      console.log(
        `Application inventory saved: ${deviceId} (${saved} applications)`
      );

      res.json({
        success: true,
        message:
          "Application inventory saved",
        deviceId,
        count: saved,
      });
    } catch (error) {
      console.error(
        "Application inventory error:",
        error
      );

      res.status(500).json({
        error:
          "Failed to save application inventory",
        message: error.message,
      });
    }
  }
);

app.get(
  "/api/applications",
  auth,
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
            SELECT
              id,
              device_id,
              application_name,
              version,
              path,
              detected_at
            FROM device_applications
            ORDER BY application_name ASC;
          `
        );

      res.json(result.rows);
    } catch (error) {
      console.error(
        "Get applications error:",
        error
      );

      res.status(500).json({
        error:
          "Failed to load applications",
      });
    }
  }
);

app.get(
  "/api/devices/:deviceId/applications",
  auth,
  async (req, res) => {
    try {
      const deviceId =
        cleanString(
          req.params.deviceId
        );

      if (!deviceId) {
        return res.status(400).json({
          error:
            "Device ID is required",
        });
      }

      const result =
        await pool.query(
          `
            SELECT
              id,
              device_id,
              application_name,
              version,
              path,
              detected_at
            FROM device_applications
            WHERE device_id = $1
            ORDER BY application_name ASC;
          `,
          [deviceId]
        );

      res.json(result.rows);
    } catch (error) {
      console.error(
        "Get device applications error:",
        error
      );

      res.status(500).json({
        error:
          "Failed to load device applications",
      });
    }
  }
);

/* =========================================================
   APPLICATION SECURITY INTELLIGENCE API
========================================================= */

app.get(
  "/api/application-security",
  auth,
  async (req, res) => {
    try {
      const result = await pool.query(`
        SELECT
          id,
          application_name,
          version_pattern,
          security_status,
          severity,
          title,
          description,
          source,
          source_reference,
          published_at,
          updated_at,
          created_at
        FROM application_security_intelligence
        ORDER BY application_name ASC, version_pattern ASC;
      `);

      res.json(result.rows);
    } catch (error) {
      console.error(
        "Get application security intelligence error:",
        error
      );

      res.status(500).json({
        error:
          "Failed to load application security intelligence",
      });
    }
  }
);


app.post(
  "/api/application-security",
  auth,
  async (req, res) => {
    try {
      const body = req.body || {};

      const applicationName =
        cleanString(
          body.application_name
        );

      const versionPattern =
        cleanString(
          body.version_pattern
        ) || null;

      const securityStatus =
        cleanString(
          body.security_status
        ) || "UNKNOWN";

      const severity =
        cleanString(
          body.severity
        ) || "INFO";

      const title =
        cleanString(
          body.title
        ) || null;

      const description =
        cleanString(
          body.description
        ) || null;

      const source =
        cleanString(
          body.source
        ) || null;

      const sourceReference =
        cleanString(
          body.source_reference
        ) || null;

      const publishedAt =
        safeDate(
          body.published_at
        ) || null;

      if (!applicationName) {
        return res.status(400).json({
          error:
            "application_name is required",
        });
      }

      const allowedStatuses = [
        "UNKNOWN",
        "MONITORED",
        "REVIEW",
        "VULNERABLE",
        "SECURE",
      ];

      const allowedSeverities = [
        "INFO",
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
      ];

      if (
        !allowedStatuses.includes(
          securityStatus
        )
      ) {
        return res.status(400).json({
          error:
            "Invalid security_status",
        });
      }

      if (
        !allowedSeverities.includes(
          severity
        )
      ) {
        return res.status(400).json({
          error:
            "Invalid severity",
        });
      }

      const result = await pool.query(
        `
          INSERT INTO application_security_intelligence (
            application_name,
            version_pattern,
            security_status,
            severity,
            title,
            description,
            source,
            source_reference,
            published_at,
            updated_at
          )
          VALUES (
            $1,
            $2,
            $3,
            $4,
            $5,
            $6,
            $7,
            $8,
            $9,
            CURRENT_TIMESTAMP
          )
          RETURNING
            id,
            application_name,
            version_pattern,
            security_status,
            severity,
            title,
            description,
            source,
            source_reference,
            published_at,
            updated_at,
            created_at;
        `,
        [
          applicationName,
          versionPattern,
          securityStatus,
          severity,
          title,
          description,
          source,
          sourceReference,
          publishedAt,
        ]
      );

      res.status(201).json({
        success: true,
        message:
          "Application security intelligence created",
        data: result.rows[0],
      });
    } catch (error) {
      console.error(
        "Create application security intelligence error:",
        error
      );

      res.status(500).json({
        error:
          "Failed to create application security intelligence",
        message: error.message,
      });
    }
  }
);


app.delete(
  "/api/application-security/:id",
  auth,
  async (req, res) => {
    try {
      const id =
        Number(req.params.id);

      if (
        !Number.isInteger(id) ||
        id <= 0
      ) {
        return res.status(400).json({
          error:
            "Invalid intelligence ID",
        });
      }

      const result = await pool.query(
        `
          DELETE FROM
            application_security_intelligence
          WHERE id = $1
          RETURNING id;
        `,
        [id]
      );

      if (
        result.rows.length === 0
      ) {
        return res.status(404).json({
          error:
            "Application security intelligence not found",
        });
      }

      res.json({
        success: true,
        message:
          "Application security intelligence deleted",
        id,
      });
    } catch (error) {
      console.error(
        "Delete application security intelligence error:",
        error
      );

      res.status(500).json({
        error:
          "Failed to delete application security intelligence",
      });
    }
  }
);


app.get(
  "/api/application-security/check/:applicationName",
  auth,
  async (req, res) => {
    try {
      const applicationName =
        cleanString(
          req.params.applicationName
        );

      if (!applicationName) {
        return res.status(400).json({
          error:
            "Application name is required",
        });
      }

      const result = await pool.query(
        `
          SELECT
            id,
            application_name,
            version_pattern,
            security_status,
            severity,
            title,
            description,
            source,
            source_reference,
            published_at,
            updated_at
          FROM
            application_security_intelligence
          WHERE
            LOWER(application_name)
            =
            LOWER($1)
          ORDER BY
            updated_at DESC;
        `,
        [applicationName]
      );

      if (
        result.rows.length === 0
      ) {
        return res.json({
          application_name:
            applicationName,

          security_status:
            "UNKNOWN",

          severity:
            "INFO",

          message:
            "No verified security intelligence is available for this application.",
        });
      }

      res.json({
        application_name:
          applicationName,

        results:
          result.rows,
      });
    } catch (error) {
      console.error(
        "Check application security error:",
        error
      );

      res.status(500).json({
        error:
          "Failed to check application security",
      });
    }
  }
);


/* =========================================================
   SECURITY POLICY GET
========================================================= */

app.get(
  "/api/security-policy",
  auth,
  async (req, res) => {
    try {
      const policy =
        await getSecurityPolicy();

      res.json(policy);
    } catch (error) {
      console.error(
        "Get security policy error:",
        error
      );

      res.status(500).json({
        error:
          "Failed to load security policy",
      });
    }
  }
);

/* =========================================================
   SECURITY POLICY UPDATE
========================================================= */

app.put(
  "/api/security-policy",
  auth,
  requireManager,
  async (req, res) => {
    try {
      const body =
        req.body || {};

      const current =
        await getSecurityPolicy();

      const antivirusRequired =
        body.antivirusRequired !==
        undefined
          ? parseBoolean(
              body.antivirusRequired,
              current.antivirus_required
            )
          : body.antivirus_required !==
              undefined
          ? parseBoolean(
              body.antivirus_required,
              current.antivirus_required
            )
          : current.antivirus_required;

      const firewallRequired =
        body.firewallRequired !==
        undefined
          ? parseBoolean(
              body.firewallRequired,
              current.firewall_required
            )
          : body.firewall_required !==
              undefined
          ? parseBoolean(
              body.firewall_required,
              current.firewall_required
            )
          : current.firewall_required;

      const backupRequired =
        body.backupRequired !==
        undefined
          ? parseBoolean(
              body.backupRequired,
              current.backup_required
            )
          : body.backup_required !==
              undefined
          ? parseBoolean(
              body.backup_required,
              current.backup_required
            )
          : current.backup_required;

      const result =
        await pool.query(
          `
            UPDATE security_policy
            SET
              antivirus_required = $1,

              firewall_required = $2,

              backup_required = $3,

              updated_at = NOW()

            WHERE id = 1

            RETURNING *;
          `,
          [
            antivirusRequired,
            firewallRequired,
            backupRequired,
          ]
        );

      await writeAudit({
        userId:
          req.user.id,

        action:
          "SECURITY_POLICY_UPDATED",

        entityType:
          "security_policy",

        entityId:
          1,

        details:
          `Antivirus=${antivirusRequired}, Firewall=${firewallRequired}, Backup=${backupRequired}`,
      });

      await refreshDeviceSecurityStatuses();

      res.json(
        result.rows[0]
      );
    } catch (error) {
      console.error(
        "Update security policy error:",
        error
      );

      res.status(500).json({
        error:
          "Failed to update security policy",
      });
    }
  }
);

/* =========================================================
   SECURITY ALERT SUMMARY
========================================================= */

app.get(
  "/api/security-alerts/summary",
  auth,
  async (req, res) => {
    try {
      const result =
        await pool.query(`
          SELECT
            COUNT(*) FILTER (
              WHERE UPPER(status) = 'OPEN'
            ) AS open_count,

            COUNT(*) FILTER (
              WHERE UPPER(status) = 'ACKNOWLEDGED'
            ) AS acknowledged_count,

            COUNT(*) FILTER (
              WHERE UPPER(status) = 'RESOLVED'
            ) AS resolved_count,

            COUNT(*) FILTER (
              WHERE
                UPPER(status) IN (
                  'OPEN',
                  'ACKNOWLEDGED'
                )
                AND LOWER(severity) = 'critical'
            ) AS critical_count,

            COUNT(*) FILTER (
              WHERE
                UPPER(status) IN (
                  'OPEN',
                  'ACKNOWLEDGED'
                )
                AND LOWER(severity) = 'warning'
            ) AS warning_count,

            COUNT(*) AS total_count

          FROM security_alerts;
        `);

      res.json(
        result.rows[0] || {
          open_count: 0,
          acknowledged_count: 0,
          resolved_count: 0,
          critical_count: 0,
          warning_count: 0,
          total_count: 0,
        }
      );
    } catch (error) {
      console.error(
        "Alert summary error:",
        error
      );

      res.status(500).json({
        error:
          "Failed to load alert summary",
      });
    }
  }
);

/* =========================================================
   GET SECURITY ALERTS
========================================================= */

app.get(
  "/api/security-alerts",
  auth,
  async (req, res) => {
    try {
      const status =
        cleanString(
          req.query.status
        );

      const severity =
        cleanString(
          req.query.severity
        );

      const deviceId =
        req.query.deviceId
          ? Number(
              req.query.deviceId
            )
          : null;

      const conditions = [];

      const values = [];

      if (
        status &&
        [
          "OPEN",
          "ACKNOWLEDGED",
          "RESOLVED",
        ].includes(
          status.toUpperCase()
        )
      ) {
        values.push(
          status.toUpperCase()
        );

        conditions.push(
          `UPPER(sa.status) = $${values.length}`
        );
      }

      if (
        severity &&
        [
          "critical",
          "warning",
          "info",
        ].includes(
          severity.toLowerCase()
        )
      ) {
        values.push(
          severity.toLowerCase()
        );

        conditions.push(
          `LOWER(sa.severity) = $${values.length}`
        );
      }

      if (
        Number.isInteger(
          deviceId
        )
      ) {
        values.push(
          deviceId
        );

        conditions.push(
          `sa.device_id = $${values.length}`
        );
      }

      const whereClause =
        conditions.length
          ? `WHERE ${conditions.join(
              " AND "
            )}`
          : "";

      const result =
        await pool.query(
          `
            SELECT
              sa.*,

              d.name
                AS device_name,

              d.hostname
                AS device_hostname,

              d.device_id
                AS device_identifier,

              d.operating_system,

              d.employee,

              d.department,

              d.security_status
                AS device_security_status,

              d.connection_status
                AS device_connection_status,

              au.name
                AS acknowledged_by_name,

              au.email
                AS acknowledged_by_email,

              ru.name
                AS resolved_by_name,

              ru.email
                AS resolved_by_email

            FROM security_alerts sa

            LEFT JOIN devices d
              ON d.id =
                sa.device_id

            LEFT JOIN users au
              ON au.id =
                sa.acknowledged_by

            LEFT JOIN users ru
              ON ru.id =
                sa.resolved_by

            ${whereClause}

            ORDER BY
              CASE
                WHEN UPPER(sa.status) = 'OPEN'
                  THEN 1

                WHEN UPPER(sa.status) = 'ACKNOWLEDGED'
                  THEN 2

                ELSE 3
              END,

              CASE
                WHEN LOWER(sa.severity) = 'critical'
                  THEN 1

                WHEN LOWER(sa.severity) = 'warning'
                  THEN 2

                ELSE 3
              END,

              COALESCE(
                sa.last_detected_at,
                sa.created_at
              ) DESC;
          `,
          values
        );

      res.json(
        result.rows
      );
    } catch (error) {
      console.error(
        "Get security alerts error:",
        error
      );

      res.status(500).json({
        error:
          "Failed to load security alerts",
      });
    }
  }
);

/* =========================================================
   GET SINGLE ALERT
========================================================= */

app.get(
  "/api/security-alerts/:id",
  auth,
  async (req, res) => {
    try {
      const alertId =
        Number(
          req.params.id
        );

      if (
        !Number.isInteger(
          alertId
        )
      ) {
        return res.status(400).json({
          error:
            "Invalid alert ID",
        });
      }

      const result =
        await pool.query(
          `
            SELECT
              sa.*,

              d.name
                AS device_name,

              d.hostname
                AS device_hostname,

              d.device_id
                AS device_identifier,

              d.operating_system,

              d.employee,

              d.department,

              d.ip_address,

              d.cpu,

              d.ram_gb,

              d.agent_version,

              d.security_status
                AS device_security_status,

              d.connection_status
                AS device_connection_status,

              d.last_seen,

              au.name
                AS acknowledged_by_name,

              au.email
                AS acknowledged_by_email,

              ru.name
                AS resolved_by_name,

              ru.email
                AS resolved_by_email

            FROM security_alerts sa

            LEFT JOIN devices d
              ON d.id =
                sa.device_id

            LEFT JOIN users au
              ON au.id =
                sa.acknowledged_by

            LEFT JOIN users ru
              ON ru.id =
                sa.resolved_by

            WHERE sa.id = $1

            LIMIT 1;
          `,
          [alertId]
        );

      if (
        result.rows.length ===
        0
      ) {
        return res.status(404).json({
          error:
            "Security alert not found",
        });
      }

      res.json(
        result.rows[0]
      );
    } catch (error) {
      console.error(
        "Get single alert error:",
        error
      );

      res.status(500).json({
        error:
          "Failed to load security alert",
      });
    }
  }
);

/* =========================================================
   ACKNOWLEDGE ALERT
========================================================= */

app.put(
  "/api/security-alerts/:id/acknowledge",
  auth,
  requireManager,
  async (req, res) => {
    try {
      const alertId =
        Number(
          req.params.id
        );

      if (
        !Number.isInteger(
          alertId
        )
      ) {
        return res.status(400).json({
          error:
            "Invalid alert ID",
        });
      }

      const alertResult =
        await pool.query(
          `
            SELECT *
            FROM security_alerts
            WHERE id = $1
            LIMIT 1;
          `,
          [alertId]
        );

      if (
        alertResult.rows.length ===
        0
      ) {
        return res.status(404).json({
          error:
            "Security alert not found",
        });
      }

      const alert =
        alertResult.rows[0];

      const status =
        normalizeAlertStatus(
          alert.status
        );

      if (
        status ===
        "RESOLVED"
      ) {
        return res.status(409).json({
          error:
            "Resolved alerts cannot be acknowledged",
        });
      }

      if (
        status ===
        "ACKNOWLEDGED"
      ) {
        return res.json({
          message:
            "Alert is already acknowledged",

          alert,
        });
      }

      const acknowledged =
        await acknowledgeAlert(
          alertId,
          req.user.id
        );

      if (!acknowledged) {
        return res.status(409).json({
          error:
            "Alert could not be acknowledged",
        });
      }

      await writeAudit({
        userId:
          req.user.id,

        action:
          "SECURITY_ALERT_ACKNOWLEDGED",

        entityType:
          "security_alert",

        entityId:
          alertId,

        details:
          `Alert ${alertId} acknowledged`,
      });

      res.json({
        message:
          "Security alert acknowledged",

        alert:
          acknowledged,
      });
    } catch (error) {
      console.error(
        "Acknowledge alert error:",
        error
      );

      res.status(500).json({
        error:
          "Failed to acknowledge security alert",
      });
    }
  }
);

/* =========================================================
   RESOLVE ALERT
========================================================= */

app.put(
  "/api/security-alerts/:id/resolve",
  auth,
  requireManager,
  async (req, res) => {
    try {
      const alertId =
        Number(
          req.params.id
        );

      if (
        !Number.isInteger(
          alertId
        )
      ) {
        return res.status(400).json({
          error:
            "Invalid alert ID",
        });
      }

      const existingResult =
        await pool.query(
          `
            SELECT *
            FROM security_alerts
            WHERE id = $1
            LIMIT 1;
          `,
          [alertId]
        );

      if (
        existingResult.rows.length ===
        0
      ) {
        return res.status(404).json({
          error:
            "Security alert not found",
        });
      }

      const alert =
        existingResult.rows[0];

      if (
        normalizeAlertStatus(
          alert.status
        ) ===
        "RESOLVED"
      ) {
        return res.json({
          message:
            "Security alert is already resolved",

          alert,
        });
      }

      const reason =
        cleanString(
          req.body?.reason
        ) ||
        "Manually resolved by authorized user";

      const result =
        await pool.query(
          `
            UPDATE security_alerts
            SET
              status = 'RESOLVED',

              resolved_at = NOW(),

              resolved_by = $2,

              resolution_reason = $3

            WHERE
              id = $1

              AND UPPER(status) IN (
                'OPEN',
                'ACKNOWLEDGED'
              )

            RETURNING *;
          `,
          [
            alertId,
            req.user.id,
            sanitizeLogText(
              reason
            ),
          ]
        );

      if (
        result.rows.length ===
        0
      ) {
        return res.status(409).json({
          error:
            "Alert could not be resolved",
        });
      }

      await writeAudit({
        userId:
          req.user.id,

        action:
          "SECURITY_ALERT_RESOLVED",

        entityType:
          "security_alert",

        entityId:
          alertId,

        details:
          `Alert resolved manually: ${reason}`,
      });

      res.json({
        message:
          "Security alert resolved",

        alert:
          result.rows[0],
      });
    } catch (error) {
      console.error(
        "Resolve alert error:",
        error
      );

      res.status(500).json({
        error:
          "Failed to resolve security alert",
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
          ORDER BY id DESC;
        `);

      res.json(
        result.rows
      );
    } catch (error) {
      console.error(
        "Get users error:",
        error
      );

      res.status(500).json({
        error:
          "Failed to load users",
      });
    }
  }
);

/* =========================================================
   USERS - CREATE
========================================================= */

app.post(
  "/api/users",
  auth,
  requireAdmin,
  async (req, res) => {
    try {
      const name =
        cleanString(
          req.body?.name
        );

      const email =
        cleanString(
          req.body?.email
        );

      const role =
        cleanString(
          req.body?.role
        ) ||
        "IT Staff";

      const password =
        cleanString(
          req.body?.password
        );

      const allowedRoles = [
        "Administrator",
        "IT Manager",
        "IT Staff",
      ];

      if (
        !name ||
        !email ||
        !password
      ) {
        return res.status(400).json({
          error:
            "Name, email and password are required",
        });
      }

      if (
        !allowedRoles.includes(
          role
        )
      ) {
        return res.status(400).json({
          error:
            "Invalid user role",
        });
      }

      if (
        password.length < 8
      ) {
        return res.status(400).json({
          error:
            "Password must contain at least 8 characters",
        });
      }

      const existing =
        await pool.query(
          `
            SELECT id
            FROM users
            WHERE LOWER(email) = LOWER($1)
            LIMIT 1;
          `,
          [email]
        );

      if (
        existing.rows.length >
        0
      ) {
        return res.status(409).json({
          error:
            "A user with this email already exists",
        });
      }

      const passwordHash =
        await bcrypt.hash(
          password,
          12
        );

      const result =
        await pool.query(
          `
            INSERT INTO users (
              name,
              email,
              role,
              password_hash
            )
            VALUES (
              $1,
              $2,
              $3,
              $4
            )
            RETURNING
              id,
              name,
              email,
              role,
              created_at;
          `,
          [
            name,
            email,
            role,
            passwordHash,
          ]
        );

      const user =
        result.rows[0];

      await writeAudit({
        userId:
          req.user.id,

        action:
          "USER_CREATED",

        entityType:
          "user",

        entityId:
          user.id,

        details:
          `Created ${role} account ${email}`,
      });

      res.status(201).json(
        user
      );
    } catch (error) {
      console.error(
        "Create user error:",
        error
      );

      res.status(500).json({
        error:
          "Failed to create user",
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
      const userId =
        Number(
          req.params.id
        );

      if (
        !Number.isInteger(
          userId
        )
      ) {
        return res.status(400).json({
          error:
            "Invalid user ID",
        });
      }

      if (
        userId ===
        req.user.id
      ) {
        return res.status(400).json({
          error:
            "You cannot delete your own account",
        });
      }

      const existing =
        await pool.query(
          `
            SELECT
              id,
              name,
              email,
              role
            FROM users
            WHERE id = $1
            LIMIT 1;
          `,
          [userId]
        );

      if (
        existing.rows.length ===
        0
      ) {
        return res.status(404).json({
          error:
            "User not found",
        });
      }

      await pool.query(
        `
          DELETE FROM users
          WHERE id = $1;
        `,
        [userId]
      );

      await writeAudit({
        userId:
          req.user.id,

        action:
          "USER_DELETED",

        entityType:
          "user",

        entityId:
          userId,

        details:
          `Deleted user ${existing.rows[0].email}`,
      });

      res.json({
        message:
          "User deleted successfully",
      });
    } catch (error) {
      console.error(
        "Delete user error:",
        error
      );

      res.status(500).json({
        error:
          "Failed to delete user",
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
  async (req, res) => {
    try {
      const result =
        await pool.query(`
          SELECT
            al.id,

            al.user_id,

            al.action,

            al.entity_type,

            al.entity_id,

            al.details,

            al.created_at,

            COALESCE(
              u.name,
              'System'
            ) AS user_name,

            COALESCE(
              u.email,
              ''
            ) AS user_email,

            COALESCE(
              u.role,
              ''
            ) AS user_role

          FROM audit_logs al

          LEFT JOIN users u
            ON u.id =
              al.user_id

          ORDER BY
            al.created_at DESC

          LIMIT 200;
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
          "Failed to load audit logs",
      });
    }
  }
);

/* =========================================================
   AUTOMATIC OFFLINE MONITOR
========================================================= */

async function detectOfflineDevices() {
  try {
    const result =
      await pool.query(`
        UPDATE devices

        SET
          online = FALSE,

          connection_status =
            'OFFLINE',

          security_status =
            'AT RISK',

          updated_at =
            NOW()

        WHERE
          online = TRUE

          AND (
            last_seen IS NULL

            OR last_seen <
              NOW() -
              INTERVAL '90 seconds'
          )

        RETURNING
          id,
          name,
          last_seen;
      `);

    for (
      const device of result.rows
    ) {
      console.log(
        `Device automatically marked OFFLINE: ${device.name}`
      );

      await evaluateDeviceSecurity(
        device.id
      );
    }
  } catch (error) {
    console.error(
      "Offline monitor error:",
      error.message
    );
  }
}
/* =========================================================
   SECURITY REPORTS & ANALYTICS
========================================================= */

app.get(
  "/api/security-reports",
  auth,
  async (req, res) => {
    try {
      /* =====================================================
         REFRESH CURRENT DEVICE SECURITY
      ===================================================== */

      await refreshDeviceSecurityStatuses();

      /* =====================================================
         DEVICE SUMMARY
      ===================================================== */

      const deviceSummaryResult =
        await pool.query(`
          SELECT
            COUNT(*)::INTEGER AS total_devices,

            COUNT(*) FILTER (
              WHERE UPPER(
                COALESCE(
                  security_status,
                  'UNKNOWN'
                )
              ) = 'SECURE'
            )::INTEGER AS secure_devices,

            COUNT(*) FILTER (
              WHERE UPPER(
                COALESCE(
                  security_status,
                  'UNKNOWN'
                )
              ) = 'AT RISK'
            )::INTEGER AS at_risk_devices,

            COUNT(*) FILTER (
              WHERE UPPER(
                COALESCE(
                  security_status,
                  'UNKNOWN'
                )
              ) = 'UNKNOWN'
            )::INTEGER AS unknown_devices,

            COUNT(*) FILTER (
              WHERE
                online = TRUE
                OR UPPER(
                  COALESCE(
                    connection_status,
                    ''
                  )
                ) = 'ONLINE'
            )::INTEGER AS online_devices,

            COUNT(*) FILTER (
              WHERE NOT (
                online = TRUE
                OR UPPER(
                  COALESCE(
                    connection_status,
                    ''
                  )
                ) = 'ONLINE'
              )
            )::INTEGER AS offline_devices

          FROM devices;
        `);

      /* =====================================================
         SECURITY CONTROL SUMMARY
      ===================================================== */

      const controlSummaryResult =
        await pool.query(`
          SELECT

            COUNT(*) FILTER (
              WHERE UPPER(
                COALESCE(
                  antivirus_status,
                  'UNKNOWN'
                )
              ) = 'ENABLED'
            )::INTEGER AS antivirus_enabled,

            COUNT(*) FILTER (
              WHERE UPPER(
                COALESCE(
                  antivirus_status,
                  'UNKNOWN'
                )
              ) = 'DISABLED'
            )::INTEGER AS antivirus_disabled,

            COUNT(*) FILTER (
              WHERE UPPER(
                COALESCE(
                  antivirus_status,
                  'UNKNOWN'
                )
              ) = 'UNKNOWN'
            )::INTEGER AS antivirus_unknown,


            COUNT(*) FILTER (
              WHERE UPPER(
                COALESCE(
                  firewall_status,
                  'UNKNOWN'
                )
              ) = 'ENABLED'
            )::INTEGER AS firewall_enabled,

            COUNT(*) FILTER (
              WHERE UPPER(
                COALESCE(
                  firewall_status,
                  'UNKNOWN'
                )
              ) = 'DISABLED'
            )::INTEGER AS firewall_disabled,

            COUNT(*) FILTER (
              WHERE UPPER(
                COALESCE(
                  firewall_status,
                  'UNKNOWN'
                )
              ) = 'UNKNOWN'
            )::INTEGER AS firewall_unknown,


            COUNT(*) FILTER (
              WHERE UPPER(
                COALESCE(
                  backup_status,
                  'UNKNOWN'
                )
              ) = 'ENABLED'
            )::INTEGER AS backup_enabled,

            COUNT(*) FILTER (
              WHERE UPPER(
                COALESCE(
                  backup_status,
                  'UNKNOWN'
                )
              ) = 'DISABLED'
            )::INTEGER AS backup_disabled,

            COUNT(*) FILTER (
              WHERE UPPER(
                COALESCE(
                  backup_status,
                  'UNKNOWN'
                )
              ) = 'UNKNOWN'
            )::INTEGER AS backup_unknown

          FROM devices;
        `);

      /* =====================================================
         ALERT SUMMARY
      ===================================================== */

      const alertSummaryResult =
        await pool.query(`
          SELECT

            COUNT(*)::INTEGER
              AS total_alerts,

            COUNT(*) FILTER (
              WHERE UPPER(
                COALESCE(
                  status,
                  ''
                )
              ) = 'OPEN'
            )::INTEGER
              AS open_alerts,

            COUNT(*) FILTER (
              WHERE UPPER(
                COALESCE(
                  status,
                  ''
                )
              ) = 'ACKNOWLEDGED'
            )::INTEGER
              AS acknowledged_alerts,

            COUNT(*) FILTER (
              WHERE UPPER(
                COALESCE(
                  status,
                  ''
                )
              ) = 'RESOLVED'
            )::INTEGER
              AS resolved_alerts,

            COUNT(*) FILTER (
              WHERE
                UPPER(
                  COALESCE(
                    status,
                    ''
                  )
                ) IN (
                  'OPEN',
                  'ACKNOWLEDGED'
                )
                AND LOWER(
                  COALESCE(
                    severity,
                    ''
                  )
                ) = 'critical'
            )::INTEGER
              AS active_critical_alerts,

            COUNT(*) FILTER (
              WHERE
                UPPER(
                  COALESCE(
                    status,
                    ''
                  )
                ) IN (
                  'OPEN',
                  'ACKNOWLEDGED'
                )
                AND LOWER(
                  COALESCE(
                    severity,
                    ''
                  )
                ) = 'warning'
            )::INTEGER
              AS active_warning_alerts,

            COUNT(*) FILTER (
              WHERE
                UPPER(
                  COALESCE(
                    status,
                    ''
                  )
                ) IN (
                  'OPEN',
                  'ACKNOWLEDGED'
                )
                AND LOWER(
                  COALESCE(
                    severity,
                    ''
                  )
                ) = 'info'
            )::INTEGER
              AS active_info_alerts

          FROM security_alerts;
        `);

      /* =====================================================
         DEPARTMENT SECURITY REPORT
      ===================================================== */

      const departmentResult =
        await pool.query(`
          SELECT

            COALESCE(
              NULLIF(
                TRIM(department),
                ''
              ),
              'Unassigned'
            ) AS department,

            COUNT(*)::INTEGER
              AS total_devices,

            COUNT(*) FILTER (
              WHERE UPPER(
                COALESCE(
                  security_status,
                  'UNKNOWN'
                )
              ) = 'SECURE'
            )::INTEGER
              AS secure_devices,

            COUNT(*) FILTER (
              WHERE UPPER(
                COALESCE(
                  security_status,
                  'UNKNOWN'
                )
              ) = 'AT RISK'
            )::INTEGER
              AS at_risk_devices,

            COUNT(*) FILTER (
              WHERE UPPER(
                COALESCE(
                  security_status,
                  'UNKNOWN'
                )
              ) = 'UNKNOWN'
            )::INTEGER
              AS unknown_devices,

            COUNT(*) FILTER (
              WHERE
                online = TRUE
                OR UPPER(
                  COALESCE(
                    connection_status,
                    ''
                  )
                ) = 'ONLINE'
            )::INTEGER
              AS online_devices,

            COUNT(*) FILTER (
              WHERE NOT (
                online = TRUE
                OR UPPER(
                  COALESCE(
                    connection_status,
                    ''
                  )
                ) = 'ONLINE'
              )
            )::INTEGER
              AS offline_devices

          FROM devices

          GROUP BY
            COALESCE(
              NULLIF(
                TRIM(department),
                ''
              ),
              'Unassigned'
            )

          ORDER BY
            department ASC;
        `);

      /* =====================================================
         SECURITY STATUS BREAKDOWN
      ===================================================== */

      const securityStatusResult =
        await pool.query(`
          SELECT

            UPPER(
              COALESCE(
                security_status,
                'UNKNOWN'
              )
            ) AS status,

            COUNT(*)::INTEGER
              AS device_count

          FROM devices

          GROUP BY
            UPPER(
              COALESCE(
                security_status,
                'UNKNOWN'
              )
            )

          ORDER BY
            device_count DESC;
        `);

      /* =====================================================
         OPERATING SYSTEM BREAKDOWN
      ===================================================== */

      const operatingSystemResult =
        await pool.query(`
          SELECT

            COALESCE(
              NULLIF(
                TRIM(operating_system),
                ''
              ),
              'Unknown'
            ) AS operating_system,

            COUNT(*)::INTEGER
              AS device_count

          FROM devices

          GROUP BY
            COALESCE(
              NULLIF(
                TRIM(operating_system),
                ''
              ),
              'Unknown'
            )

          ORDER BY
            device_count DESC;
        `);

      /* =====================================================
         ALERT TYPE BREAKDOWN
      ===================================================== */

      const alertTypeResult =
        await pool.query(`
          SELECT

            alert_type,

            COUNT(*)::INTEGER
              AS total_alerts,

            COUNT(*) FILTER (
              WHERE UPPER(
                COALESCE(
                  status,
                  ''
                )
              ) IN (
                'OPEN',
                'ACKNOWLEDGED'
              )
            )::INTEGER
              AS active_alerts,

            COUNT(*) FILTER (
              WHERE UPPER(
                COALESCE(
                  status,
                  ''
                )
              ) = 'RESOLVED'
            )::INTEGER
              AS resolved_alerts

          FROM security_alerts

          GROUP BY
            alert_type

          ORDER BY
            total_alerts DESC;
        `);

      /* =====================================================
         RECENT SECURITY EVENTS
      ===================================================== */

      const recentActivityResult =
        await pool.query(`
          SELECT

            al.id,

            al.user_id,

            al.action,

            al.entity_type,

            al.entity_id,

            al.details,

            al.created_at,

            COALESCE(
              u.name,
              'System'
            ) AS user_name,

            COALESCE(
              u.email,
              ''
            ) AS user_email,

            COALESCE(
              u.role,
              ''
            ) AS user_role

          FROM audit_logs al

          LEFT JOIN users u
            ON u.id = al.user_id

          ORDER BY
            al.created_at DESC

          LIMIT 20;
        `);

      /* =====================================================
         MOST RECENT SECURITY ALERTS
      ===================================================== */

      const recentAlertsResult =
        await pool.query(`
          SELECT

            sa.id,

            sa.device_id,

            sa.alert_type,

            sa.severity,

            sa.message,

            sa.status,

            sa.occurrence_count,

            sa.first_detected_at,

            sa.last_detected_at,

            sa.acknowledged_at,

            sa.resolved_at,

            sa.created_at,

            d.name AS device_name,

            d.hostname,

            d.department,

            d.employee

          FROM security_alerts sa

          LEFT JOIN devices d
            ON d.id = sa.device_id

          ORDER BY
            COALESCE(
              sa.last_detected_at,
              sa.created_at
            ) DESC

          LIMIT 20;
        `);

      /* =====================================================
         RESPONSE
      ===================================================== */

      res.json({
        success: true,

        generatedAt:
          new Date().toISOString(),

        devices:
          deviceSummaryResult.rows[0] || {
            total_devices: 0,
            secure_devices: 0,
            at_risk_devices: 0,
            unknown_devices: 0,
            online_devices: 0,
            offline_devices: 0,
          },

        controls:
          controlSummaryResult.rows[0] || {
            antivirus_enabled: 0,
            antivirus_disabled: 0,
            antivirus_unknown: 0,
            firewall_enabled: 0,
            firewall_disabled: 0,
            firewall_unknown: 0,
            backup_enabled: 0,
            backup_disabled: 0,
            backup_unknown: 0,
          },

        alerts:
          alertSummaryResult.rows[0] || {
            total_alerts: 0,
            open_alerts: 0,
            acknowledged_alerts: 0,
            resolved_alerts: 0,
            active_critical_alerts: 0,
            active_warning_alerts: 0,
            active_info_alerts: 0,
          },

        departments:
          departmentResult.rows,

        securityStatus:
          securityStatusResult.rows,

        operatingSystems:
          operatingSystemResult.rows,

        alertTypes:
          alertTypeResult.rows,

        recentActivity:
          recentActivityResult.rows,

        recentAlerts:
          recentAlertsResult.rows,
      });

    } catch (error) {
      console.error(
        "Security reports error:",
        error
      );

      res.status(500).json({
        success: false,

        error:
          "Failed to generate security report",

        message:
          error.message,
      });
    }
  }
);

/* =========================================================
   404
========================================================= */

app.use(
  (req, res) => {
    res.status(404).json({
      error:
        "Endpoint not found",
    });
  }
);

/* =========================================================
   GLOBAL ERROR HANDLER
========================================================= */

app.use(
  (
    error,
    req,
    res,
    next
  ) => {
    console.error(
      "Unhandled server error:",
      error
    );

    if (
      res.headersSent
    ) {
      return next(error);
    }

    res.status(500).json({
      error:
        "Internal server error",
    });
  }
);

/* =========================================================
   GRACEFUL SHUTDOWN
========================================================= */

async function shutdown(signal) {
  console.log(
    `${signal} received. Shutting down Sentinel API...`
  );

  try {
    await pool.end();

    console.log(
      "Database connection pool closed."
    );

    process.exit(0);
  } catch (error) {
    console.error(
      "Shutdown error:",
      error
    );

    process.exit(1);
  }
}

process.on(
  "SIGINT",
  () =>
    shutdown("SIGINT")
);

process.on(
  "SIGTERM",
  () =>
    shutdown("SIGTERM")
);

/* =========================================================
   START SERVER
========================================================= */

async function startServer() {
  try {
    await ensureDatabase();

    console.log(
      "Database initialized successfully"
    );

    await refreshDeviceSecurityStatuses();

    // Serve React frontend
app.use(express.static(path.join(__dirname, "..", "dist")));

app.get(/.*/, (req, res) => {
  res.sendFile(path.join(__dirname, "..", "dist", "index.html"));
});

    app.listen(
      PORT,
      () => {
        console.log(
          `Sentinel API running on http://localhost:${PORT}`
        );
      }
    );

    /* =====================================================
       OFFLINE CHECK EVERY 30 SECONDS
    ===================================================== */

    setInterval(
      detectOfflineDevices,
      30 * 1000
    );

    /* =====================================================
       SECURITY REFRESH EVERY 60 SECONDS
    ===================================================== */

    setInterval(
      async () => {
        try {
          await refreshDeviceSecurityStatuses();
        } catch (error) {
          console.error(
            "Periodic security refresh error:",
            error.message
          );
        }
      },
      60 * 1000
    );
  } catch (error) {
    console.error(
      "Failed to start Sentinel API:",
      error
    );

    process.exit(1);
  }
}

/* =========================================================
   START
========================================================= */

startServer();