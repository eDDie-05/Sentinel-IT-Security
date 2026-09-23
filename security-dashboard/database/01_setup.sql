-- Sentinel IT Security System
-- Run this once against PostgreSQL database: security_system
CREATE TABLE IF NOT EXISTS users(
  id SERIAL PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  email VARCHAR(150) NOT NULL UNIQUE,
  role VARCHAR(50) NOT NULL CHECK(role IN ('Administrator','IT Manager','IT Staff')),
  password_hash VARCHAR(255)
);

CREATE TABLE IF NOT EXISTS devices(
  id SERIAL PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  operating_system VARCHAR(100) NOT NULL,
  employee VARCHAR(100) NOT NULL,
  department VARCHAR(100) NOT NULL,
  ip_address VARCHAR(50) NOT NULL,
  antivirus BOOLEAN NOT NULL DEFAULT TRUE,
  firewall BOOLEAN NOT NULL DEFAULT TRUE,
  backup BOOLEAN NOT NULL DEFAULT TRUE,
  online BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS security_policy(
  id SERIAL PRIMARY KEY,
  antivirus_required BOOLEAN NOT NULL DEFAULT TRUE,
  firewall_required BOOLEAN NOT NULL DEFAULT TRUE,
  backup_required BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS audit_logs(
  id SERIAL PRIMARY KEY,
  user_id INTEGER,
  user_name VARCHAR(100),
  action VARCHAR(100) NOT NULL,
  details TEXT,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO security_policy(antivirus_required,firewall_required,backup_required)
SELECT TRUE,TRUE,TRUE
WHERE NOT EXISTS (SELECT 1 FROM security_policy);

-- The application automatically creates the default administrator if absent:
-- Email: admin@company.com
-- Password: Admin123456
-- =========================================================
-- APPLICATION INVENTORY
-- =========================================================

CREATE TABLE IF NOT EXISTS device_applications (
    id SERIAL PRIMARY KEY,
    device_id VARCHAR(255) NOT NULL,
    application_name VARCHAR(255) NOT NULL,
    version VARCHAR(100),
    path TEXT,
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_device_applications_device_id
ON device_applications(device_id);

CREATE UNIQUE INDEX IF NOT EXISTS idx_device_applications_unique
ON device_applications(device_id, application_name, path);

/* =========================================================
   APPLICATION SECURITY INTELLIGENCE
========================================================= */

CREATE TABLE IF NOT EXISTS application_security_intelligence (
    id SERIAL PRIMARY KEY,

    application_name VARCHAR(255) NOT NULL,

    version_pattern VARCHAR(255),

    security_status VARCHAR(50) NOT NULL DEFAULT 'UNKNOWN',

    severity VARCHAR(50) NOT NULL DEFAULT 'INFO',

    title VARCHAR(500),

    description TEXT,

    source VARCHAR(500),

    source_reference VARCHAR(500),

    published_at TIMESTAMP,

    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT application_security_status_check
        CHECK (
            security_status IN (
                'UNKNOWN',
                'MONITORED',
                'REVIEW',
                'VULNERABLE',
                'SECURE'
            )
        ),

    CONSTRAINT application_security_severity_check
        CHECK (
            severity IN (
                'INFO',
                'LOW',
                'MEDIUM',
                'HIGH',
                'CRITICAL'
            )
        )
);

CREATE INDEX IF NOT EXISTS idx_app_security_name
ON application_security_intelligence(application_name);

CREATE INDEX IF NOT EXISTS idx_app_security_status
ON application_security_intelligence(security_status);

CREATE INDEX IF NOT EXISTS idx_app_security_severity
ON application_security_intelligence(severity);

CREATE INDEX IF NOT EXISTS idx_app_security_updated
ON application_security_intelligence(updated_at);
