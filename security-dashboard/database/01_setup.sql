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
