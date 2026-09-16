# SENTINEL — Company IT Security Management System

A professional, database-backed endpoint security management dashboard for an organization.

## What the system does

### Security operations
- Central dashboard showing fleet size, secure devices, at-risk devices and online devices.
- Compliance is calculated from the **actual PostgreSQL device state**, not fake/demo values.
- Security findings identify exactly which required control is missing.
- Antivirus, firewall, backup and connectivity are tracked per endpoint.
- Security policy controls which protections are mandatory.

### Device management
- Register endpoints.
- Edit endpoint identity and security state.
- Remove endpoints.
- Search by device, employee, department, OS or IP.
- Filter by all/online/offline/secure/at-risk and department.
- View OS, IP, employee, department and protection controls.

### Access control
- JWT authentication.
- Administrator: full management + users + audit log.
- IT Manager: device and policy management.
- IT Staff: endpoint visibility without management actions.

### Governance
- Audit trail for login, device changes, user changes and policy changes.
- Cannot delete the currently signed-in administrator account.

## Technology

- React + Vite
- Express
- PostgreSQL
- JWT
- bcrypt
- REST API

## Requirements

- Node.js 20+ recommended
- PostgreSQL 14+
- VS Code or another editor

## 1. Create the database

Create a PostgreSQL database named:

`security_system`

Then either run `database/01_setup.sql` or simply start the API; the API also creates missing tables automatically.

## 2. PostgreSQL configuration

The default connection expects:

- user: `georgemollel`
- host: `localhost`
- database: `security_system`
- password: empty
- port: `5432`

You can override these with environment variables:

`PGUSER`, `PGHOST`, `PGDATABASE`, `PGPASSWORD`, `PGPORT`

## 3. Install dependencies

From the project folder:

```bash
npm install
cd server
npm install
cd ..
```

## 4. Start the backend

```bash
npm run server
```

API: http://localhost:5000

Health check: http://localhost:5000/api/health

## 5. Start the frontend

In another terminal:

```bash
npm run dev
```

Open:

http://localhost:5173

## Default administrator

Email: `admin@company.com`

Password: `Admin123456`

Change the default password after first deployment.

## Important production notes

This is a functional management application, not an endpoint antivirus engine. It records endpoint security state and enforces organizational policy at the management layer. In a real company deployment, connect it to an endpoint-management/EDR platform, backup platform, identity provider and monitoring system rather than attempting to implement those security engines inside this web application.

Before production:
- Set a strong random `JWT_SECRET`.
- Use HTTPS.
- Use a PostgreSQL password and least-privilege database account.
- Put the API behind a reverse proxy/firewall.
- Add real endpoint agents or integrations for trustworthy device telemetry.
- Back up the PostgreSQL database.
