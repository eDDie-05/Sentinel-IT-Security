const { Pool } = require("pg");

const pool = new Pool({
  user: process.env.PGUSER || "georgemollel",
  host: process.env.PGHOST || "localhost",
  database: process.env.PGDATABASE || "security_system",
  password: process.env.PGPASSWORD || "",
  port: Number(process.env.PGPORT || 5432),
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000
});

pool.on("error", err => console.error("Unexpected PostgreSQL pool error:", err.message));

module.exports = pool;
