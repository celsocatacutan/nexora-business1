require("dotenv").config();

const { Pool } = require("pg");
const bcrypt = require("bcryptjs");

async function main() {
  const {
    DATABASE_URL,
    ADMIN_NAME,
    ADMIN_EMAIL,
    ADMIN_PASSWORD
  } = process.env;

  if (!DATABASE_URL || !ADMIN_NAME ||
      !ADMIN_EMAIL || !ADMIN_PASSWORD) {
    throw new Error("Missing administrator settings.");
  }

  if (ADMIN_PASSWORD.length < 16 ||
      Buffer.byteLength(ADMIN_PASSWORD, "utf8") > 72) {
    throw new Error("Admin password must be 16–72 bytes.");
  }

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(ADMIN_EMAIL)) {
    throw new Error("Invalid administrator email.");
  }

  const pool = new Pool({
    connectionString: DATABASE_URL,
    max: 2,
    connectionTimeoutMillis: 10000
  });

  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id BIGSERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        email VARCHAR(254) NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role VARCHAR(10) NOT NULL DEFAULT 'user'
          CHECK (role IN ('user', 'admin')),
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    const hash = await bcrypt.hash(ADMIN_PASSWORD, 12);

    const result = await pool.query(
      `INSERT INTO users
       (name, email, password_hash, role)
       VALUES ($1, $2, $3, 'admin')
       ON CONFLICT (email) DO NOTHING
       RETURNING id`,
      [
        ADMIN_NAME.trim(),
        ADMIN_EMAIL.trim().toLowerCase(),
        hash
      ]
    );

    if (!result.rowCount) {
      throw new Error(
        "This email already exists. No account was changed."
      );
    }

    console.log("Administrator created.");
    console.log("Account ID:", result.rows[0].id);

  } finally {
    await pool.end();
  }
}

main().catch(error => {
  console.error(error.message);
  process.exitCode = 1;
});
