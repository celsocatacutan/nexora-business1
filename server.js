require("dotenv").config();

const express = require("express");
const session = require("express-session");
const PgSession = require("connect-pg-simple")(session);
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { doubleCsrf } = require("csrf-csrf");
const path = require("path");

const app = express();
const production = process.env.NODE_ENV === "production";

for (const key of [
  "DATABASE_URL",
  "SESSION_SECRET",
  "CSRF_SECRET"
]) {
  if (!process.env[key] ||
      process.env[key].startsWith("replace-")) {
    throw new Error("Missing environment variable: " + key);
  }
}

if (process.env.TRUST_PROXY === "1") {
  app.set("trust proxy", 1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

pool.on("error", error => {
  console.error("Unexpected database error:", error.message);
});

app.disable("x-powered-by");

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      frameAncestors: ["'none'"]
    }
  },
  strictTransportSecurity: production
    ? { maxAge: 31536000, includeSubDomains: true }
    : false
}));

app.use(express.json({ limit: "10kb" }));
app.use(express.urlencoded({
  extended: false,
  limit: "10kb"
}));

app.use(session({
  name: production ? "__Host-nexora.sid" : "nexora.sid",
  store: new PgSession({
    pool,
    tableName: "session",
    createTableIfMissing: true
  }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: production,
    sameSite: "lax",
    path: "/",
    maxAge: 8 * 60 * 60 * 1000
  }
}));

const {
  generateToken,
  doubleCsrfProtection
} = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET,
  getSessionIdentifier: req => req.sessionID,
  cookieName: production
    ? "__Host-nexora.csrf"
    : "nexora.csrf",
  cookieOptions: {
    httpOnly: true,
    secure: production,
    sameSite: "strict",
    path: "/"
  },
  size: 64
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-8",
  legacyHeaders: false
});

const contactLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 5,
  standardHeaders: "draft-8",
  legacyHeaders: false
});

const api = express.Router();

function clean(value, max) {
  return typeof value === "string"
    ? value.trim().slice(0, max)
    : "";
}

function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function validPassword(password) {
  return typeof password === "string" &&
    password.length >= 12 &&
    Buffer.byteLength(password, "utf8") <= 72;
}

function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({
      error: "Please log in."
    });
  }
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user ||
      req.session.user.role !== "admin") {
    return res.status(403).json({
      error: "Administrator access required."
    });
  }
  next();
}

function safeUser(user) {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    role: user.role
  };
}

async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      name VARCHAR(100) NOT NULL,
      email VARCHAR(254) NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role VARCHAR(10) NOT NULL DEFAULT 'user'
        CHECK (role IN ('user', 'admin')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS messages (
      id BIGSERIAL PRIMARY KEY,
      name VARCHAR(100) NOT NULL,
      email VARCHAR(254) NOT NULL,
      subject VARCHAR(150) NOT NULL,
      message TEXT NOT NULL,
      status VARCHAR(20) NOT NULL DEFAULT 'new'
        CHECK (status IN ('new', 'read', 'closed')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS messages_created_idx
      ON messages(created_at DESC);

    CREATE INDEX IF NOT EXISTS users_created_idx
      ON users(created_at DESC);
  `);
}

// CSRF token initialization
api.get("/csrf-token", (req, res) => {
  req.session.csrfInitialized = true;

  req.session.save(error => {
    if (error) {
      return res.status(500).json({
        error: "Security initialization failed."
      });
    }

    res.json({
      csrfToken: generateToken(req, res)
    });
  });
});

// Registration
api.post("/register",
  authLimiter,
  doubleCsrfProtection,
  async (req, res) => {
    try {
      const name = clean(req.body.name, 100);
      const email = clean(req.body.email, 254).toLowerCase();
      const password = req.body.password;

      if (!name || !validEmail(email) ||
          !validPassword(password)) {
        return res.status(400).json({
          error: "Enter a valid name, email and password of at least 12 characters."
        });
      }

      const hash = await bcrypt.hash(password, 12);

      const result = await pool.query(
        `INSERT INTO users(name, email, password_hash)
         VALUES($1, $2, $3)
         RETURNING id, name, email, role`,
        [name, email, hash]
      );

      const user = safeUser(result.rows[0]);

      req.session.regenerate(error => {
        if (error) {
          return res.status(500).json({
            error: "Session creation failed."
          });
        }

        req.session.user = user;

        req.session.save(error => {
          if (error) {
            return res.status(500).json({
              error: "Session save failed."
            });
          }

          res.status(201).json({
            message: "Account created.",
            user
          });
        });
      });

    } catch (error) {
      if (error.code === "23505") {
        return res.status(409).json({
          error: "Email already registered."
        });
      }

      console.error("Registration:", error.message);
      res.status(500).json({
        error: "Registration failed."
      });
    }
  }
);

// Login
const dummyHash = bcrypt.hashSync(
  "Nexora-invalid-password-for-timing-only",
  12
);

api.post("/login",
  authLimiter,
  doubleCsrfProtection,
  async (req, res) => {
    try {
      const email = clean(req.body.email, 254).toLowerCase();
      const password = req.body.password;

      if (!validEmail(email) ||
          typeof password !== "string" ||
          Buffer.byteLength(password, "utf8") > 72) {
        return res.status(400).json({
          error: "Invalid email or password."
        });
      }

      const result = await pool.query(
        `SELECT id, name, email, password_hash, role
         FROM users WHERE email = $1`,
        [email]
      );

      const user = result.rows[0];
      const valid = await bcrypt.compare(
        password,
        user ? user.password_hash : dummyHash
      );

      if (!user || !valid) {
        return res.status(401).json({
          error: "Invalid email or password."
        });
      }

      const account = safeUser(user);

      req.session.regenerate(error => {
        if (error) {
          return res.status(500).json({
            error: "Session creation failed."
          });
        }

        req.session.user = account;

        req.session.save(error => {
          if (error) {
            return res.status(500).json({
              error: "Session save failed."
            });
          }

          res.json({
            message: "Login successful.",
            user: account
          });
        });
      });

    } catch (error) {
      console.error("Login:", error.message);
      res.status(500).json({
        error: "Login failed."
      });
    }
  }
);

// Current user
api.get("/me", (req, res) => {
  res.json({
    user: req.session.user || null
  });
});

// Logout
api.post("/logout",
  doubleCsrfProtection,
  requireLogin,
  (req, res) => {
    req.session.destroy(error => {
      if (error) {
        return res.status(500).json({
          error: "Logout failed."
        });
      }

      res.clearCookie(
        production ? "__Host-nexora.sid" : "nexora.sid",
        {
          httpOnly: true,
          secure: production,
          sameSite: "lax",
          path: "/"
        }
      );

      res.json({ message: "Logged out." });
    });
  }
);

// Contact form
api.post("/contact",
  contactLimiter,
  doubleCsrfProtection,
  async (req, res) => {
    try {
      const name = clean(req.body.name, 100);
      const email = clean(req.body.email, 254).toLowerCase();
      const subject = clean(req.body.subject, 150);
      const message = clean(req.body.message, 5000);

      if (!name || !validEmail(email) ||
          !subject || message.length < 10) {
        return res.status(400).json({
          error: "Please complete all fields correctly."
        });
      }

      await pool.query(
        `INSERT INTO messages(name, email, subject, message)
         VALUES($1, $2, $3, $4)`,
        [name, email, subject, message]
      );

      res.status(201).json({
        message: "Your inquiry has been submitted."
      });

    } catch (error) {
      console.error("Contact:", error.message);
      res.status(500).json({
        error: "Could not submit your inquiry."
      });
    }
  }
);

// User dashboard
api.get("/dashboard", requireLogin, (req, res) => {
  res.json({ user: req.session.user });
});

// Admin statistics
api.get("/admin/stats", requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        (SELECT COUNT(*) FROM users)::int AS users,
        (SELECT COUNT(*) FROM messages)::int AS messages,
        (SELECT COUNT(*) FROM messages
         WHERE status = 'new')::int AS new_messages
    `);

    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({
      error: "Could not load statistics."
    });
  }
});

// Admin users
api.get("/admin/users", requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, name, email, role, created_at
      FROM users
      ORDER BY created_at DESC
      LIMIT 200
    `);

    res.json(result.rows);
  } catch (error) {
    res.status(500).json({
      error: "Could not load users."
    });
  }
});

// Admin messages
api.get("/admin/messages", requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, name, email, subject, message,
             status, created_at
      FROM messages
      ORDER BY created_at DESC
      LIMIT 200
    `);

    res.json(result.rows);
  } catch (error) {
    res.status(500).json({
      error: "Could not load messages."
    });
  }
});

// Admin message status
api.patch("/admin/messages/:id",
  requireAdmin,
  doubleCsrfProtection,
  async (req, res) => {
    const id = Number(req.params.id);
    const status = req.body.status;

    if (!Number.isSafeInteger(id) || id <= 0 ||
        !["new", "read", "closed"].includes(status)) {
      return res.status(400).json({
        error: "Invalid update."
      });
    }

    try {
      const result = await pool.query(
        `UPDATE messages
         SET status = $1
         WHERE id = $2
         RETURNING id, status`,
        [status, id]
      );

      if (!result.rowCount) {
        return res.status(404).json({
          error: "Message not found."
        });
      }

      res.json(result.rows[0]);
    } catch (error) {
      res.status(500).json({
        error: "Update failed."
      });
    }
  }
);

app.use("/api", api);

app.get("/healthz", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.status(200).json({ status: "ok" });
  } catch {
    res.status(503).json({ status: "unavailable" });
  }
});

app.use(express.static(path.join(__dirname, "public"), {
  index: "index.html",
  dotfiles: "deny",
  fallthrough: false
}));

app.use((error, req, res, next) => {
  if (res.headersSent) return next(error);

  if (error.status === 404) {
    return res.status(404).send("Page not found.");
  }

  console.error("Request error:", error.message);
  res.status(500).send("Internal server error.");
});

async function start() {
  await initializeDatabase();

  const port = Number(process.env.PORT) || 3000;

  app.listen(port, "0.0.0.0", () => {
    console.log("Nexora is running on port " + port);
  });
}

start().catch(error => {
  console.error("Startup failed:", error);
  process.exit(1);
});
