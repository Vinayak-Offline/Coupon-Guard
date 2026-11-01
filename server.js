
require("dotenv").config();

const express = require("express");
const cookieParser = require("cookie-parser");
const session = require("express-session");
const Database = require("better-sqlite3");
const crypto = require("node:crypto");
const path = require("node:path");

const app = express();
const db = new Database(path.join(__dirname, "coupon.db"));

const PORT = 3000;
const COOKIE_NAME = "coupon_device";
const COOKIE_MAX_AGE = 365 * 24 * 60 * 60 * 1000;
const SECURE_COOKIE = process.env.SECURE_COOKIE === "true";

// Ensure the required admin secrets exist.
if (
  !process.env.ADMIN_USERNAME ||
  !process.env.ADMIN_PASSWORD ||
  !process.env.SESSION_SECRET
) {
  throw new Error("Missing ADMIN_USERNAME, ADMIN_PASSWORD or SESSION_SECRET in .env");
}

app.use(express.json({ limit: "10kb" }));
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

// Server-side admin sessions.
app.use(session({
  name: "coupon_guard_admin",
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: SECURE_COOKIE,
    sameSite: "strict",
    maxAge: 30 * 60 * 1000
  }
}));

// ==========================================
// ADMIN LOGIN, SESSION AND LOGOUT
// ==========================================

app.post("/api/admin/login", (req, res, next) => {
  const { username, password } = req.body || {};

  if (
    typeof username !== "string" ||
    typeof password !== "string" ||
    username !== process.env.ADMIN_USERNAME ||
    password !== process.env.ADMIN_PASSWORD
  ) {
    return res.status(401).json({
      ok: false,
      message: "Incorrect username or password."
    });
  }

  // Regenerate the session to prevent session fixation.
  req.session.regenerate(error => {
    if (error) return next(error);

    req.session.isAdmin = true;

    req.session.save(error => {
      if (error) return next(error);

      res.json({
        ok: true,
        message: "Login successful."
      });
    });
  });
});

// Allows the login page to check whether a session exists.
app.get("/api/admin/session", (req, res) => {
  res.json({
    authenticated: req.session.isAdmin === true
  });
});

// Logout and destroy the server-side session.
app.post("/api/admin/logout", (req, res, next) => {
  req.session.destroy(error => {
    if (error) return next(error);

    res.clearCookie("coupon_guard_admin", {
      httpOnly: true,
      secure: SECURE_COOKIE,
      sameSite: "strict"
    });

    res.json({
      ok: true,
      message: "Logged out successfully."
    });
  });
});

// Middleware protecting admin APIs.
function requireAdmin(req, res, next) {
  if (req.session && req.session.isAdmin === true) {
    return next();
  }

  return res.status(401).json({
    ok: false,
    message: "Admin login required."
  });
}

// Login and logout routes above remain public.
// Every other /api/admin route is protected.
app.use("/api/admin", requireAdmin);

// Protect the actual dashboard files before static serving.
app.use((req, res, next) => {
  const protectedFiles = ["/admin.html", "/admin.js"];

  if (protectedFiles.includes(req.path)) {
    if (req.session && req.session.isAdmin === true) {
      return next();
    }

    return res.redirect("/admin-login.html");
  }

  next();
});

// Serve customer pages and the public admin login page.
app.use(express.static(path.join(__dirname, "public")));

// Enable SQLite foreign keys.
db.pragma("foreign_keys = ON");


// Enable SQLite foreign keys.
db.pragma("foreign_keys = ON");

// ==========================================
// 1. DATABASE SETUP
// ==========================================

db.exec(`
  CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS promotions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT NOT NULL UNIQUE,
    discount_percent INTEGER NOT NULL,
    max_per_device INTEGER NOT NULL DEFAULT 2,
    active INTEGER NOT NULL DEFAULT 1
  );

  CREATE TABLE IF NOT EXISTS redemptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL REFERENCES devices(id),
    promotion_id INTEGER NOT NULL REFERENCES promotions(id),
    account_ref TEXT NOT NULL,
    order_ref TEXT NOT NULL UNIQUE,
    redeemed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE INDEX IF NOT EXISTS idx_redemptions_device_promo
  ON redemptions(device_id, promotion_id);

  CREATE INDEX IF NOT EXISTS idx_redemptions_account_promo
  ON redemptions(account_ref, promotion_id);

  CREATE TABLE IF NOT EXISTS rejected_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER REFERENCES devices(id),
    promotion_id INTEGER REFERENCES promotions(id),
    account_ref TEXT,
    attempted_code TEXT NOT NULL,
    reason TEXT NOT NULL,
    risk_score INTEGER NOT NULL DEFAULT 0,
    attempted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE INDEX IF NOT EXISTS idx_rejected_device
  ON rejected_attempts(device_id);

  CREATE INDEX IF NOT EXISTS idx_rejected_time
  ON rejected_attempts(attempted_at);
`);

// Seed the demonstration promotion without overwriting settings.
db.prepare(`
  INSERT OR IGNORE INTO promotions
  (code, discount_percent, max_per_device, active)
  VALUES ('FIRST20', 20, 2, 1)
`).run();

// ==========================================
// 2. DEVICE IDENTIFICATION
// ==========================================

function hashToken(token) {
  return crypto
    .createHash("sha256")
    .update(token)
    .digest("hex");
}

function getDevice(req, res) {
  let token = req.cookies[COOKIE_NAME];

  if (!token) {
    token = crypto.randomBytes(32).toString("hex");

    res.cookie(COOKIE_NAME, token, {
      httpOnly: true,
      secure: SECURE_COOKIE,
      sameSite: "strict",
      maxAge: COOKIE_MAX_AGE,
      path: "/"
    });
  }

  const tokenHash = hashToken(token);

  db.prepare(`
    INSERT OR IGNORE INTO devices (token_hash)
    VALUES (?)
  `).run(tokenHash);

  const device = db.prepare(`
    SELECT id FROM devices WHERE token_hash = ?
  `).get(tokenHash);

  db.prepare(`
    UPDATE devices
    SET last_seen_at = CURRENT_TIMESTAMP
    WHERE id = ?
  `).run(device.id);

  return device.id;
}

// ==========================================
// 3. REJECTION LOGGING
// ==========================================

function logRejectedAttempt({
  deviceId,
  promotionId,
  accountRef,
  code,
  reason,
  riskScore
}) {
  db.prepare(`
    INSERT INTO rejected_attempts (
      device_id,
      promotion_id,
      account_ref,
      attempted_code,
      reason,
      risk_score
    )
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(
    deviceId ?? null,
    promotionId ?? null,
    accountRef ?? null,
    code || "UNKNOWN",
    reason,
    riskScore
  );
}

// ==========================================
// 4. SESSION ENDPOINT
// ==========================================

app.get("/api/session", (req, res) => {
  const existingCookie = Boolean(req.cookies[COOKIE_NAME]);
  getDevice(req, res);

  res.json({
    ok: true,
    deviceRecognised: existingCookie,
    message: existingCookie
      ? "Browser recognised."
      : "New browser token created."
  });
});

// ==========================================
// 5. PROMOTION INFORMATION
// ==========================================

app.get("/api/promotion", (req, res) => {
  const promotion = db.prepare(`
    SELECT code, discount_percent, max_per_device, active
    FROM promotions
    WHERE code = 'FIRST20'
  `).get();

  res.json(promotion);
});

// ==========================================
// 6. COUPON REDEMPTION
// ==========================================

app.post("/api/redeem", (req, res) => {
  const { accountRef, code } = req.body || {};

  if (
    typeof accountRef !== "string" ||
    !/^[a-zA-Z0-9_-]{1,50}$/.test(accountRef) ||
    typeof code !== "string" ||
    code.trim().length < 1 ||
    code.trim().length > 30
  ) {
    return res.status(400).json({
      ok: false,
      message: "Enter a valid account reference and coupon code."
    });
  }

  const cleanCode = code.trim().toUpperCase();
  const deviceId = getDevice(req, res);

  const promotion = db.prepare(`
    SELECT * FROM promotions
    WHERE code = ?
  `).get(cleanCode);

  if (!promotion || promotion.active !== 1) {
    logRejectedAttempt({
      deviceId,
      promotionId: promotion?.id,
      accountRef,
      code: cleanCode,
      reason: "Invalid or inactive coupon",
      riskScore: 15
    });

    return res.status(400).json({
      ok: false,
      message: "This coupon is invalid or inactive."
    });
  }

  // Check account and browser limits atomically.
  const redeem = db.transaction(() => {

    const accountCount = db.prepare(`
      SELECT COUNT(*) AS count
      FROM redemptions
      WHERE account_ref = ? AND promotion_id = ?
    `).get(accountRef, promotion.id).count;

    const deviceCount = db.prepare(`
      SELECT COUNT(*) AS count
      FROM redemptions
      WHERE device_id = ? AND promotion_id = ?
    `).get(deviceId, promotion.id).count;

    if (accountCount >= 1) {
      logRejectedAttempt({
        deviceId,
        promotionId: promotion.id,
        accountRef,
        code: cleanCode,
        reason: "Account already redeemed this promotion",
        riskScore: 80
      });

      return {
        ok: false,
        status: 409,
        message: "This account has already used this promotion."
      };
    }

    if (deviceCount >= promotion.max_per_device) {
      logRejectedAttempt({
        deviceId,
        promotionId: promotion.id,
        accountRef,
        code: cleanCode,
        reason: "Browser redemption limit reached",
        riskScore: 70
      });

      return {
        ok: false,
        status: 409,
        message: "The redemption limit for this browser has been reached."
      };
    }

    const orderRef = "DEMO-" + crypto.randomUUID();

    db.prepare(`
      INSERT INTO redemptions (
        device_id,
        promotion_id,
        account_ref,
        order_ref
      )
      VALUES (?, ?, ?, ?)
    `).run(
      deviceId,
      promotion.id,
      accountRef,
      orderRef
    );

    return {
      ok: true,
      status: 200,
      message: `Coupon accepted! ${promotion.discount_percent}% discount recorded.`,
      orderRef,
      discountPercent: promotion.discount_percent,
      redemptionsUsed: deviceCount + 1,
      redemptionsAllowed: promotion.max_per_device
    };
  });

  const result = redeem();

  return res.status(result.status).json(result);
});

// ==========================================
// 7. ADMIN DASHBOARD STATISTICS
// ==========================================

app.get("/api/admin/stats", (req, res) => {

  const promotion = db.prepare(`
    SELECT id, code, discount_percent, max_per_device, active
    FROM promotions
    WHERE code = 'FIRST20'
`).get();

  const total = db.prepare(`
    SELECT COUNT(*) AS count
    FROM redemptions
    WHERE promotion_id = ?
  `).get(promotion.id).count;

  const devices = db.prepare(`
    SELECT COUNT(DISTINCT device_id) AS count
    FROM redemptions
    WHERE promotion_id = ?
  `).get(promotion.id).count;

  const rejectedTotal = db.prepare(`
    SELECT COUNT(*) AS count
    FROM rejected_attempts
    WHERE promotion_id = ?
  `).get(promotion.id).count;

  const flaggedTotal = db.prepare(`
    SELECT COUNT(*) AS count
    FROM rejected_attempts
    WHERE promotion_id = ?
    AND risk_score >= 60
  `).get(promotion.id).count;

  // Browsers associated with multiple account references.
  // This is an indicator for review, not proof of abuse.
  const multiAccountDevices = db.prepare(`
    SELECT COUNT(*) AS count
    FROM (
      SELECT device_id
      FROM redemptions
      WHERE promotion_id = ?
      GROUP BY device_id
      HAVING COUNT(DISTINCT account_ref) > 1
    )
  `).get(promotion.id).count;

  const recent = db.prepare(`
    SELECT
      r.order_ref,
      r.account_ref,
      r.redeemed_at,
      p.code,
      d.id AS device_id
    FROM redemptions r
    JOIN promotions p ON p.id = r.promotion_id
    JOIN devices d ON d.id = r.device_id
    WHERE r.promotion_id = ?
    ORDER BY r.id DESC
    LIMIT 20
  `).all(promotion.id);

  const recentRejected = db.prepare(`
    SELECT
      a.id,
      a.account_ref,
      a.attempted_code,
      a.reason,
      a.risk_score,
      a.attempted_at,
      a.device_id
    FROM rejected_attempts a
    WHERE a.promotion_id = ?
    ORDER BY a.id DESC
    LIMIT 20
  `).all(promotion.id);

  // Combine both types of activity for a unified activity feed.
  const recentActivity = [
    ...recent.map(item => ({
      type: "approved",
      account_ref: item.account_ref,
      device_id: item.device_id,
      code: item.code,
      reference: item.order_ref,
      reason: "Coupon successfully redeemed",
      risk_score: 0,
      timestamp: item.redeemed_at
    })),

    ...recentRejected.map(item => ({
      type: "rejected",
      account_ref: item.account_ref,
      device_id: item.device_id,
      code: item.attempted_code,
      reference: `ATTEMPT-${item.id}`,
      reason: item.reason,
      risk_score: item.risk_score,
      timestamp: item.attempted_at
    }))
  ].sort((a, b) =>
    b.timestamp.localeCompare(a.timestamp)
  ).slice(0, 20);

  res.json({
    promotion,
    total,
    devices,
    rejectedTotal,
    flaggedTotal,
    multiAccountDevices,
    recent,
    recentRejected,
    recentActivity
  });
});


// ==========================================
// 8. ADMIN: DEVICE INTELLIGENCE
// ==========================================

// Get all recorded browser/device profiles.
app.get("/api/admin/devices", (req, res) => {
  const promotion = db.prepare(`
    SELECT id, code
    FROM promotions
    WHERE code = 'FIRST20'
  `).get();

  if (!promotion) {
    return res.status(404).json({
      ok: false,
      message: "Promotion not found."
    });
  }

  const devices = db.prepare(`
    SELECT
      d.id AS device_id,
      d.created_at,
      d.last_seen_at,

      (
        SELECT COUNT(*)
        FROM redemptions r
        WHERE r.device_id = d.id
          AND r.promotion_id = ?
      ) AS successful_redemptions,

      (
        SELECT COUNT(*)
        FROM rejected_attempts a
        WHERE a.device_id = d.id
          AND a.promotion_id = ?
      ) AS rejected_attempts,

      (
        SELECT COUNT(DISTINCT r.account_ref)
        FROM redemptions r
        WHERE r.device_id = d.id
          AND r.promotion_id = ?
      ) AS distinct_accounts,

      (
        SELECT COALESCE(MAX(a.risk_score), 0)
        FROM rejected_attempts a
        WHERE a.device_id = d.id
          AND a.promotion_id = ?
      ) AS highest_risk_score

    FROM devices d
    WHERE EXISTS (
      SELECT 1
      FROM redemptions r
      WHERE r.device_id = d.id
        AND r.promotion_id = ?
    )
    OR EXISTS (
      SELECT 1
      FROM rejected_attempts a
      WHERE a.device_id = d.id
        AND a.promotion_id = ?
    )
    ORDER BY d.id DESC
  `).all(
    promotion.id,
    promotion.id,
    promotion.id,
    promotion.id,
    promotion.id,
    promotion.id
  );

  const result = devices.map(device => {
    const multipleAccounts = device.distinct_accounts > 1;

    let riskLevel = "Low";

    if (
      device.highest_risk_score >= 70 ||
      multipleAccounts
    ) {
      riskLevel = "High";
    } else if (
      device.highest_risk_score >= 30 ||
      device.rejected_attempts > 0
    ) {
      riskLevel = "Medium";
    }

    return {
      ...device,
      risk_level: riskLevel,
      multiple_accounts: multipleAccounts
    };
  });

  res.json({
    ok: true,
    totalDevices: result.length,
    devices: result
  });
});


// Get the detailed profile and activity timeline for one browser.
app.get("/api/admin/devices/:id", (req, res) => {
  const deviceId = Number(req.params.id);

  if (!Number.isInteger(deviceId) || deviceId < 1) {
    return res.status(400).json({
      ok: false,
      message: "Invalid device ID."
    });
  }

  const promotion = db.prepare(`
    SELECT id, code
    FROM promotions
    WHERE code = 'FIRST20'
  `).get();

  if (!promotion) {
    return res.status(404).json({
      ok: false,
      message: "Promotion not found."
    });
  }

  const device = db.prepare(`
    SELECT id, created_at, last_seen_at
    FROM devices
    WHERE id = ?
  `).get(deviceId);

  if (!device) {
    return res.status(404).json({
      ok: false,
      message: "Device not found."
    });
  }

  const successful = db.prepare(`
    SELECT
      account_ref,
      order_ref AS reference,
      redeemed_at AS timestamp
    FROM redemptions
    WHERE device_id = ?
      AND promotion_id = ?
  `).all(deviceId, promotion.id);

  const rejected = db.prepare(`
    SELECT
      account_ref,
      attempted_code,
      reason,
      risk_score,
      attempted_at AS timestamp,
      id
    FROM rejected_attempts
    WHERE device_id = ?
      AND promotion_id = ?
  `).all(deviceId, promotion.id);

  const timeline = [
    ...successful.map(item => ({
      type: "approved",
      account_ref: item.account_ref,
      reference: item.reference,
      timestamp: item.timestamp,
      reason: "Coupon successfully redeemed",
      risk_score: 0
    })),

    ...rejected.map(item => ({
      type: "rejected",
      account_ref: item.account_ref,
      reference: `ATTEMPT-${item.id}`,
      code: item.attempted_code,
      timestamp: item.timestamp,
      reason: item.reason,
      risk_score: item.risk_score
    }))
  ].sort((a, b) =>
    new Date(b.timestamp + "Z") -
    new Date(a.timestamp + "Z")
  );

  const distinctAccounts = [
    ...new Set(
      successful
        .map(item => item.account_ref)
        .filter(Boolean)
    )
  ];

  const highestRisk = rejected.reduce(
    (highest, item) => Math.max(highest, item.risk_score || 0),
    0
  );

  const multipleAccounts = distinctAccounts.length > 1;

  let riskLevel = "Low";

  if (highestRisk >= 70 || multipleAccounts) {
    riskLevel = "High";
  } else if (highestRisk >= 30 || rejected.length > 0) {
    riskLevel = "Medium";
  }

  res.json({
    ok: true,

    device: {
      id: device.id,
      created_at: device.created_at,
      last_seen_at: device.last_seen_at,
      successful_redemptions: successful.length,
      rejected_attempts: rejected.length,
      distinct_accounts: distinctAccounts.length,
      highest_risk_score: highestRisk,
      risk_level: riskLevel,
      multiple_accounts: multipleAccounts,
      warning: multipleAccounts
        ? "Multiple accounts have successfully redeemed from this browser."
        : null
    },

    timeline
  });
});


// ==========================================
// 9. ADMIN: CHANGE REDEMPTION LIMIT
// ==========================================



app.post("/api/admin/limit", (req, res) => {
  const limit = Number(req.body?.limit);

  if (!Number.isInteger(limit) || limit < 1 || limit > 10) {
    return res.status(400).json({
      ok: false,
      message: "The limit must be an integer between 1 and 10."
    });
  }

  db.prepare(`
    UPDATE promotions
    SET max_per_device = ?
    WHERE code = 'FIRST20'
  `).run(limit);

  res.json({
    ok: true,
    limit
  });
});

// ==========================================
// 10. START SERVER
// ==========================================

app.listen(PORT, () => {
  console.log(
    `Coupon Guard running at http://localhost:${PORT}`
  );
});
