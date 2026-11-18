
"use strict";

const express = require("express");
const { Pool } = require("pg");
const crypto = require("crypto");
const path = require("path");

const app = express();

app.disable("x-powered-by");
app.use(express.json({ limit: "256kb" }));

const PORT = process.env.PORT || 3000;
const BOT_TOKEN = process.env.BOT_TOKEN || "";
const BOT_USERNAME = (process.env.BOT_USERNAME || "").replace(/^@/, "");
const ADMIN_ID = String(process.env.ADMIN_TELEGRAM_ID || "");
const DATABASE_URL = process.env.DATABASE_URL || "";
const PRODUCTION = process.env.NODE_ENV === "production";

if (!BOT_TOKEN || !BOT_USERNAME || !ADMIN_ID || !DATABASE_URL) {
  console.error("Missing environment variables.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: PRODUCTION ? { rejectUnauthorized: false } : false
});

const db = (sql, values = []) => pool.query(sql, values);

const asyncRoute = fn => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

// Rate limiting
const limits = new Map();

app.use("/api", (req, res, next) => {
  const key = req.ip + ":" + req.path;
  const now = Date.now();

  let item = limits.get(key);

  if (!item || now > item.reset) {
    item = { count: 0, reset: now + 60000 };
  }

  item.count++;
  limits.set(key, item);

  if (item.count > 90) {
    return res.status(429).json({ error: "Too many requests." });
  }

  next();
});

// DATABASE
async function initDatabase() {
  await db(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGINT PRIMARY KEY,
      username TEXT DEFAULT '',
      first_name TEXT DEFAULT '',
      balance NUMERIC(24,6) DEFAULT 0 CHECK(balance >= 0),
      wallet TEXT DEFAULT '',
      referred_by BIGINT REFERENCES users(id),
      referrals INTEGER DEFAULT 0,
      banned BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS channels (
      id BIGSERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      url TEXT NOT NULL,
      chat_id TEXT NOT NULL,
      enabled BOOLEAN DEFAULT TRUE
    );

    CREATE TABLE IF NOT EXISTS tasks (
      id BIGSERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      description TEXT DEFAULT '',
      reward NUMERIC(24,6) NOT NULL,
      task_url TEXT DEFAULT '',
      enabled BOOLEAN DEFAULT TRUE
    );

    CREATE TABLE IF NOT EXISTS task_claims (
      user_id BIGINT REFERENCES users(id),
      task_id BIGINT REFERENCES tasks(id),
      claimed_at TIMESTAMPTZ DEFAULT NOW(),
      PRIMARY KEY(user_id, task_id)
    );

    CREATE TABLE IF NOT EXISTS withdrawals (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT REFERENCES users(id),
      amount NUMERIC(24,6) NOT NULL,
      wallet TEXT NOT NULL,
      status TEXT DEFAULT 'Pending',
      admin_note TEXT DEFAULT '',
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS transactions (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT REFERENCES users(id),
      type TEXT NOT NULL,
      amount NUMERIC(24,6) NOT NULL,
      note TEXT DEFAULT '',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS admin_logs (
      id BIGSERIAL PRIMARY KEY,
      admin_id BIGINT NOT NULL,
      action TEXT NOT NULL,
      details JSONB DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  const defaults = {
    referral_bonus: process.env.REFERRAL_BONUS || "100",
    minimum_withdrawal: process.env.MIN_WITHDRAWAL || "500",
    maximum_withdrawal: "1000000",
    withdrawal_fee_percent: "0",
    maintenance: "false",
    automatic_payouts: "false"
  };

  for (const [key, value] of Object.entries(defaults)) {
    await db(
      `INSERT INTO settings(key,value)
       VALUES($1,$2) ON CONFLICT(key) DO NOTHING`,
      [key, String(value)]
    );
  }
}

// TELEGRAM AUTHENTICATION
function verifyTelegram(initData) {
  if (!initData || typeof initData !== "string") return null;

  const params = new URLSearchParams(initData);
  const receivedHash = params.get("hash");

  if (!receivedHash || !/^[a-f0-9]{64}$/i.test(receivedHash)) {
    return null;
  }

  params.delete("hash");
  params.delete("signature");

  const checkString = [...params.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => `${key}=${value}`)
    .join("\n");

  const secret = crypto
    .createHmac("sha256", "WebAppData")
    .update(BOT_TOKEN)
    .digest();

  const calculatedHash = crypto
    .createHmac("sha256", secret)
    .update(checkString)
    .digest("hex");

  const a = Buffer.from(calculatedHash, "hex");
  const b = Buffer.from(receivedHash, "hex");

  if (
    a.length !== b.length ||
    !crypto.timingSafeEqual(a, b)
  ) return null;

  const authDate = Number(params.get("auth_date"));
  const now = Math.floor(Date.now() / 1000);

  if (!authDate || authDate > now + 60 || now - authDate > 86400) {
    return null;
  }

  try {
    const user = JSON.parse(params.get("user") || "null");

    if (!user || !/^\d+$/.test(String(user.id))) return null;

    return user;
  } catch {
    return null;
  }
}

const auth = asyncRoute(async (req, res, next) => {
  const user = verifyTelegram(req.get("x-telegram-init-data"));

  if (!user) {
    return res.status(401).json({
      error: "Telegram verification failed. Open the app through Telegram."
    });
  }

  const result = await db(
    "SELECT banned FROM users WHERE id=$1",
    [String(user.id)]
  );

  if (result.rows[0]?.banned) {
    return res.status(403).json({ error: "Your account is suspended." });
  }

  req.telegramUser = user;
  req.userId = String(user.id);

  next();
});

function adminOnly(req, res, next) {
  if (req.userId !== ADMIN_ID) {
    return res.status(403).json({ error: "Admin access denied." });
  }

  next();
}

async function getSetting(key, fallback) {
  const result = await db(
    "SELECT value FROM settings WHERE key=$1",
    [key]
  );

  return result.rows[0]?.value ?? fallback;
}

async function adminLog(action, details = {}) {
  await db(
    "INSERT INTO admin_logs(admin_id,action,details) VALUES($1,$2,$3)",
    [ADMIN_ID, action, JSON.stringify(details)]
  );
}

// REGISTER USER AND PROCESS REFERRAL
async function registerUser(user, startParam) {
  const id = String(user.id);
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const existing = await client.query(
      "SELECT id FROM users WHERE id=$1 FOR UPDATE",
      [id]
    );

    if (existing.rowCount) {
      await client.query(
        "UPDATE users SET username=$2,first_name=$3 WHERE id=$1",
        [id, user.username || "", user.first_name || ""]
      );

      await client.query("COMMIT");
      return;
    }

    let referrer = null;

    if (typeof startParam === "string" && startParam.startsWith("ref_")) {
      const candidate = startParam.slice(4);

      if (/^\d+$/.test(candidate) && candidate !== id) {
        const ref = await client.query(
          "SELECT id FROM users WHERE id=$1",
          [candidate]
        );

        if (ref.rowCount) referrer = candidate;
      }
    }

    await client.query(
      `INSERT INTO users(id,username,first_name,referred_by)
       VALUES($1,$2,$3,$4)`,
      [id, user.username || "", user.first_name || "", referrer]
    );

    if (referrer) {
      const bonusResult = await client.query(
        "SELECT value FROM settings WHERE key='referral_bonus'"
      );

      const bonus = Number(bonusResult.rows[0]?.value || 100);

      if (Number.isFinite(bonus) && bonus >= 0) {
        await client.query(
          "UPDATE users SET balance=balance+$2,referrals=referrals+1 WHERE id=$1",
          [referrer, bonus]
        );

        await client.query(
          `INSERT INTO transactions(user_id,type,amount,note)
           VALUES($1,'Referral',$2,$3)`,
          [referrer, bonus, "Referral from user " + id]
        );
      }
    }

    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

// PUBLIC ROUTES
app.use(express.static(path.join(__dirname, "public")));

app.get("/health", (req, res) => {
  res.json({ ok: true, app: "DOGS PAY" });
});

app.get("/api/config", asyncRoute(async (req, res) => {
  res.json({
    appName: "DOGS PAY",
    botUsername: BOT_USERNAME,
    minimumWithdrawal: Number(await getSetting("minimum_withdrawal", "500")),
    maximumWithdrawal: Number(await getSetting("maximum_withdrawal", "1000000")),
    feePercent: Number(await getSetting("withdrawal_fee_percent", "0")),
    maintenance: (await getSetting("maintenance", "false")) === "true"
  });
}));

// AUTHENTICATED ROUTES
app.use("/api", auth);

app.post("/api/register", asyncRoute(async (req, res) => {
  await registerUser(
    req.telegramUser,
    req.body?.startParam || ""
  );

  res.json({ success: true });
}));

// DASHBOARD
app.get("/api/dashboard", asyncRoute(async (req, res) => {
  const user = await db(
    `SELECT id,username,first_name,balance,wallet,referrals,created_at
     FROM users WHERE id=$1`,
    [req.userId]
  );

  if (!user.rowCount) {
    return res.status(404).json({ error: "Account not found." });
  }

  const transactions = await db(
    `SELECT * FROM transactions
     WHERE user_id=$1 ORDER BY id DESC LIMIT 50`,
    [req.userId]
  );

  const withdrawals = await db(
    `SELECT * FROM withdrawals
     WHERE user_id=$1 ORDER BY id DESC LIMIT 30`,
    [req.userId]
  );

  res.json({
    user: user.rows[0],
    transactions: transactions.rows,
    withdrawals: withdrawals.rows
  });
}));

// FORCE JOIN CHANNELS
app.get("/api/channels", asyncRoute(async (req, res) => {
  const result = await db(
    "SELECT id,title,url,chat_id FROM channels WHERE enabled=true ORDER BY id"
  );

  res.json(result.rows);
}));

app.post("/api/check-joins", asyncRoute(async (req, res) => {
  const channels = await db(
    "SELECT id,title,url,chat_id FROM channels WHERE enabled=true"
  );

  const results = [];

  for (const channel of channels.rows) {
    try {
      const response = await fetch(
        `https://api.telegram.org/bot${BOT_TOKEN}/getChatMember`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            chat_id: channel.chat_id,
            user_id: req.userId
          })
        }
      );

      const data = await response.json();
      const status = data.result?.status;

      results.push({
        id: channel.id,
        title: channel.title,
        url: channel.url,
        joined: Boolean(
          data.ok &&
          ["creator", "administrator", "member"].includes(status)
        )
      });
    } catch {
      results.push({
        id: channel.id,
        title: channel.title,
        url: channel.url,
        joined: false
      });
    }
  }

  res.json({
    allJoined: results.every(item => item.joined),
    channels: results
  });
}));

// TASKS
app.get("/api/tasks", asyncRoute(async (req, res) => {
  const result = await db(
    `SELECT t.*,
      EXISTS(
        SELECT 1 FROM task_claims c
        WHERE c.task_id=t.id AND c.user_id=$1
      ) AS claimed
     FROM tasks t
     WHERE t.enabled=true
     ORDER BY t.id DESC`,
    [req.userId]
  );

  res.json(result.rows);
}));

app.post("/api/tasks/:id/claim", asyncRoute(async (req, res) => {
  const taskId = Number(req.params.id);

  if (!Number.isSafeInteger(taskId) || taskId <= 0) {
    return res.status(400).json({ error: "Invalid task." });
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const task = await client.query(
      "SELECT * FROM tasks WHERE id=$1 AND enabled=true FOR UPDATE",
      [taskId]
    );

    if (!task.rowCount) throw new Error("Task unavailable.");

    const claim = await client.query(
      `INSERT INTO task_claims(user_id,task_id)
       VALUES($1,$2)
       ON CONFLICT DO NOTHING
       RETURNING user_id`,
      [req.userId, taskId]
    );

    if (!claim.rowCount) {
      throw new Error("You already claimed this task.");
    }

    const reward = task.rows[0].reward;

    await client.query(
      "UPDATE users SET balance=balance+$2 WHERE id=$1",
      [req.userId, reward]
    );

    await client.query(
      `INSERT INTO transactions(user_id,type,amount,note)
       VALUES($1,'Task',$2,$3)`,
      [req.userId, reward, task.rows[0].title]
    );

    await client.query("COMMIT");

    res.json({ success: true, reward });
  } catch (error) {
    await client.query("ROLLBACK");
    res.status(400).json({ error: error.message });
  } finally {
    client.release();
  }
}));

// WALLET
app.post("/api/wallet", asyncRoute(async (req, res) => {
  const wallet = String(req.body?.wallet || "").trim();

  if (
    wallet.length < 20 ||
    wallet.length > 150 ||
    /\s/.test(wallet)
  ) {
    return res.status(400).json({
      error: "Enter a valid DOGS-compatible wallet address."
    });
  }

  await db(
    "UPDATE users SET wallet=$2 WHERE id=$1",
    [req.userId, wallet]
  );

  res.json({ success: true });
}));

// WITHDRAWAL
app.post("/api/withdraw", asyncRoute(async (req, res) => {
  const amount = Number(req.body?.amount);

  if (!Number.isFinite(amount) || amount <= 0) {
    return res.status(400).json({ error: "Invalid amount." });
  }

  const minimum = Number(await getSetting("minimum_withdrawal", "500"));
  const maximum = Number(await getSetting("maximum_withdrawal", "1000000"));

  if (amount < minimum) {
    return res.status(400).json({
      error: `Minimum withdrawal is ${minimum} DOGS.`
    });
  }

  if (amount > maximum) {
    return res.status(400).json({
      error: `Maximum withdrawal is ${maximum} DOGS.`
    });
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const user = await client.query(
      "SELECT balance,wallet FROM users WHERE id=$1 FOR UPDATE",
      [req.userId]
    );

    if (!user.rowCount || !user.rows[0].wallet) {
      throw new Error("Set your wallet first.");
    }

    if (Number(user.rows[0].balance) < amount) {
      throw new Error("Insufficient balance.");
    }

    await client.query(
      "UPDATE users SET balance=balance-$2 WHERE id=$1",
      [req.userId, amount]
    );

    const withdrawal = await client.query(
      `INSERT INTO withdrawals(user_id,amount,wallet)
       VALUES($1,$2,$3) RETURNING id`,
      [req.userId, amount, user.rows[0].wallet]
    );

    await client.query(
      `INSERT INTO transactions(user_id,type,amount,note)
       VALUES($1,'Withdrawal',$2,$3)`,
      [
        req.userId,
        -amount,
        "Withdrawal request #" + withdrawal.rows[0].id
      ]
    );

    await client.query("COMMIT");

    res.json({
      success: true,
      withdrawalId: withdrawal.rows[0].id
    });
  } catch (error) {
    await client.query("ROLLBACK");
    res.status(400).json({ error: error.message });
  } finally {
    client.release();
  }
}));

// ADMIN DASHBOARD DATA
app.get("/api/admin", adminOnly, asyncRoute(async (req, res) => {
  const [users, withdrawals, tasks, channels, settings, stats] =
    await Promise.all([
      db("SELECT * FROM users ORDER BY created_at DESC LIMIT 250"),
      db("SELECT * FROM withdrawals ORDER BY id DESC LIMIT 250"),
      db("SELECT * FROM tasks ORDER BY id DESC"),
      db("SELECT * FROM channels ORDER BY id DESC"),
      db("SELECT key,value FROM settings"),
      db("SELECT COUNT(*) AS users,COALESCE(SUM(balance),0) AS balances FROM users")
    ]);

  res.json({
    users: users.rows,
    withdrawals: withdrawals.rows,
    tasks: tasks.rows,
    channels: channels.rows,
    settings: Object.fromEntries(
      settings.rows.map(item => [item.key, item.value])
    ),
    stats: stats.rows[0]
  });
}));

// ADMIN: ADD TASK
app.post("/api/admin/task", adminOnly, asyncRoute(async (req, res) => {
  const title = String(req.body?.title || "").trim();
  const description = String(req.body?.description || "").trim();
  const reward = Number(req.body?.reward);
  const taskUrl = String(req.body?.task_url || "").trim();

  if (!title || !Number.isFinite(reward) || reward <= 0) {
    return res.status(400).json({ error: "Invalid task details." });
  }

  await db(
    `INSERT INTO tasks(title,description,reward,task_url)
     VALUES($1,$2,$3,$4)`,
    [title, description, reward, taskUrl]
  );

  await adminLog("task_created", { title, reward });

  res.json({ success: true });
}));

app.delete("/api/admin/task/:id", adminOnly, asyncRoute(async (req, res) => {
  await db(
    "UPDATE tasks SET enabled=false WHERE id=$1",
    [Number(req.params.id)]
  );

  await adminLog("task_disabled", { id: req.params.id });

  res.json({ success: true });
}));

// ADMIN: CHANNELS
app.post("/api/admin/channel", adminOnly, asyncRoute(async (req, res) => {
  const title = String(req.body?.title || "").trim();
  const url = String(req.body?.url || "").trim();
  const chatId = String(req.body?.chat_id || "").trim();

  if (!title || !chatId || !/^https:\/\/t\.me\//i.test(url)) {
    return res.status(400).json({ error: "Invalid channel details." });
  }

  await db(
    "INSERT INTO channels(title,url,chat_id) VALUES($1,$2,$3)",
    [title, url, chatId]
  );

  await adminLog("channel_created", { title, chatId });

  res.json({ success: true });
}));

app.delete("/api/admin/channel/:id", adminOnly, asyncRoute(async (req, res) => {
  await db(
    "UPDATE channels SET enabled=false WHERE id=$1",
    [Number(req.params.id)]
  );

  await adminLog("channel_disabled", { id: req.params.id });

  res.json({ success: true });
}));

// ADMIN: SETTINGS
app.post("/api/admin/settings", adminOnly, asyncRoute(async (req, res) => {
  const allowed = [
    "referral_bonus",
    "minimum_withdrawal",
    "maximum_withdrawal",
    "withdrawal_fee_percent",
    "maintenance"
  ];

  for (const key of allowed) {
    if (req.body?.[key] === undefined) continue;

    const value = String(req.body[key]);

    if (key !== "maintenance") {
      const number = Number(value);

      if (!Number.isFinite(number) || number < 0) {
        return res.status(400).json({ error: "Invalid " + key });
      }
    } else if (!["true", "false"].includes(value)) {
      return res.status(400).json({ error: "Invalid maintenance setting." });
    }

    await db(
      `INSERT INTO settings(key,value) VALUES($1,$2)
       ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value`,
      [key, value]
    );
  }

  await adminLog("settings_updated", req.body || {});

  res.json({ success: true });
}));

// ADMIN: APPROVE OR REJECT WITHDRAWAL
app.post("/api/admin/withdrawal/:id", adminOnly, asyncRoute(async (req, res) => {
  const id = Number(req.params.id);
  const status = String(req.body?.status || "");

  if (
    !Number.isSafeInteger(id) ||
    id <= 0 ||
    !["Successful", "Failed"].includes(status)
  ) {
    return res.status(400).json({ error: "Invalid withdrawal update." });
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const result = await client.query(
      "SELECT * FROM withdrawals WHERE id=$1 FOR UPDATE",
      [id]
    );

    if (!result.rowCount) throw new Error("Withdrawal not found.");

    const withdrawal = result.rows[0];

    if (withdrawal.status !== "Pending") {
      throw new Error("Withdrawal already processed.");
    }

    if (status === "Failed") {
      await client.query(
        "UPDATE users SET balance=balance+$2 WHERE id=$1",
        [withdrawal.user_id, withdrawal.amount]
      );

      await client.query(
        `INSERT INTO transactions(user_id,type,amount,note)
         VALUES($1,'Refund',$2,$3)`,
        [
          withdrawal.user_id,
          withdrawal.amount,
          "Refund for withdrawal #" + id
        ]
      );
    }

    await client.query(
      `UPDATE withdrawals
     
