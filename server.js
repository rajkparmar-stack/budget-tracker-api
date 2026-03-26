const express  = require('express');
const Database = require('better-sqlite3');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const cors     = require('cors');

const app  = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET    = process.env.JWT_SECRET;
const FRONTEND_URL  = process.env.FRONTEND_URL || '*';
const ADMIN         = 'rajparmar';

if (!JWT_SECRET) {
  console.error('ERROR: JWT_SECRET environment variable is not set. Exiting.');
  process.exit(1);
}

// ── Database ───────────────────────────────────────────────────────────────
const db = new Database(process.env.DB_PATH || 'budget.db');
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    username     TEXT PRIMARY KEY COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    is_admin     INTEGER NOT NULL DEFAULT 0,
    created_at   INTEGER NOT NULL DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS budget_data (
    username   TEXT NOT NULL COLLATE NOCASE,
    key        TEXT NOT NULL,
    value      TEXT NOT NULL,
    updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (username, key),
    FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
  );

  CREATE INDEX IF NOT EXISTS idx_data_user ON budget_data(username);
`);

// ── Middleware ─────────────────────────────────────────────────────────────
app.use(cors({ origin: FRONTEND_URL, credentials: true }));
app.use(express.json());

const auth = (req, res, next) => {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorised' });
  try {
    req.user = jwt.verify(header.slice(7), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Token invalid or expired' });
  }
};

const adminOnly = (req, res, next) => {
  auth(req, res, () => {
    if (!req.user.isAdmin) return res.status(403).json({ error: 'Admin only' });
    next();
  });
};

// ── Setup ──────────────────────────────────────────────────────────────────
// Returns whether the admin account needs to be created.
// Used by the frontend to decide whether to show the setup screen.
app.get('/api/setup-needed', (_req, res) => {
  const row = db.prepare('SELECT username FROM users WHERE username = ?').get(ADMIN);
  res.json({ needed: !row });
});

// Creates the admin account. Only works once — blocked after admin exists.
app.post('/api/setup', async (req, res) => {
  try {
    const row = db.prepare('SELECT username FROM users WHERE username = ?').get(ADMIN);
    if (row) return res.status(403).json({ error: 'Admin account already exists' });

    const { password } = req.body;
    if (!password || password.length < 6)
      return res.status(400).json({ error: 'Password must be at least 6 characters' });

    const hash = await bcrypt.hash(password, 12);
    db.prepare('INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 1)')
      .run(ADMIN, hash);

    res.json({ success: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// ── Auth ───────────────────────────────────────────────────────────────────
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password)
      return res.status(400).json({ error: 'Username and password required' });

    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username.toLowerCase());
    // Always compare to prevent timing-based username enumeration
    const valid = user ? await bcrypt.compare(password, user.password_hash) : false;
    if (!user || !valid)
      return res.status(401).json({ error: 'Invalid username or password' });

    const token = jwt.sign(
      { username: user.username, isAdmin: user.is_admin === 1 },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({ token, username: user.username, isAdmin: user.is_admin === 1 });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// Verify current session — used by the frontend on page load
app.get('/api/me', auth, (req, res) => {
  res.json({ username: req.user.username, isAdmin: req.user.isAdmin });
});

// ── User Data ──────────────────────────────────────────────────────────────
// Fetch all budget data for the logged-in user in one request
app.get('/api/data', auth, (req, res) => {
  const rows = db.prepare('SELECT key, value FROM budget_data WHERE username = ?')
    .all(req.user.username);
  const result = {};
  rows.forEach(r => {
    try { result[r.key] = JSON.parse(r.value); } catch { result[r.key] = r.value; }
  });
  res.json(result);
});

// Save / update a single key
app.put('/api/data/:key', auth, (req, res) => {
  const { value } = req.body;
  if (value === undefined) return res.status(400).json({ error: 'value required' });
  db.prepare(`
    INSERT INTO budget_data (username, key, value, updated_at)
    VALUES (?, ?, ?, unixepoch())
    ON CONFLICT(username, key)
    DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
  `).run(req.user.username, req.params.key, JSON.stringify(value));
  res.json({ success: true });
});

// Delete a single key
app.delete('/api/data/:key', auth, (req, res) => {
  db.prepare('DELETE FROM budget_data WHERE username = ? AND key = ?')
    .run(req.user.username, req.params.key);
  res.json({ success: true });
});

// ── Admin: User Management ─────────────────────────────────────────────────
app.get('/api/admin/users', adminOnly, (_req, res) => {
  const users = db.prepare(
    'SELECT username, is_admin, created_at FROM users ORDER BY created_at'
  ).all();
  res.json(users);
});

app.post('/api/admin/users', adminOnly, async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password)
      return res.status(400).json({ error: 'Username and password required' });
    if (username.length < 3)
      return res.status(400).json({ error: 'Username must be at least 3 characters' });
    if (password.length < 4)
      return res.status(400).json({ error: 'Password must be at least 4 characters' });

    const exists = db.prepare('SELECT username FROM users WHERE username = ?')
      .get(username.toLowerCase());
    if (exists) return res.status(409).json({ error: `Username "${username}" already exists` });

    const hash = await bcrypt.hash(password, 12);
    db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)')
      .run(username.toLowerCase(), hash);

    res.json({ success: true, username: username.toLowerCase() });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/admin/users/:username', adminOnly, (req, res) => {
  const target = req.params.username.toLowerCase();
  if (target === ADMIN)
    return res.status(403).json({ error: 'Cannot delete the admin account' });
  // budget_data is cascade-deleted via the FK constraint
  db.prepare('DELETE FROM users WHERE username = ?').run(target);
  res.json({ success: true });
});

app.put('/api/admin/users/:username/password', adminOnly, async (req, res) => {
  try {
    const { password } = req.body;
    if (!password || password.length < 4)
      return res.status(400).json({ error: 'Password must be at least 4 characters' });
    const hash = await bcrypt.hash(password, 12);
    db.prepare('UPDATE users SET password_hash = ? WHERE username = ?')
      .run(hash, req.params.username.toLowerCase());
    res.json({ success: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// ── Start ──────────────────────────────────────────────────────────────────
app.listen(PORT, () => console.log(`Budget Tracker API on port ${PORT}`));
