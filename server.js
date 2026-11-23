const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.static(__dirname));

const DB_FILE = path.join(__dirname, 'db.json');
const SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

let db = { orders: [], admin: null };
try {
  if (fs.existsSync(DB_FILE)) {
    const parsed = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    db = Object.assign({ orders: [], admin: null }, parsed);
  }
} catch (e) {}

function flush() {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

function hashPw(pw, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.scryptSync(String(pw), salt, 64).toString('hex');
  return { salt, hash };
}

function checkPw(pw, a) {
  if (!a || !a.salt || !a.hash) return false;
  const g = crypto.scryptSync(String(pw), a.salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(a.hash, 'hex'), Buffer.from(g, 'hex'));
}

const adminUser = process.env.ADMIN_USER || 'admin';
const adminPass = process.env.ADMIN_PASS || '12345678';
db.admin = Object.assign({ user: adminUser }, hashPw(adminPass));
flush();

function makeToken(user) {
  const exp = Date.now() + 1000 * 60 * 60 * 24;
  const payload = Buffer.from(JSON.stringify({ user, exp })).toString('base64url');
  const sig = crypto.createHmac('sha256', SECRET).update(payload).digest('base64url');
  return `${payload}.${sig}`;
}

function verifyToken(token) {
  if (!token) return null;
  const [payload, sig] = token.split('.');
  if (!payload || !sig) return null;
  const expected = crypto.createHmac('sha256', SECRET).update(payload).digest('base64url');
  if (sig.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    return data.exp > Date.now() ? data : null;
  } catch (e) {
    return null;
  }
}

app.post('/api/admin/login', (req, res) => {
  const { user, pass } = req.body || {};
  if (user === db.admin.user && checkPw(pass, db.admin)) {
    return res.json({ ok: true, token: makeToken(user) });
  }
  return res.status(401).json({ ok: false, error: 'Invalid credentials' });
});

app.get('/api/orders', (req, res) => {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  if (!verifyToken(token)) return res.status(401).json({ error: 'Unauthorized' });
  res.json(db.orders || []);
});

app.post('/api/orders', (req, res) => {
  const order = Object.assign({ id: Date.now().toString(), createdAt: new Date().toISOString() }, req.body || {});
  db.orders.unshift(order);
  flush();
  res.status(201).json({ ok: true, order });
});

app.get('/admin', (req, res) => {
  const adminHtml = path.join(__dirname, 'admin.html');
  if (fs.existsSync(adminHtml)) return res.sendFile(adminHtml);
  res.send('<h1>Admin Panel</h1><p>Server is running.</p>');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server listening on ${PORT}`));
