// Minimal server for hosting the Container Cost Ledger dashboard.
// Render (and most hosts) set PORT automatically — we just need to listen on it.

const express = require('express');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;
const APP_USERNAME = process.env.APP_USERNAME;
const APP_PASSWORD = process.env.APP_PASSWORD;
const SESSION_SECRET = process.env.SESSION_SECRET;
const sharePointHeaders = {
  'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
  'Accept': 'application/octet-stream,application/vnd.ms-excel,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet,*/*',
  'Accept-Language': 'en-US,en;q=0.9',
};
const pool = process.env.DATABASE_URL ? new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
}) : null;

app.use(express.json({ limit: '10mb' }));

function sessionToken(username){
  const payload = Buffer.from(JSON.stringify({username, expires: Date.now() + 86400000})).toString('base64url');
  const signature = crypto.createHmac('sha256', SESSION_SECRET || '').update(payload).digest('base64url');
  return `${payload}.${signature}`;
}

function sessionUsername(req){
  if(!SESSION_SECRET) return null;
  const cookies = String(req.headers.cookie || '').split(';').map(value => value.trim());
  const token = cookies.find(value => value.startsWith('cst_session='))?.slice('cst_session='.length);
  if(!token) return null;
  const [payload, signature] = token.split('.');
  if(!payload || !signature) return null;
  const expected = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url');
  if(signature.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) return null;
  try{
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString());
    return data.expires > Date.now() ? data.username : null;
  }catch(error){
    return null;
  }
}

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/register', (req, res) => {
  res.redirect('/login');
});

app.post('/api/login', async (req, res) => {
  const {username, password} = req.body || {};
  if(!pool || !SESSION_SECRET){
    return res.status(503).json({error: 'Login is not configured on the server'});
  }
  const result = await pool.query('SELECT username, password_hash FROM users WHERE username = $1', [String(username || '').trim().toLowerCase()]);
  if(!result.rowCount || !(await bcrypt.compare(String(password || ''), result.rows[0].password_hash))){
    return res.status(401).json({error: 'Invalid username or password'});
  }
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  res.setHeader('Set-Cookie', `cst_session=${sessionToken(result.rows[0].username)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=86400${secure}`);
  res.json({ok: true});
});

app.post('/api/logout', (req, res) => {
  res.setHeader('Set-Cookie', 'cst_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0');
  res.json({ok: true});
});

app.use((req, res, next) => {
  if(sessionUsername(req)) return next();
  if(req.path.startsWith('/api/')) return res.status(401).json({error: 'Login required'});
  res.redirect('/login');
});

app.get('/change-password', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'change-password.html'));
});

app.patch('/api/me/password', async (req, res) => {
  const username = sessionUsername(req);
  const currentPassword = String(req.body?.currentPassword || '');
  const newPassword = String(req.body?.newPassword || '');
  if(newPassword.length < 8) return res.status(400).json({error: 'New password must be at least 8 characters'});
  const result = await pool.query('SELECT password_hash FROM users WHERE username = $1', [username]);
  if(!result.rowCount || !(await bcrypt.compare(currentPassword, result.rows[0].password_hash))){
    return res.status(401).json({error: 'Current password is incorrect'});
  }
  const passwordHash = await bcrypt.hash(newPassword, 12);
  await pool.query('UPDATE users SET password_hash = $1 WHERE username = $2', [passwordHash, username]);
  res.json({ok: true});
});

async function requireAdmin(req, res, next){
  if(!pool) return res.status(503).json({error: 'Database is not configured'});
  const username = sessionUsername(req);
  const result = await pool.query('SELECT username, display_name, role FROM users WHERE username = $1', [username]);
  if(!result.rowCount || result.rows[0].role !== 'admin') return res.status(403).json({error: 'Administrator access required'});
  req.user = result.rows[0];
  next();
}

app.get('/admin/users', requireAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin-users.html'));
});

app.get('/api/me', async (req, res) => {
  const result = await pool.query('SELECT display_name, username, role FROM users WHERE username = $1', [sessionUsername(req)]);
  res.json(result.rows[0] || {});
});

app.post('/api/admin/users', requireAdmin, async (req, res) => {
  const displayName = String(req.body?.displayName || '').trim();
  const password = String(req.body?.password || '');
  if(displayName.length < 2 || password.length < 8){
    return res.status(400).json({error: 'Name and a password of 8+ characters are required'});
  }
  try{
    const baseUsername = displayName.toLowerCase().replace(/[^a-z0-9]+/g, '.').replace(/^\.|\.$/g, '') || 'user';
    let username = baseUsername;
    let suffix = 2;
    while((await pool.query('SELECT 1 FROM users WHERE username = $1', [username])).rowCount){
      username = baseUsername + suffix;
      suffix++;
    }
    const passwordHash = await bcrypt.hash(password, 12);
    await pool.query('INSERT INTO users (display_name, username, password_hash, role) VALUES ($1, $2, $3, $4)', [displayName, username, passwordHash, 'user']);
    res.json({ok: true, username});
  }catch(error){
    if(error.code === '23505') return res.status(409).json({error: 'That user ID already exists'});
    console.error('Admin user creation failed:', error);
    res.status(500).json({error: 'Could not create user'});
  }
});

app.get('/api/admin/users', requireAdmin, async (req, res) => {
  const result = await pool.query('SELECT display_name, username, role, created_at FROM users ORDER BY created_at DESC');
  res.json(result.rows);
});

app.patch('/api/admin/users/:username/password', requireAdmin, async (req, res) => {
  const password = String(req.body?.password || '');
  if(password.length < 8) return res.status(400).json({error: 'Password must be at least 8 characters'});
  const passwordHash = await bcrypt.hash(password, 12);
  const result = await pool.query('UPDATE users SET password_hash = $1 WHERE username = $2', [passwordHash, req.params.username.toLowerCase()]);
  if(!result.rowCount) return res.status(404).json({error: 'User not found'});
  res.json({ok: true});
});

app.delete('/api/admin/users/:username', requireAdmin, async (req, res) => {
  const username = req.params.username.toLowerCase();
  const target = await pool.query('SELECT role FROM users WHERE username = $1', [username]);
  if(!target.rowCount) return res.status(404).json({error: 'User not found'});
  if(target.rows[0].role === 'admin' || username === sessionUsername(req)){
    return res.status(400).json({error: 'Admin accounts cannot be deleted'});
  }
  await pool.query('DELETE FROM users WHERE username = $1', [username]);
  res.json({ok: true});
});

app.get('/api/cloud-file', requireAdmin, async (req, res) => {
  const sourceUrl = String(req.query.url || '');
  if(!/^https?:\/\//i.test(sourceUrl)){
    return res.status(400).json({error: 'A public http(s) file URL is required'});
  }
  try{
    const separator = sourceUrl.includes('?') ? '&' : '?';
    const candidates = [
      sourceUrl + separator + 'download=1',
      sourceUrl + separator + 'download=1&raw=1',
      sourceUrl.replace(/\?.*$/, '') + '?download=1',
      sourceUrl,
    ];
    let lastStatus = 502;
    for(const candidate of candidates){
      const response = await fetch(candidate, {redirect: 'follow', headers: sharePointHeaders});
      lastStatus = response.status;
      if(!response.ok) continue;
      const buffer = Buffer.from(await response.arrayBuffer());
      const contentType = response.headers.get('content-type') || '';
      const isWorkbook = buffer.subarray(0, 2).toString() === 'PK' || contentType.includes('excel');
      if(isWorkbook){
        return res.type('application/octet-stream').send(buffer);
      }
    }
    return res.status(lastStatus === 200 ? 422 : lastStatus).json({error: 'SharePoint did not return the Excel file. Use the file upload, or create a new Anyone-with-the-link view-only link.'});
  }catch(error){
    console.error('Cloud file fetch failed:', error);
    res.status(502).json({error: 'Could not download the cloud file. Check that the link is public.'});
  }
});

async function ensureDatabase(){
  if(!pool) return;
  await pool.query(`
    CREATE TABLE IF NOT EXISTS shipment_rows (
      id BIGSERIAL PRIMARY KEY,
      data JSONB NOT NULL
    );
    CREATE TABLE IF NOT EXISTS daywise_rows (
      id BIGSERIAL PRIMARY KEY,
      data JSONB NOT NULL
    );
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      display_name TEXT NOT NULL,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'user';
  `);
  if(APP_USERNAME && APP_PASSWORD){
    const passwordHash = await bcrypt.hash(APP_PASSWORD, 12);
    await pool.query(`
      INSERT INTO users (display_name, username, password_hash)
      VALUES ($1, $2, $3)
      ON CONFLICT (username) DO UPDATE SET role = 'admin'
    `, [APP_USERNAME, APP_USERNAME.toLowerCase(), passwordHash]);
  }
}

app.get('/api/data', async (req, res) => {
  if(!pool) return res.status(503).json({error: 'DATABASE_URL is not configured'});
  try{
    const [shipments, daywise] = await Promise.all([
      pool.query('SELECT data FROM shipment_rows ORDER BY id'),
      pool.query('SELECT data FROM daywise_rows ORDER BY id'),
    ]);
    res.json({
      shipRows: shipments.rows.map(row => row.data),
      daywiseRows: daywise.rows.map(row => row.data),
    });
  }catch(error){
    console.error('Database read failed:', error);
    res.status(500).json({error: 'Could not read dashboard data'});
  }
});

app.put('/api/data', async (req, res) => {
  if(!pool) return res.status(503).json({error: 'DATABASE_URL is not configured'});
  const user = await pool.query('SELECT role FROM users WHERE username = $1', [sessionUsername(req)]);
  if(!user.rowCount || user.rows[0].role !== 'admin') return res.status(403).json({error: 'Only administrators can upload or sync files'});
  const {shipRows, daywiseRows} = req.body || {};
  if(!Array.isArray(shipRows) || !Array.isArray(daywiseRows)){
    return res.status(400).json({error: 'shipRows and daywiseRows must be arrays'});
  }
  const client = await pool.connect();
  try{
    await client.query('BEGIN');
    await client.query('TRUNCATE shipment_rows, daywise_rows');
    for(const row of shipRows) await client.query('INSERT INTO shipment_rows (data) VALUES ($1)', [row]);
    for(const row of daywiseRows) await client.query('INSERT INTO daywise_rows (data) VALUES ($1)', [row]);
    await client.query('COMMIT');
    res.json({saved: true, shipments: shipRows.length, daywise: daywiseRows.length});
  }catch(error){
    await client.query('ROLLBACK');
    console.error('Database write failed:', error);
    res.status(500).json({error: 'Could not save dashboard data'});
  }finally{
    client.release();
  }
});

// Serve everything in /public (index.html, and any assets you add later)
app.use(express.static(path.join(__dirname, 'public')));

// Fallback: always serve the dashboard for any route
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Container Cost Ledger running on port ${PORT}`);
  ensureDatabase().catch(error => {
    console.error('Database setup failed; app remains available:', error);
  });
});
