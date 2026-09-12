// Minimal server for hosting the Container Cost Ledger dashboard.
// Render (and most hosts) set PORT automatically — we just need to listen on it.

const express = require('express');
const path = require('path');
const crypto = require('crypto');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;
const APP_USERNAME = process.env.APP_USERNAME;
const APP_PASSWORD = process.env.APP_PASSWORD;
const SESSION_SECRET = process.env.SESSION_SECRET;
const pool = process.env.DATABASE_URL ? new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
}) : null;

app.use(express.json({ limit: '10mb' }));

function sessionToken(){
  return crypto.createHmac('sha256', SESSION_SECRET || '').update(APP_USERNAME || '').digest('hex');
}

function isAuthenticated(req){
  if(!APP_USERNAME || !APP_PASSWORD || !SESSION_SECRET) return false;
  const cookies = String(req.headers.cookie || '').split(';').map(value => value.trim());
  const token = cookies.find(value => value.startsWith('cst_session='))?.slice('cst_session='.length);
  if(!token) return false;
  const expected = sessionToken();
  return token.length === expected.length && crypto.timingSafeEqual(Buffer.from(token), Buffer.from(expected));
}

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.post('/api/login', (req, res) => {
  const {username, password} = req.body || {};
  if(!APP_USERNAME || !APP_PASSWORD || !SESSION_SECRET){
    return res.status(503).json({error: 'Login is not configured on the server'});
  }
  if(username !== APP_USERNAME || password !== APP_PASSWORD){
    return res.status(401).json({error: 'Invalid username or password'});
  }
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  res.setHeader('Set-Cookie', `cst_session=${sessionToken()}; HttpOnly; SameSite=Lax; Path=/; Max-Age=86400${secure}`);
  res.json({ok: true});
});

app.post('/api/logout', (req, res) => {
  res.setHeader('Set-Cookie', 'cst_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0');
  res.json({ok: true});
});

app.use((req, res, next) => {
  if(isAuthenticated(req)) return next();
  if(req.path.startsWith('/api/')) return res.status(401).json({error: 'Login required'});
  res.redirect('/login');
});

app.get('/api/cloud-file', async (req, res) => {
  const sourceUrl = String(req.query.url || '');
  if(!/^https?:\/\//i.test(sourceUrl)){
    return res.status(400).json({error: 'A public http(s) file URL is required'});
  }
  try{
    const response = await fetch(sourceUrl, {redirect: 'follow'});
    if(!response.ok) return res.status(response.status).json({error: `Cloud file returned HTTP ${response.status}`});
    const buffer = Buffer.from(await response.arrayBuffer());
    res.type('application/octet-stream').send(buffer);
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
  `);
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

ensureDatabase().then(() => {
  app.listen(PORT, () => {
    console.log(`Container Cost Ledger running on port ${PORT}`);
  });
}).catch(error => {
  console.error('Database setup failed:', error);
  process.exit(1);
});
