// ============================================================
//  ParkSpace — Vehicle Parking Slot Reservation System
//  Backend Server (Node.js + Express + MySQL + JWT)
// ============================================================

const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = 3000;
const JWT_SECRET = crypto.randomBytes(32).toString('hex');

// ── Middleware ───────────────────────────────────────────────
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

// ── MySQL Connection Pool ───────────────────────────────────
const pool = mysql.createPool({
  host: 'localhost',
  user: 'root',
  password: '',          // XAMPP default: no password
  database: 'parkspace',
  port: 3306,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// ── Database Initialization ─────────────────────────────────
async function initDatabase() {
  const conn = await pool.getConnection();
  try {
    // Create tables if they don't exist
    await conn.query(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        role ENUM('user', 'admin') DEFAULT 'user',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await conn.query(`
      CREATE TABLE IF NOT EXISTS slots (
        id VARCHAR(10) PRIMARY KEY,
        status ENUM('available', 'occupied') DEFAULT 'available',
        vehicle VARCHAR(50) DEFAULT NULL
      )
    `);

    await conn.query(`
      CREATE TABLE IF NOT EXISTS reservations (
        id VARCHAR(20) PRIMARY KEY,
        user_id INT NOT NULL,
        slot_id VARCHAR(10) NOT NULL,
        date VARCHAR(20) NOT NULL,
        time VARCHAR(10) NOT NULL,
        duration INT NOT NULL,
        plate VARCHAR(20) NOT NULL,
        cost VARCHAR(20) NOT NULL,
        status ENUM('active', 'cancelled') DEFAULT 'active',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (slot_id) REFERENCES slots(id)
      )
    `);

    // Seed parking slots
    const [slotRows] = await conn.query('SELECT COUNT(*) as count FROM slots');
    if (slotRows[0].count === 0) {
      console.log('📦 Seeding parking slots...');
      const zones = ['A', 'B', 'C'];
      for (const zone of zones) {
        for (let i = 1; i <= 8; i++) {
          await conn.query(
            'INSERT INTO slots (id, status, vehicle) VALUES (?, ?, ?)',
            [`${zone}-${i}`, 'available', null]
          );
        }
      }
      console.log('✅ 24 parking slots created (A-1 to C-8)');
    }

    // Seed default admin account
    const [adminRows] = await conn.query('SELECT COUNT(*) as count FROM users WHERE role = ?', ['admin']);
    if (adminRows[0].count === 0) {
      const hashedPw = bcrypt.hashSync('admin123', 10);
      await conn.query(
        'INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)',
        ['Admin', 'admin@parkspace.com', hashedPw, 'admin']
      );
      console.log('✅ Default admin created: admin@parkspace.com / admin123');
    }

    console.log('✅ MySQL database ready');
  } finally {
    conn.release();
  }
}

// ── Auth Middleware ──────────────────────────────────────────
function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  try {
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// Admin-only middleware
function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
}

// ── ROUTES ──────────────────────────────────────────────────

// ─── Auth Routes ────────────────────────────────────────────

// POST /api/register — Create a new USER account (not admin)
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Name, email, and password are required' });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    // Check if email already exists
    const [existing] = await pool.query('SELECT id FROM users WHERE email = ?', [email]);
    if (existing.length > 0) {
      return res.status(409).json({ error: 'Email already registered' });
    }

    const hashedPassword = bcrypt.hashSync(password, 10);
    const [result] = await pool.query(
      'INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)',
      [name, email, hashedPassword, 'user']
    );

    const token = jwt.sign(
      { id: result.insertId, name, email, role: 'user' },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.status(201).json({
      message: 'Account created successfully',
      token,
      user: { id: result.insertId, name, email, role: 'user' }
    });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /api/login — Authenticate user (returns role for routing)
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const [users] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    if (users.length === 0) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const user = users[0];
    const valid = bcrypt.compareSync(password, user.password);
    if (!valid) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const token = jwt.sign(
      { id: user.id, name: user.name, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: { id: user.id, name: user.name, email: user.email, role: user.role }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ─── Slot Routes (User) ────────────────────────────────────

// GET /api/slots — Get all parking slots
app.get('/api/slots', authenticate, async (req, res) => {
  try {
    const [slots] = await pool.query('SELECT * FROM slots ORDER BY id');
    res.json(slots);
  } catch (err) {
    console.error('Slots error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ─── Reservation Routes (User) ─────────────────────────────

// POST /api/reserve — Reserve a parking slot
app.post('/api/reserve', authenticate, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const { slotId, date, time, duration, plate } = req.body;

    if (!slotId || !date || !time || !duration || !plate) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    await conn.beginTransaction();

    // Lock the slot row for update (prevents race conditions / double booking)
    const [slotRows] = await conn.query('SELECT * FROM slots WHERE id = ? FOR UPDATE', [slotId]);
    if (slotRows.length === 0) {
      await conn.rollback();
      return res.status(404).json({ error: 'Slot not found' });
    }
    if (slotRows[0].status === 'occupied') {
      await conn.rollback();
      return res.status(409).json({ error: 'Slot is already occupied — double booking prevented!' });
    }

    // Check for active reservations on the same date
    const [conflicts] = await conn.query(
      'SELECT id FROM reservations WHERE slot_id = ? AND date = ? AND status = ?',
      [slotId, date, 'active']
    );
    if (conflicts.length > 0) {
      await conn.rollback();
      return res.status(409).json({ error: 'This slot already has an active reservation for this date' });
    }

    const cost = `$${(duration * 5).toFixed(2)}`;
    const bookingId = 'BKG-' + crypto.randomBytes(3).toString('hex').toUpperCase();

    // Update slot status
    await conn.query('UPDATE slots SET status = ?, vehicle = ? WHERE id = ?',
      ['occupied', plate.toUpperCase(), slotId]);

    // Create reservation
    await conn.query(
      'INSERT INTO reservations (id, user_id, slot_id, date, time, duration, plate, cost, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [bookingId, req.user.id, slotId, date, time, duration, plate.toUpperCase(), cost, 'active']
    );

    await conn.commit();

    res.status(201).json({
      message: `Slot ${slotId} reserved successfully!`,
      booking: { id: bookingId, slotId, date, time, duration, plate: plate.toUpperCase(), cost, status: 'active' }
    });
  } catch (err) {
    await conn.rollback();
    console.error('Reserve error:', err);
    res.status(500).json({ error: 'Server error' });
  } finally {
    conn.release();
  }
});

// GET /api/bookings — Get current user's active bookings
app.get('/api/bookings', authenticate, async (req, res) => {
  try {
    const [bookings] = await pool.query(
      'SELECT * FROM reservations WHERE user_id = ? AND status = ? ORDER BY created_at DESC',
      [req.user.id, 'active']
    );
    res.json(bookings);
  } catch (err) {
    console.error('Bookings error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// DELETE /api/reservation/:id — Cancel a reservation
app.delete('/api/reservation/:id', authenticate, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const [bookings] = await conn.query(
      'SELECT * FROM reservations WHERE id = ? AND user_id = ?',
      [req.params.id, req.user.id]
    );

    if (bookings.length === 0) {
      return res.status(404).json({ error: 'Reservation not found' });
    }

    const booking = bookings[0];
    if (booking.status === 'cancelled') {
      return res.status(400).json({ error: 'Reservation already cancelled' });
    }

    await conn.beginTransaction();

    await conn.query('UPDATE reservations SET status = ? WHERE id = ?', ['cancelled', booking.id]);
    await conn.query('UPDATE slots SET status = ?, vehicle = ? WHERE id = ?', ['available', null, booking.slot_id]);

    await conn.commit();
    res.json({ message: 'Reservation cancelled successfully' });
  } catch (err) {
    await conn.rollback();
    console.error('Cancel error:', err);
    res.status(500).json({ error: 'Server error' });
  } finally {
    conn.release();
  }
});

// ─── Admin Routes (Protected) ──────────────────────────────

// GET /api/admin/stats — Get dashboard stats
app.get('/api/admin/stats', authenticate, requireAdmin, async (req, res) => {
  try {
    const [totalRows] = await pool.query('SELECT COUNT(*) as count FROM slots');
    const [availRows] = await pool.query('SELECT COUNT(*) as count FROM slots WHERE status = ?', ['available']);
    const [occupiedRows] = await pool.query('SELECT COUNT(*) as count FROM slots WHERE status = ?', ['occupied']);
    const [userRows] = await pool.query('SELECT COUNT(*) as count FROM users WHERE role = ?', ['user']);
    const [bookingRows] = await pool.query('SELECT COUNT(*) as count FROM reservations WHERE status = ?', ['active']);

    res.json({
      total: totalRows[0].count,
      available: availRows[0].count,
      occupied: occupiedRows[0].count,
      totalUsers: userRows[0].count,
      activeBookings: bookingRows[0].count
    });
  } catch (err) {
    console.error('Stats error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/admin/slots — Get all slots with details
app.get('/api/admin/slots', authenticate, requireAdmin, async (req, res) => {
  try {
    const [slots] = await pool.query('SELECT * FROM slots ORDER BY id');
    res.json(slots);
  } catch (err) {
    console.error('Admin slots error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// PUT /api/admin/slot/:id — Toggle slot status
app.put('/api/admin/slot/:id', authenticate, requireAdmin, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const [slotRows] = await conn.query('SELECT * FROM slots WHERE id = ?', [req.params.id]);
    if (slotRows.length === 0) {
      return res.status(404).json({ error: 'Slot not found' });
    }

    const slot = slotRows[0];
    const newStatus = slot.status === 'available' ? 'occupied' : 'available';
    const vehicle = newStatus === 'occupied' ? 'ADMIN SET' : null;

    await conn.beginTransaction();

    await conn.query('UPDATE slots SET status = ?, vehicle = ? WHERE id = ?', [newStatus, vehicle, req.params.id]);

    // If freeing a slot, also cancel any active reservation on it
    if (newStatus === 'available') {
      await conn.query('UPDATE reservations SET status = ? WHERE slot_id = ? AND status = ?',
        ['cancelled', req.params.id, 'active']);
    }

    await conn.commit();
    res.json({ message: `Slot ${req.params.id} updated to ${newStatus}` });
  } catch (err) {
    await conn.rollback();
    console.error('Toggle slot error:', err);
    res.status(500).json({ error: 'Server error' });
  } finally {
    conn.release();
  }
});

// GET /api/admin/reservations — Get ALL reservations (admin view)
app.get('/api/admin/reservations', authenticate, requireAdmin, async (req, res) => {
  try {
    const [reservations] = await pool.query(`
      SELECT r.*, u.name as user_name, u.email as user_email 
      FROM reservations r 
      JOIN users u ON r.user_id = u.id 
      ORDER BY r.created_at DESC
    `);
    res.json(reservations);
  } catch (err) {
    console.error('Admin reservations error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/admin/users — Get all registered users
app.get('/api/admin/users', authenticate, requireAdmin, async (req, res) => {
  try {
    const [users] = await pool.query(
      'SELECT id, name, email, role, created_at FROM users ORDER BY created_at DESC'
    );
    res.json(users);
  } catch (err) {
    console.error('Admin users error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// DELETE /api/admin/reservation/:id — Admin permanently deletes a reservation
app.delete('/api/admin/reservation/:id', authenticate, requireAdmin, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const [rows] = await conn.query('SELECT * FROM reservations WHERE id = ?', [req.params.id]);
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Reservation not found' });
    }

    const reservation = rows[0];

    await conn.beginTransaction();

    // If the reservation was active, free the slot
    if (reservation.status === 'active') {
      await conn.query('UPDATE slots SET status = ?, vehicle = ? WHERE id = ?',
        ['available', null, reservation.slot_id]);
    }

    // Permanently delete the reservation
    await conn.query('DELETE FROM reservations WHERE id = ?', [req.params.id]);

    await conn.commit();
    res.json({ message: 'Reservation ' + req.params.id + ' deleted successfully' });
  } catch (err) {
    await conn.rollback();
    console.error('Admin delete reservation error:', err);
    res.status(500).json({ error: 'Server error' });
  } finally {
    conn.release();
  }
});

// ── Catch-all: serve index.html ─────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ── Start Server ────────────────────────────────────────────
async function startServer() {
  try {
    await initDatabase();
    app.listen(PORT, () => {
      console.log('');
      console.log('🚗 ═══════════════════════════════════════════');
      console.log('   ParkSpace — Parking Reservation System');
      console.log('   ─────────────────────────────────────────');
      console.log(`   🌐 Server:    http://localhost:${PORT}`);
      console.log('   🗄️  Database:  MySQL (parkspace)');
      console.log('   👤 Admin:     admin@parkspace.com / admin123');
      console.log('🚗 ═══════════════════════════════════════════');
      console.log('');
    });
  } catch (err) {
    console.error('❌ Failed to start server:', err.message);
    console.error('   Make sure MySQL is running on localhost:3306');
    process.exit(1);
  }
}

startServer();
