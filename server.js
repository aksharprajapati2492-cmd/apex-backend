const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_trading_jwt_key_2026';

// Security Headers (Helmet)
app.use(helmet());
app.use(cors());
app.use(express.json());

// Rate Limiting (Prevent Brute-Force & DDoS)
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: { error: 'Too many requests from this IP, please try again after 15 minutes.' }
});
app.use('/api/', limiter);

// Strict Login Rate Limiter (Prevent Brute Force on Auth)
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5, // 5 login attempts per 15 minutes
    message: { error: 'Too many login attempts. Please try again later.' }
});

// Database Initialization (SQLite with Parameterized Queries for SQL Injection Prevention)
const db = new sqlite3.Database('./trading_journal.db', (err) => {
    if (err) console.error('Database opening error: ', err.message);
    else console.log('Connected to SQLite database.');
});

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS trades (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        date TEXT,
        symbol TEXT,
        strike TEXT,
        type TEXT,
        lotSize INTEGER,
        lots INTEGER,
        entryPrice REAL,
        exitPrice REAL,
        commission REAL,
        netPnl REAL,
        capitalUsed REAL,
        notes TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);

    // Seed default user: ax4r / ax4r
    const saltRounds = 10;
    bcrypt.hash('ax4r', saltRounds, (err, hash) => {
        if (!err) {
            db.run(`INSERT OR IGNORE INTO users (id, username, password) VALUES (1, 'ax4r', ?)`, [hash]);
        }
    });
});

// Authentication Middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Access token required' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid or expired token' });
        req.user = user;
        next();
    });
}

// 1. Login Route (Protected against SQL Injection via parameterized queries)
app.post('/api/login', loginLimiter, (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }

    // Parameterized query prevents SQL Injection completely
    db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
        if (err) return res.status(500).json({ error: 'Internal server error' });
        if (!user) return res.status(401).json({ error: 'Invalid username or password' });

        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.status(401).json({ error: 'Invalid username or password' });

        const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ token, username: user.username });
    });
});

// 2. Get Trades for Authenticated User
app.get('/api/trades', authenticateToken, (req, res) => {
    db.all(`SELECT * FROM trades WHERE user_id = ? ORDER BY id DESC`, [req.user.id], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

// 3. Add Trade
app.post('/api/trades', authenticateToken, (req, res) => {
    const { date, symbol, strike, type, lotSize, lots, entryPrice, exitPrice, commission, netPnl, capitalUsed, notes } = req.body;
    
    const query = `INSERT INTO trades (user_id, date, symbol, strike, type, lotSize, lots, entryPrice, exitPrice, commission, netPnl, capitalUsed, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;
    db.run(query, [req.user.id, date, symbol, strike, type, lotSize, lots, entryPrice, exitPrice, commission, netPnl, capitalUsed, notes], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ id: this.lastID, success: true });
    });
});

// 4. Delete Trade
app.delete('/api/trades/:id', authenticateToken, (req, res) => {
    db.run(`DELETE FROM trades WHERE id = ? AND user_id = ?`, [req.params.id, req.user.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, deletedCount: this.changes });
    });
});

app.listen(PORT, () => {
    console.log(`Secure Trading Backend running on port ${PORT}`);
});