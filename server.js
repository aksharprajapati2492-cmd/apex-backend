const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_trading_jwt_key_2026';
const DB_FILE = path.join(__dirname, 'database.json');

// Security Headers & Middleware
app.use(helmet());
app.use(cors());
app.use(express.json());

// Rate Limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { error: 'Too many requests, please try again later.' }
});
app.use('/api/', limiter);

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: { error: 'Too many login attempts. Please try again later.' }
});

// Initialize JSON Database
function readDB() {
    if (!fs.existsSync(DB_FILE)) {
        const initialData = {
            users: [{ id: 1, username: 'ax4r', password: '' }],
            trades: []
        };
        // Hash default password 'ax4r'
        bcrypt.hash('ax4r', 10, (err, hash) => {
            if (!err) {
                initialData.users[0].password = hash;
                fs.writeFileSync(DB_FILE, JSON.stringify(initialData, null, 2));
            }
        });
        return initialData;
    }
    return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
}

function writeDB(data) {
    fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}

// Ensure DB is initialized on startup
readDB();

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
// 3. Add Trade
app.post('/api/trades', authenticateToken, (req, res) => {
    const { symbol, strike, type, lotSize, lots, entryPrice, exitPrice, commission, netPnl, capitalUsed, notes } = req.body;
    const db = readDB();
    
    const newTrade = {
        id: Date.now(),
        user_id: req.user.id,
        date: new Date().toISOString().split('T')[0],
        symbol, strike, type, lotSize, lots, entryPrice, exitPrice, commission, netPnl, capitalUsed, notes: notes || ''
    };

    db.trades.push(newTrade);
    writeDB(db);
    res.json({ id: newTrade.id, success: true });
});

// 4. Delete Trade
app.delete('/api/trades/:id', authenticateToken, (req, res) => {
    const db = readDB();
    const tradeId = Number(req.params.id);
    const initialLength = db.trades.length;
    
    db.trades = db.trades.filter(t => !(t.id === tradeId && t.user_id === req.user.id));
    
    if (db.trades.length !== initialLength) {
        writeDB(db);
        res.json({ success: true });
    } else {
        res.status(404).json({ error: 'Trade not found' });
    }
});

app.listen(PORT, () => {
    console.log(`Secure Trading Backend running on port ${PORT}`);
});