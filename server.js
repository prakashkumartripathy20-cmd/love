const express = require('express');
const path = require('path');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();

const SECRET_KEY = "Local_StudentPortal_Secret"; // Static key for local testing

// Initialize SQLite Database
const db = new sqlite3.Database(path.join(__dirname, 'portal.db'));
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS bookings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        regNumber TEXT,
        mobile TEXT,
        branch TEXT,
        semester TEXT,
        subjects TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS settings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key TEXT UNIQUE,
        value TEXT
    )`);
    
    // Initialize default passkey if not set
    db.get("SELECT value FROM settings WHERE key = 'system_passkey'", (err, row) => {
        if (!row) {
            db.run("INSERT INTO settings (key, value) VALUES ('system_passkey', '00000000')");
        }
    });
});

// Serve Static Frontend Files
app.use(express.static(path.join(__dirname, 'public')));

app.use(express.json()); // Parses application/json bodies

// Secure API Endpoints (Phase 2 Implementation)
app.post('/api/login', (req, res) => {
    const { passkey } = req.body;
    
    // Check database for custom passkey override first
    db.get("SELECT value FROM settings WHERE key = 'system_passkey'", (err, row) => {
        const customPasskey = row ? row.value : '00000000';
        
        const d = new Date();
        const dynamicExpected = String(d.getDate()).padStart(2, '0') + 
                               String(d.getFullYear()) + 
                               String(d.getMonth() + 1).padStart(2, '0');
        
        const expected = (customPasskey === '00000000') ? dynamicExpected : customPasskey;
                         
        if(passkey === expected) {
            const token = jwt.sign({ role: 'student' }, SECRET_KEY, { expiresIn: '2h' });
            return res.json({ success: true, token, message: "Authentication Confirmed" });
        } else {
            return res.status(401).json({ success: false, message: "Invalid Passkey Signature" });
        }
    });
});

const ADMIN_HASH = bcrypt.hashSync("6370000001", 10);

app.post('/api/admin', (req, res) => {
    const { phone } = req.body;
    if(phone && bcrypt.compareSync(phone, ADMIN_HASH)) {
        const token = jwt.sign({ role: 'admin' }, SECRET_KEY, { expiresIn: '1h' });
        return res.json({ success: true, token, message: "Admin Authenticated" });
    } else {
        return res.status(401).json({ success: false, message: "Invalid Admin Credentials" });
    }
});

app.post('/api/book-subjects', (req, res) => {
    // 1. Verify Authorization Token
    const authHeader = req.headers['authorization'];
    if(!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Unauthorized Access. Missing Token.' });
    }
    
    const token = authHeader.split(' ')[1];
    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if(err) {
            return res.status(403).json({ error: 'Forbidden: Invalid or Expired Token' });
        }
        
        // 2. Insert into local SQLite database securely
        const { name, regNumber, contact, branch, semester, subjects } = req.body;
        
        // Handle subjects if provided as array or string
        const subjectsStr = Array.isArray(subjects) ? subjects.join(', ') : (subjects || "");
        
        const stmt = db.prepare("INSERT INTO bookings (name, regNumber, mobile, branch, semester, subjects) VALUES (?, ?, ?, ?, ?, ?)");
        stmt.run(name, regNumber, contact, branch, semester, subjectsStr, function(error) {
            if(error) {
                console.error("Database Insert Error: ", error);
                return res.status(500).json({ error: 'Database Internal Error' });
            }
            res.json({ success: true, message: "Booking securely logged into internal database." });
        });
        stmt.finalize();
    });
});

// Admin: Get all bookings
app.get('/api/bookings', (req, res) => {
    const authHeader = req.headers['authorization'];
    if(!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    
    const token = authHeader.split(' ')[1];
    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if(err || decoded.role !== 'admin') {
            return res.status(403).json({ error: 'Forbidden' });
        }
        
        db.all("SELECT * FROM bookings ORDER BY timestamp DESC", [], (err, rows) => {
            if(err) {
                return res.status(500).json({ error: 'Database Error' });
            }
            res.json({ success: true, bookings: rows });
        });
    });
});

// Admin: Update passkey
app.post('/api/update-passkey', (req, res) => {
    const authHeader = req.headers['authorization'];
    if(!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    
    const token = authHeader.split(' ')[1];
    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if(err || decoded.role !== 'admin') {
            return res.status(403).json({ error: 'Forbidden' });
        }
        
        const { newPasskey } = req.body;
        db.run("UPDATE settings SET value = ? WHERE key = 'system_passkey'", [newPasskey || '00000000'], function(err) {
            if(err) {
                return res.status(500).json({ error: 'Database Error' });
            }
            res.json({ success: true, message: 'System passkey updated successfully' });
        });
    });
});

// Start Server
app.listen(PORT, () => {
    console.log(`Student Portal Secure Backend running on http://localhost:${PORT}`);
});
