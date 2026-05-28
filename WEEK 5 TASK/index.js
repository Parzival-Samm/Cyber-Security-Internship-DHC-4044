const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const winston = require('winston');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// 🛠️ WEEK 5 LIBRARIES EXTENSION
const cookieParser = require('cookie-parser');
const csrf = require('csurf');
const sqlite3 = require('sqlite3').verbose();

const app = express();
app.use(express.json());
app.use(cookieParser()); // Required to parse tracking elements for CSRF double-submit cookies

const JWT_SECRET = "DHC-4044-SUPER-SECRET-KEY-2026";

// Winston telemetry module configuration
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    ),
    transports: [
        new winston.transports.File({ filename: 'security.log' }),
        new winston.transports.File({ filename: 'security_week5.log' }) // Appends Week 5 specific audits separate
    ]
});

const failedLoginAttempts = {};

const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { error: 'Too many requests from this IP, please try again later.' }
});
app.use(globalLimiter);

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: { error: 'Brute-force protection: Too many login attempts. Automated lockout initiated.' }
});

const corsOptions = {
    origin: ['http://localhost:3000', 'https://localhost:8443'], 
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token'], // Allowed token tracking header values
    credentials: true,
    optionsSuccessStatus: 200
};
app.use(cors(corsOptions));

app.use(
    helmet({
        contentSecurityPolicy: {
            directives: {
                defaultSrc: ["'self'"],
                scriptSrc: ["'self'", "'trusted-cdn.com'"], 
                styleSrc: ["'self'", "'fonts.googleapis.com'"],
                imgSrc: ["'self'", "data:"],
                connectSrc: ["'self'"],
                upgradeInsecureRequests: [], 
            },
        },
        hsts: {
            maxAge: 31536000,
            includeSubDomains: true,
            preload: true
        }
    })
);

// Native Mock User Database Profile (Week 4 Core Setup)
const mockUser = {
    username: "admin",
    passwordHash: bcrypt.hashSync("admin123", 10)
};

// =========================================================================
// 🗄️ WEEK 5 DATABASE CORE INITIALIZATION (SQLite In-Memory Lab Sandbox)
// =========================================================================
const db = new sqlite3.Database(':memory:');

db.serialize(() => {
    db.run("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, role TEXT)");
    db.run("INSERT INTO users (username, role) VALUES ('admin', 'Administrator')");
    db.run("INSERT INTO users (username, role) VALUES ('analyst', 'Security Analyst')");
});

// Configure custom cookie tracking for double-submit checks
const csrfProtection = csrf({ cookie: true });

// =========================================================================
// 🔑 PRE-EXISTING AUTHENTICATION ROUTING INTERFACES (Week 4 Work Kept Intact)
// =========================================================================

app.post('/login', loginLimiter, async (req, res) => {
    const { username, password } = req.body;
    const clientIp = req.ip;

    console.log("➡️ SERVER RECEIVED:", req.body);

    if (!username || !password) {
        return res.status(400).json({ error: "Missing required identification parameters" });
    }

    if (username === mockUser.username && await bcrypt.compare(password, mockUser.passwordHash)) {
        failedLoginAttempts[clientIp] = 0; 
        
        const token = jwt.sign({ user: username }, JWT_SECRET, { expiresIn: '1h' });
        logger.info({ message: `Successful authentication verified for user: ${username}`, ip: clientIp });
        
        return res.json({ token: token });
    } else {
        failedLoginAttempts[clientIp] = (failedLoginAttempts[clientIp] || 0) + 1;
        logger.warn({ message: `Failed authentication validation attempt for user: ${username}`, ip: clientIp });

        if (failedLoginAttempts[clientIp] >= 3) {
            logger.error({ 
                alert: "INTRUSION DETECTION ALERT", 
                message: `Suspicious activity detected: ${failedLoginAttempts[clientIp]} consecutive failed logins from IP address: ${clientIp}`,
                timestamp: new Date()
            });
        }

        return res.status(401).json({ error: "Invalid credentials" });
    }
});

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        logger.warn({ message: "Unauthorized resource access blocked: Missing token parameter." });
        return res.status(401).json({ error: "Access Denied: Missing authentication token" });
    }

    console.log("👀 SERVER IS CURRENTLY VERIFYING THIS TOKEN:", token.substring(0, 25) + "...");

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            console.log("❌ JWT VERIFICATION FAILED:", err.message);
            return res.status(403).json({ error: "Access Denied: Invalid token", reason: err.message });
        }
        req.user = user;
        next();
    });
};

app.get('/list', authenticateToken, (req, res) => {
    res.json({
        status: "Success",
        environment: "Production Secure Environment Backend",
        data: ["System Profile", "Network Log Integrity Metrics", "Operational Logs"]
    });
});

// =========================================================================
// 🎯 NEW ROUTING ADDITIONS: WEEK 5 LABORATORY EXPANSION
// =========================================================================

// 🧼 Task 2A: SQL Injection Vulnerable Pathway (Dynamic Concatenation)
app.get('/api/v1/search-vulnerable', (req, res) => {
    const userParam = req.query.username || '';
    const executionQuery = `SELECT * FROM users WHERE username = '${userParam}'`;
    
    console.log(`📡 EXECUTING INSECURE SQL QUERY: ${executionQuery}`);
    
    db.all(executionQuery, [], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json({ status: "Success", data: rows });
    });
});

// 🛡️ Task 2B: SQL Injection Secure Mitigation Pathway (Parameterized/Prepared)
app.get('/api/v1/search-secure', (req, res) => {
    const userParam = req.query.username || '';
    const secureQuery = `SELECT * FROM users WHERE username = ?`;
    
    console.log(`🛡️ EXECUTING SECURE PARAMETERIZED QUERY: ${secureQuery} | bound: [${userParam}]`);
    
    db.all(secureQuery, [userParam], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json({ status: "Success", data: rows });
    });
});

// 🎟️ Task 3A: CSRF Cryptographic Token Handshake Vending Machine
app.get('/api/v1/csrf-token', csrfProtection, (req, res) => {
    res.json({ csrfToken: req.csrfToken() });
});

// 🔒 Task 3B: CSRF Secure State-Change Endpoint (Profile Engine Simulation)
app.post('/api/v1/update-profile', csrfProtection, (req, res) => {
    const { role } = req.body;
    res.json({ 
        status: "Success", 
        message: "Security configuration values modified securely.", 
        updatedRole: role 
    });
});

// 🛑 Core Overriding CSRF Threat Failure Signature Trap Error Handler
app.use((err, req, res, next) => {
    if (err.code === 'EBADCSRFTOKEN') {
        logger.error({ 
            alert: "CSRF Validation Attack Vector Blocked", 
            message: "Cross-Site Request Forgery verification failed. Request dropped.", 
            ip: req.ip,
            timestamp: new Date()
        });
        return res.status(403).json({ error: "Cross-Site Request Forgery verification failed. Request dropped." });
    }
    next(err);
});

// =========================================================================
// 🚀 APP INCEPTION
// =========================================================================
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`\n==============================================`);
    console.log(`🚀 SECURE SERVER IS ACTIVE AND RUNNING`);
    console.log(`📡 Listening on: http://localhost:${PORT}`);
    console.log(`==============================================\n`);
});