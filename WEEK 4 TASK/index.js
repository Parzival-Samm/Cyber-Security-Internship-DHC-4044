const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const winston = require('winston');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

const JWT_SECRET = "DHC-4044-SUPER-SECRET-KEY-2026";

const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    ),
    transports: [
        new winston.transports.File({ filename: 'security.log' })
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
    allowedHeaders: ['Content-Type', 'Authorization'],
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

// Delete the old static mockUser and replace it with this:
const mockUser = {
    username: "admin",
    passwordHash: bcrypt.hashSync("admin123", 10) // Generates a flawless hash on startup
};

app.post('/login', loginLimiter, async (req, res) => {
    const { username, password } = req.body;
    const clientIp = req.ip;

    console.log("➡️ SERVER RECEIVED:", req.body);

    // Strict parameter evaluation
    if (!username || !password) {
        return res.status(400).json({ error: "Missing required identification parameters" });
    }

    // Secure authentication check via Bcrypt comparison
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

    // ➡️ ADD THIS LINE HERE TO SNIFF THE TOKEN:
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

const PORT = 3000;
app.listen(PORT, () => {
    console.log(`\n==============================================`);
    console.log(`🚀 SECURE SERVER IS ACTIVE AND RUNNING`);
    console.log(`📡 Listening on: http://localhost:${PORT}`);
    console.log(`==============================================\n`);
});