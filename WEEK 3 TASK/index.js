const express = require('express');
const helmet = require('helmet');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const validator = require('validator');
const winston = require('winston');
const authenticateToken = require('./Middleware/authenticateToken');

const app = express();
app.use(express.json());

// WEEK 2: Security Headers
app.use(helmet()); 

// WEEK 3: Logging
const logger = winston.createLogger({
    transports: [
        new winston.transports.Console(),
        new winston.transports.File({ filename: 'security.log' })
    ]
});

// Mock Database
const users = [];

// WEEK 2: Secure Registration
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).send("Missing credentials");
    
    const hashedPassword = await bcrypt.hash(password, 10);
    users.push({ username, password: hashedPassword });
    res.status(201).send("User Registered Successfully");
});

// WEEK 2: JWT Authentication
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);
    
    if (user && await bcrypt.compare(password, user.password)) {
        const token = jwt.sign({ username }, 'your-secret-key', { expiresIn: '1h' });
        logger.info(`Login attempt by ${username} at ${new Date().toISOString()}`);
        res.json({ message: "Authentication successful", token: token });
    } else {
        res.status(401).send("Invalid credentials");
    }
});

// WEEK 2 & 3: Protected CRUD Route
app.get('/list', authenticateToken, (req, res) => {
    res.status(200).send(users);
});

app.listen(3000, () => {
    console.log("Server Running on port 3000");
});