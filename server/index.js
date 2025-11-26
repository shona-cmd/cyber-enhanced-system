import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import morgan from 'morgan';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import dotenv from 'dotenv';
import https from 'https';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// ==== Security Middleware ====
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      scriptSrc: ["'self'"]
    }
  }
}));
app.use(cors({ origin: process.env.ALLOWED_ORIGIN, credentials: true }));
app.use(morgan('combined'));
app.use(express.json());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use('/api', limiter);

// ==== Simple Auth System (for demo - replace with real users later) ====
const users = [
  { id: 1, username: 'mtac-admin', password: '', role: 'admin' } // password: Mtac2025!
];

// Login route
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);
  if (!user || !await bcrypt.compare(password, user.password)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const token = jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: '8h' }
  );
  res.json({ token, role: user.role });
});

// Protected route middleware
const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

// ==== Protected API ====
app.get('/api/devices', authenticate, (req, res) => {
  const devices = [
    { id: 1, name: 'Temperature Sensor', status: 'online', value: 24.8, location: 'Server Room A', lastSeen: new Date() },
    { id: 2, name: 'Humidity Sensor', status: 'online', value: 58, location: 'Server Room A' },
    { id: 3, name: 'Motion Detector', status: 'online', value: 'active', location: 'Perimeter Gate' },
    { id: 4, name: 'Access Control', status: 'offline', alert: true, message: 'Door forced - Alert!' }
  ];
  res.json(devices);
});

app.get('/api/audit', authenticate, (req, res) => {
  res.json([
    { time: new Date(), user: 'mtac-admin', action: 'Logged in' },
    { time: new Date(), user: 'sensor-01', action: 'Reported anomaly' }
  ]);
});

// ==== HTTPS Server ====
const httpsOptions = {
  key: fs.readFileSync(path.join(__dirname, 'certs/key.pem')),
  cert: fs.readFileSync(path.join(__dirname, 'certs/cert.pem'))
};

https.createServer(httpsOptions, app).listen(3000, () => {
  console.log('NaashonSecureIoT Secure Backend Running on HTTPS port 3000');
  console.log('HTTPS: https://localhost:3000 (accept self-signed cert in browser)');
  console.log('Login: mtac-admin / Mtac2025!');
});

// Add HTTP server for local testing (non-SSL)
import http from 'http';
http.createServer(app).listen(3001, () => {
  console.log('NaashonSecureIoT Backend Running on HTTP port 3001 for local testing without SSL');
});

console.log('MTAC-Compliant Secure Server Starting...');
