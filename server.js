require('dotenv').config();
const fs = require('fs');
const path = require('path');
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const DATA_DIR = process.env.DATA_DIR || __dirname;
const USERS_FILE = path.join(DATA_DIR, 'users.json');

app.use(express.json());

const allowedOrigins = [
  /^https:\/\/Schousboe\.github\.io$/i,   
  /^https:\/\/[a-z0-9-]+\.github\.io\/.*$/i,    
  /^https:\/\/.*\.app\.github\.dev$/i               
];

app.use(cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true); 
    const ok = allowedOrigins.some((o) => o.test(origin));
    cb(ok ? null : new Error('CORS blocked'), ok);
  },
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

async function ensureUsersFile() {
  try {
    await fs.promises.access(USERS_FILE);
  } catch (_) {
    await fs.promises.writeFile(USERS_FILE, '[]', 'utf8');
  }
}

async function readUsers() {
  await ensureUsersFile();
  const raw = await fs.promises.readFile(USERS_FILE, 'utf8');
  return JSON.parse(raw);
}

async function writeUsers(users) {
  const tmp = USERS_FILE + '.tmp';
  await fs.promises.writeFile(tmp, JSON.stringify(users, null, 2), 'utf8');
  await fs.promises.rename(tmp, USERS_FILE); 
}

function isValidEmail(email) {
  return /.+@.+\..+/.test(email);
}

function isStrongPassword(pw) {
  return typeof pw === 'string' && pw.length >= 8; 
}

// Healthcheck
app.get('/healthz', (_req, res) => res.json({ ok: true }));

// REGISTER
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({ message: 'Fill out name, password and email' });
    }
    if (!isValidEmail(email)) {
      return res.status(400).json({ message: 'Not usable email.' });
    }
    if (!isStrongPassword(password)) {
      return res.status(400).json({ message: 'Password needs to be minimum 8 characters' });
    }

    const users = await readUsers();
    if (users.find(u => u.email.toLowerCase() === email.toLowerCase())) {
      return res.status(409).json({ message: 'Email is already registered' });
    }

    const hashed = await bcrypt.hash(password, 12); // 12 rounds of hashing
    users.push({ name, email, password: hashed, createdAt: new Date().toISOString() });
    await writeUsers(users);

    return res.json({ message: 'Registrering fuldført!' });
  } catch (err) {
    console.error('Registering error:', err);
    res.status(500).json({ message: 'Server fail while registering.' });
  }
});

// LOGIN
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ message: 'Fill out username and password' });
    }

    const users = await readUsers();
    const user = users.find(u => u.email.toLowerCase() === email.toLowerCase());
    if (!user) return res.status(400).json({ message: 'User not found.' });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(400).json({ message: 'Wrong password.' });

    const token = jwt.sign({ sub: user.email, name: user.name }, JWT_SECRET, { expiresIn: '1h' });
    return res.json({ message: `Velkommen, ${user.name}!`, token });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ message: 'Server fail while logging in' });
  }
});

// PROFIL (beskyttet)
app.get('/api/profile', (req, res) => {
  const auth = req.headers['authorization'] || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ message: 'Misses token.' });

  jwt.verify(token, JWT_SECRET, (err, payload) => {
    if (err) return res.status(403).json({ message: 'Not usable token.' });
    res.json({ message: `Hello ${payload.name}`, email: payload.sub });
  });
});

// 404 fallback
app.use((_req, res) => res.status(404).json({ message: 'Not found' }));

app.listen(PORT, () => {
  console.log(`Server kører på port ${PORT}`);
});