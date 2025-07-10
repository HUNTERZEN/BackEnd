require('dotenv').config(); // Load env vars

console.log('DB_USER:', process.env.DB_USER);
console.log('DB_PASSWORD:', process.env.DB_PASSWORD ? '[SET]' : '[NOT SET]');

const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer'); // Added for email

const app = express();
app.use(express.json()); // Parse JSON in request body

// MySQL Connection
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT || 3306
});

db.connect(err => {
  if (err) {
    console.error('Database connection failed:', err);
    return;
  }
  console.log('Connected to MySQL database');
});

// JWT secret key
const JWT_SECRET = process.env.JWT_SECRET || 'your_secret_key';

// Nodemailer setup
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,     // Your Gmail address
    pass: process.env.EMAIL_PASS      // App password
  }
});

// ------------------ API Routes ------------------ //

// 🧾 Sign Up (Registration)
app.post('/api/signup', async (req, res) => {
  const { username, password, email } = req.body;

  if (!username || !password || !email) {
    return res.status(400).json({ error: 'Username, password, and email are required' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    db.query(
      'INSERT INTO users (username, password, email) VALUES (?, ?, ?)',
      [username, hashedPassword, email],
      (err) => {
        if (err) {
          if (err.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ error: 'Username already exists' });
          }
          return res.status(500).json({ error: 'Database error' });
        }

        // Send welcome email
        const mailOptions = {
          from: process.env.EMAIL_USER,
          to: email,
          subject: 'Welcome to Our App!',
          text: `Hello ${username},\n\nThank you for registering. We're glad to have you!`
        };

        transporter.sendMail(mailOptions, (error, info) => {
          if (error) {
            console.error('Failed to send welcome email:', error);
          } else {
            console.log('Email sent: ' + info.response);
          }
        });

        res.status(201).json({ message: 'User registered and welcome email sent' });
      }
    );
  } catch (error) {
    res.status(500).json({ error: 'Server error during sign up' });
  }
});

// 🔐 Login
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  db.query(
    'SELECT * FROM users WHERE username = ?',
    [username],
    async (err, results) => {
      if (err || results.length === 0) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      const user = results[0];
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      const token = jwt.sign({ userId: user.id, username: user.username }, JWT_SECRET, { expiresIn: '1h' });

      res.json({ message: 'Login successful', token });
    }
  );
});

// 🚪 Logout
app.post('/api/logout', (req, res) => {
  res.json({ message: 'Logout successful. Please delete the token on client side.' });
});

// 🔒 Protected Profile Route
app.get('/api/profile', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Token required' });

  const token = authHeader.split(' ')[1];
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });

    res.json({ message: 'Access granted', user: decoded });
  });
});

// 📧 Test Email Route (Optional)
app.post('/api/send-email', (req, res) => {
  const { to, subject, text } = req.body;

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to,
    subject,
    text
  };

  transporter.sendMail(mailOptions, (err, info) => {
    if (err) {
      console.error('Email send failed:', err);
      return res.status(500).json({ error: 'Email failed to send' });
    }
    res.json({ message: 'Email sent!', info });
  });
});

// ------------------ Server Start ------------------ //
const PORT = process.env.APP_PORT || 8080;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
