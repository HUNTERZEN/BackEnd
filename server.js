require('dotenv').config();

console.log('DB_USER:', process.env.DB_USER);
console.log('DB_PASSWORD:', process.env.DB_PASSWORD ? '[SET]' : '[NOT SET]');

const express = require('express');
const cors = require('cors');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const session = require('express-session');

// ✨ NEW: Twilio imports
const twilio = require('twilio');
const AccessToken = twilio.jwt.AccessToken;
const VideoGrant = AccessToken.VideoGrant;
const ChatGrant = AccessToken.ChatGrant;

const app = express();

// CORS Configuration
app.use(cors({
  origin: 'http://localhost:3000', // Update for your frontend port
  credentials: true
}));

app.use(express.json());

// Session Configuration
app.use(session({
  secret: process.env.SESSION_SECRET || 'some-strong-secret',
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

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

const JWT_SECRET = process.env.JWT_SECRET || 'your_secret_key';

// Nodemailer setup
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Google Strategy Configuration
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "/api/auth/google/callback"
  },
  (accessToken, refreshToken, profile, done) => {
    db.query('SELECT * FROM users WHERE google_id = ?', [profile.id], (err, results) => {
      if (err) return done(err);

      if (results.length > 0) {
        return done(null, results[0]);
      } else {
        db.query(
          'INSERT INTO users (username, email, google_id, password) VALUES (?, ?, ?, NULL)',
          [profile.displayName || '', profile.emails[0].value, profile.id],
          (insertErr, insertResult) => {
            if (insertErr) return done(insertErr);

            db.query('SELECT * FROM users WHERE id = ?', [insertResult.insertId], (err2, newResults) => {
              if (err2) return done(err2);
              return done(null, newResults[0]);
            });
          }
        );
      }
    });
  }
));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => {
  db.query('SELECT * FROM users WHERE id = ?', [id], (err, results) => {
    if (err) return done(err);
    done(null, results[0]);
  });
});

// ✨ NEW: Twilio Token Generation Route
app.post('/api/twilio/token', (req, res) => {
  const accountSid = process.env.TWILIO_ACCOUNT_SID;
  const apiKey = process.env.TWILIO_API_KEY;
  const apiSecret = process.env.TWILIO_API_SECRET;
  const chatServiceSid = process.env.TWILIO_CHAT_SERVICE_SID;

  const { identity, roomName } = req.body;

  // Check if Twilio credentials are configured
  if (!accountSid || !apiKey || !apiSecret) {
    console.error('Missing Twilio credentials');
    return res.status(500).json({ 
      error: 'Twilio credentials not configured',
      details: {
        accountSid: !!accountSid,
        apiKey: !!apiKey,
        apiSecret: !!apiSecret
      }
    });
  }

  try {
    // Create access token
    const token = new AccessToken(accountSid, apiKey, apiSecret, {
      identity: identity || `user_${Date.now()}`,
      ttl: 3600, // 1 hour
    });

    // Add video grant if roomName provided
    if (roomName) {
      const videoGrant = new VideoGrant({
        room: roomName,
      });
      token.addGrant(videoGrant);
      console.log(`Video grant added for room: ${roomName}`);
    }

    // Add chat grant if service configured
    if (chatServiceSid) {
      const chatGrant = new ChatGrant({
        serviceSid: chatServiceSid,
      });
      token.addGrant(chatGrant);
      console.log('Chat grant added');
    }

    const jwtToken = token.toJwt();
    console.log('Twilio token generated successfully for:', identity);

    res.json({
      token: jwtToken,
      identity: identity || `user_${Date.now()}`,
      roomName: roomName
    });
  } catch (error) {
    console.error('Error generating Twilio token:', error);
    res.status(500).json({ 
      error: 'Failed to generate token',
      message: error.message 
    });
  }
});

// ✨ NEW: Get Twilio Configuration Status
app.get('/api/twilio/status', (req, res) => {
  const status = {
    configured: !!(process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_API_KEY && process.env.TWILIO_API_SECRET),
    accountSid: !!process.env.TWILIO_ACCOUNT_SID,
    apiKey: !!process.env.TWILIO_API_KEY,
    apiSecret: !!process.env.TWILIO_API_SECRET,
    chatService: !!process.env.TWILIO_CHAT_SERVICE_SID
  };
  
  res.json(status);
});

// Google OAuth Routes
app.get('/api/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

// **UPDATED:** JWT-based Google callback
app.get('/api/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login', session: false }),
  (req, res) => {
    // Generate JWT token
    const token = jwt.sign(
      { userId: req.user.id, username: req.user.username, email: req.user.email },
      JWT_SECRET,
      { expiresIn: '1h' }
    );

    // Redirect to frontend with token
    const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:3000';
    res.redirect(`${frontendUrl}/?token=${token}`);
  }
);

// Session check endpoint for Google OAuth
app.get('/api/auth/check', (req, res) => {
  if (req.isAuthenticated && req.isAuthenticated()) {
    res.json({ 
      authenticated: true, 
      user: { 
        id: req.user.id, 
        username: req.user.username, 
        email: req.user.email 
      } 
    });
  } else {
    res.json({ authenticated: false });
  }
});

// Sign Up Route
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

// ✅ UPDATED LOGIN ROUTE - Returns user data along with token
app.post('/api/login', (req, res) => {
  const { login, password } = req.body;

  db.query(
    'SELECT * FROM users WHERE username = ? OR email = ?',
    [login, login],
    async (err, results) => {
      if (err || results.length === 0) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      const user = results[0];
      
      // Skip password check if user signed up with Google (password is NULL)
      if (user.password === null) {
        return res.status(401).json({ error: 'Please sign in with Google' });
      }

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      const token = jwt.sign(
        { userId: user.id, username: user.username, email: user.email }, // Include email
        JWT_SECRET, 
        { expiresIn: '1h' }
      );

      // ✅ RETURN BOTH TOKEN AND USER DATA
      res.json({ 
        message: 'Login successful', 
        token,
        user: {
          id: user.id,
          username: user.username,
          email: user.email
        }
      });
    }
  );
});

// ✅ UPDATED LOGOUT ROUTE - Handles both JWT and Google OAuth sessions
app.post('/api/logout', (req, res) => {
  // Destroy session if it exists (for Google OAuth users)
  if (req.session) {
    req.session.destroy((err) => {
      if (err) {
        console.error('Session destroy error:', err);
      }
    });
  }
  
  // Logout passport session if user is authenticated
  if (req.isAuthenticated && req.isAuthenticated()) {
    req.logout((err) => {
      if (err) console.error('Passport logout error:', err);
    });
  }
  
  // Clear session cookie - handles different possible cookie names
  res.clearCookie('connect.sid'); // Default express-session cookie name
  res.clearCookie('session'); // Alternative session cookie name
  
  // Clear any other auth-related cookies
  res.clearCookie('authToken');
  
  res.json({ 
    message: 'Logout successful. Please delete the token on client side.',
    success: true 
  });
});

// ✅ UPDATED PROFILE ROUTE - Returns user data in correct format
app.get('/api/profile', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Token required' });

  const token = authHeader.split(' ')[1];
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });

    // ✅ RETURN USER DATA IN CORRECT FORMAT
    res.json({ 
      message: 'Access granted', 
      user: {
        id: decoded.userId,
        username: decoded.username,
        email: decoded.email
      }
    });
  });
});

// Test Email Route
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

// Start Server
const PORT = process.env.APP_PORT || 8080;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log('Available endpoints:');
  console.log('  - POST /api/twilio/token (Generate Twilio token)');
  console.log('  - GET /api/twilio/status (Check Twilio configuration)');
  console.log('  - All existing endpoints...');
});
