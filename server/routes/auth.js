import express from 'express';
import bcrypt from 'bcryptjs';
import { db } from '../db.js';
import { signToken, requireAuth, logAudit } from '../auth.js';

const router = express.Router();

// Admin Login
router.post('/login', (req, res) => {
  const { username, password } = req.body;
  const ipAddress = req.ip || req.connection?.remoteAddress || '127.0.0.1';

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user) {
    logAudit({
      adminUser: username,
      action: 'LOGIN_FAILED',
      target: 'AUTH',
      result: 'FAILED',
      ipAddress,
      details: 'User does not exist'
    });
    return res.status(401).json({ error: 'Invalid username or password' });
  }

  const match = bcrypt.compareSync(password, user.password_hash);
  if (!match) {
    logAudit({
      adminUser: username,
      action: 'LOGIN_FAILED',
      target: 'AUTH',
      result: 'FAILED',
      ipAddress,
      details: 'Password mismatch'
    });
    return res.status(401).json({ error: 'Invalid username or password' });
  }

  // Update last login
  const now = new Date().toISOString();
  db.prepare('UPDATE users SET last_login = ? WHERE id = ?').run(now, user.id);

  const token = signToken(user);

  logAudit({
    adminUser: username,
    action: 'LOGIN_SUCCESS',
    target: 'AUTH',
    result: 'SUCCESS',
    ipAddress,
    details: 'Administrator logged into security console'
  });

  res.json({
    token,
    user: {
      id: user.id,
      username: user.username,
      role: user.role,
      lastLogin: now
    }
  });
});

// Admin Logout
router.post('/logout', requireAuth, (req, res) => {
  const ipAddress = req.ip || req.connection?.remoteAddress || '127.0.0.1';
  logAudit({
    adminUser: req.user.username,
    action: 'LOGOUT',
    target: 'AUTH',
    result: 'SUCCESS',
    ipAddress
  });
  res.json({ success: true, message: 'Logged out successfully' });
});

// Current User Info
router.get('/me', requireAuth, (req, res) => {
  const user = db.prepare('SELECT id, username, role, created_at, last_login FROM users WHERE id = ?').get(req.user.id);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  res.json({ user });
});

// Change Password
router.put('/password', requireAuth, (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const ipAddress = req.ip || req.connection?.remoteAddress || '127.0.0.1';

  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: 'Current password and new password are required' });
  }

  if (newPassword.length < 8) {
    return res.status(400).json({ error: 'New password must be at least 8 characters long' });
  }

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  const match = bcrypt.compareSync(currentPassword, user.password_hash);
  if (!match) {
    return res.status(401).json({ error: 'Current password is incorrect' });
  }

  const salt = bcrypt.genSaltSync(10);
  const newHash = bcrypt.hashSync(newPassword, salt);

  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(newHash, user.id);

  logAudit({
    adminUser: user.username,
    action: 'PASSWORD_CHANGE',
    target: 'USER',
    result: 'SUCCESS',
    ipAddress,
    details: 'Administrator updated account credentials'
  });

  res.json({ success: true, message: 'Password updated successfully' });
});

export default router;
