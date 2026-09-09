import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { db } from './db.js';

const JWT_SECRET = process.env.JWT_SECRET || 'phishguard-enterprise-super-secret-jwt-key-2026';
const TOKEN_EXPIRY = '24h';

export function signToken(user) {
  return jwt.sign(
    {
      id: user.id,
      username: user.username,
      role: user.role
    },
    JWT_SECRET,
    { expiresIn: TOKEN_EXPIRY }
  );
}

export function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch {
    return null;
  }
}

// Authentication middleware for Express
export function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  let token = null;

  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.substring(7);
  } else if (req.query && req.query.token) {
    token = req.query.token;
  }

  if (!token) {
    return res.status(401).json({ error: 'Authentication required. No token provided.' });
  }

  const decoded = verifyToken(token);
  if (!decoded) {
    return res.status(401).json({ error: 'Invalid or expired session token.' });
  }

  req.user = decoded;
  next();
}

// Audit logging helper
export function logAudit({ adminUser, action, target, result = 'SUCCESS', ipAddress, details }) {
  try {
    const id = 'audit-' + Date.now() + '-' + Math.random().toString(36).substring(2, 7);
    const timestamp = new Date().toISOString();
    const detailsStr = typeof details === 'object' ? JSON.stringify(details) : (details || '');

    db.prepare(`
      INSERT INTO audit_logs (id, timestamp, admin_user, action, target, result, ip_address, details)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(id, timestamp, adminUser || 'system', action, target || '', result, ipAddress || '127.0.0.1', detailsStr);
  } catch (err) {
    console.error('[AUDIT] Failed to write audit record:', err);
  }
}

export { bcrypt };
