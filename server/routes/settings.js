import express from 'express';
import { db } from '../db.js';
import { requireAuth, logAudit } from '../auth.js';

const router = express.Router();

// Get settings & server configuration
router.get('/', (req, res) => {
  const configs = db.prepare('SELECT key, value, updated_at FROM system_config').all();
  const configMap = {};
  for (const c of configs) {
    configMap[c.key] = c.value;
  }

  res.json({
    settings: configMap,
    server: {
      version: '2.0.0-enterprise',
      platform: process.platform,
      nodeVersion: process.version,
      uptimeSeconds: Math.floor(process.uptime()),
      port: process.env.SERVER_PORT || 3000
    }
  });
});

// Update settings
router.put('/', requireAuth, (req, res) => {
  const { settings } = req.body;
  if (!settings || typeof settings !== 'object') {
    return res.status(400).json({ error: 'settings object required' });
  }

  const now = new Date().toISOString();
  const updateStmt = db.prepare(`
    INSERT INTO system_config (key, value, updated_at)
    VALUES (?, ?, ?)
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
  `);

  for (const [k, v] of Object.entries(settings)) {
    updateStmt.run(k, String(v), now);
  }

  logAudit({
    adminUser: req.user.username,
    action: 'UPDATE_SETTINGS',
    target: 'CONFIG',
    result: 'SUCCESS',
    ipAddress: req.ip,
    details: `Updated settings: ${Object.keys(settings).join(', ')}`
  });

  res.json({ success: true, message: 'Settings saved successfully' });
});

export default router;
