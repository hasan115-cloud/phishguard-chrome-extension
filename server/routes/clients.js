import express from 'express';
import { db } from '../db.js';
import { broadcast } from '../sse.js';
import { requireAuth, logAudit } from '../auth.js';

const router = express.Router();

function getHeartbeatTimeoutSeconds() {
  const row = db.prepare("SELECT value FROM system_config WHERE key = 'HEARTBEAT_TIMEOUT_SECONDS'").get();
  return row ? parseInt(row.value, 10) || 90 : 90;
}

// Helper: Validate enrollment token
function validateEnrollmentToken(token) {
  if (!token) return { valid: true }; // allow open registration if token not strictly required
  const row = db.prepare('SELECT * FROM enrollment_tokens WHERE token = ?').get(token.trim());
  if (!row) {
    return { valid: false, error: 'Invalid enrollment token' };
  }
  if (row.status !== 'ACTIVE') {
    return { valid: false, error: `Enrollment token is ${row.status.toLowerCase()}` };
  }
  if (new Date(row.expires_at).getTime() < Date.now()) {
    return { valid: false, error: 'Enrollment token has expired' };
  }
  if (row.uses_count >= row.max_uses) {
    return { valid: false, error: 'Enrollment token maximum usage limit reached' };
  }
  return { valid: true, tokenRow: row };
}

// 1. Client Registration / Enrollment (Called by Chrome Extension on install/startup)
const handleEnrollment = (req, res) => {
  const {
    clientId,
    systemName,
    hostname,
    os,
    browser,
    extensionVersion,
    metadata,
    enrollmentToken
  } = req.body;

  const ipAddress = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.ip || req.connection?.remoteAddress || '127.0.0.1';
  const now = new Date().toISOString();

  if (!clientId) {
    return res.status(400).json({ error: 'clientId is required' });
  }

  // Token validation if token provided
  if (enrollmentToken) {
    const tokenCheck = validateEnrollmentToken(enrollmentToken);
    if (!tokenCheck.valid) {
      return res.status(401).json({ error: tokenCheck.error });
    }
    // Increment usage count
    db.prepare('UPDATE enrollment_tokens SET uses_count = uses_count + 1 WHERE token = ?').run(enrollmentToken.trim());
  }

  const assignedSystemName = systemName || hostname || `CLIENT-${clientId.substring(0, 6).toUpperCase()}`;

  // Check if client exists
  const existing = db.prepare('SELECT * FROM clients WHERE client_id = ?').get(clientId);

  if (existing) {
    // Update existing client
    db.prepare(`
      UPDATE clients
      SET system_name = ?,
          hostname = COALESCE(?, hostname),
          os = COALESCE(?, os),
          browser = COALESCE(?, browser),
          extension_version = COALESCE(?, extension_version),
          last_seen = ?,
          status = 'ONLINE',
          ip_address = ?,
          client_metadata = COALESCE(?, client_metadata)
      WHERE client_id = ?
    `).run(
      assignedSystemName,
      hostname || null,
      os || null,
      browser || null,
      extensionVersion || null,
      now,
      ipAddress,
      typeof metadata === 'object' ? JSON.stringify(metadata) : metadata || null,
      clientId
    );
  } else {
    // Insert brand new client
    db.prepare(`
      INSERT INTO clients (
        client_id, system_name, hostname, os, browser,
        extension_version, first_seen, last_seen, status, ip_address, client_metadata
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'ONLINE', ?, ?)
    `).run(
      clientId,
      assignedSystemName,
      hostname || 'unknown-host',
      os || 'Chrome OS/Linux/Windows',
      browser || 'Google Chrome',
      extensionVersion || '1.4',
      now,
      now,
      ipAddress,
      typeof metadata === 'object' ? JSON.stringify(metadata) : metadata || '{}'
    );
  }

  const clientRecord = db.prepare('SELECT * FROM clients WHERE client_id = ?').get(clientId);

  // Broadcast real-time SSE event
  broadcast('CLIENT_REGISTERED', { client: clientRecord });

  res.json({
    success: true,
    clientId,
    systemName: assignedSystemName,
    status: 'ONLINE',
    registeredAt: now,
    message: 'Extension enrolled successfully'
  });
};

router.post('/register', handleEnrollment);
router.post('/enroll', handleEnrollment);

// Token Management Endpoints
router.get('/tokens', (req, res) => {
  const tokens = db.prepare('SELECT * FROM enrollment_tokens ORDER BY created_at DESC').all();
  res.json({ tokens });
});

router.post('/tokens/generate', requireAuth, (req, res) => {
  const { description, maxUses = 25, expiresInDays = 30 } = req.body;
  const randChars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let rand = '';
  for (let i = 0; i < 6; i++) {
    rand += randChars.charAt(Math.floor(Math.random() * randChars.length));
  }
  const token = `ENROLL-${rand}`;
  const now = new Date();
  const expires = new Date(now.getTime() + (parseInt(expiresInDays, 10) || 30) * 24 * 60 * 60 * 1000);
  const adminUser = req.user?.username || 'admin';

  db.prepare(`
    INSERT INTO enrollment_tokens (token, created_by, created_at, expires_at, status, max_uses, uses_count, description)
    VALUES (?, ?, ?, ?, 'ACTIVE', ?, 0, ?)
  `).run(token, adminUser, now.toISOString(), expires.toISOString(), parseInt(maxUses, 10) || 25, description || 'Admin generated token');

  logAudit({
    adminUser,
    action: 'GENERATE_ENROLLMENT_TOKEN',
    target: token,
    result: 'SUCCESS',
    ipAddress: req.ip,
    details: `Generated enrollment token ${token} (expires: ${expires.toISOString().split('T')[0]})`
  });

  const created = db.prepare('SELECT * FROM enrollment_tokens WHERE token = ?').get(token);
  res.status(201).json({ success: true, token: created });
});

router.post('/tokens/:token/revoke', requireAuth, (req, res) => {
  const { token } = req.params;
  const existing = db.prepare('SELECT * FROM enrollment_tokens WHERE token = ?').get(token);
  if (!existing) {
    return res.status(404).json({ error: 'Token not found' });
  }

  db.prepare("UPDATE enrollment_tokens SET status = 'REVOKED' WHERE token = ?").run(token);

  logAudit({
    adminUser: req.user?.username || 'admin',
    action: 'REVOKE_ENROLLMENT_TOKEN',
    target: token,
    result: 'SUCCESS',
    ipAddress: req.ip,
    details: `Revoked enrollment token ${token}`
  });

  res.json({ success: true, message: `Token ${token} revoked` });
});

// 2. Client Heartbeat (Called periodically by Chrome Extension)
router.post('/heartbeat', (req, res) => {
  const { clientId } = req.body;
  const ipAddress = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.ip || req.connection?.remoteAddress || '127.0.0.1';
  const now = new Date().toISOString();

  if (!clientId) {
    return res.status(400).json({ error: 'clientId is required' });
  }

  const existing = db.prepare('SELECT * FROM clients WHERE client_id = ?').get(clientId);
  if (!existing) {
    // Auto-enroll if not in DB yet
    const systemName = `CLIENT-${clientId.substring(0, 6).toUpperCase()}`;
    db.prepare(`
      INSERT INTO clients (
        client_id, system_name, hostname, os, browser,
        extension_version, first_seen, last_seen, status, ip_address, client_metadata
      ) VALUES (?, ?, 'enrolled-host', 'Auto-detected', 'Google Chrome', '1.4', ?, ?, 'ONLINE', ?, '{}')
    `).run(clientId, systemName, now, now, ipAddress);
  } else {
    db.prepare(`
      UPDATE clients
      SET last_seen = ?, status = 'ONLINE', ip_address = ?
      WHERE client_id = ?
    `).run(now, ipAddress, clientId);
  }

  broadcast('CLIENT_HEARTBEAT', {
    clientId,
    lastSeen: now,
    status: 'ONLINE',
    ipAddress
  });

  res.json({
    success: true,
    status: 'ONLINE',
    serverTime: now,
    heartbeatIntervalSeconds: 30
  });
});

// 3. List all registered systems (Dashboard)
router.get('/', (req, res) => {
  const timeoutSec = getHeartbeatTimeoutSeconds();
  const nowMs = Date.now();

  const clients = db.prepare('SELECT * FROM clients ORDER BY first_seen DESC').all();

  // Get aggregated counts per client from url_events
  const statsRows = db.prepare(`
    SELECT
      client_id,
      COUNT(*) as total_events,
      SUM(CASE WHEN decision = 'BLOCK' THEN 1 ELSE 0 END) as blocked_count,
      SUM(CASE WHEN decision = 'WARNING' THEN 1 ELSE 0 END) as warning_count,
      SUM(CASE WHEN decision = 'ALLOW' THEN 1 ELSE 0 END) as allowed_count
    FROM url_events
    GROUP BY client_id
  `).all();

  const statsMap = new Map();
  for (const row of statsRows) {
    statsMap.set(row.client_id, row);
  }

  // Update dynamic ONLINE / OFFLINE status based on actual last_seen timestamp
  const result = clients.map(c => {
    const lastSeenMs = new Date(c.last_seen).getTime();
    const isOnline = (nowMs - lastSeenMs) <= (timeoutSec * 1000);
    const computedStatus = isOnline ? 'ONLINE' : 'OFFLINE';

    // Persist computed status if changed
    if (c.status !== computedStatus) {
      db.prepare('UPDATE clients SET status = ? WHERE client_id = ?').run(computedStatus, c.client_id);
      c.status = computedStatus;
    }

    const st = statsMap.get(c.client_id) || {
      total_events: 0,
      blocked_count: 0,
      warning_count: 0,
      allowed_count: 0
    };

    return {
      ...c,
      status: computedStatus,
      totalEvents: st.total_events || 0,
      blockedCount: st.blocked_count || 0,
      warningCount: st.warning_count || 0,
      allowedCount: st.allowed_count || 0
    };
  });

  res.json({ clients: result, timeoutSeconds: timeoutSec });
});

// 4. Get specific client detail with recent events
router.get('/:id', (req, res) => {
  const { id } = req.params;
  const timeoutSec = getHeartbeatTimeoutSeconds();
  const nowMs = Date.now();

  const client = db.prepare('SELECT * FROM clients WHERE client_id = ?').get(id);
  if (!client) {
    return res.status(404).json({ error: 'Client not found' });
  }

  const lastSeenMs = new Date(client.last_seen).getTime();
  const isOnline = (nowMs - lastSeenMs) <= (timeoutSec * 1000);
  client.status = isOnline ? 'ONLINE' : 'OFFLINE';

  // Get client's specific URL events
  const events = db.prepare(`
    SELECT * FROM url_events
    WHERE client_id = ?
    ORDER BY timestamp DESC
    LIMIT 100
  `).all(id);

  // Get client's specific alerts
  const alerts = db.prepare(`
    SELECT * FROM alerts
    WHERE client_id = ?
    ORDER BY timestamp DESC
    LIMIT 50
  `).all(id);

  // Aggregate stats
  const stats = db.prepare(`
    SELECT
      COUNT(*) as total_events,
      SUM(CASE WHEN decision = 'BLOCK' THEN 1 ELSE 0 END) as blocked_count,
      SUM(CASE WHEN decision = 'WARNING' THEN 1 ELSE 0 END) as warning_count,
      SUM(CASE WHEN decision = 'ALLOW' THEN 1 ELSE 0 END) as allowed_count
    FROM url_events
    WHERE client_id = ?
  `).get(id);

  res.json({
    client,
    stats: {
      totalEvents: stats?.total_events || 0,
      blockedCount: stats?.blocked_count || 0,
      warningCount: stats?.warning_count || 0,
      allowedCount: stats?.allowed_count || 0
    },
    events,
    alerts
  });
});

// 5. Delete / Decommission a client
router.delete('/:id', requireAuth, (req, res) => {
  const { id } = req.params;
  const client = db.prepare('SELECT * FROM clients WHERE client_id = ?').get(id);
  if (!client) {
    return res.status(404).json({ error: 'Client not found' });
  }

  db.prepare('DELETE FROM clients WHERE client_id = ?').run(id);

  logAudit({
    adminUser: req.user.username,
    action: 'DECOMMISSION_CLIENT',
    target: id,
    result: 'SUCCESS',
    ipAddress: req.ip,
    details: `Removed client ${client.system_name} (${id})`
  });

  broadcast('CLIENT_DELETED', { clientId: id });

  res.json({ success: true, message: 'Client deleted successfully' });
});

export default router;
