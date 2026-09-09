import express from 'express';
import { db } from '../db.js';
import { broadcast } from '../sse.js';
import { requireAuth, logAudit } from '../auth.js';

const router = express.Router();

// List alerts with optional filters
router.get('/', (req, res) => {
  const { status, severity, clientId, limit = 100 } = req.query;

  const where = [];
  const params = [];

  if (status && status !== 'ALL') {
    where.push('status = ?');
    params.push(status.toUpperCase());
  }
  if (severity && severity !== 'ALL') {
    where.push('severity = ?');
    params.push(severity.toUpperCase());
  }
  if (clientId) {
    where.push('client_id = ?');
    params.push(clientId);
  }

  const whereSql = where.length > 0 ? `WHERE ${where.join(' AND ')}` : '';
  const limitNum = Math.min(200, Math.max(1, parseInt(limit, 10) || 100));

  const alerts = db.prepare(`
    SELECT * FROM alerts
    ${whereSql}
    ORDER BY timestamp DESC
    LIMIT ?
  `).all(...params, limitNum);

  res.json({ alerts });
});

// Update alert status (Acknowledge / Resolve)
router.put('/:id', requireAuth, (req, res) => {
  const { id } = req.params;
  const { status, note } = req.body;

  const alert = db.prepare('SELECT * FROM alerts WHERE id = ?').get(id);
  if (!alert) {
    return res.status(404).json({ error: 'Alert not found' });
  }

  const validStatuses = ['NEW', 'ACKNOWLEDGED', 'RESOLVED'];
  if (!status || !validStatuses.includes(status.toUpperCase())) {
    return res.status(400).json({ error: 'Status must be NEW, ACKNOWLEDGED, or RESOLVED' });
  }

  const now = new Date().toISOString();
  const username = req.user?.username || 'admin';

  db.prepare(`
    UPDATE alerts
    SET status = ?,
        resolved_at = CASE WHEN ? = 'RESOLVED' THEN ? ELSE resolved_at END,
        resolved_by = CASE WHEN ? = 'RESOLVED' THEN ? ELSE resolved_by END
    WHERE id = ?
  `).run(status.toUpperCase(), status.toUpperCase(), now, status.toUpperCase(), username, id);

  const updated = db.prepare('SELECT * FROM alerts WHERE id = ?').get(id);

  logAudit({
    adminUser: username,
    action: `ALERT_${status.toUpperCase()}`,
    target: id,
    result: 'SUCCESS',
    ipAddress: req.ip,
    details: `${username} set alert ${id} to ${status.toUpperCase()}${note ? ': ' + note : ''}`
  });

  broadcast('ALERT_STATUS_CHANGED', updated);

  res.json({ success: true, alert: updated });
});

// Delete alert
router.delete('/:id', requireAuth, (req, res) => {
  const { id } = req.params;
  const alert = db.prepare('SELECT * FROM alerts WHERE id = ?').get(id);
  if (!alert) {
    return res.status(404).json({ error: 'Alert not found' });
  }

  db.prepare('DELETE FROM alerts WHERE id = ?').run(id);

  logAudit({
    adminUser: req.user?.username || 'admin',
    action: 'DELETE_ALERT',
    target: id,
    result: 'SUCCESS',
    ipAddress: req.ip,
    details: `Deleted alert for ${alert.domain}`
  });

  res.json({ success: true, message: 'Alert deleted successfully' });
});

export default router;
