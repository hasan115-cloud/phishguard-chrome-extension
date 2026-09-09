import express from 'express';
import { db } from '../db.js';
import { broadcast } from '../sse.js';
import { requireAuth, logAudit } from '../auth.js';

const router = express.Router();

// List all incidents
router.get('/', (req, res) => {
  const { status, clientId } = req.query;

  const where = [];
  const params = [];

  if (status && status !== 'ALL') {
    where.push('status = ?');
    params.push(status.toUpperCase());
  }
  if (clientId) {
    where.push('client_id = ?');
    params.push(clientId);
  }

  const whereSql = where.length > 0 ? `WHERE ${where.join(' AND ')}` : '';

  const incidents = db.prepare(`
    SELECT * FROM incidents
    ${whereSql}
    ORDER BY last_activity DESC
    LIMIT 100
  `).all(...params);

  res.json({ incidents });
});

// Get incident details with related alerts and URLs
router.get('/:id', (req, res) => {
  const { id } = req.params;
  const incident = db.prepare('SELECT * FROM incidents WHERE id = ?').get(id);
  if (!incident) {
    return res.status(404).json({ error: 'Incident not found' });
  }

  // Related alerts from same client
  const relatedAlerts = db.prepare(`
    SELECT * FROM alerts
    WHERE client_id = ?
    ORDER BY timestamp DESC
    LIMIT 20
  `).all(incident.client_id);

  // Related blocked URLs
  const relatedUrls = db.prepare(`
    SELECT * FROM url_events
    WHERE client_id = ? AND decision = 'BLOCK'
    ORDER BY timestamp DESC
    LIMIT 20
  `).all(incident.client_id);

  res.json({
    incident,
    relatedAlerts,
    relatedUrls
  });
});

// Update incident status / notes
router.put('/:id', requireAuth, (req, res) => {
  const { id } = req.params;
  const { status, notes, title, severity } = req.body;

  const incident = db.prepare('SELECT * FROM incidents WHERE id = ?').get(id);
  if (!incident) {
    return res.status(404).json({ error: 'Incident not found' });
  }

  const now = new Date().toISOString();

  db.prepare(`
    UPDATE incidents
    SET status = COALESCE(?, status),
        notes = COALESCE(?, notes),
        title = COALESCE(?, title),
        severity = COALESCE(?, severity),
        last_activity = ?
    WHERE id = ?
  `).run(
    status ? status.toUpperCase() : null,
    notes !== undefined ? notes : null,
    title || null,
    severity || null,
    now,
    id
  );

  const updated = db.prepare('SELECT * FROM incidents WHERE id = ?').get(id);

  logAudit({
    adminUser: req.user?.username || 'admin',
    action: 'UPDATE_INCIDENT',
    target: id,
    result: 'SUCCESS',
    ipAddress: req.ip,
    details: `Updated incident ${id} status to ${updated.status}`
  });

  broadcast('INCIDENT_UPDATED', updated);

  res.json({ success: true, incident: updated });
});

export default router;
