import express from 'express';
import { db } from '../db.js';

const router = express.Router();

// Aggregated report statistics
router.get('/summary', (req, res) => {
  const { startDate, endDate, clientId } = req.query;

  const where = [];
  const params = [];

  if (startDate) {
    where.push('timestamp >= ?');
    params.push(startDate);
  }
  if (endDate) {
    where.push('timestamp <= ?');
    params.push(endDate);
  }
  if (clientId) {
    where.push('client_id = ?');
    params.push(clientId);
  }

  const whereSql = where.length > 0 ? `WHERE ${where.join(' AND ')}` : '';

  const totals = db.prepare(`
    SELECT
      COUNT(*) as total_events,
      SUM(CASE WHEN decision = 'ALLOW' THEN 1 ELSE 0 END) as allowed_events,
      SUM(CASE WHEN decision = 'WARNING' THEN 1 ELSE 0 END) as warning_events,
      SUM(CASE WHEN decision = 'BLOCK' THEN 1 ELSE 0 END) as blocked_events
    FROM url_events
    ${whereSql}
  `).get(...params) || { total_events: 0, allowed_events: 0, warning_events: 0, blocked_events: 0 };

  const byThreatLevel = db.prepare(`
    SELECT threat_level, COUNT(*) as count
    FROM url_events
    ${whereSql}
    GROUP BY threat_level
    ORDER BY count DESC
  `).all(...params);

  const topBlocked = db.prepare(`
    SELECT domain, COUNT(*) as count
    FROM url_events
    ${where.length > 0 ? whereSql + " AND decision = 'BLOCK'" : "WHERE decision = 'BLOCK'"}
    GROUP BY domain
    ORDER BY count DESC
    LIMIT 10
  `).all(...params);

  const byClient = db.prepare(`
    SELECT client_id, system_name, COUNT(*) as count,
           SUM(CASE WHEN decision = 'BLOCK' THEN 1 ELSE 0 END) as blocked
    FROM url_events
    ${whereSql}
    GROUP BY client_id
    ORDER BY count DESC
    LIMIT 10
  `).all(...params);

  res.json({
    totals,
    byThreatLevel,
    topBlocked,
    byClient
  });
});

// CSV Export
router.get('/export-csv', (req, res) => {
  const { type = 'url-events', clientId, startDate, endDate } = req.query;

  const where = [];
  const params = [];

  if (startDate) {
    where.push('timestamp >= ?');
    params.push(startDate);
  }
  if (endDate) {
    where.push('timestamp <= ?');
    params.push(endDate);
  }
  if (clientId) {
    where.push('client_id = ?');
    params.push(clientId);
  }

  const whereSql = where.length > 0 ? `WHERE ${where.join(' AND ')}` : '';

  if (type === 'alerts') {
    const alerts = db.prepare(`
      SELECT id, client_id, system_name, url, domain, timestamp, severity, alert_type, reason, status
      FROM alerts
      ${whereSql}
      ORDER BY timestamp DESC
      LIMIT 1000
    `).all(...params);

    const headers = ['Alert ID', 'Client ID', 'System Name', 'URL', 'Domain', 'Timestamp', 'Severity', 'Alert Type', 'Reason', 'Status'];
    const rows = alerts.map(a => [
      a.id, a.client_id, a.system_name, `"${(a.url || '').replace(/"/g, '""')}"`, a.domain, a.timestamp, a.severity, a.alert_type, `"${(a.reason || '').replace(/"/g, '""')}"`, a.status
    ]);

    const csvContent = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="phishguard_alerts_${Date.now()}.csv"`);
    return res.send(csvContent);
  }

  // Default: URL events
  const events = db.prepare(`
    SELECT id, client_id, system_name, url, domain, timestamp, decision, threat_level, rule_name, reason
    FROM url_events
    ${whereSql}
    ORDER BY timestamp DESC
    LIMIT 2000
  `).all(...params);

  const headers = ['Event ID', 'Client ID', 'System Name', 'URL', 'Domain', 'Timestamp', 'Decision', 'Threat Level', 'Rule Name', 'Reason'];
  const rows = events.map(e => [
    e.id, e.client_id, e.system_name, `"${(e.url || '').replace(/"/g, '""')}"`, e.domain, e.timestamp, e.decision, e.threat_level, `"${(e.rule_name || '').replace(/"/g, '""')}"`, `"${(e.reason || '').replace(/"/g, '""')}"`
  ]);

  const csvContent = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', `attachment; filename="phishguard_url_events_${Date.now()}.csv"`);
  res.send(csvContent);
});

export default router;
