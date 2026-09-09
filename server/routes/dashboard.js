import express from 'express';
import { db } from '../db.js';
import { sseHandler } from '../sse.js';

const router = express.Router();

// Real-Time Server-Sent Events Stream
router.get('/events-stream', sseHandler);

// Aggregated Real Security Statistics
router.get('/stats', (req, res) => {
  const timeoutRow = db.prepare("SELECT value FROM system_config WHERE key = 'HEARTBEAT_TIMEOUT_SECONDS'").get();
  const timeoutSec = timeoutRow ? parseInt(timeoutRow.value, 10) || 90 : 90;
  const nowMs = Date.now();

  // All clients & calculate actual online/offline based on last_seen
  const allClients = db.prepare('SELECT client_id, last_seen, status FROM clients').all();
  let onlineClients = 0;
  let offlineClients = 0;

  for (const c of allClients) {
    const lastSeenMs = new Date(c.last_seen).getTime();
    if (nowMs - lastSeenMs <= timeoutSec * 1000) {
      onlineClients++;
    } else {
      offlineClients++;
    }
  }

  // URL events counts
  const urlStats = db.prepare(`
    SELECT
      COUNT(*) as total_urls,
      SUM(CASE WHEN decision = 'ALLOW' THEN 1 ELSE 0 END) as allowed_urls,
      SUM(CASE WHEN decision = 'WARNING' THEN 1 ELSE 0 END) as warning_urls,
      SUM(CASE WHEN decision = 'BLOCK' THEN 1 ELSE 0 END) as blocked_urls
    FROM url_events
  `).get() || { total_urls: 0, allowed_urls: 0, warning_urls: 0, blocked_urls: 0 };

  // Alert counts
  const alertStats = db.prepare(`
    SELECT
      COUNT(*) as total_alerts,
      SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical_alerts,
      SUM(CASE WHEN status = 'NEW' THEN 1 ELSE 0 END) as new_alerts
    FROM alerts
  `).get() || { total_alerts: 0, critical_alerts: 0, new_alerts: 0 };

  // Rule counts
  const ruleStats = db.prepare(`
    SELECT
      COUNT(*) as total_rules,
      SUM(CASE WHEN enabled = 1 THEN 1 ELSE 0 END) as enabled_rules
    FROM rules
  `).get() || { total_rules: 0, enabled_rules: 0 };

  // Incident counts
  const incidentStats = db.prepare(`
    SELECT
      COUNT(*) as total_incidents,
      SUM(CASE WHEN status IN ('OPEN', 'INVESTIGATING') THEN 1 ELSE 0 END) as active_incidents
    FROM incidents
  `).get() || { total_incidents: 0, active_incidents: 0 };

  // Top blocked threat domains
  const topBlockedDomains = db.prepare(`
    SELECT domain, COUNT(*) as count
    FROM url_events
    WHERE decision = 'BLOCK'
    GROUP BY domain
    ORDER BY count DESC
    LIMIT 5
  `).all();

  // Recent 10 events
  const recentEvents = db.prepare(`
    SELECT * FROM url_events
    ORDER BY timestamp DESC
    LIMIT 10
  `).all();

  res.json({
    totalClients: allClients.length,
    onlineClients,
    offlineClients,
    totalUrlsMonitored: urlStats.total_urls || 0,
    allowedUrls: urlStats.allowed_urls || 0,
    warningUrls: urlStats.warning_urls || 0,
    blockedUrls: urlStats.blocked_urls || 0,
    totalAlerts: alertStats.total_alerts || 0,
    criticalAlerts: alertStats.critical_alerts || 0,
    newAlerts: alertStats.new_alerts || 0,
    totalRules: ruleStats.total_rules || 0,
    enabledRules: ruleStats.enabled_rules || 0,
    totalIncidents: incidentStats.total_incidents || 0,
    activeIncidents: incidentStats.active_incidents || 0,
    topBlockedDomains,
    recentEvents
  });
});

export default router;
