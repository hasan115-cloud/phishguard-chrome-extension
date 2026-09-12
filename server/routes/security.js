import express from 'express';
import { db } from '../db.js';
import { evaluateUrlDecision } from '../decisionEngine.js';
import { broadcast } from '../sse.js';

const router = express.Router();

// 1. Check URL & Make Decision (Core Security Engine endpoint)
const handleCheckUrl = (req, res) => {
  const { url, tabId, browserInfo, detectionSource } = req.body;
  const clientId = req.body.clientId || req.headers['x-client-id'];
  const systemName = req.body.systemName || req.headers['x-system-name'];
  const ipAddress = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.ip || req.connection?.remoteAddress || '127.0.0.1';
  const now = new Date().toISOString();

  if (!url) {
    return res.status(400).json({ error: 'url parameter is required' });
  }

  // Ensure client exists in database, or auto-enroll if unknown
  const activeClientId = clientId || 'CLIENT-ANONYMOUS';
  let clientRecord = db.prepare('SELECT * FROM clients WHERE client_id = ?').get(activeClientId);
  if (!clientRecord) {
    const assignedName = systemName || `CLIENT-${activeClientId.substring(0, 6).toUpperCase()}`;
    db.prepare(`
      INSERT INTO clients (
        client_id, system_name, hostname, os, browser,
        extension_version, first_seen, last_seen, status, ip_address, client_metadata
      ) VALUES (?, ?, 'enrolled-workstation', 'Workstation OS', 'Google Chrome', '1.4', ?, ?, 'ONLINE', ?, '{}')
    `).run(activeClientId, assignedName, now, now, ipAddress);
    clientRecord = { client_id: activeClientId, system_name: assignedName };
    broadcast('CLIENT_REGISTERED', {
      clientId: activeClientId,
      systemName: assignedName,
      status: 'ONLINE',
      ipAddress,
      firstSeen: now,
      lastSeen: now
    });
  } else {
    // Update client last_seen
    db.prepare("UPDATE clients SET last_seen = ?, status = 'ONLINE', ip_address = ? WHERE client_id = ?")
      .run(now, ipAddress, activeClientId);
  }

  // Evaluate URL against Rules + ML heuristic engine
  const evalResult = evaluateUrlDecision(url);

  let parsedDomain = url;
  try {
    const u = new URL(url.startsWith('http') ? url : 'https://' + url);
    parsedDomain = u.hostname.toLowerCase();
  } catch {
    parsedDomain = url.toLowerCase();
  }

  // Insert URL event record
  const eventId = 'ev-' + Date.now() + '-' + Math.random().toString(36).substring(2, 7);
  db.prepare(`
    INSERT INTO url_events (
      id, client_id, system_name, url, domain, timestamp,
      decision, threat_level, rule_id, rule_name, reason, browser_info
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    eventId,
    activeClientId,
    clientRecord.system_name,
    url,
    parsedDomain,
    now,
    evalResult.decision,
    evalResult.threatLevel,
    evalResult.ruleId,
    evalResult.ruleName,
    evalResult.reason,
    typeof browserInfo === 'object' ? JSON.stringify(browserInfo) : (browserInfo || null)
  );

  const eventRecord = {
    id: eventId,
    clientId: activeClientId,
    systemName: clientRecord.system_name,
    url,
    domain: parsedDomain,
    timestamp: now,
    decision: evalResult.decision,
    threatLevel: evalResult.threatLevel,
    ruleId: evalResult.ruleId,
    ruleName: evalResult.ruleName,
    reason: evalResult.reason
  };

  // If BLOCK or WARNING or HIGH/CRITICAL threat, create an alert and check incident grouping
  let alertCreated = null;
  if (evalResult.decision === 'BLOCK' || evalResult.threatLevel === 'HIGH' || evalResult.threatLevel === 'CRITICAL' || evalResult.decision === 'WARNING') {
    const alertId = 'alt-' + Date.now() + '-' + Math.random().toString(36).substring(2, 7);
    const alertType = evalResult.decision === 'BLOCK' ? 'PHISHING_BLOCKED' : 'SUSPICIOUS_WARNING';

    db.prepare(`
      INSERT INTO alerts (
        id, client_id, system_name, url, domain, timestamp,
        severity, alert_type, reason, rule_id, status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'NEW')
    `).run(
      alertId,
      activeClientId,
      clientRecord.system_name,
      url,
      parsedDomain,
      now,
      evalResult.threatLevel,
      alertType,
      evalResult.reason,
      evalResult.ruleId
    );

    alertCreated = {
      id: alertId,
      clientId: activeClientId,
      systemName: clientRecord.system_name,
      url,
      domain: parsedDomain,
      timestamp: now,
      severity: evalResult.threatLevel,
      alertType,
      reason: evalResult.reason,
      status: 'NEW'
    };

    // Broadcast alert via SSE
    broadcast('SECURITY_ALERT', alertCreated);
  }

  // Broadcast URL event via SSE for Overview stats
  broadcast('URL_EVENT', eventRecord);

  // Return decision to extension
  res.json({
    verdict: evalResult.decision === 'BLOCK' ? 'phishing' : (evalResult.decision === 'WARNING' ? 'suspicious' : 'safe'),
    decision: evalResult.decision, // 'ALLOW', 'WARNING', 'BLOCK'
    threatLevel: evalResult.threatLevel,
    threat_level: evalResult.threatLevel,
    reason: evalResult.reason,
    reasons: evalResult.reason ? [evalResult.reason] : [],
    ruleId: evalResult.ruleId,
    ruleName: evalResult.ruleName,
    url,
    domain: parsedDomain,
    timestamp: now,
    heuristicScore: evalResult.heuristicScore,
    score: evalResult.heuristicScore
  });
};

router.post('/check-url', handleCheckUrl);
router.post('/url', handleCheckUrl);

// 2. Explicit URL Event Logging
router.post('/url-events', (req, res) => {
  const { url, clientId, systemName, decision, threatLevel, reason, ruleId, browserInfo } = req.body;
  const now = new Date().toISOString();

  if (!url || !clientId) {
    return res.status(400).json({ error: 'url and clientId are required' });
  }

  let domain = url;
  try {
    const u = new URL(url.startsWith('http') ? url : 'https://' + url);
    domain = u.hostname.toLowerCase();
  } catch {
    domain = url;
  }

  const eventId = 'ev-' + Date.now() + '-' + Math.random().toString(36).substring(2, 7);
  const clientName = systemName || `CLIENT-${clientId.substring(0, 6).toUpperCase()}`;

  db.prepare(`
    INSERT INTO url_events (
      id, client_id, system_name, url, domain, timestamp,
      decision, threat_level, rule_id, rule_name, reason, browser_info
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    eventId,
    clientId,
    clientName,
    url,
    domain,
    now,
    decision || 'ALLOW',
    threatLevel || 'SAFE',
    ruleId || null,
    null,
    reason || '',
    typeof browserInfo === 'object' ? JSON.stringify(browserInfo) : (browserInfo || null)
  );

  const eventRecord = {
    id: eventId,
    clientId,
    systemName: clientName,
    url,
    domain,
    timestamp: now,
    decision: decision || 'ALLOW',
    threatLevel: threatLevel || 'SAFE',
    reason
  };

  broadcast('URL_EVENT', eventRecord);

  res.json({ success: true, eventId });
});

// 3. Query URL History (Search, Filter, Paginate)
const handleListEvents = (req, res) => {
  const {
    clientId,
    decision,
    threatLevel,
    domain,
    search,
    startDate,
    endDate,
    page = 1,
    limit = 50
  } = req.query;

  const pageNum = Math.max(1, parseInt(page, 10) || 1);
  const limitNum = Math.min(200, Math.max(1, parseInt(limit, 10) || 50));
  const offset = (pageNum - 1) * limitNum;

  const whereClauses = [];
  const params = [];

  if (clientId) {
    whereClauses.push('client_id = ?');
    params.push(clientId);
  }
  if (decision && decision !== 'ALL') {
    whereClauses.push('decision = ?');
    params.push(decision.toUpperCase());
  }
  if (threatLevel && threatLevel !== 'ALL') {
    whereClauses.push('threat_level = ?');
    params.push(threatLevel.toUpperCase());
  }
  if (domain) {
    whereClauses.push('domain LIKE ?');
    params.push(`%${domain.toLowerCase().trim()}%`);
  }
  if (search) {
    whereClauses.push('(url LIKE ? OR domain LIKE ? OR reason LIKE ? OR system_name LIKE ?)');
    const s = `%${search.trim()}%`;
    params.push(s, s, s, s);
  }
  if (startDate) {
    whereClauses.push('timestamp >= ?');
    params.push(startDate);
  }
  if (endDate) {
    whereClauses.push('timestamp <= ?');
    params.push(endDate);
  }

  const whereSql = whereClauses.length > 0 ? `WHERE ${whereClauses.join(' AND ')}` : '';

  const totalCount = db.prepare(`SELECT COUNT(*) as count FROM url_events ${whereSql}`).get(...params).count;

  const events = db.prepare(`
    SELECT * FROM url_events
    ${whereSql}
    ORDER BY timestamp DESC
    LIMIT ? OFFSET ?
  `).all(...params, limitNum, offset);

  res.json({
    events,
    pagination: {
      total: totalCount,
      page: pageNum,
      limit: limitNum,
      totalPages: Math.ceil(totalCount / limitNum)
    }
  });
};

router.get('/url-events', handleListEvents);
router.get('/', handleListEvents);

export default router;
