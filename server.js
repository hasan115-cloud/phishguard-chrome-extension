import express from 'express';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';
import { initDatabase, db } from './server/db.js';
import { broadcast } from './server/sse.js';
import { evaluatePhishing, extractUrlFeatures, TRUSTED_DEFAULT_DOMAINS } from './engine.js';

import authRoutes from './server/routes/auth.js';
import clientsRoutes from './server/routes/clients.js';
import securityRoutes from './server/routes/security.js';
import rulesRoutes from './server/routes/rules.js';
import alertsRoutes from './server/routes/alerts.js';
import incidentsRoutes from './server/routes/incidents.js';
import dashboardRoutes from './server/routes/dashboard.js';
import reportsRoutes from './server/routes/reports.js';
import auditLogsRoutes from './server/routes/auditLogs.js';
import settingsRoutes from './server/routes/settings.js';
import extensionRoutes from './server/routes/extension.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Initialize persistent SQLite database
initDatabase();

const app = express();
const PORT = process.env.SERVER_PORT || 3000;

// Security & Middleware
app.use(cors({ origin: '*', credentials: true }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Request logger for diagnostic tracing
app.use((req, res, next) => {
  if (req.path.startsWith('/api/') && req.path !== '/api/clients/heartbeat' && req.path !== '/api/dashboard/events-stream') {
    console.log(`[HTTP] ${req.method} ${req.path}`);
  }
  next();
});

// Health endpoint
app.get('/api/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptimeSeconds: Math.floor(process.uptime()),
    service: 'FortiNex Central Enterprise Platform'
  });
});

// Core Enterprise API Routes
app.use('/api/auth', authRoutes);
app.use('/api/clients', clientsRoutes);
app.use('/api/security', securityRoutes);
app.use('/api/url-events', securityRoutes);
app.use('/api/events', securityRoutes);
app.use('/api/extension', extensionRoutes);
app.use('/api/rules', rulesRoutes);
app.use('/api/alerts', alertsRoutes);
app.use('/api/incidents', incidentsRoutes);
app.use('/api/dashboard', dashboardRoutes);
app.use('/api/reports', reportsRoutes);
app.use('/api/audit-logs', auditLogsRoutes);
app.use('/api/settings', settingsRoutes);

// Backwards-compatible endpoints for extension popup / existing client calls
const trustedDomains = new Set([...TRUSTED_DEFAULT_DOMAINS]);

app.post('/api/scan', (req, res) => {
  const { url, trusted, clientId, systemName } = req.body;
  if (!url || typeof url !== 'string') {
    return res.status(400).json({ error: 'URL parameter is required' });
  }

  // Forward to central security check-url logic
  const now = new Date().toISOString();
  const activeClientId = clientId || 'CLIENT-WEB-SCANNER';
  const assignedName = systemName || 'Web Scanner';

  let clientRecord = db.prepare('SELECT * FROM clients WHERE client_id = ?').get(activeClientId);
  if (!clientRecord) {
    db.prepare(`
      INSERT INTO clients (
        client_id, system_name, hostname, os, browser,
        extension_version, first_seen, last_seen, status, ip_address, client_metadata
      ) VALUES (?, ?, 'web-host', 'Web Interface', 'Google Chrome', '1.4', ?, ?, 'ONLINE', '127.0.0.1', '{}')
    `).run(activeClientId, assignedName, now, now);
  }

  const combinedTrusted = Array.from(trustedDomains);
  if (Array.isArray(trusted)) {
    trusted.forEach(d => combinedTrusted.push(d));
  }

  const result = evaluatePhishing(url, combinedTrusted);

  // Check if administrative rules override
  const rules = db.prepare('SELECT * FROM rules WHERE enabled = 1 ORDER BY priority DESC').all();
  let finalVerdict = result.verdict;
  let finalReasons = [...(result.reasons || [])];
  let matchedRuleName = null;

  try {
    const u = new URL(url.startsWith('http') ? url : 'https://' + url);
    const domain = u.hostname.toLowerCase();

    for (const r of rules) {
      const p = r.pattern.toLowerCase();
      let matches = false;
      if (r.target_type === 'domain') {
        matches = domain === p || domain.endsWith('.' + p);
      } else if (p.includes('*')) {
        const regex = new RegExp('^' + p.replace(/\./g, '\\.').replace(/\*/g, '.*') + '$', 'i');
        matches = regex.test(domain) || regex.test(url);
      } else {
        matches = url.toLowerCase().includes(p);
      }

      if (matches) {
        if (r.type === 'BLOCK') finalVerdict = 'phishing';
        else if (r.type === 'WARNING') finalVerdict = 'suspicious';
        else if (r.type === 'ALLOW') finalVerdict = 'safe';
        matchedRuleName = r.pattern;
        finalReasons.unshift(`Matched policy rule: ${r.type} (${r.pattern})`);
        break;
      }
    }
  } catch {
    // fallback to heuristic
  }

  const decision = finalVerdict === 'phishing' ? 'BLOCK' : (finalVerdict === 'suspicious' ? 'WARNING' : 'ALLOW');
  const threatLevel = finalVerdict === 'phishing' ? 'HIGH' : (finalVerdict === 'suspicious' ? 'MEDIUM' : 'SAFE');

  // Insert URL event
  const eventId = 'ev-' + Date.now() + '-' + Math.random().toString(36).substring(2, 7);
  let domain = url;
  try {
    domain = new URL(url.startsWith('http') ? url : 'https://' + url).hostname;
  } catch {
    domain = url;
  }

  db.prepare(`
    INSERT INTO url_events (
      id, client_id, system_name, url, domain, timestamp,
      decision, threat_level, rule_id, rule_name, reason, browser_info
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, '{}')
  `).run(
    eventId,
    activeClientId,
    assignedName,
    url,
    domain,
    now,
    decision,
    threatLevel,
    matchedRuleName,
    finalReasons.join('; ')
  );

  broadcast('URL_EVENT', {
    id: eventId,
    clientId: activeClientId,
    systemName: assignedName,
    url,
    domain,
    timestamp: now,
    decision,
    threatLevel,
    reason: finalReasons.join('; ')
  });

  res.json({
    url: result.url,
    domain: result.domain,
    verdict: finalVerdict,
    score: result.score,
    reasons: finalReasons,
    features: result.features
  });
});

app.post('/api/batch-scan', (req, res) => {
  const { urls } = req.body;
  if (!Array.isArray(urls)) {
    return res.status(400).json({ error: 'urls array is required' });
  }
  const combinedTrusted = Array.from(trustedDomains);
  const results = urls.map(u => evaluatePhishing(u, combinedTrusted));
  res.json({ count: results.length, results });
});

app.post('/api/analyze-features', (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'URL is required' });
  const features = extractUrlFeatures(url);
  res.json(features);
});

app.get('/api/stats', (req, res) => {
  const urlStats = db.prepare(`
    SELECT
      COUNT(*) as total_scanned,
      SUM(CASE WHEN decision = 'BLOCK' THEN 1 ELSE 0 END) as phishing_blocked,
      SUM(CASE WHEN decision = 'WARNING' THEN 1 ELSE 0 END) as suspicious_flagged,
      SUM(CASE WHEN decision = 'ALLOW' THEN 1 ELSE 0 END) as safe_verified
    FROM url_events
  `).get();

  const clientCount = db.prepare('SELECT COUNT(*) as count FROM clients').get().count;

  res.json({
    totalScanned: urlStats.total_scanned || 0,
    phishingBlocked: urlStats.phishing_blocked || 0,
    suspiciousFlagged: urlStats.suspicious_flagged || 0,
    safeVerified: urlStats.safe_verified || 0,
    totalClients: clientCount,
    trustedCount: trustedDomains.size
  });
});

app.get('/api/trusted', (req, res) => {
  res.json({ trusted: Array.from(trustedDomains) });
});

app.post('/api/trust', (req, res) => {
  const { domain } = req.body;
  if (!domain) return res.status(400).json({ error: 'Domain is required' });
  trustedDomains.add(domain.toLowerCase().trim());
  res.json({ success: true, trusted: Array.from(trustedDomains) });
});

app.delete('/api/trust/:domain', (req, res) => {
  const domain = req.params.domain.toLowerCase().trim();
  trustedDomains.delete(domain);
  res.json({ success: true, trusted: Array.from(trustedDomains) });
});

app.get('/api/recent', (req, res) => {
  const events = db.prepare(`
    SELECT url, domain,
           CASE WHEN decision = 'BLOCK' THEN 'phishing'
                WHEN decision = 'WARNING' THEN 'suspicious'
                ELSE 'safe' END as verdict,
           CASE WHEN decision = 'BLOCK' THEN 95
                WHEN decision = 'WARNING' THEN 50
                ELSE 5 END as score,
           reason as reasons,
           timestamp
    FROM url_events
    ORDER BY timestamp DESC
    LIMIT 20
  `).all();

  res.json({ recent: events });
});

// Periodic background task to transition inactive clients to OFFLINE
setInterval(() => {
  try {
    const timeoutRow = db.prepare("SELECT value FROM system_config WHERE key = 'HEARTBEAT_TIMEOUT_SECONDS'").get();
    const timeoutSec = timeoutRow ? parseInt(timeoutRow.value, 10) || 90 : 90;
    const thresholdDate = new Date(Date.now() - (timeoutSec * 1000)).toISOString();

    const result = db.prepare(`
      UPDATE clients
      SET status = 'OFFLINE'
      WHERE status = 'ONLINE' AND last_seen < ?
    `).run(thresholdDate);

    if (result.changes > 0) {
      broadcast('CLIENT_STATUS_REFRESH', { offlineCount: result.changes });
    }
  } catch (err) {
    console.debug('Heartbeat audit note:', err.message);
  }
}, 30000);

// Serve static extension and web application files
app.use(express.static(__dirname));

// Primary route: Enterprise Security Dashboard & Hub
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Start listening on port 3000
app.listen(PORT, '0.0.0.0', () => {
  console.log(`[PhishGuard] Central Enterprise Security Server listening on http://0.0.0.0:${PORT}`);
});
